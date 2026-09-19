# frozen_string_literal: true

# The explicit release inventory (PRD §15.2): the one place that decides
# which bytes are part of a release.
#
# It replaces two globs that used to make that decision by accident:
#
#   Dir[File.join(DIST_DIR, "*")]          # everything in the directory got uploaded
#   Dir.children(DIST_DIR).sort            # everything in the directory got checksummed
#
# A glob answers "what is lying in this folder", which is a different
# question from "what did this build produce". The difference is not
# theoretical: the exports write a 59MB raw SQLite and a 70MB raw CSV as
# intermediate files, the Go writer leaves an `openasn.mmdb.candidate`
# behind when it fails, and the categories CSV is written through a `.tmp`
# name. Any of those landing in a release is either a private artifact
# published by mistake or a partial file presented as data. So nothing is
# uploaded, checksummed or mirrored unless a build stage REGISTERED it, by
# name, with the size and digest it expects that file to have.
#
# Envelopes are the two files that describe the others - manifest.json and
# SHA256SUMS. They are registered separately because they must travel with
# the release and must NOT appear inside `manifest.files` or inside
# SHA256SUMS: a file cannot honestly carry its own hash (PRD §15.2, and the
# existing convention that manifest.json is the checksum authority rather
# than one of the checksummed files).

require "digest"
require_relative "env"

module OpenASNPipeline
  class ReleaseAssets
    # manifest.json is the checksum authority and SHA256SUMS is its plain
    # text twin; the ORDER here is the publication order (PRD §16.1): the
    # manifest is always the last thing a consumer can see change.
    ENVELOPE_NAMES = %w[SHA256SUMS manifest.json].freeze

    # A release asset name is a bare file name that has to survive a URL, a
    # shell script, a `sha256sum -c` line and an `hf upload` staging copy.
    # Anything with a path separator, a leading dot or a space is rejected
    # here rather than quoted at four call sites.
    SAFE_NAME = /\A[A-Za-z0-9][A-Za-z0-9._-]*\z/

    # name/path/bytes/sha256/records plus the optional `export` block of
    # PRD §15.3. `records` is the LOGICAL count for that file: base ranges
    # for a native artifact, coalesced effective intervals for an export.
    Asset = Struct.new(:name, :path, :bytes, :sha256, :records, :export, keyword_init: true) do
      def manifest_entry
        entry = { name: name, sha256: sha256, bytes: bytes, records: records }
        entry[:export] = export if export
        entry
      end

      # "<lowercase sha256><two spaces><name>" - the sha256sum -c format.
      def checksum_line = "#{sha256}  #{name}"

      def export? = !export.nil?
    end

    attr_reader :root

    def initialize(root:)
      @root = File.expand_path(root)
      @payloads = []
      @envelopes = []
      @by_name = {}
    end

    # Adds one downloadable payload. `bytes`/`sha256` are the values the
    # producing stage believes it wrote; when they are given they are
    # CHECKED against the file on disk rather than trusted, which is what
    # catches a truncated write, a file replaced after validation, or a
    # descriptor that was carried across a move.
    def register(name:, path:, records:, export: nil, bytes: nil, sha256: nil)
      resolved = accept!(name, path)
      actual_bytes = File.size(resolved)
      if bytes && bytes != actual_bytes
        fail!("#{name} is #{actual_bytes} bytes on disk but was registered as #{bytes}; the file changed " \
              "after the stage that produced it measured it")
      end
      actual_sha = Digest::SHA256.file(resolved).hexdigest
      if sha256 && sha256 != actual_sha
        fail!("#{name} hashes to #{actual_sha} on disk but was registered as #{sha256}; the file changed " \
              "after the stage that produced it hashed it")
      end
      unless records.is_a?(Integer) && !records.negative?
        fail!("#{name} was registered with records=#{records.inspect}; a payload has a logical record count")
      end

      asset = Asset.new(name: name, path: resolved, bytes: actual_bytes, sha256: actual_sha,
                        records: records, export: export)
      @by_name[name] = asset
      @payloads << asset
      asset
    end

    # Adds manifest.json / SHA256SUMS. They are uploaded and mirrored, and
    # they are deliberately absent from `manifest_files` and `checksums`.
    def envelope(name:, path:)
      unless ENVELOPE_NAMES.include?(name)
        fail!("#{name} is not an envelope file; register it as a payload or do not register it at all")
      end

      resolved = accept!(name, path)
      asset = Asset.new(name: name, path: resolved, bytes: File.size(resolved),
                        sha256: Digest::SHA256.file(resolved).hexdigest, records: 0)
      @by_name[name] = asset
      @envelopes << asset
      asset
    end

    def payloads = @payloads.dup
    def payload_names = @payloads.map(&:name)
    def exports = @payloads.select(&:export?)
    def [](name) = @by_name[name]

    def manifest_files = @payloads.map(&:manifest_entry)

    # Sorted lexically by FILE NAME, self-excluding, LF-terminated.
    #
    # Sorting the finished lines instead would sort by SHA-256, because the
    # hash comes first on every line - a random order that changes completely
    # whenever any byte of any asset changes. PRD §15.2 asks for filename
    # order, and so does the `Dir.children(DIST_DIR).sort` this replaced, so
    # a reader diffing two nights of SHA256SUMS still sees one line move.
    def checksums = "#{@payloads.sort_by(&:name).map(&:checksum_line).join("\n")}\n"

    # The publication order of PRD §16.1: payloads, then SHA256SUMS, then
    # manifest.json. Manifest-last is what keeps a consumer that reads the
    # manifest first from ever being pointed at bytes that are not there yet.
    def upload_sequence
      missing = ENVELOPE_NAMES - @envelopes.map(&:name)
      fail!("the release is missing its envelope file(s): #{missing.join(', ')}") unless missing.empty?

      @payloads + ENVELOPE_NAMES.map { |name| @by_name.fetch(name) }
    end

    def upload_paths = upload_sequence.map(&:path)

    # What the HuggingFace mirror stages: every registered name, nothing
    # else. The mirror's own dataset card is added by the mirror script.
    def mirror_names = upload_sequence.map(&:name)

    # Re-reads every registered file and proves it is still exactly what was
    # registered. Called immediately before upload (PRD §16.1: "recompute
    # final payload hashes. Fail if any candidate has changed after
    # validation").
    def verify!
      (@payloads + @envelopes).each do |asset|
        fail!("#{asset.name} is gone from the candidate (#{asset.path})") unless File.file?(asset.path)

        bytes = File.size(asset.path)
        sha = Digest::SHA256.file(asset.path).hexdigest
        next if bytes == asset.bytes && sha == asset.sha256

        fail!("#{asset.name} changed after it was registered: #{asset.bytes} bytes/#{asset.sha256} became " \
              "#{bytes} bytes/#{sha}")
      end
      self
    end

    # The mode's required payload set (from the dataset's export-contract.json)
    # must be present EXACTLY. A missing one means a build that would publish
    # an incomplete generation; an extra one means an asset nobody declared.
    def require_exports!(names)
      have = exports.map(&:name).sort
      want = names.sort
      return self if have == want

      fail!("the export inventory is #{have.inspect} but this mode requires #{want.inspect}")
    end

    private

    def accept!(name, path)
      fail!("#{name.inspect} is not a usable release asset name") unless name.is_a?(String) && name.match?(SAFE_NAME)
      fail!("#{name} is already registered") if @by_name.key?(name)

      resolved = File.expand_path(path)
      unless resolved == File.join(@root, name) || resolved.start_with?("#{@root}#{File::SEPARATOR}")
        fail!("#{path} is outside the candidate root #{@root}; a release asset is a file this build wrote")
      end
      unless File.basename(resolved) == name
        fail!("#{path} would be published as #{name}; the file name and the asset name must be the same, or " \
              "SHA256SUMS would name a file that is not the one it hashed")
      end
      fail!("#{name} does not exist at #{resolved}") unless File.file?(resolved)

      resolved
    end

    def fail!(message) = Env.fail_stage!("release inventory: #{message}")
  end
end
