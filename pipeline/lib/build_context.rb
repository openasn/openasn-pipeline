# frozen_string_literal: true

# One build identity for one run (PRD §9, §15.1).
#
# Before this existed, the answer to "when was this built, from which
# revisions, into which directory" was computed three times: compile took
# `Time.now`, publish re-derived the build id from it, and the export
# metadata asked git a second time on its own. Three answers that agree
# today are three answers that can disagree on the night a build straddles
# midnight or a checkout moves under a long run, and the disagreement would
# be published as provenance.
#
# So the timestamp, both repository revisions, the dirty flag, the staging
# directories and the source catalogue are decided ONCE, here, and every
# later stage is handed this object. In particular the source catalogue
# (Publish.source_provenance) is built once and shared by the SQLite `meta`
# table, the MMDB description and the final manifest, because "the same
# list" built twice is two lists.
#
# The build works in a FRESH directory it owns, never in build/dist. A
# release inventory assembled in a directory that survives between runs can
# pick up last night's file; a directory created per build cannot. build/dist
# is a promotion target for operator inspection, reached only after the
# candidate assembled successfully.

require "fileutils"
require "time"
require_relative "env"
require_relative "../export/metadata"

module OpenASNPipeline
  class BuildContext
    attr_reader :build_ts, :build_id, :candidate_dir, :export_dir,
                :data_repo_commit, :pipeline_repo_commit, :working_tree_dirty, :mode

    # `publishing` only tightens the provenance rules: an unreadable git
    # revision is a warning locally and a stage failure when the build
    # intends to upload (PRD §10.2).
    def self.create(mode:, build_ts: Time.now.to_i, publishing: ENV["PUBLISH"] == "1", root: WORK_DIR)
      build_id = Time.at(build_ts).utc.iso8601
      generation = build_id.tr(":", "-")

      new(build_ts: build_ts, mode: mode,
          candidate_dir: File.join(root, "candidate", generation),
          export_dir: File.join(root, "export", generation),
          data_repo_commit: Export::Metadata.repo_commit(Env.data_repo, "data repo", publishing: publishing),
          pipeline_repo_commit: Export::Metadata.repo_commit(ROOT, "pipeline repo", publishing: publishing),
          working_tree_dirty: Export::Metadata.dirty?(Env.data_repo) || Export::Metadata.dirty?(ROOT))
    end

    def initialize(build_ts:, mode:, candidate_dir:, export_dir:,
                   data_repo_commit:, pipeline_repo_commit:, working_tree_dirty:)
      @build_ts = build_ts
      @build_id = Time.at(build_ts).utc.iso8601
      @mode = mode
      @candidate_dir = File.expand_path(candidate_dir)
      @export_dir = File.expand_path(export_dir)
      @data_repo_commit = data_repo_commit
      @pipeline_repo_commit = pipeline_repo_commit
      @working_tree_dirty = working_tree_dirty
      @sources = nil
    end

    # Creates the candidate directory and refuses a dirty one. An existing
    # non-empty candidate means two builds are sharing a generation, and the
    # second one would inherit the first one's files.
    def prepare!
      sweep_previous_generations!
      if File.directory?(@candidate_dir) && !Dir.children(@candidate_dir).empty?
        Env.fail_stage!("candidate directory #{@candidate_dir} already exists and is not empty; a build " \
                        "assembles its release in a directory it created")
      end
      FileUtils.mkdir_p(@candidate_dir)
      self
    end

    # A build leaves roughly 350MB of export intermediates behind (the JSONL
    # spool, the raw CSV, the raw SQLite). They are worth keeping right
    # after a build, for `rake exports:validate` and for a local install,
    # and they are worthless the moment the next build starts - so a
    # starting build sweeps the PREVIOUS generations rather than growing the
    # workspace by a third of a gigabyte per night. Only directories named
    # like a generation are touched, and never this build's own.
    GENERATION = /\A\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z\z/

    def sweep_previous_generations!
      [@candidate_dir, @export_dir].each do |dir|
        parent = File.dirname(dir)
        next unless File.directory?(parent)

        Dir.children(parent).each do |child|
          next if child == File.basename(dir) || !child.match?(GENERATION)

          FileUtils.rm_rf(File.join(parent, child))
        end
      end
    end

    # Built once (run.rb calls Publish.source_provenance), read everywhere.
    def sources=(value)
      Env.fail_stage!("the source catalogue is built once per build") unless @sources.nil?

      @sources = value
    end

    def sources
      return @sources if @sources

      Env.fail_stage!("the source catalogue has not been built yet; it must exist before any export metadata")
    end

    # The three provenance values a publisher gates on, in the exact string
    # encoding Export::Metadata uses, so that one function
    # (Metadata.nonpublishable_reasons) answers "is this good enough to
    # release" for an export-carrying build and a native-only build alike.
    def provenance
      { "data_repo_commit" => @data_repo_commit,
        "pipeline_repo_commit" => @pipeline_repo_commit,
        "working_tree_dirty" => @working_tree_dirty.to_s }
    end

    # The export metadata context, carrying THIS build's identity rather
    # than asking git again. The snapshot's build timestamp is the one
    # compile stamped into the bytes; if it ever disagreed with this build's
    # identity the export would describe a different build than the manifest.
    def export_context(snapshot:, producer:, attribution: File.read(Env.attribution_path))
      unless snapshot.build_ts == @build_ts
        Env.fail_stage!("the compiled artifacts carry build_ts #{snapshot.build_ts} but this build is " \
                        "#{@build_ts}; the exports would describe a different build than the manifest")
      end

      Export::Metadata::Context.new(
        build_id: @build_id, build_unix_ts: @build_ts, sources: sources, attribution: attribution,
        producer: producer, data_repo_commit: @data_repo_commit,
        pipeline_repo_commit: @pipeline_repo_commit, working_tree_dirty: @working_tree_dirty
      )
    end

    # Promotes the assembled candidate to build/dist for operator
    # inspection. The swap keeps the previous dist until the new one is in
    # place, so a failure at any point leaves a complete directory behind
    # rather than half of two builds.
    def promote!(dest: DIST_DIR)
      target = File.expand_path(dest)
      previous = "#{target}.previous"
      FileUtils.rm_rf(previous)
      FileUtils.mkdir_p(File.dirname(target))
      File.rename(target, previous) if File.directory?(target)

      begin
        File.rename(@candidate_dir, target)
      rescue SystemCallError => e
        File.rename(previous, target) if File.directory?(previous) && !File.exist?(target)
        Env.fail_stage!("could not promote #{@candidate_dir} to #{target} (#{e.message}); the candidate is " \
                        "intact where it is and the previous #{File.basename(target)} was restored")
      end
      FileUtils.rm_rf(previous)
      Env.log("build: candidate promoted to #{target}")
      target
    end
  end
end
