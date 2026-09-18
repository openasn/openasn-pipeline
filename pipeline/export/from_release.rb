# frozen_string_literal: true

# Reproduce the exports locally from an already published release
# (PRD §14, `rake exports:from_release[INPUT,OUTPUT]`).
#
# The use is a development and reproduction convenience: take a downloaded
# release directory, prove its native bytes are the ones its manifest
# describes, and run the same projection and writers over them. That is
# useful for bisecting a consumer bug against a specific dated release, and
# for reproducing an export without a full fetch.
#
# IT IS NOT A PUBLISHER, AND THE DIFFICULT PART IS MAKING THAT TRUE RATHER
# THAN MERELY STATED. A repackaged historical snapshot has not passed
# today's license gate, today's drift gate, or any crosscheck; it was
# unpacked from a directory. If its output could ever be picked up as a
# release candidate, then "download last week's release and re-export it"
# would be a route around every legal gate the project has. So:
#
#   * it refuses to run at all when PUBLISH=1 is set,
#   * it refuses to write into DIST_DIR or anywhere beneath it, so nothing
#     it produces can be mistaken for a build-produced release directory,
#   * it records the repository revisions as `unknown` rather than the
#     revisions of whatever happens to be checked out now, which is what
#     §10.2 requires for an archive-only input and which a publisher must
#     refuse (Metadata.nonpublishable_reasons),
#   * it drops a NOT-PUBLISHABLE marker naming the snapshot and the gates
#     that did not run, and
#   * it asserts, after the fact, that the metadata it produced is one a
#     publisher would reject. If that assertion ever fails, this task has
#     become a hole and stops instead.
#
# Verification before any of that: every input the exports need must be
# named in the manifest AND present AND match its recorded size and digest,
# the two OASN files must carry the same build timestamp as each other and
# as the manifest, OORG must validate structurally, and the source
# catalogue must come through from the manifest rather than be invented.

require "digest"
require "json"
require "time"
require_relative "../lib/env"
require_relative "inputs"
require_relative "metadata"
require_relative "run"
require_relative "sqlite"

module OpenASNPipeline
  module Export
    module FromRelease
      # What an export needs, which is more than a native client needs:
      # OORG is optional for readers and mandatory here, and ATTRIBUTION.md
      # is embedded verbatim in the metadata, so it has to be the SNAPSHOT's
      # attribution rather than whatever the data repo says today.
      REQUIRED_INPUTS = %w[openasn-ipv4.bin openasn-ipv6.bin openasn-orgs.bin ATTRIBUTION.md].freeze
      MARKER = "NOT-PUBLISHABLE.txt"

      Result = Struct.new(:build_id, :input, :output, :run, :marker, :nonpublishable_reasons,
                          keyword_init: true)

      module_function

      def call(input:, output:, mode: "portable")
        refuse_publication!
        refuse_dist!(output)

        manifest = read_manifest(input)
        paths = verify_inputs!(manifest, input)
        snapshot = Inputs.load(v4_path: paths.fetch("openasn-ipv4.bin"),
                               v6_path: paths.fetch("openasn-ipv6.bin"),
                               orgs_path: paths.fetch("openasn-orgs.bin"))
        build_id = verify_build_identity!(manifest, snapshot, input)

        context = Metadata.archive_context(
          snapshot: snapshot,
          sources: verify_sources!(manifest, input),
          attribution: File.read(paths.fetch("ATTRIBUTION.md")),
          producer: Metadata.producer_versions(python: Sqlite.interpreter)
        )

        FileUtils.mkdir_p(output)
        marker = write_marker(output, build_id: build_id, input: input)
        result = Run.call(snapshot: snapshot, context: context, staging: output, mode: mode)

        reasons = assert_nonpublishable!(output, mode: mode)
        Env.warn("exports:from_release: #{build_id} reproduced into #{output}. NOT PUBLISHABLE: " \
                 "#{reasons.join('; ')}. See #{MARKER}.")

        Result.new(build_id: build_id, input: input, output: output, run: result, marker: marker,
                   nonpublishable_reasons: reasons)
      end

      def refuse_publication!
        return unless ENV["PUBLISH"] == "1"

        Env.fail_stage!("exports:from_release repackages an archived snapshot and cannot be published: it " \
                        "passed no license gate, no drift gate and no crosscheck. Unset PUBLISH and run the " \
                        "real pipeline if you mean to publish.")
      end

      # Writing into build/dist would put unvalidated files where the
      # release inventory looks. Refuse the directory and everything under
      # it rather than trusting a later stage to notice.
      def refuse_dist!(output)
        dist = File.expand_path(DIST_DIR)
        target = File.expand_path(output)
        return unless target == dist || target.start_with?("#{dist}#{File::SEPARATOR}")

        Env.fail_stage!("exports:from_release refuses to write into #{DIST_DIR}: its output is a local " \
                        "reproduction, not a release candidate. Choose a directory outside build/dist.")
      end

      def read_manifest(input)
        path = File.join(input, "manifest.json")
        unless File.file?(path)
          Env.fail_stage!("#{input} has no manifest.json, so there is nothing to verify these bytes against. " \
                          "Point this task at an unpacked release directory.")
        end
        JSON.parse(File.read(path))
      rescue JSON::ParserError => e
        Env.fail_stage!("#{path} is not valid JSON: #{e.message}")
      end

      # Every required input must be NAMED in the manifest, PRESENT on
      # disk, and match the size and digest recorded for it. A release that
      # predates one of them fails here by name, which is the common first
      # encounter: openasn-orgs.bin is younger than the artifacts it sits
      # beside, and an export without it would ship 574k null org names.
      def verify_inputs!(manifest, input)
        entries = Array(manifest["files"]).to_h { |file| [file["name"], file] }
        build_id = manifest["build_id"] || "unknown build"

        REQUIRED_INPUTS.to_h do |name|
          entry = entries[name]
          if entry.nil?
            Env.fail_stage!("release #{build_id} lists no #{name} in manifest.json: this snapshot does not " \
                            "carry an input the exports require. Use a release that does; do not substitute " \
                            "a file from another build.")
          end
          path = File.join(input, name)
          unless File.file?(path)
            Env.fail_stage!("release #{build_id} lists #{name} but #{path} is missing from the directory")
          end

          bytes = File.size(path)
          unless bytes == entry["bytes"]
            Env.fail_stage!("#{name}: #{bytes} bytes on disk, manifest says #{entry['bytes'].inspect}")
          end
          digest = Digest::SHA256.file(path).hexdigest
          unless digest == entry["sha256"]
            Env.fail_stage!("#{name}: sha256 #{digest} does not match the manifest's #{entry['sha256'].inspect}. " \
                            "These are not the bytes this release published.")
          end
          [name, path]
        end
      end

      # Inputs.load already refuses two OASN files with different build
      # timestamps. This adds the third party to the agreement: the manifest
      # that claims to describe them.
      def verify_build_identity!(manifest, snapshot, input)
        build_id = manifest["build_id"]
        unless build_id.is_a?(String) && !build_id.empty?
          Env.fail_stage!("#{input}/manifest.json has no build_id")
        end

        artifact_id = Time.at(snapshot.build_ts).utc.iso8601
        unless build_id == artifact_id
          Env.fail_stage!("manifest.json says build #{build_id} but the artifacts carry #{artifact_id}. " \
                          "This directory mixes a manifest with another build's bytes.")
        end
        build_id
      end

      # Carried through, never reconstructed: the pins and fetch timestamps
      # that belong to THIS snapshot are the ones in its own manifest, and
      # today's pin file describes today.
      def verify_sources!(manifest, input)
        sources = manifest["sources"]
        unless sources.is_a?(Array) && !sources.empty?
          Env.fail_stage!("#{input}/manifest.json has no sources array; an export cannot invent the source " \
                          "provenance of a snapshot it did not build")
        end
        sources.each_with_index do |source, index|
          next if source.is_a?(Hash) && source["id"].is_a?(String) && source["license"].is_a?(String)

          Env.fail_stage!("#{input}/manifest.json sources[#{index}] has no id/license: #{source.inspect}")
        end
        sources
      end

      def write_marker(output, build_id:, input:)
        path = File.join(output, MARKER)
        File.write(path, <<~TEXT)
          These exports are a LOCAL REPRODUCTION and must not be published.

          They were rebuilt by `rake exports:from_release` from the already
          published snapshot #{build_id}, unpacked at:

              #{File.expand_path(input)}

          Its native bytes were verified against that release's manifest.json
          (size and SHA-256), and the two OASN files agree with each other and
          with the manifest on the build timestamp.

          What did NOT run, and therefore what these files cannot claim:

            * the upstream license gate (no license hash was checked today)
            * the drift gates and the crosscheck stage
            * any fetch of upstream data

          The metadata records both repository revisions as `unknown`, because
          the inputs came out of an archive rather than out of a checkout, and
          `working_tree_dirty` as `true`. A publisher must refuse both.
        TEXT
        path
      end

      # The guarantee, checked rather than asserted in prose: the metadata
      # this task just wrote is one a publisher rejects.
      def assert_nonpublishable!(output, mode:)
        return ["export mode #{mode}"] if mode == "none"

        meta = JSON.parse(File.read(File.join(output, Run::METADATA_NAME)))
        reasons = Metadata.nonpublishable_reasons(meta)
        if reasons.empty?
          Env.fail_stage!("exports:from_release produced metadata a publisher would ACCEPT. That is a hole: " \
                          "a repackaged snapshot must never be publishable. Refusing to leave it in place.")
        end
        reasons
      end
    end
  end
end
