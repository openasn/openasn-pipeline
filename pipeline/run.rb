# frozen_string_literal: true

# The nightly build, end to end (PRD §15.1):
#
#   fetch -> license gate -> normalize -> crosscheck -> compile native
#     -> validate native -> prepare catalog/docs/provenance -> project/spool
#     -> export writers -> validate exports -> assemble manifest/checksums
#     -> validate the complete candidate -> optional publish
#
#   ruby pipeline/run.rb            # full build into build/dist/
#   OFFLINE=1 ruby pipeline/run.rb  # rebuild from cache (dev iteration; gates
#                                   # that need the network are skipped LOUDLY)
#   PUBLISH=1 ruby pipeline/run.rb  # + upload to the rolling `latest` release
#   OPENASN_EXPORTS=none|portable|all
#                                   # which portable exports to build; the
#                                   # default is whatever the data repo's
#                                   # export-contract.json requires
#
# THE BUILD ASSEMBLES IN A DIRECTORY IT OWNS, not in build/dist. build/dist
# survives between runs, so a release assembled there inherits whatever the
# last run (or a crashed tool, or an operator) left behind. Each run creates
# build/work/candidate/<build_id>, compiles into it, and promotes it to
# build/dist only after the candidate validated - so build/dist is the last
# GOOD build rather than a pile of every build.
#
# Exit codes: 0 success, 1 gate/stage failure (message on stderr). CI treats
# any nonzero as a failed nightly and opens/updates an issue (build.yml).

require_relative "lib/env"
require_relative "lib/build_context"
require_relative "lib/http"
require_relative "lib/license_gate"
require_relative "lib/overrides"
require_relative "lib/drift_gate"
require_relative "export/inputs"
require_relative "export/mode"
require_relative "export/run"
require_relative "fetch"
require_relative "normalize"
require_relative "crosscheck"
require_relative "compile"
require_relative "validate"
require_relative "publish"

module OpenASNPipeline
  module Run
    module_function

    def call
      started = Time.now
      offline = ENV["OFFLINE"] == "1"
      publishing = ENV["PUBLISH"] == "1"
      http    = Http.new

      Env.log("OpenASN pipeline starting#{offline ? ' (OFFLINE)' : ''}")

      paths = Fetch.run(http: http, offline: offline)
      LicenseGate.run(http: http, offline: offline)

      normalized = Normalize.run(paths)

      # Drift-gate references (both skipped offline, loudly): the previous
      # published build (rolling `latest`) and the two most recent weekly
      # pins - the long-run baseline that makes a recovery distinguishable
      # from a catastrophe (lib/drift_gate.rb; DECISIONS.md D-GATE-1).
      if offline
        Env.warn("OFFLINE: previous-manifest and weekly-pin fetches skipped - drift gates (crosscheck, G4) will SKIP")
        previous = nil
        baselines = []
      else
        previous  = Crosscheck.previous_stats(release_base_url)
        baselines = Crosscheck.baseline_stats(release_root_url)
      end
      if DriftGate.normalize_ack(ENV[DriftGate::ACK_ENV])
        Env.warn("#{DriftGate::ACK_ENV} is set (#{ENV[DriftGate::ACK_ENV].strip.inspect}): a drift FAIL this run " \
                 "becomes a WARN and the reason is stamped into manifest.json")
      end
      crosscheck_stats = Crosscheck.run(normalized, previous_stats: previous, baseline_stats: baselines)

      # One build identity for every later stage: the timestamp compile
      # stamps into the bytes, both repository revisions, the dirty flag,
      # the candidate directory and (below) the source catalogue.
      mode    = Export::Mode.resolve(publishing: publishing)
      context = BuildContext.create(mode: mode, publishing: publishing).prepare!
      Env.log("build #{context.build_id}: assembling in #{context.candidate_dir}")

      compiled  = Compile.run(normalized, http: http, offline: offline,
                              dest: context.candidate_dir, build_ts: context.build_ts)
      artifacts = Validate.run(compiled, previous_stats: previous, baseline_stats: baselines)

      assemble_and_publish(context: context, compiled: compiled, normalized: normalized,
                           artifacts: artifacts, crosscheck_stats: crosscheck_stats,
                           http: http, publishing: publishing)
      context.promote!

      Env.log(format("pipeline complete in %.1fs", Time.now - started))
    rescue StageFailure => e
      Env.logger.error("PIPELINE FAILED: #{e.message}")
      exit 1
    end

    # Everything from the prepared catalog to the uploader, as one sequence.
    # The order is the safety property and is unit-tested as such: a failure
    # anywhere in it - an export writer, the assembler, the candidate gate -
    # raises before `Publish.publish!` is ever reached, so no partial
    # generation can be uploaded (PRD §19.4 U20/U21).
    def assemble_and_publish(context:, compiled:, normalized:, artifacts:, crosscheck_stats:, http:,
                             publishing: ENV["PUBLISH"] == "1")
      Publish.prepare(normalized, compiled, dir: context.candidate_dir)
      context.sources = Publish.source_provenance(context.build_id, http)

      exports = export!(context: context, compiled: compiled)
      manifest, registry = Publish.assemble(context: context, compiled: compiled, artifacts: artifacts,
                                            crosscheck_stats: crosscheck_stats, exports: exports)
      Validate.candidate!(registry: registry, manifest: manifest, mode: context.mode,
                          dir: context.candidate_dir)

      Publish.publish!(manifest, registry, context: context, exports: exports, publishing: publishing)
      [manifest, registry, exports]
    end

    # The portable exports, read from the bytes this build just compiled and
    # validated - not from build/dist, not from a download. Returns nil in
    # mode `none`, which is the only mode that produces no export at all.
    def export!(context:, compiled:)
      return nil unless context.mode.exports?

      snapshot = Export::Inputs.load(v4_path: compiled[:v4_path], v6_path: compiled[:v6_path],
                                     orgs_path: compiled[:orgs_path])
      export_context = context.export_context(snapshot: snapshot,
                                              producer: Export::Run.producer(mode: context.mode.selected))
      Export::Run.call(snapshot: snapshot, context: export_context,
                       staging: context.export_dir, mode: context.mode.selected)
    end

    # Where crosscheck fetches the PREVIOUS build's manifest for the
    # day-over-day delta gates. Tag-addressed on purpose - the badge-form
    # `releases/latest/download/...` resolves via GitHub's "Latest" badge,
    # which a weekly dated snapshot stole once (2026-07-05); the delta gates
    # would then quietly diff against a week-old manifest and a real ±20%
    # overnight swing could slip through. Full write-up: pipeline/publish.rb
    # ("Latest badge semantics") and data-repo DECISIONS.md D-REL-1.
    def release_base_url
      ENV.fetch("OPENASN_RELEASE_URL", "#{release_root_url}latest/")
    end

    # Root of the tag-addressed download URLs; weekly pins are fetched as
    # "#{release_root_url}vYYYY.MM.DD/manifest.json".
    def release_root_url
      ENV.fetch("OPENASN_RELEASE_ROOT", "https://github.com/#{PUBLISH_REPO}/releases/download/")
    end
  end
end

OpenASNPipeline::Run.call if $PROGRAM_NAME == __FILE__
