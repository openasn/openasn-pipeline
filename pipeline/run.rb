# frozen_string_literal: true

# The nightly build, end to end:
#
#   fetch -> license gate -> normalize -> crosscheck -> compile -> validate -> publish
#
#   ruby pipeline/run.rb            # full build into build/dist/
#   OFFLINE=1 ruby pipeline/run.rb  # rebuild from cache (dev iteration; gates
#                                   # that need the network are skipped LOUDLY)
#   PUBLISH=1 ruby pipeline/run.rb  # + upload to the rolling `latest` release
#
# Exit codes: 0 success, 1 gate/stage failure (message on stderr). CI treats
# any nonzero as a failed nightly and opens/updates an issue (build.yml).

require_relative "lib/env"
require_relative "lib/http"
require_relative "lib/license_gate"
require_relative "lib/overrides"
require_relative "lib/drift_gate"
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

      compiled  = Compile.run(normalized, http: http, offline: offline)
      artifacts = Validate.run(compiled, previous_stats: previous, baseline_stats: baselines)

      Publish.run(compiled, normalized, crosscheck_stats, artifacts, http: http)

      Env.log(format("pipeline complete in %.1fs", Time.now - started))
    rescue StageFailure => e
      Env.logger.error("PIPELINE FAILED: #{e.message}")
      exit 1
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
