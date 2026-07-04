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

      previous = offline ? nil : Crosscheck.previous_stats(release_base_url)
      crosscheck_stats = Crosscheck.run(normalized, previous_stats: previous)

      compiled  = Compile.run(normalized, http: http, offline: offline)
      artifacts = Validate.run(compiled, previous_stats: previous)

      Publish.run(compiled, normalized, crosscheck_stats, artifacts, http: http)

      Env.log(format("pipeline complete in %.1fs", Time.now - started))
    rescue StageFailure => e
      Env.logger.error("PIPELINE FAILED: #{e.message}")
      exit 1
    end

    def release_base_url
      ENV.fetch("OPENASN_RELEASE_URL", "https://github.com/openasn/openasn/releases/latest/download/")
    end
  end
end

OpenASNPipeline::Run.call if $PROGRAM_NAME == __FILE__
