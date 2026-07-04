# frozen_string_literal: true

# Shared environment for all pipeline stages: canonical paths, logging, and
# the handful of constants that must match the artifact format spec.
#
# TWO-REPO LAYOUT (since the 2026-07 split): this repo is the COMPILER;
# the curated inputs and published spec live in the open data repo,
# github.com/openasn/openasn. The pipeline resolves that checkout at run
# time (never at require time — unit tests must run without it):
#
#   1. ENV["OPENASN_DATA_REPO"] — explicit path (CI sets this)
#   2. ../openasn sibling checkout — the local-dev convention
#      (~/GitHub/openasn-pipeline next to ~/GitHub/openasn)
#
# From the data repo we read:  data/overrides/, data/licenses/,
# spotchecks.yml, fetch-manifest.json, ATTRIBUTION.md.
# Everything under THIS repo's build/ is disposable workspace:
#   build/cache/  - raw upstream downloads (+ etag state), kept between runs
#   build/work/   - intermediate files for the current run
#   build/dist/   - artifacts published to the DATA repo's GitHub Release
#
# Ruby: stdlib only (see README). `jq` is used for the ~69MB ipverse
# as.json when available (see lib/asjson.rb for the fallback chain).

require "fileutils"
require "json"
require "logger"
require "time"

module OpenASNPipeline
  ROOT      = File.expand_path("../..", __dir__)
  BUILD_DIR = File.join(ROOT, "build")
  CACHE_DIR = File.join(BUILD_DIR, "cache")
  WORK_DIR  = File.join(BUILD_DIR, "work")
  DIST_DIR  = File.join(BUILD_DIR, "dist")

  # The GitHub repo whose Releases receive the artifacts — the public
  # flagship. Overridable for forks/staging (OPENASN_PUBLISH_REPO).
  PUBLISH_REPO = ENV.fetch("OPENASN_PUBLISH_REPO", "openasn/openasn")

  # Sent on every outbound request. Some upstreams 403 UA-less clients
  # (crates.io did during the naming research; assume others do too).
  USER_AGENT = "openasn-pipeline/1.0 (+https://github.com/openasn/openasn)"

  # Artifact identity. Must stay in sync with the reader in the `openasn`
  # gem (openasn/openasn-ruby: lib/openasn/binary_format.rb) and the format
  # spec in the data repo's FORMAT.md. Bump FORMAT_VERSION on any
  # byte-layout change.
  MAGIC          = "OASN"
  FORMAT_VERSION = 0x01

  # Pipeline failures are always loud. Stages raise StageFailure with an
  # actionable message; run.rb turns that into a non-zero exit for CI.
  class StageFailure < StandardError; end

  module Env
    module_function

    def prepare_dirs!
      [CACHE_DIR, WORK_DIR, DIST_DIR].each { |d| FileUtils.mkdir_p(d) }
    end

    # Resolved lazily and memoized; raises with setup instructions when the
    # data repo can't be found (only when a stage actually needs it, so the
    # unit tests never require a data checkout).
    def data_repo
      @data_repo ||= begin
        candidates = [ENV["OPENASN_DATA_REPO"], File.expand_path("../openasn", ROOT)].compact
        found = candidates.find { |p| File.directory?(File.join(p, "data", "overrides")) }
        unless found
          fail_stage!(
            "cannot find the openasn data repo (looked at: #{candidates.join(', ')}). " \
            "Clone github.com/openasn/openasn as a SIBLING of this repo, or set OPENASN_DATA_REPO=/path/to/openasn"
          )
        end
        found
      end
    end

    def overrides_dir       = File.join(data_repo, "data", "overrides")
    def licenses_dir        = File.join(data_repo, "data", "licenses")
    def spotchecks_path     = File.join(data_repo, "spotchecks.yml")
    def fetch_manifest_path = File.join(data_repo, "fetch-manifest.json")
    def attribution_path    = File.join(data_repo, "ATTRIBUTION.md")

    def logger
      @logger ||= Logger.new($stdout).tap do |l|
        l.level = ENV["OPENASN_DEBUG"] ? Logger::DEBUG : Logger::INFO
        l.formatter = proc do |severity, datetime, _progname, msg|
          "#{datetime.utc.strftime('%H:%M:%S')} [#{severity}] #{msg}\n"
        end
      end
    end

    def log(msg)  = logger.info(msg)
    def warn(msg) = logger.warn(msg)

    def fail_stage!(msg)
      raise StageFailure, msg
    end
  end
end
