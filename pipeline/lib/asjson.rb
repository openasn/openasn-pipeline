# frozen_string_literal: true

# Reader for ipverse/as-metadata's as.json: ~69MB, a single top-level JSON
# array with one object per assigned ASN (123k+ entries).
#
# The file is too big to naively slurp on a memory-constrained runner, so:
#
#   1. `jq` binary (if on PATH) - `jq -c '.[]'` re-emits the array as NDJSON
#      which we parse line by line; peak memory stays flat. jq is
#      preinstalled on all GitHub-hosted runners
#      (https://github.com/actions/runner-images), so CI always takes this
#      path, and it's a one-liner brew/apt install locally.
#   2. stdlib JSON.parse of the whole file - correctness fallback for dev
#      machines without jq. Peak RSS is roughly 10-15x file size in Ruby
#      objects; fine on a laptop, logged loudly so nobody is surprised.
#
# (A third option, Oj in SAJ mode, was considered and skipped: it would be
# an untested branch on both CI and the reference dev machine. Add it only
# if someone actually hits a memory wall without jq.)
#
# We reduce every entry to exactly the fields the pipeline needs and discard
# the rest immediately - the working set after this reader is a few hashes
# of Integers/short Strings, not 123k parsed JSON objects.
#
# Empirical schema (verified against live data 2026-07-04):
#   { "asn": 13335,
#     "metadata": { "handle": "...", "description": "Cloudflare, Inc.",
#                   "countryCode": "US", "country": "United States",
#                   "origin": "authoritative", "category": "hosting",
#                   "networkRole": "content_network",
#                   "registered": "YYYY-MM-DD", "lastModified": ... },
#     "stats": {...} | null, "lastAnnounced": ... }
# `category`/`networkRole` exist ONLY here, not in as.csv (its header is
# asn,handle,description,country-code - no category), and only since
# 2026-02-08. Young, single-maintainer data: that's what crosscheck.rb and
# data/overrides/ are for. Note `registered`/`lastModified` are DATE-ONLY
# strings since 2026-03-04 - never parse them as datetimes.

require "json"
require "open3"
require_relative "env"

module OpenASNPipeline
  module AsJson
    # Category/role integer codes are part of the artifact format (FORMAT.md,
    # flags bits 0-3 / 4-7). nil means "no category assigned by upstream".
    CATEGORY_CODES = {
      nil => 0, "isp" => 1, "hosting" => 2, "business" => 3,
      "education_research" => 4, "government_admin" => 5
    }.freeze
    ROLE_CODES = {
      nil => 0, "tier1_transit" => 1, "major_transit" => 2, "midsize_transit" => 3,
      "access_provider" => 4, "content_network" => 5, "stub" => 6
    }.freeze

    CATEGORY_NAMES = CATEGORY_CODES.invert.freeze
    ROLE_NAMES     = ROLE_CODES.invert.freeze

    Record = Struct.new(:asn, :description, :country, :category, :network_role)

    module_function

    # Yields Record structs. Returns the count of entries processed.
    def each_record(path, &block)
      strategy = jq_available? ? :jq : :stdlib
      Env.log("as.json parse strategy: #{strategy}")
      count = strategy == :jq ? parse_with_jq(path, &block) : parse_with_stdlib(path, &block)
      # 123,392 ASNs measured 2026-07-04; the floor catches upstream
      # truncation or a schema change that yields empty records.
      Env.fail_stage!("as.json produced only #{count} ASNs - upstream truncated or schema changed") if count < 90_000
      count
    end

    def jq_available?
      system("jq --version", out: File::NULL, err: File::NULL)
    end

    def parse_with_jq(path)
      count = 0
      Open3.popen2("jq", "-c", ".[]", path) do |_stdin, stdout, wait_thr|
        stdout.each_line do |line|
          yield to_record(JSON.parse(line))
          count += 1
        end
        Env.fail_stage!("jq failed while splitting as.json") unless wait_thr.value.success?
      end
      count
    end

    def parse_with_stdlib(path)
      Env.warn("parsing #{File.size(path) / 1_000_000}MB as.json with stdlib JSON.parse - " \
               "expect a transient multi-GB RSS spike; `brew install jq` / `apt install jq` to avoid")
      entries = JSON.parse(File.read(path))
      entries.each { |e| yield to_record(e) }
      entries.length
    end

    def to_record(e)
      meta = e["metadata"] || {}
      Record.new(
        e["asn"],
        meta["description"] || meta["handle"],
        meta["countryCode"],
        meta["category"],
        meta["networkRole"]
      )
    end
  end
end
