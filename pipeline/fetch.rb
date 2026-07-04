# frozen_string_literal: true

# Stage 1: fetch all Tier A inputs into build/cache/.
#
# Every download is a conditional GET (ETag/If-Modified-Since) with
# keep-last-good fallback, so a flaky upstream degrades to yesterday's data
# instead of killing the nightly build. See lib/http.rb for the semantics.
#
# Run standalone:  ruby pipeline/fetch.rb        (or: rake fetch)
# Offline mode:    OFFLINE=1 ruby pipeline/fetch.rb  (requires warm cache)

require_relative "lib/env"
require_relative "lib/http"
require_relative "lib/sources"

module OpenASNPipeline
  module Fetch
    # Cache keys are stable identifiers; the artifact manifest records the
    # fetched_at + sha256 of each so every published build is traceable to
    # exact input bytes.
    KEYS = {
      sapics_v4: "sapics/origin-asn-ipv4-num.csv",
      sapics_v6: "sapics/origin-asn-ipv6-num.csv",
      as_json: "ipverse/as.json",
      x4b_vpn: "x4bnet/vpn-ipv4.txt",
      x4b_dc: "x4bnet/datacenter-ipv4.txt",
      x4b_vpn_asn: "x4bnet/input-vpn-ASN.txt",
      x4b_dc_asn: "x4bnet/input-datacenter-ASN.txt",
      bad_asn: "brianhama/bad-asn-list.csv"
    }.freeze

    module_function

    def run(http: Http.new, offline: ENV["OFFLINE"] == "1")
      Env.prepare_dirs!
      paths = {}

      sapics = Sources.resolve_sapics_urls(http) unless offline
      sapics ||= Sources::SAPICS_FALLBACK
      paths[:sapics_v4] = http.fetch(sapics["origin-asn-ipv4-num.csv"], KEYS[:sapics_v4], offline: offline)
      paths[:sapics_v6] = http.fetch(sapics["origin-asn-ipv6-num.csv"], KEYS[:sapics_v6], offline: offline)

      paths[:as_json] = http.fetch(Sources::IPVERSE_AS_JSON_URL, KEYS[:as_json], offline: offline)

      paths[:x4b_vpn]     = http.fetch(Sources::X4B_VPN_URL, KEYS[:x4b_vpn], offline: offline)
      paths[:x4b_dc]      = http.fetch(Sources::X4B_DC_URL, KEYS[:x4b_dc], offline: offline)
      paths[:x4b_vpn_asn] = http.fetch(Sources::X4B_VPN_ASN_URL, KEYS[:x4b_vpn_asn], offline: offline)
      paths[:x4b_dc_asn]  = http.fetch(Sources::X4B_DC_ASN_URL, KEYS[:x4b_dc_asn], offline: offline)

      paths[:bad_asn] = http.fetch(Sources::BAD_ASN_URL, KEYS[:bad_asn], offline: offline)

      # Cheap sanity floor: catch an upstream serving an error page / empty
      # body with HTTP 200 before we waste a build on it. Real validation
      # gates run later (validate.rb); this is just "is it plausibly data".
      min_bytes = { sapics_v4: 5_000_000, sapics_v6: 1_000_000, as_json: 10_000_000,
                    x4b_vpn: 50_000, x4b_dc: 200_000, x4b_vpn_asn: 100,
                    x4b_dc_asn: 5_000, bad_asn: 5_000 }
      min_bytes.each do |key, floor|
        size = File.size(paths[key])
        Env.fail_stage!("#{key} suspiciously small: #{size} bytes (< #{floor})") if size < floor
      end

      Env.log("fetch complete: #{paths.size} inputs cached")
      paths
    end
  end
end

OpenASNPipeline::Fetch.run if $PROGRAM_NAME == __FILE__
