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
require_relative "lib/routeviews"

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
      x4b_vpn_manual: "x4bnet/input-vpn-ips-Manual.txt",
      x4b_dc_manual: "x4bnet/input-datacenter-ips-Manual.txt",
      bad_asn: "brianhama/bad-asn-list.csv",
      wikidata: "wikidata/p3797-names.json"
    }.freeze

    module_function

    def run(http: Http.new, offline: ENV["OFFLINE"] == "1")
      Env.prepare_dirs!
      paths = {}

      # The IP->ASN backbone: our own derivation from RouteViews RIBs
      # (lib/routeviews.rb; the default) or, with OPENASN_BACKBONE=sapics, the
      # legacy sapics files. Either way normalize.rb reads :backbone_v4/_v6.
      if Sources.routeviews?
        paths.merge!(RouteViews.build(http: http, offline: offline))
      else
        sapics = Sources.resolve_sapics_urls(http) unless offline
        sapics ||= Sources::SAPICS_FALLBACK
        paths[:sapics_v4] = http.fetch(sapics["origin-asn-ipv4-num.csv"], KEYS[:sapics_v4], offline: offline)
        paths[:sapics_v6] = http.fetch(sapics["origin-asn-ipv6-num.csv"], KEYS[:sapics_v6], offline: offline)
        paths[:backbone_v4] = paths[:sapics_v4]
        paths[:backbone_v6] = paths[:sapics_v6]
      end

      paths[:as_json] = http.fetch(Sources::IPVERSE_AS_JSON_URL, KEYS[:as_json], offline: offline)

      paths[:x4b_vpn]     = http.fetch(Sources::X4B_VPN_URL, KEYS[:x4b_vpn], offline: offline)
      paths[:x4b_dc]      = http.fetch(Sources::X4B_DC_URL, KEYS[:x4b_dc], offline: offline)
      paths[:x4b_vpn_asn] = http.fetch(Sources::X4B_VPN_ASN_URL, KEYS[:x4b_vpn_asn], offline: offline)
      paths[:x4b_dc_asn]  = http.fetch(Sources::X4B_DC_ASN_URL, KEYS[:x4b_dc_asn], offline: offline)
      # No size floor below for the Manual.txt files: a comment-only file is
      # legitimate (input/datacenter/ips/Manual.txt is exactly that today).
      paths[:x4b_vpn_manual] = http.fetch(Sources::X4B_VPN_MANUAL_URL, KEYS[:x4b_vpn_manual], offline: offline)
      paths[:x4b_dc_manual]  = http.fetch(Sources::X4B_DC_MANUAL_URL, KEYS[:x4b_dc_manual], offline: offline)
      # Third-party files, fetched only to be SUBTRACTED from the dc overlay.
      # http.fetch, not fetch_optional: a transient failure must fall back to
      # yesterday's copy (over-subtracting is harmless) or fail loudly -
      # never silently skip the subtraction and republish the feed.
      paths[:x4b_dc_feeds] = Sources::X4B_DC_FEEDS.map do |rel, url|
        http.fetch(url, "x4bnet/feeds/#{rel.tr('/', '-')}", offline: offline)
      end

      paths[:bad_asn] = http.fetch(Sources::BAD_ASN_URL, KEYS[:bad_asn], offline: offline)

      # CC0 org names (D-SRC-2). One SPARQL GET; keep-last-good like the rest.
      paths[:wikidata] = http.fetch(Sources::WIKIDATA_P3797_URL, KEYS[:wikidata], offline: offline)

      # Cheap sanity floor: catch an upstream serving an error page / empty
      # body with HTTP 200 before we waste a build on it. Real validation
      # gates run later (validate.rb); this is just "is it plausibly data".
      min_bytes = { backbone_v4: 5_000_000, backbone_v6: 1_000_000, as_json: 10_000_000,
                    x4b_vpn: 50_000, x4b_dc: 200_000, x4b_vpn_asn: 100,
                    x4b_dc_asn: 5_000, bad_asn: 5_000, wikidata: 100_000 }
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
