# frozen_string_literal: true

# The Tier A source registry: every input to the canonical published artifact,
# with its license identity. This file is the single place where upstream
# URLs live. If an upstream moves, fix it here and nowhere else.
#
# LEGAL INVARIANT (PRD R1, do not weaken): only sources whose EXACT
# redistributed artifact carries explicit redistribution rights may appear
# here - PDDL, CC0, or MIT-where-the-license-explicitly-covers-output.
# A builder repo's license does not sanitize the data it aggregates.
# Anything else belongs in fetch-manifest.json (fetched by end users from
# the original authority, never republished by us) or nowhere at all.
# The full catalog with rationale for every exclusion: see README + PRD §5.

require_relative "env"
require_relative "http"

module OpenASNPipeline
  module Sources
    # --- sapics/ip-location-db (origin-asn): the IP->ASN backbone ------------
    # PDDL v1.0 ("free use without attribution", per their README license
    # section). Compiled by sapics from RIR delegated stats + RouteViews/RIPE
    # RIS BGP data, deliberately avoiding RIR WHOIS - the same licensing
    # discipline this project needs.
    #
    # GOTCHA (2026-06-18): sapics changed their release URL scheme once
    # already. We therefore RESOLVE the asset URLs from their README table at
    # build time instead of trusting a hardcoded path; the constants below are
    # only the last-known-good fallback (used with a loud warning if the
    # README no longer parses).
    SAPICS_README_URL = "https://raw.githubusercontent.com/sapics/ip-location-db/main/README.md"
    SAPICS_FALLBACK = {
      "origin-asn-ipv4-num.csv" => "https://github.com/sapics/ip-location-db/releases/download/latest/origin-asn-ipv4-num.csv",
      "origin-asn-ipv6-num.csv" => "https://github.com/sapics/ip-location-db/releases/download/latest/origin-asn-ipv6-num.csv"
    }.freeze

    # --- ipverse/as-metadata: ASN -> description/country/category/role -------
    # CC0 1.0 (LICENSE pinned below). The `category`/`networkRole` fields
    # exist ONLY in as.json (~69MB), NOT in as.csv (verified 2026-07-04:
    # csv header is asn,handle,description,country-code) - so we must
    # stream-parse the JSON. Fields are young (added 2026-02-08) and
    # single-maintainer; ipverse themselves call the categorization a
    # "useful default, not gospel". Hence the crosscheck stage.
    IPVERSE_AS_JSON_URL = "https://raw.githubusercontent.com/ipverse/as-metadata/master/as.json"

    # --- ipverse/as-ip-blocks: per-ASN announced prefixes ---------------------
    # CC0 1.0. Used ONLY to expand override-listed ASNs that are absent from
    # the origin-asn backbone (mostly IPv6 for VPN providers). Repo was
    # renamed from `asn-ip`; canonical name verified 2026-07-04 (old raw
    # paths 301-redirect, we use the canonical one).
    IPVERSE_AS_BLOCKS_RAW = "https://raw.githubusercontent.com/ipverse/as-ip-blocks/master/as/%d/%s-aggregated.txt"

    # --- X4BNet/lists_vpn: VPN + datacenter range overlays --------------------
    # MIT, and the README explicitly extends the license to "the list itself
    # (source files and generated output)" - the wording that makes X4B
    # redistributable when most aggregated lists are not (PRD Appendix C).
    #
    # GOTCHA: the legacy root ipv4.txt path was REMOVED in 2026 (it broke
    # MISP's generator which still hardcodes it). Only output/... paths are
    # stable. IPv4 only - X4B publishes no IPv6; v6 VPN signal comes from
    # ASN-level overrides instead (see compile.rb).
    X4B_VPN_URL = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt"
    X4B_DC_URL  = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt"
    # Hand-curated ASN input files (first-party curation, MIT) - seeds for
    # data/overrides/ and the crosscheck reference set.
    X4B_VPN_ASN_URL = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/input/vpn/ASN.txt"
    X4B_DC_ASN_URL  = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/input/datacenter/ASN.txt"

    # --- brianhama/bad-asn-list: curated hosting/cloud/colo ASNs --------------
    # MIT, first-party curation (~700+ ASNs). Also the market thesis: its
    # author ran a 500K-MAU network and found ASN-blocking solved ~90% of
    # abuse. CSV has a header row (ASN,Entity) - parser must skip it.
    BAD_ASN_URL = "https://raw.githubusercontent.com/brianhama/bad-asn-list/master/bad-asn-list.csv"

    # --- License pinning (PRD R4) ---------------------------------------------
    # We pin the SHA-256 of every upstream license-declaring file and FAIL THE
    # BUILD if any changes. Licenses have changed under projects before
    # (MaxMind Dec 2019). Expected hashes live in data/licenses/pins.json;
    # human-readable copies in data/licenses/*.txt.
    #
    # Two sources have no standalone LICENSE file (verified 2026-07-04):
    #   * sapics: license is declared in origin-asn/SOURCES.md (first line is
    #     the PDDL statement) - we pin that whole file.
    #   * X4BNet: MIT lives in README.md under a "# License" heading, with the
    #     load-bearing sentence extending it to "the list itself (source files
    #     and generated output)". We pin just that extracted section so
    #     unrelated README churn (stats, docs) doesn't trip the gate, but any
    #     edit to the grant itself does. Extraction: license_gate.rb.
    LICENSE_URLS = {
      "sapics-origin-asn" => {
        url: "https://raw.githubusercontent.com/sapics/ip-location-db/main/origin-asn/SOURCES.md",
        extract: :whole_file
      },
      "ipverse-as-metadata" => {
        url: "https://raw.githubusercontent.com/ipverse/as-metadata/master/LICENSE",
        extract: :whole_file
      },
      "ipverse-as-ip-blocks" => {
        url: "https://raw.githubusercontent.com/ipverse/as-ip-blocks/master/LICENSE",
        extract: :whole_file
      },
      "x4bnet-lists_vpn" => {
        url: "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/README.md",
        extract: :license_heading_section
      },
      "brianhama-bad-asn-list" => {
        url: "https://raw.githubusercontent.com/brianhama/bad-asn-list/master/LICENSE",
        extract: :whole_file
      }
    }.freeze

    # Metadata that ends up in manifest.json's `sources` array so every
    # artifact is self-describing about provenance.
    CATALOG = [
      { id: "sapics-origin-asn",     url: "https://github.com/sapics/ip-location-db", license: "PDDL-1.0" },
      { id: "ipverse-as-metadata",   url: "https://github.com/ipverse/as-metadata",   license: "CC0-1.0" },
      { id: "ipverse-as-ip-blocks",  url: "https://github.com/ipverse/as-ip-blocks",  license: "CC0-1.0" },
      { id: "x4bnet-lists_vpn",      url: "https://github.com/X4BNet/lists_vpn",      license: "MIT" },
      { id: "brianhama-bad-asn-list", url: "https://github.com/brianhama/bad-asn-list", license: "MIT" },
      { id: "openasn-overrides",     url: "https://github.com/openasn/openasn",       license: "CC0-1.0" }
    ].freeze

    module_function

    # Resolve the actual origin-asn download URLs from sapics' README table.
    # Returns { filename => url }. Falls back to SAPICS_FALLBACK with a
    # warning if the README stops matching (tripwire for their next URL-scheme
    # change - see gotcha above).
    def resolve_sapics_urls(http)
      readme = http.get!(SAPICS_README_URL)
      resolved = {}
      SAPICS_FALLBACK.each_key do |filename|
        # The README links assets as
        # https://github.com/sapics/ip-location-db/releases/download/<tag>/<file>
        if (m = readme.match(%r{https://github\.com/sapics/ip-location-db/releases/download/[^)\s]+/#{Regexp.escape(filename)}}))
          resolved[filename] = m[0]
        end
      end
      if resolved.size == SAPICS_FALLBACK.size
        resolved
      else
        Env.warn("sapics README no longer lists expected origin-asn assets; " \
                 "falling back to last-known URL scheme. INVESTIGATE - their URL scheme may have changed again.")
        SAPICS_FALLBACK.merge(resolved)
      end
    rescue StandardError => e
      Env.warn("could not resolve sapics README (#{e.message}); using fallback URLs")
      SAPICS_FALLBACK
    end
  end
end
