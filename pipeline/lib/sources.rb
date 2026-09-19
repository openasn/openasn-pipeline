# frozen_string_literal: true

# The Tier A source registry: every input to the canonical published artifact,
# with its license identity. This file is the single place where upstream
# URLs live. If an upstream moves, fix it here and nowhere else.
#
# LEGAL INVARIANT (data-repo README "Legal design" rule 1, do not weaken): only sources whose EXACT
# redistributed artifact carries explicit redistribution rights may appear
# here - PDDL, CC0, or MIT-where-the-license-explicitly-covers-output.
# A builder repo's license does not sanitize the data it aggregates.
# Anything else belongs in fetch-manifest.json (fetched by end users from
# the original authority, never republished by us) or nowhere at all.
# The full catalog with rationale for every exclusion: see the data-repo README.

require_relative "env"
require_relative "http"

module OpenASNPipeline
  module Sources
    # --- sapics/ip-location-db (origin-asn): LEGACY backbone ------------------
    # RETIRED as the default by D-SRC-2 (backbone) (coordinator ruling CD-12,
    # 2026-09-19); still selectable with OPENASN_BACKBONE=sapics so the
    # switchover can be rolled back without a code change. Removable in a
    # follow-up once the RouteViews backbone has published cleanly for a few
    # weeks: delete these constants, SAPICS_LICENSE/SAPICS_CATALOG,
    # resolve_sapics_urls, the sapics branch of fetch.rb and publish.rb's
    # "sapics-origin-asn" fetch keys.
    #
    # Why retired: sapics labels its table PDDL v1.0, but it is compiled from
    # RouteViews + RIPE RIS BGP data and fills unrouted space from RIR
    # delegated stats (P4-L audit; P4-B measured 10.8% of its v4 and 59.8%
    # of its v6 space as RIR-stats fill). An aggregator's relabel is not a
    # grant from the authority, so it fails README "Legal design" rule 1.
    # Its licence pin is dropped from data/licenses/pins.json, so a sapics
    # build FAILS the licence gate ("no pin recorded") until someone re-pins
    # it in a reviewed PR - rolling back is a deliberate act.
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

    # --- RouteViews (University of Oregon): raw BGP RIBs -> our own backbone --
    # THE DEFAULT IP->ASN backbone (data-repo DECISIONS.md D-SRC-2 (backbone);
    # coordinator rulings CD-5 and CD-12, 2026-09-19). Measured against
    # sapics on the same day: origin agreement 98.94% v4 / 97.45% v6 where
    # both cover, compiled verdicts 99.81% identical, spot panel green.
    #
    # Why: sapics origin-asn is itself compiled from RouteViews + RIPE RIS
    # (+ RIR stats for unrouted space) and relabelled PDDL, so it fails the
    # "aggregators never qualify" invariant (P4-L audit). Deriving
    # prefix->origin ourselves from RouteViews only removes the aggregator
    # and the RIPE RIS dependency (EU database right, revocable permission).
    #
    # Terms (verified 2026-09-19, docs/enrichment/research/parts/
    # P4-B-routeviews-terms-2026-09-19.jsonl): "RouteViews Data" is CC BY 4.0
    # with attribution-type requests (credit + link, logo, boilerplate) and a
    # revocation clause conditioned on missing attribution or "abuse". The
    # published table holds only prefix->origin facts recomputed by our code
    # (tools/rib2origin); ATTRIBUTION.md credits RouteViews in their
    # prescribed words regardless.
    #
    # GOTCHAS: archive.routeviews.org's robots.txt is "Disallow: /" - we fetch
    # a fixed list of named files once per build and never crawl directory
    # listings. RIBs are written every 2h (00,02,...,22 UTC) and appear some
    # minutes after the slot; route-views2 lives at the archive ROOT
    # (/bgpdata/...), every other collector under /<collector>/bgpdata/...
    ROUTEVIEWS_ARCHIVE = "https://archive.routeviews.org"
    # Picked for geography (US west/east, UK, DE, ZA, SG, AU, BR, JP) plus the
    # v6-focused route-views6. Measured on the 2026-09-18 20:00 slot: these 10
    # = 186 distinct peer ASes, 852 MB; adding 6 more (rv3/4/5, amsix,
    # chicago, isc) = 256 peer ASes, 1.33 GB, but v4 coverage moved only
    # +0.02 pt and origin agreement +0.02 pt, so they stay out.
    ROUTEVIEWS_COLLECTORS = %w[
      route-views2 route-views.eqix route-views.linx decix.fra route-views.napafrica
      route-views.sg route-views.sydney ix-br.gru route-views.wide route-views6
    ].freeze
    # The WordPress JSON rendering of the licence page: same text as
    # https://www.routeviews.org/routeviews/licenses/ without the theme's
    # markup, so theme churn cannot trip the gate (verified: identical bytes
    # on repeated fetches, 2026-09-19). Text is tag-stripped before hashing.
    ROUTEVIEWS_LICENSE_URL = "https://www.routeviews.org/routeviews/wp-json/wp/v2/pages/45927?_fields=content"

    # First entry is the default (OPENASN_BACKBONE unset or empty).
    BACKBONES = %w[routeviews sapics].freeze
    ROUTEVIEWS_LICENSE = { url: ROUTEVIEWS_LICENSE_URL, extract: :wp_json_rendered_text }.freeze
    ROUTEVIEWS_CATALOG = { id: "routeviews", url: "https://www.routeviews.org/", license: "CC-BY-4.0" }.freeze

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
    # redistributable when most aggregated lists are not (quote pinned in data/licenses/).
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

    # --- License pinning ---------------------------------------------------------
    # We pin the SHA-256 of every upstream license-declaring file and FAIL THE
    # BUILD if any changes. Licenses have changed under projects before
    # (MaxMind Dec 2019). Expected hashes live in data/licenses/pins.json;
    # human-readable copies in data/licenses/*.txt.
    #
    # Three sources have no standalone LICENSE file:
    #   * RouteViews: the terms are a WordPress page; we pin the tag-stripped
    #     text of its JSON rendering (ROUTEVIEWS_LICENSE_URL, 2026-09-19).
    #   * sapics (LEGACY, OPENASN_BACKBONE=sapics only - see license_urls):
    #     license is declared in origin-asn/SOURCES.md (first line is the
    #     PDDL statement) - we pin that whole file (verified 2026-07-04).
    #   * X4BNet: MIT lives in README.md under a "# License" heading, with the
    #     load-bearing sentence extending it to "the list itself (source files
    #     and generated output)". We pin just that extracted section so
    #     unrelated README churn (stats, docs) doesn't trip the gate, but any
    #     edit to the grant itself does. Extraction: license_gate.rb.
    LICENSE_URLS = {
      "routeviews" => ROUTEVIEWS_LICENSE,
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
    SAPICS_LICENSE = {
      url: "https://raw.githubusercontent.com/sapics/ip-location-db/main/origin-asn/SOURCES.md",
      extract: :whole_file
    }.freeze

    # Metadata that ends up in manifest.json's `sources` array so every
    # artifact is self-describing about provenance.
    CATALOG = [
      ROUTEVIEWS_CATALOG,
      { id: "ipverse-as-metadata",   url: "https://github.com/ipverse/as-metadata",   license: "CC0-1.0" },
      { id: "ipverse-as-ip-blocks",  url: "https://github.com/ipverse/as-ip-blocks",  license: "CC0-1.0" },
      { id: "x4bnet-lists_vpn",      url: "https://github.com/X4BNet/lists_vpn",      license: "MIT" },
      { id: "brianhama-bad-asn-list", url: "https://github.com/brianhama/bad-asn-list", license: "MIT" },
      { id: "openasn-overrides",     url: "https://github.com/openasn/openasn",       license: "CC0-1.0" }
    ].freeze
    SAPICS_CATALOG = { id: "sapics-origin-asn", url: "https://github.com/sapics/ip-location-db", license: "PDDL-1.0" }.freeze

    module_function

    # Which IP->ASN backbone this build compiles from: RouteViews unless
    # OPENASN_BACKBONE=sapics (legacy, see above); anything unknown fails
    # loudly.
    def backbone
      b = ENV.fetch("OPENASN_BACKBONE", "").strip
      b = BACKBONES.first if b.empty?
      Env.fail_stage!("OPENASN_BACKBONE=#{b.inspect} - expected one of #{BACKBONES.join(', ')}") unless BACKBONES.include?(b)
      b
    end

    def routeviews? = backbone == "routeviews"

    # Licence-gate targets for THIS build: the backbone we do not compile
    # from is not pinned (its terms no longer reach the artifact).
    def license_urls
      return LICENSE_URLS if routeviews?

      { "sapics-origin-asn" => SAPICS_LICENSE }.merge(LICENSE_URLS.reject { |id, _| id == "routeviews" })
    end

    # manifest.json `sources` for THIS build.
    def catalog
      return CATALOG if routeviews?

      [SAPICS_CATALOG] + CATALOG.reject { |s| s[:id] == "routeviews" }
    end

    # RouteViews RIB URL for one collector and a slot "YYYYMMDD.HHMM" (UTC).
    def routeviews_rib_url(collector, slot)
      month = "#{slot[0, 4]}.#{slot[4, 2]}"
      base = collector == "route-views2" ? ROUTEVIEWS_ARCHIVE : "#{ROUTEVIEWS_ARCHIVE}/#{collector}"
      "#{base}/bgpdata/#{month}/RIBS/rib.#{slot}.bz2"
    end

    # The newest 2-hourly RIB slot that is safely complete: at least `lag`
    # seconds old (dumps of big collectors take a while to land). Override
    # with OPENASN_RV_RIB_SLOT=YYYYMMDD.HHMM to rebuild a specific day.
    def routeviews_slot(now = Time.now.utc, lag: 3 * 3600)
      return ENV["OPENASN_RV_RIB_SLOT"] if ENV["OPENASN_RV_RIB_SLOT"].to_s.match?(/\A\d{8}\.\d{4}\z/)

      t = now - lag
      t = Time.utc(t.year, t.month, t.day, t.hour - (t.hour % 2))
      t.strftime("%Y%m%d.%H%M")
    end

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
