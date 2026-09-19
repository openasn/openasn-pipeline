# frozen_string_literal: true

# Wikidata P3797 ("autonomous system number") -> English item label: the CC0
# half of the published org names (openasn-orgs.bin, asn-categories.csv
# `org`). See the data repo's DECISIONS.md D-SRC-2 (org names) for why the
# ipverse WHOIS descriptions left the core and what replaced them.
#
# Licence: "All structured data from the main, Property, Lexeme, and
# EntitySchema namespaces is available under the Creative Commons CC0 License"
# (https://www.wikidata.org/wiki/Wikidata:Copyright). P3797 statements and item
# labels are main-namespace structured data. The sentence is pinned by the
# licence gate (Sources::LICENSE_URLS "wikidata-p3797", extract :wikidata_cc0).
#
# JUDGED BY ITS INPUTS, NOT ITS LABEL (proposed D-SRC-2). Measured 2026-09-19:
# 1,138 of Wikidata's 1,817 P3797 statements cite one reference, ARIN's bulk
# https://ftp.arin.net/pub/resource_registry_service/asns.csv, which ARIN
# serves "subject to terms of use" (its Whois ToU: no republishing or making
# publicly available). A further ~100 cite RIR WHOIS/RDAP, PeeringDB,
# bgp.he.net and similar. Wikidata's CC0 cannot launder those, so a statement
# is ADMISSIBLE only if it has no reference at all (a contributor's own
# assertion, which is what Wikidata's CC0 actually covers) or at least one
# reference that cites nothing on RESTRICTED_REF_HOSTS. Statements whose
# every reference points at a restricted registry or aggregator are dropped
# and counted.
#
# Other rules (from the S workstream prototype, sources/rir-delegated-stats
# lib/wikidata_asn.rb): deprecated-rank statements are dropped; statements
# with an end time (P582) are former ASNs and dropped; an ASN claimed by two
# items is a conflict and yields no name. Several ASNs per item is normal
# (Google: AS15169, AS396982 -> Q95). No RIR-sibling propagation: the RIR
# delegated stats are curation-only (D-SRC-1) and may not shape published data.

require "json"
require "uri"
require_relative "env"

module OpenASNPipeline
  module WikidataNames
    ENDPOINT = "https://query.wikidata.org/sparql"
    LICENSE_URL = "https://www.wikidata.org/wiki/Wikidata:Copyright"

    # One row per (item, statement value, rank, end); references folded into
    # "refId|url" pairs so admissibility can be judged per reference.
    QUERY = <<~SPARQL
      SELECT ?item ?asn ?rank ?end ?en ?mul
             (GROUP_CONCAT(DISTINCT CONCAT(STR(?ref), "|", COALESCE(STR(?refurl), "")); separator=" ") AS ?refs)
      WHERE {
        ?item p:P3797 ?st .
        ?st ps:P3797 ?asn ; wikibase:rank ?rank .
        OPTIONAL { ?st pq:P582 ?end . }
        OPTIONAL { ?item rdfs:label ?en . FILTER(LANG(?en) = "en") }
        OPTIONAL { ?item rdfs:label ?mul . FILTER(LANG(?mul) = "mul") }
        OPTIONAL { ?st prov:wasDerivedFrom ?ref . OPTIONAL { ?ref pr:P854 ?refurl . } }
      }
      GROUP BY ?item ?asn ?rank ?end ?en ?mul
    SPARQL

    # Reference hosts whose data we may not republish (RIR WHOIS/RDAP/bulk
    # files, PeeringDB's AUP) or that aggregate them (CAIDA AS Rank names come
    # from AS2Org, which is built from WHOIS). Suffix match. Shared with the
    # org_names.txt source check (lib/overrides.rb) and the dossier drafter.
    RESTRICTED_REF_HOSTS = %w[
      arin.net ripe.net apnic.net lacnic.net afrinic.net
      registro.br nic.br jpnic.ad.jp nic.ad.jp twnic.net.tw kisa.or.kr cnnic.cn cnnic.net.cn idnic.net irinn.in
      peeringdb.com bgp.he.net bgp.tools bgpview.io ipinfo.io ipip.net
      ipgeolocation.io bigdatacloud.com radar.qrator.net radar.cloudflare.com
      caida.org db-ip.com ipverse.net
    ].freeze

    MAX_ASN = 4_294_967_295

    module_function

    def url = "#{ENDPOINT}?format=json&query=#{URI.encode_www_form_component(QUERY)}"

    # SPARQL JSON -> [names, stats]. Pure.
    # names: { asn => { "name" => label, "qid" => "Q95" } }
    # stats: counts of every drop reason (the build logs and manifest carry them)
    def parse(json)
      bindings = JSON.parse(json).dig("results", "bindings")
      raise ArgumentError, "wikidata: response has no results.bindings" unless bindings.is_a?(Array)

      stats = Hash.new(0)
      claims = Hash.new { |h, k| h[k] = {} }
      bindings.each do |b|
        stats["statements"] += 1
        if b.dig("rank", "value").to_s.end_with?("DeprecatedRank")
          stats["deprecated"] += 1
          next
        end
        if b["end"]
          stats["ended"] += 1
          next
        end
        asn = parse_asn(b.dig("asn", "value"))
        unless asn
          stats["bad_asn"] += 1
          next
        end
        unless admissible?(b.dig("refs", "value"))
          stats["restricted_refs_only"] += 1
          next
        end
        qid = b.dig("item", "value").to_s.split("/").last
        label = clean_label(b.dig("en", "value") || b.dig("mul", "value"))
        claims[asn][qid] ||= label # ||= : a later row for the same item may carry the label
      end

      names = {}
      claims.each do |asn, items|
        if items.size > 1
          stats["conflict"] += 1
          next
        end
        qid, label = items.first
        if label.nil?
          stats["no_label"] += 1
          next
        end
        names[asn] = { "name" => label, "qid" => qid }
      end
      stats["admitted_asns"] = names.size
      [names, stats.to_h]
    end

    # "refId|url refId| refId|url2" -> admissible?
    # No references at all -> admissible (the contributor's own CC0 assertion).
    # Otherwise at least one reference must cite no restricted host.
    def admissible?(refs_value)
      pairs = refs_value.to_s.split(" ").map { |p| p.split("|", 2) }.reject { |ref, _| ref.to_s.empty? }
      return true if pairs.empty?

      by_ref = pairs.group_by(&:first).transform_values { |ps| ps.map { |(_, u)| u.to_s }.reject(&:empty?) }
      by_ref.values.any? { |urls| urls.none? { |u| restricted_url?(u) } }
    end

    def restricted_url?(url)
      host = URI.parse(url).host.to_s.downcase
      RESTRICTED_REF_HOSTS.any? { |h| host == h || host.end_with?(".#{h}") }
    rescue URI::InvalidURIError
      false
    end

    def clean_label(label)
      s = label.to_s.unicode_normalize(:nfc).gsub(/[[:cntrl:]]/, " ").squeeze(" ").strip
      s.empty? ? nil : s
    end

    # "AS15169", "15169", " 15169 " -> 15169; ranges, junk, 0 -> nil.
    def parse_asn(v)
      s = v.to_s.strip.sub(/\AAS/i, "")
      return nil unless s.match?(/\A\d+\z/)

      n = s.to_i
      n.between?(1, MAX_ASN) ? n : nil
    end
  end
end
