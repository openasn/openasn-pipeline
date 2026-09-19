# frozen_string_literal: true

# Wikidata country of the operator item linked to an ASN (P3797): the CC0
# half of the published `country` column in asn-categories.csv. The data
# repo's DECISIONS.md D-SRC-2 (country) says why the ipverse country codes
# (RIR registry data) left the core and what replaced them.
#
# Licence: the same Wikidata:Copyright CC0 sentence that covers the P3797
# names (pinned as "wikidata-p3797"; P17/P159/P297 are main-namespace
# structured data as well).
#
# WHICH ITEM. Only the item that lib/wikidata_names.rb already admitted for
# the ASN: its P3797 statement is not deprecated, not ended, not contested by
# another item, and does not rest only on registry/aggregator references. So
# the ASN -> operator link is exactly as strict as for the names, and an ASN
# without an admissible name gets no Wikidata country either.
#
# WHICH COUNTRY, per item, first hit wins:
#   1. P17 "country" of the operator item
#   2. P159 "headquarters location" -> that place's P17
# The country item's P297 (ISO 3166-1 alpha-2) is the published value.
# Statement rules, per property: deprecated rank and statements with an end
# time (P582) are dropped; statements whose every reference cites a
# restricted registry/aggregator (by URL, WikidataNames::RESTRICTED_REF_HOSTS,
# or by "stated in" item, RESTRICTED_STATED_IN) are dropped, the same rule as
# for P3797. If preferred-rank statements survive, only they count. More than
# one distinct code left means the item is ambiguous for that property
# (multinationals often list several P17 values): it yields nothing there and
# the next property is tried.
#
# Measured 2026-09-19: no P17/P159 reference cites an Internet registry. The
# cited databases are GRID, GLEIF, Crunchbase, national company registers,
# GeoNames and Wikipedia imports, and most statements carry no reference. The
# restricted-reference rule is kept anyway, so a future bulk import from a
# registry cannot enter silently.
#
# SEMANTICS. The value means "the country the ASN's operator is based in"
# (seat or headquarters). That is close to, but not the same as, a registry
# country, which records the address on the registrant's record.

require "json"
require "uri"
require_relative "env"
require_relative "wikidata_names"

module OpenASNPipeline
  module WikidataCountries
    # The optimizer hint keeps Blazegraph on the written join order: starting
    # from the ~1.8k P3797 items. Without it the planner starts from every
    # country-bearing statement and the query times out (measured 2026-09-19:
    # 60s timeout without the hint, 1.9s with it).
    QUERY = <<~SPARQL
      SELECT ?item ?via ?cc ?rank ?end
             (GROUP_CONCAT(DISTINCT CONCAT(STR(?ref), "|", COALESCE(STR(?refurl), ""), "|", COALESCE(STR(?stated), "")); separator=" ") AS ?refs)
      WHERE {
        hint:Query hint:optimizer "None" .
        ?item p:P3797 ?any .
        {
          ?item p:P17 ?st . ?st ps:P17 ?c . BIND("P17" AS ?via)
        } UNION {
          ?item p:P159 ?st . ?st ps:P159 ?loc . ?loc wdt:P17 ?c . BIND("P159" AS ?via)
        }
        ?st wikibase:rank ?rank .
        ?c wdt:P297 ?cc .
        OPTIONAL { ?st pq:P582 ?end . }
        OPTIONAL { ?st prov:wasDerivedFrom ?ref .
                   OPTIONAL { ?ref pr:P854 ?refurl . }
                   OPTIONAL { ?ref pr:P248 ?stated . } }
      }
      GROUP BY ?item ?via ?cc ?rank ?end
    SPARQL

    # "stated in" items that are registry databases or their aggregators.
    # Verified 2026-09-19 via wbsearchentities / an rdfs:label SPARQL lookup.
    RESTRICTED_STATED_IN = %w[
      Q282503 Q1504968 Q726801 Q1311100 Q384211 Q17123290
    ].freeze
    # Q282503   American Registry for Internet Numbers (ARIN)
    # Q1504968  RIPE Network Coordination Centre
    # Q726801   APNIC
    # Q1311100  LACNIC
    # Q384211   AFRINIC
    # Q17123290 PeeringDB

    PROPERTY_ORDER = %w[P17 P159].freeze
    ISO2 = /\A[A-Z]{2}\z/
    # Not countries: user-assigned / exceptionally reserved codes.
    NOT_COUNTRIES = %w[XX ZZ EU AP AA QM QN QO QP QQ QR QS QT QU QV QW QX QY QZ].freeze

    module_function

    def url = "#{WikidataNames::ENDPOINT}?format=json&query=#{URI.encode_www_form_component(QUERY)}"

    # SPARQL JSON -> [{ qid => { "cc" => "US", "via" => "P17" } }, stats]. Pure.
    def parse(json)
      bindings = JSON.parse(json).dig("results", "bindings")
      raise ArgumentError, "wikidata countries: response has no results.bindings" unless bindings.is_a?(Array)

      stats = Hash.new(0)
      # qid -> via -> { preferred: Set-ish Array, normal: Array }
      claims = Hash.new { |h, k| h[k] = Hash.new { |hh, kk| hh[kk] = { "preferred" => [], "normal" => [] } } }
      bindings.each do |b|
        stats["statements"] += 1
        rank = b.dig("rank", "value").to_s
        if rank.end_with?("DeprecatedRank")
          stats["deprecated"] += 1
          next
        end
        if b["end"]
          stats["ended"] += 1
          next
        end
        cc = b.dig("cc", "value").to_s.strip.upcase
        if !cc.match?(ISO2) || NOT_COUNTRIES.include?(cc)
          stats["bad_code"] += 1
          next
        end
        unless admissible?(b.dig("refs", "value"))
          stats["restricted_refs_only"] += 1
          next
        end
        qid = b.dig("item", "value").to_s.split("/").last
        via = b.dig("via", "value").to_s
        next unless PROPERTY_ORDER.include?(via)

        claims[qid][via][rank.end_with?("PreferredRank") ? "preferred" : "normal"] << cc
      end

      out = {}
      claims.each do |qid, by_via|
        PROPERTY_ORDER.each do |via|
          next unless by_via.key?(via)

          ranked = by_via[via]
          codes = (ranked["preferred"].empty? ? ranked["normal"] : ranked["preferred"]).uniq
          if codes.size == 1
            out[qid] = { "cc" => codes.first, "via" => via }
            break
          end
          stats["ambiguous_#{via}"] += 1 if codes.size > 1
        end
      end
      stats["items_with_country"] = out.size
      [out, stats.to_h]
    end

    # Joins the admitted ASN -> item links (WikidataNames.parse) with the item
    # countries. -> { asn => { "cc", "qid", "via" } }
    def for_asns(names, item_countries)
      (names || {}).each_with_object({}) do |(asn, r), out|
        c = item_countries[r["qid"]] or next
        out[asn] = { "cc" => c["cc"], "qid" => r["qid"], "via" => c["via"] }
      end
    end

    # "refId|url|statedIn ..." -> admissible? Same rule as P3797: no
    # references at all is the contributor's own CC0 assertion (admissible);
    # otherwise at least one reference must cite no restricted host and no
    # restricted "stated in" item.
    def admissible?(refs_value)
      triples = refs_value.to_s.split(" ").map { |p| p.split("|", 3) }.reject { |ref, _, _| ref.to_s.empty? }
      return true if triples.empty?

      by_ref = triples.group_by(&:first)
      by_ref.values.any? do |rows|
        rows.none? do |(_, u, stated)|
          (!u.to_s.empty? && WikidataNames.restricted_url?(u)) ||
            RESTRICTED_STATED_IN.include?(stated.to_s.split("/").last)
        end
      end
    end
  end
end
