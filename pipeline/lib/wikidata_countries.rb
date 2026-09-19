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
# REGIONS: the query also returns whether the item's HQ (P159) or location
# (P131) lies, through P131*, in one of REGIONS:
#   * Occupied and breakaway territories (CD-19a; Countries::TERRITORY_STATES):
#     an item located in Crimea, Sevastopol, the Donetsk/Luhansk/Zaporizhzhia/
#     Kherson oblasts (or the Russian-declared entities there), Abkhazia,
#     South Ossetia, Transnistria or Northern Cyprus publishes the recognised
#     state (UA, GE, MD, CY) when its own result is that state, the de facto
#     controller (Countries::DE_FACTO_CONTROLLERS) or nothing; any other
#     result makes it ambiguous and it publishes nothing. So Wikidata can
#     never put RU on a Crimean operator, whatever its P17 says.
# Measured 2026-09-19: no admitted item sits in a territory. The rule is a
# guard; asn_country.txt's `territory:` tags carry the operators we know about.
#
# SEMANTICS. The value means "the country the ASN's operator is based in"
# (seat or headquarters). That is close to, but not the same as, a registry
# country, which records the address on the registrant's record.

require "json"
require "uri"
require_relative "env"
require_relative "wikidata_names"
require_relative "countries"

module OpenASNPipeline
  module WikidataCountries
    # The optimizer hint keeps Blazegraph on the written join order: starting
    # from the ~1.8k P3797 items. Without it the planner starts from every
    # country-bearing statement and the query times out (measured 2026-09-19:
    # 60s timeout without the hint, 1.9s with it).
    # Region QID -> published ISO code. Every QID was checked by label on
    # 2026-09-19 (wbgetentities / rdfs:label SPARQL); never add one from memory.
    REGIONS = {
      "Q7835" => "UA",       # Crimea (peninsula)
      "Q756294" => "UA",     # Autonomous Republic of Crimea
      "Q15966495" => "UA",   # Republic of Crimea (Russian-declared)
      "Q7525" => "UA",       # Sevastopol
      "Q2012050" => "UA",    # Donetsk Oblast
      "Q171965" => "UA",     # Luhansk Oblast
      "Q171334" => "UA",     # Zaporizhzhia Oblast
      "Q163271" => "UA",     # Kherson Oblast
      "Q16150196" => "UA",   # Donetsk People's Republic (Russian-declared)
      "Q114334914" => "UA",  # Donetsk People's Republic (2014-2022)
      "Q16746854" => "UA",   # Luhansk People's Republic (Russian-declared)
      "Q114327408" => "UA",  # Luhansk People's Republic (2014-2022)
      "Q114318324" => "UA",  # Kherson Oblast (Sept 2022 proclamation)
      "Q114318415" => "UA",  # Zaporozhye Oblast (Sept 2022 proclamation)
      "Q114331288" => "UA",  # Kherson Oblast (Russian federal subject)
      "Q114333615" => "UA",  # Zaporozhye Oblast (Russian federal subject)
      "Q23334" => "GE",      # Abkhazia
      "Q31354462" => "GE",   # Republic of Abkhazia (de facto state)
      "Q2914461" => "GE",    # Autonomous Republic of Abkhazia
      "Q23427" => "GE",      # South Ossetia
      "Q907112" => "MD",     # Transnistria
      "Q648767" => "MD",     # Administrative-Territorial Units of the Left Bank of the Dniester
      "Q23681" => "CY"       # Northern Cyprus
    }.freeze

    QUERY = <<~SPARQL
      SELECT ?item ?via ?cc ?rank ?end ?region
             (GROUP_CONCAT(DISTINCT CONCAT(STR(?ref), "|", COALESCE(STR(?refurl), ""), "|", COALESCE(STR(?stated), "")); separator=" ") AS ?refs)
      WHERE {
        hint:Query hint:optimizer "None" .
        ?item p:P3797 ?any .
        {
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
        } UNION {
          ?item (wdt:P159|wdt:P131)/wdt:P131* ?region .
          VALUES ?region { #{REGIONS.keys.map { |q| "wd:#{q}" }.join(' ')} }
          BIND("region" AS ?via)
        }
      }
      GROUP BY ?item ?via ?cc ?rank ?end ?region
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
      regions = Hash.new { |h, k| h[k] = [] } # qid -> [published code of each region hit]
      bindings.each do |b|
        if b.dig("via", "value") == "region"
          code = REGIONS[b.dig("region", "value").to_s.split("/").last]
          regions[b.dig("item", "value").to_s.split("/").last] << code if code
          next
        end

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
      apply_regions!(out, regions, stats)
      stats["items_with_country"] = out.size
      [out, stats.to_h]
    end

    # The REGIONS rules (see the header). Mutates out and stats.
    def apply_regions!(out, regions, stats)
      regions.each do |qid, codes|
        codes = codes.uniq
        base = out[qid] && out[qid]["cc"]
        state = codes.first
        allowed = [nil, state, *Countries::DE_FACTO_CONTROLLERS.fetch(state, [])]
        if codes.size == 1 && allowed.include?(base)
          out[qid] = { "cc" => state, "via" => "territory" }
          stats["territory"] += 1
        else
          out.delete(qid)
          stats["ambiguous_territory"] += 1
        end
      end
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
