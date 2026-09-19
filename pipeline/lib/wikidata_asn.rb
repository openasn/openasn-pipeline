# frozen_string_literal: true

# PROTOTYPE — Wikidata P3797 ("autonomous system number") as a CC0 seed of
# ASN -> organisation item (QID + English label), and a measurement of how far
# RIR holder clusters (lib/rir_stats.rb) would carry those names.
#
# Licence: "All structured data from the main, Property, Lexeme, and
# EntitySchema namespaces is available under the Creative Commons CC0 License"
# (https://www.wikidata.org/wiki/Wikidata:Copyright, re-read 2026-09-19).
# P3797 statements and item labels are main-namespace structured data, so this
# source could qualify for Tier A. It is NOT wired into compile/publish:
# this prototype writes build/work/wikidata/ only. Promotion would need its own
# decision, a pinned licence receipt, and a FORMAT/EXPORT_FORMATS plan for where
# the names go.
#
# What it is (measured 2026-09-12 and 2026-09-19): a notability-gated
# encyclopaedia, not an operator registry. It has ~1.8k statements, strong on
# famous operators and legacy academia, and misses the unglamorous hosters.
# Treat it as high-precision, low-recall.
#
# Rules: deprecated-rank statements are dropped; statements with an end time
# (P582) are former ASNs and dropped; an ASN claimed by two items is a
# conflict and yields no name. Several ASNs per item is normal (Google: AS15169,
# AS396982 -> Q95).

require "json"
require "uri"
require "fileutils"
require_relative "env"
require_relative "http"
require_relative "rir_stats"

module OpenASNPipeline
  module WikidataAsn
    QUERY = <<~SPARQL
      SELECT ?item ?asn ?rank ?end ?itemLabel WHERE {
        ?item p:P3797 ?st .
        ?st ps:P3797 ?asn ; wikibase:rank ?rank .
        OPTIONAL { ?st pq:P582 ?end . }
        SERVICE wikibase:label { bd:serviceParam wikibase:language "en,mul". }
      }
    SPARQL
    ENDPOINT = "https://query.wikidata.org/sparql"
    LICENSE_URL = "https://www.wikidata.org/wiki/Wikidata:Copyright"
    OUT_DIR = File.join(WORK_DIR, "wikidata")
    MAX_ASN = 4_294_967_295

    module_function

    def url = "#{ENDPOINT}?format=json&query=#{URI.encode_www_form_component(QUERY)}"

    # SPARQL JSON -> [rows, dropped]. Pure.
    # rows: { asn => { "qid", "label" } } (conflicting ASNs removed)
    # dropped: { "deprecated" => n, "ended" => n, "bad_asn" => n, "conflict" => [asns] }
    def parse(json)
      bindings = JSON.parse(json).dig("results", "bindings") || []
      dropped = { "deprecated" => 0, "ended" => 0, "bad_asn" => 0, "conflict" => [] }
      claims = Hash.new { |h, k| h[k] = {} }
      bindings.each do |b|
        if b.dig("rank", "value").to_s.end_with?("DeprecatedRank")
          dropped["deprecated"] += 1
          next
        end
        if b["end"]
          dropped["ended"] += 1
          next
        end
        asn = parse_asn(b.dig("asn", "value"))
        unless asn
          dropped["bad_asn"] += 1
          next
        end
        qid = b.dig("item", "value").to_s.split("/").last
        label = b.dig("itemLabel", "value")
        label = nil if label.nil? || label == qid # label service echoes the QID when no label exists
        claims[asn][qid] = label
      end
      rows = {}
      claims.each do |asn, items|
        if items.size > 1
          dropped["conflict"] << asn
        else
          qid, label = items.first
          rows[asn] = { "qid" => qid, "label" => label }
        end
      end
      dropped["conflict"].sort!
      [rows, dropped]
    end

    # "AS15169", "15169", " 15169 " -> 15169; anything else (ranges, junk,
    # 0, private-use is kept - reporting, not filtering) -> nil.
    def parse_asn(v)
      s = v.to_s.strip.sub(/\AAS/i, "")
      return nil unless s.match?(/\A\d+\z/)

      n = s.to_i
      n.between?(1, MAX_ASN) ? n : nil
    end

    # How far would RIR holder clusters carry the Wikidata names? Pure.
    # A sibling inherits a name only when every named member of its cluster
    # agrees on one QID; pools never propagate (RirStats.siblings).
    def coverage(rows, rir_rows, clusters)
      delegated = rir_rows.select { |_, r| RirStats::DELEGATED.include?(r["status"]) }
      direct = rows.keys.select { |a| delegated.key?(a) }
      inherited = {}
      disagreements = 0
      clusters.each do |holder, members|
        next unless RirStats.cluster_kind(members.size) == :siblings

        named = members.filter_map { |a| rows[a]&.fetch("qid") }.uniq
        next if named.empty?
        if named.size > 1
          disagreements += 1
          next
        end
        members.each { |a| inherited[a] = named.first unless rows.key?(a) }
      end
      {
        "wikidata_asns" => rows.size,
        "wikidata_items" => rows.values.map { _1["qid"] }.uniq.size,
        "rir_delegated_asns" => delegated.size,
        "direct_in_delegated" => direct.size,
        "not_in_loaded_rir_files" => rows.size - direct.size,
        "inherited_via_siblings" => inherited.size,
        "named_after_propagation" => direct.size + inherited.size,
        "multiplier" => direct.empty? ? nil : ((direct.size + inherited.size).to_f / direct.size).round(2),
        "clusters_with_disagreeing_items" => disagreements,
        "pct_delegated_named_direct" => pct(direct.size, delegated.size),
        "pct_delegated_named_after" => pct(direct.size + inherited.size, delegated.size)
      }
    end

    def pct(a, b) = b.zero? ? nil : (100.0 * a / b).round(2)

    def build(http: Http.new, offline: ENV["OFFLINE"] == "1", out_dir: OUT_DIR, rir: nil)
      path = http.fetch(url, "wikidata/p3797.json", offline: offline)
      rows, dropped = parse(File.read(path))
      rir ||= RirStats.build(http: http, offline: offline)
      cov = coverage(rows, rir[:rows], rir[:clusters])
      stats = cov.merge("dropped" => dropped.merge("conflict" => dropped["conflict"].size),
                        "conflict_asns" => dropped["conflict"], "license" => "CC0-1.0", "license_url" => LICENSE_URL,
                        "query_url" => ENDPOINT, "fetched_at" => http.fetched_at("wikidata/p3797.json"),
                        "rir_files" => rir[:stats]["rirs"].keys, "ripe_included" => rir[:stats]["ripe_included"])
      FileUtils.mkdir_p(out_dir)
      File.open(File.join(out_dir, "asn-items.jsonl"), "w") do |f|
        rows.keys.sort.each { |a| f.puts JSON.generate({ "asn" => a }.merge(rows[a])) }
      end
      File.write(File.join(out_dir, "coverage.json"), JSON.pretty_generate(stats) + "\n")
      Env.log("wikidata: #{cov['wikidata_asns']} ASNs / #{cov['wikidata_items']} items; " \
              "#{cov['direct_in_delegated']} direct + #{cov['inherited_via_siblings']} via siblings -> #{out_dir}")
      stats
    end
  end
end
