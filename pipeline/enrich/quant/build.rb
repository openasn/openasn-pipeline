# frozen_string_literal: true

require "json"
require "fileutils"
require "time"
require_relative "../../lib/env"
require_relative "../../lib/http"
require_relative "caida"
require_relative "rir_stats"

module OpenASNPipeline
  module Quant
    # Layer-A quant importer (PRD.md §10 / §14 Phase 1). Merges the bulk,
    # LLM-free, license-clean sources (RIR stats + CAIDA AS Rank) into one
    # provenance-stamped quant record per ASN and writes build/enrich/quant.jsonl.
    #
    # Every ASN record carries a `sources` array (which fields came from which
    # source + URL + as_of) so any figure is auditable (D-ENRICH-4). This never
    # calls an LLM and is never part of the deterministic nightly `rake build`.
    module Build
      OUT = File.join(BUILD_DIR, "enrich", "quant.jsonl")

      module_function

      def run(http: Http.new, as_of: Time.now.utc.strftime("%Y-%m-%d"), caida_pages: nil, rirs: nil)
        Env.prepare_dirs!
        FileUtils.mkdir_p(File.dirname(OUT))

        rir   = RirStats.fetch_all(http: http, only: rirs)
        caida = Caida.fetch_all(http: http, max_pages: caida_pages)
        asns  = (rir.keys | caida.keys).sort

        File.open(OUT, "w") do |f|
          asns.each { |asn| f.puts JSON.generate(record(asn, rir[asn], caida[asn], as_of)) }
        end

        stats = { total: asns.size, rir: rir.size, caida: caida.size,
                  both: (rir.keys & caida.keys).size,
                  ranked: caida.count { |_a, c| c["caida_asrank"] } }
        Env.log("quant: wrote #{stats[:total]} ASNs -> #{OUT} " \
                "(rir #{stats[:rir]}, caida #{stats[:caida]}, both #{stats[:both]})")
        stats
      end

      # Merge one ASN's RIR + CAIDA rows into a provenance-stamped record. Pure.
      def record(asn, rir_row, caida_row, as_of)
        r = rir_row || {}
        c = caida_row || {}

        sources = []
        unless r.empty?
          sources << { "fields" => %w[rir country allocated status org_hash],
                       "source" => "RIR delegated-extended stats",
                       "url"    => RirStats::FILES[r["rir"].to_s] || "https://ftp.arin.net/pub/stats/",
                       "as_of"  => as_of }
        end
        unless c.empty?
          sources << { "fields" => %w[caida_asrank asn_name cone_asns cone_prefixes cone_addresses
                                      as_degree_total as_degree_customer as_degree_peer as_degree_provider caida_org_id],
                       "source" => "CAIDA AS Rank",
                       "url"    => Caida::BASE,
                       "as_of"  => as_of }
        end

        quant = {
          "asn"                => asn,
          "rir"                => (c["rir"] || r["rir"]&.upcase),   # normalize to uppercase
          "country"            => (r["country"] || c["country"]),   # prefer registry country
          "allocated"          => r["allocated"],
          "status"             => r["status"],
          "org_hash"           => r["org_hash"],
          "caida_org_id"       => c["org_id"],
          "asn_name"           => c["asn_name"],
          "caida_asrank"       => c["caida_asrank"],
          "cone_asns"          => c["cone_asns"],
          "cone_prefixes"      => c["cone_prefixes"],
          "cone_addresses"     => c["cone_addresses"],
          "as_degree_total"    => c["as_degree_total"],
          "as_degree_customer" => c["as_degree_customer"],
          "as_degree_peer"     => c["as_degree_peer"],
          "as_degree_provider" => c["as_degree_provider"],
        }

        { "asn" => asn, "quant" => quant, "sources" => sources }
      end
    end
  end
end
