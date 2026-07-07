# frozen_string_literal: true

require "json"
require "fileutils"
require "time"
require_relative "../../lib/env"
require_relative "../../lib/http"
require_relative "caida"
require_relative "rir_stats"
require_relative "apnic"
require_relative "rpki"
require_relative "prefixes"

module OpenASNPipeline
  module Quant
    # Layer-A quant importer (PRD.md §10 / §14 Phase 1). Merges the bulk,
    # LLM-free, license-clean sources into one provenance-stamped quant record per
    # ASN and writes build/enrich/quant.jsonl. Sources (all attribution-or-public,
    # never share-alike — D-ENRICH-6):
    #   RIR delegated-extended stats — allocation date, RIR, country, status, org-hash
    #   CAIDA AS Rank                — rank, customer cone, AS degree, RIR, country, org-id
    #   APNIC AS-Pop                 — eyeball (end-user) population + rank
    #   RPKI VRPs (rpki-client)      — ROA signing footprint (count)
    #   bgp.tools full table         — announced prefixes + address space (v4/v6)
    #
    # Every ASN record carries a `sources` array (which fields came from which source
    # + URL + as_of) so any figure is auditable (D-ENRICH-4). Never calls an LLM and
    # is never part of the deterministic nightly `rake build`. Each fetcher is
    # keep-partial: a dead upstream nils its section and the run continues.
    module Build
      OUT = File.join(BUILD_DIR, "enrich", "quant.jsonl")

      # For each source: the quant fields it authoritatively provides + how to name
      # its provenance URL. `url` is a proc of the per-ASN row (only RIR needs the
      # row, to pick the right RIR's file).
      SOURCE_META = {
        rir:      { name: "RIR delegated-extended stats",
                    url: ->(row) { RirStats::FILES[row["rir"].to_s] || "https://ftp.arin.net/pub/stats/" },
                    fields: %w[rir country allocated status org_hash] },
        caida:    { name: "CAIDA AS Rank", url: ->(_) { Caida::BASE },
                    fields: %w[caida_asrank asn_name cone_asns cone_prefixes cone_addresses
                               as_degree_total as_degree_customer as_degree_peer as_degree_provider caida_org_id] },
        apnic:    { name: "APNIC AS-Pop (eyeball estimates)", url: ->(_) { Apnic::URL },
                    fields: %w[eyeball_users eyeball_pct_internet eyeball_rank] },
        rpki:     { name: "RPKI VRPs (rpki-client)", url: ->(_) { Rpki::URL },
                    fields: %w[rpki_roas] },
        prefixes: { name: "bgp.tools full table", url: ->(_) { Prefixes::URL },
                    fields: %w[prefixes_v4 prefixes_v6 ipv4_addresses ipv6_addresses] },
      }.freeze

      module_function

      # caida_pages / rirs bound the sample; apnic/rpki/prefixes booleans let a quick
      # sample skip the heavy pulls (bgp.tools 75MB, RPKI ~1M rows).
      def run(http: Http.new, as_of: Time.now.utc.strftime("%Y-%m-%d"),
              caida_pages: nil, rirs: nil, apnic: true, rpki: true, prefixes: true)
        Env.prepare_dirs!
        FileUtils.mkdir_p(File.dirname(OUT))

        rows = {
          rir:      RirStats.fetch_all(http: http, only: rirs),
          caida:    Caida.fetch_all(http: http, max_pages: caida_pages),
          apnic:    (apnic    ? Apnic.fetch_all(http: http)    : {}),
          rpki:     (rpki     ? Rpki.fetch_all(http: http)     : {}),
          prefixes: (prefixes ? Prefixes.fetch_all(http: http) : {}),
        }
        asns = rows.values.flat_map(&:keys).uniq.sort

        File.open(OUT, "w") do |f|
          asns.each { |asn| f.puts JSON.generate(record(asn, per_asn(rows, asn), as_of)) }
        end

        stats = { total: asns.size }.merge(rows.transform_values(&:size))
        Env.log("quant: wrote #{stats[:total]} ASNs -> #{OUT} #{stats.inspect}")
        stats
      end

      # { source => full-hash } -> { source => this-ASN's row (or nil) }
      def per_asn(rows, asn)
        rows.transform_values { |h| h[asn] }
      end

      # Merge one ASN's rows from every source into a provenance-stamped record. Pure.
      def record(asn, rows, as_of)
        r = rows[:rir] || {}
        c = rows[:caida] || {}

        quant = {
          "asn"                => asn,
          "rir"                => (c["rir"] || r["rir"]&.upcase),   # normalize to uppercase
          "country"            => (r["country"] || c["country"]),   # prefer RIR registry country
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
        # Additive source blocks (eyeball / rpki / announced prefixes) — flat merge.
        %i[apnic rpki prefixes].each do |k|
          (rows[k] || {}).each { |field, val| quant[field] = val }
        end

        sources = []
        rows.each do |source, row|
          next if row.nil? || row.empty?
          m = SOURCE_META[source]
          sources << { "fields" => m[:fields], "source" => m[:name], "url" => m[:url].call(row), "as_of" => as_of }
        end

        { "asn" => asn, "quant" => quant, "sources" => sources }
      end
    end
  end
end
