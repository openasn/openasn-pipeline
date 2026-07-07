# frozen_string_literal: true

require "json"
require_relative "../../lib/env"
require_relative "../../lib/http"

module OpenASNPipeline
  module Quant
    # CAIDA AS Rank — customer-cone size, AS degree, rank, RIR, country and an
    # opaque org id per ASN. The quantitative spine of the Layer-A quant block.
    #
    # Source: https://api.asrank.caida.org/ (REST v2, paginated). CAIDA's AUP
    # asks that the data be cited/acknowledged (attribution), not share-alike —
    # so DERIVED metrics + a source URL are CC0-safe (D-ENRICH-4/-6). We store
    # only our derived numbers, never a mirror of CAIDA's DB. Credit CAIDA in
    # ATTRIBUTION.md when this ships.
    module Caida
      BASE = "https://api.asrank.caida.org/v2/restful/asns/"
      PAGE = 10_000

      module_function

      # Parse one REST page body -> { asn(Integer) => Hash }. Pure; offline-testable.
      def parse_page(body)
        edges = JSON.parse(body).dig("data", "asns", "edges") || []
        out = {}
        edges.each do |e|
          n = e["node"] or next
          asn = Integer(n["asn"].to_s, exception: false) or next
          cone = n["cone"] || {}
          deg  = n["asnDegree"] || {}
          out[asn] = {
            "caida_asrank"       => n["rank"],
            "asn_name"           => n["asnName"],
            "rir"                => n["source"],          # "ARIN"/"RIPE"/... (uppercase)
            "country"            => n.dig("country", "iso"),
            "org_id"             => n.dig("organization", "orgId"),
            "cone_asns"          => cone["numberAsns"],
            "cone_prefixes"      => cone["numberPrefixes"],
            "cone_addresses"     => cone["numberAddresses"],
            "as_degree_total"    => deg["total"],
            "as_degree_customer" => deg["customer"],
            "as_degree_peer"     => deg["peer"],
            "as_degree_provider" => deg["provider"],
          }
        end
        out
      end

      def next_page?(body)
        JSON.parse(body).dig("data", "asns", "pageInfo", "hasNextPage") ? true : false
      end

      # Fetch every page -> merged { asn => Hash }. `max_pages` bounds it for
      # sampling/tests (nil = all). Network.
      def fetch_all(http: Http.new, first: PAGE, max_pages: nil)
        out = {}
        offset = 0
        pages = 0
        loop do
          body = http.get!("#{BASE}?first=#{first}&offset=#{offset}")
          out.merge!(parse_page(body))
          pages += 1
          Env.log("quant/caida: #{out.size} ASNs (page #{pages}, offset #{offset})")
          break if max_pages && pages >= max_pages
          break unless next_page?(body)
          offset += first
        end
        out
      end
    end
  end
end
