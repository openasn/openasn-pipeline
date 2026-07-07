# frozen_string_literal: true

require "stringio"
require_relative "../../lib/env"
require_relative "../../lib/http"

module OpenASNPipeline
  module Quant
    # RPKI signing footprint per ASN, from the rpki-client global VRP set
    # (Validated ROA Payloads — every valid ROA in the RPKI, refreshed hourly).
    # We count how many ROAs name each ASN as the authorized origin; a non-zero
    # count means the operator publishes RPKI ROAs, a real routing-security-hygiene
    # signal. NOTE: this is a signing-FOOTPRINT count, NOT per-prefix Route-Origin
    # Validation of what the AS actually announces (that needs joining VRPs to the
    # live BGP table — a deliberate later pass). Public data, CC0-safe.
    #
    # Source: https://console.rpki-client.org/vrps.csv  (streamable CSV, ~1M rows)
    #   header: ASN,IP Prefix,Max Length,Trust Anchor,Expires
    #   row:    AS13335,1.0.0.0/24,24,apnic,1783952256
    # The JSON form (vrps.json) exists too but is a single huge object; the CSV is
    # line-oriented so we never hold the whole set in memory.
    module Rpki
      URL = "https://console.rpki-client.org/vrps.csv"

      module_function

      # Streamed line-by-line -> { asn(Integer) => { "rpki_roas" => count } }.
      def parse_io(io)
        counts = Hash.new(0)
        io.each_line do |line|
          # `\AAS(\d+),` cheaply skips the "ASN,IP Prefix,..." header and any blank
          # line while pulling the origin ASN; ~10x faster than CSV-parsing 1M rows.
          asn = line[/\AAS(\d+),/, 1] or next
          counts[asn.to_i] += 1
        end
        counts.transform_values { |n| { "rpki_roas" => n } }
      end

      def parse(str) = parse_io(StringIO.new(str))

      def fetch_all(http: Http.new)
        File.open(http.fetch(URL, "quant/rpki-vrps.csv")) { |io| parse_io(io) }
      rescue StandardError => e
        Env.warn("quant/rpki: failed (#{e.message}); continuing")
        {}
      end
    end
  end
end
