# frozen_string_literal: true

require "stringio"
require_relative "../../lib/env"
require_relative "../../lib/http"

module OpenASNPipeline
  module Quant
    # Originated prefixes + announced address space per ASN, from the bgp.tools
    # full-table snapshot (one origin ASN per prefix, ~1.46M lines / ~75MB). This
    # is what the AS actually ANNOUNCES into the DFZ — distinct from RIR-ALLOCATED
    # space (rir_stats) and from CAIDA customer-CONE totals.
    #
    # Source: https://bgp.tools/table.jsonl
    #   line: {"CIDR":"1.1.1.0/24","ASN":13335,"Hits":N}
    # bgp.tools AUP (https://bgp.tools/kb/api): send a descriptive User-Agent that
    # identifies you (our Http USER_AGENT carries the project URL) and do NOT re-pull
    # table.jsonl more than ~once per 10 min. Our Http.fetch does a conditional GET,
    # so repeat runs 304 against the cached copy. ASN 0 (unrouted/bogon origin) and
    # nonsensical prefix lengths are skipped.
    #
    # GOTCHA: ipv6_addresses is an astronomically large integer (sum of 2^(128-len)
    # across ~200k v6 prefixes) -> serialized as a STRING to keep the JSON sane and
    # to match the dossier schema's `ipv6_count` string. ipv4_addresses fits a normal
    # integer. We parse each line with a regex rather than JSON.parse — at 1.46M
    # lines the per-line JSON.parse overhead is the whole runtime; the regex is ~5x faster.
    module Prefixes
      URL = "https://bgp.tools/table.jsonl"

      module_function

      def parse_io(io)
        acc = {}
        io.each_line do |line|
          asn = line[/"ASN":(\d+)/, 1] or next
          asn = asn.to_i
          next if asn.zero?
          cidr = line[/"CIDR":"([^"]+)"/, 1] or next
          len  = cidr[%r{/(\d+)\z}, 1]&.to_i or next
          a = (acc[asn] ||= { "prefixes_v4" => 0, "prefixes_v6" => 0, "ipv4_addresses" => 0, "ipv6_addresses" => 0 })
          if cidr.include?(":")
            next if len > 128
            a["prefixes_v6"] += 1
            a["ipv6_addresses"] += (1 << (128 - len))
          else
            next if len > 32
            a["prefixes_v4"] += 1
            a["ipv4_addresses"] += (1 << (32 - len))
          end
        end
        acc.each_value { |a| a["ipv6_addresses"] = a["ipv6_addresses"].to_s } # bignum -> string
        acc
      end

      def parse(str) = parse_io(StringIO.new(str))

      def fetch_all(http: Http.new)
        File.open(http.fetch(URL, "quant/bgptable.jsonl")) { |io| parse_io(io) }
      rescue StandardError => e
        Env.warn("quant/prefixes: failed (#{e.message}); continuing")
        {}
      end
    end
  end
end
