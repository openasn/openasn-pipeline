# frozen_string_literal: true

require "ipaddr"
require_relative "../../lib/env"
require_relative "../../lib/http"
require_relative "rpki"
require_relative "prefixes"

module OpenASNPipeline
  module Quant
    # RFC 6811 Route Origin Validation (RoV) per ASN. Joins the RPKI VRP set
    # (rpki-client) to the live BGP table (bgp.tools): for every prefix an ASN
    # ANNOUNCES, decide whether that origin is RPKI valid / invalid / not-found, then
    # aggregate per ASN. This is the real routing-security signal — an ASN announcing
    # RPKI-INVALID routes is either hijacking space or misconfigured — and is stronger
    # than the rpki_roas COUNT (which only says the ASN publishes ROAs, not whether
    # what it actually announces is authorized).
    #
    # Both inputs are already fetched by the rpki/prefixes fetchers; Http's conditional
    # GET makes the re-fetch here a 304 against the cache. Public data, CC0-safe.
    #
    # Algorithm (RFC 6811 §2), for a route {prefix P, origin AS A}:
    #   covered = some VRP's prefix is equal-or-LESS-specific than P (P sits inside it)
    #   valid   = some covering VRP has ASN == A AND P.len <= VRP.maxLength
    #   => Valid if valid; else Invalid if covered; else NotFound.
    # The classic invalids this catches: wrong-origin (someone else's space) and
    # more-specific-than-maxLength (a /24 under a /22-max ROA). We only probe VRP
    # prefix-lengths that actually occur (lens_present), cutting per-route work to ~20
    # lookups instead of walking every length 0..32/0..128.
    module Rov
      module_function

      MASK4 = (0..32).map  { |l| l.zero? ? 0 : (((1 << l) - 1) << (32 - l)) }.freeze
      MASK6 = (0..128).map { |l| l.zero? ? 0 : (((1 << l) - 1) << (128 - l)) }.freeze

      # "1.2.3.0/24" / "2606:4700::/32" -> [v6?, network_int, prefixlen] or nil.
      # Hand-parses v4 (the ~1.26M-route hot path); IPAddr handles the ~200k v6.
      def parse_cidr(cidr)
        slash = cidr.index("/") or return nil
        len = cidr[(slash + 1)..].to_i
        addr = cidr[0...slash]
        if addr.include?(":")
          begin
            [true, IPAddr.new(cidr).to_i, len]
          rescue StandardError
            nil
          end
        else
          a, b, c, d = addr.split(".", 4)
          return nil unless d
          [false, ((a.to_i << 24) | (b.to_i << 16) | (c.to_i << 8) | d.to_i), len]
        end
      end

      # VRP CSV -> [ index{[v6?,net,len]=>[[asn,maxlen]]}, lens4_desc, lens6_desc ].
      def build_index(io)
        idx = Hash.new { |h, k| h[k] = [] }
        l4 = {}
        l6 = {}
        io.each_line do |line|
          m = line.match(/\AAS(\d+),([^,]+),(\d+),/) or next # skips "ASN,IP Prefix,..." header + blanks
          p = parse_cidr(m[2]) or next
          idx[[p[0], p[1], p[2]]] << [m[1].to_i, m[3].to_i]
          (p[0] ? l6 : l4)[p[2]] = true
        end
        [idx, l4.keys.sort.reverse, l6.keys.sort.reverse]
      end

      # RFC 6811 state for one route. `lens` = candidate VRP lengths (desc) for the AF.
      def classify(v6, net, len, origin, idx, lens)
        masks = v6 ? MASK6 : MASK4
        covered = false
        lens.each do |l|
          next if l > len # a covering VRP can never be MORE-specific than the route
          vrps = idx[[v6, net & masks[l], l]]
          next if vrps.empty?
          covered = true
          vrps.each { |asn, maxlen| return :valid if asn == origin && len <= maxlen }
        end
        covered ? :invalid : :notfound
      end

      # Aggregate over the announced table -> { asn => {rov_valid,rov_invalid,rov_notfound,rpki_rov_status} }.
      def compute(routes_io, idx, lens4, lens6)
        out = {}
        routes_io.each_line do |line|
          asn = line[/"ASN":(\d+)/, 1] or next
          asn = asn.to_i
          next if asn.zero?
          cidr = line[/"CIDR":"([^"]+)"/, 1] or next
          p = parse_cidr(cidr) or next
          st = classify(p[0], p[1], p[2], asn, idx, p[0] ? lens6 : lens4)
          r = (out[asn] ||= { "rov_valid" => 0, "rov_invalid" => 0, "rov_notfound" => 0 })
          r["rov_#{st}"] += 1
        end
        out.each_value do |r|
          r["rpki_rov_status"] =
            if    r["rov_invalid"].positive?                          then "has_invalids"
            elsif r["rov_valid"].positive? && r["rov_notfound"].zero? then "all_valid"
            elsif r["rov_valid"].positive?                            then "partial"
            else "unknown"
            end
        end
        out
      end

      def fetch_all(http: Http.new)
        idx, l4, l6 = File.open(http.fetch(Rpki::URL, "quant/rpki-vrps.csv")) { |io| build_index(io) }
        File.open(http.fetch(Prefixes::URL, "quant/bgptable.jsonl")) { |io| compute(io, idx, l4, l6) }
      rescue StandardError => e
        Env.warn("quant/rov: failed (#{e.message}); continuing")
        {}
      end
    end
  end
end
