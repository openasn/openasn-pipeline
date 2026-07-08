# frozen_string_literal: true

require "ipaddr"
require "zlib"
require_relative "../../lib/env"
require_relative "../../lib/http"
require_relative "rpki"
require_relative "prefixes"

module OpenASNPipeline
  module Quant
    # RFC 6811 Route Origin Validation (RoV) per ASN. Joins the RPKI VRP set
    # (rpki-client) to the live routing table (CAIDA RouteViews prefix2as, the same
    # source `prefixes.rb` uses): for every prefix an ASN ANNOUNCES, decide whether
    # the origin is RPKI valid / invalid / not-found, then aggregate per ASN. Stronger
    # than the rpki_roas COUNT — an ASN announcing RPKI-INVALID routes is hijacking
    # space or misconfigured. Public data, CC0-safe.
    #
    # RFC 6811 §2, for a route {prefix P, origin AS A}:
    #   covered = some VRP's prefix is equal-or-LESS-specific than P (P sits inside it)
    #   valid   = some covering VRP has ASN == A AND P.len <= VRP.maxLength
    #   => Valid if valid; else Invalid if covered; else NotFound.
    # We only probe VRP prefix-lengths that actually occur (~20 lookups/route).
    module Rov
      module_function

      MASK4 = (0..32).map  { |l| l.zero? ? 0 : (((1 << l) - 1) << (32 - l)) }.freeze
      MASK6 = (0..128).map { |l| l.zero? ? 0 : (((1 << l) - 1) << (128 - l)) }.freeze

      # "1.2.3.0/24" -> [v6?, network_int, prefixlen] (with host bits masked off) or nil.
      def parse_cidr(cidr)
        slash = cidr.index("/") or return nil
        len = cidr[(slash + 1)..].to_i
        net = parse_addr(cidr[0...slash]) or return nil
        v6 = cidr.include?(":")
        [v6, net & (v6 ? MASK6[len] : MASK4[len]), len] # mask so a VRP row is stored at its true network
      end

      # Bare address (no slash) -> integer. Hand-parses v4 (hot path); IPAddr for v6.
      def parse_addr(addr)
        if addr.include?(":")
          begin
            IPAddr.new(addr).to_i
          rescue StandardError
            nil
          end
        else
          a, b, c, d = addr.split(".", 4)
          return nil unless d
          ((a.to_i << 24) | (b.to_i << 16) | (c.to_i << 8) | d.to_i)
        end
      end

      # VRP CSV -> [ index{[v6?,net,len]=>[[asn,maxlen]]}, lens4_desc, lens6_desc ].
      # A PLAIN hash (no auto-vivifying default) so classify's missing-key reads do NOT
      # insert phantom empty arrays and bloat memory over 1.4M routes (audit finding).
      def build_index(io)
        idx = {}
        l4 = {}
        l6 = {}
        io.each_line do |line|
          m = line.match(/\AAS(\d+),([^,]+),(\d+),/) or next # skips header + blanks
          p = parse_cidr(m[2]) or next
          (idx[[p[0], p[1], p[2]]] ||= []) << [m[1].to_i, m[3].to_i]
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
          next if vrps.nil? || vrps.empty?
          covered = true
          vrps.each { |asn, maxlen| return :valid if asn == origin && len <= maxlen }
        end
        covered ? :invalid : :notfound
      end

      # Aggregate RoV over the announced table (CAIDA prefix2as v4+v6) ->
      # { asn => {rov_valid,rov_invalid,rov_notfound,rpki_rov_status} }.
      def compute(route_files, idx, lens4, lens6)
        out = {}
        route_files.each do |_af, path|
          Zlib::GzipReader.open(path) do |gz|
            gz.each_line do |line|
              pfx, len, asf = line.split("\t")
              next unless asf
              len = len.to_i
              v6 = pfx.include?(":")
              net = parse_addr(pfx) or next
              asf.strip.split(/[,_]/).each do |a|
                asn = a.to_i
                next if asn.zero?
                st = classify(v6, net, len, asn, idx, v6 ? lens6 : lens4)
                r = (out[asn] ||= { "rov_valid" => 0, "rov_invalid" => 0, "rov_notfound" => 0 })
                r["rov_#{st}"] += 1
              end
            end
          end
        end
        out.each_value { |r| r["rpki_rov_status"] = rov_status(r) }
        out
      end

      def rov_status(r)
        if    r["rov_invalid"].positive?                          then "has_invalids"
        elsif r["rov_valid"].positive? && r["rov_notfound"].zero? then "all_valid"
        elsif r["rov_valid"].positive?                            then "partial"
        else "unknown"
        end
      end

      def fetch_all(http: Http.new)
        idx, l4, l6 = File.open(http.fetch(Rpki::URL, "quant/rpki-vrps.csv")) { |io| build_index(io) }
        compute(Prefixes.route_files(http: http), idx, l4, l6)
      rescue StandardError => e
        Env.warn("quant/rov: failed (#{e.message}); continuing")
        {}
      end
    end
  end
end
