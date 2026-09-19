# frozen_string_literal: true

require "zlib"
require "ipaddr"
require "socket"
require_relative "../../lib/env"
require_relative "../../lib/http"

module OpenASNPipeline
  module Quant
    # Originated prefixes + announced address space per ASN, from CAIDA's RouteViews
    # prefix2as snapshots (v4 + v6): the origin-AS for every prefix in the global
    # table. This is what an AS ANNOUNCES (distinct from RIR-ALLOCATED space and CAIDA
    # customer-CONE totals).
    #
    # SOURCE CHOICE (changed 2026-07-08 after the adversarial audit): we previously
    # used bgp.tools/table.jsonl, but bgp.tools grants NO redistribution/attribution
    # license (its AUP sanctions only rate-limited per-ASN cross-checks), which would
    # taint a CC0 product. CAIDA RouteViews prefix2as is attribution-only — the SAME
    # basis as our CAIDA AS Rank use (D-ENRICH-6) — so it is redistribution-clean.
    # Credit CAIDA + the RouteViews Project (University of Oregon) in ATTRIBUTION.md.
    #
    # Format (gzipped, tab-separated): "prefix\tprefixlen\tAS". The AS field may be a
    # MOAS set ("AS1_AS2") or multi-origin ("AS1,AS2"); we attribute the prefix to
    # each listed origin.
    #
    # ADDRESS COUNTS ARE UNIONS (fixed 2026-09-19): an AS routinely announces a covering
    # aggregate AND more-specifics inside it (10.0.0.0/16 + 10.0.1.0/24). Summing
    # 2^(32-len) per prefix counted that space two or more times (Orange Egypt AS37069:
    # 13.26M summed vs 4.51M unique, which equals CAIDA's cone for its single-AS cone).
    # ipv4_addresses / ipv6_addresses are therefore the size of the UNION of the AS's
    # announced ranges; prefixes_v4 / prefixes_v6 stay plain prefix counts. Space announced
    # by two DIFFERENT origins (MOAS, or a customer's more-specific inside a provider
    # aggregate) still counts once for EACH origin: these are per-AS figures and must not
    # be summed across ASes to get a world total. Files are DATED snapshots, so we discover the newest file in
    # the current (or previous) month directory. ipv6_addresses is an astronomically
    # large integer -> serialized as a STRING.
    module Prefixes
      DIRS = {
        v4: "https://publicdata.caida.org/datasets/routing/routeviews-prefix2as",
        v6: "https://publicdata.caida.org/datasets/routing/routeviews6-prefix2as",
      }.freeze
      URL = "https://publicdata.caida.org/datasets/routing/routeviews-prefix2as (+ routeviews6-prefix2as)"

      module_function

      # Newest dated pfx2as file URL for an AF (this month, else last month).
      def latest_url(http, af)
        base = DIRS[af]
        t = Time.now.utc
        [[t.year, t.month], (t.month == 1 ? [t.year - 1, 12] : [t.year, t.month - 1])].each do |y, m|
          dir = format("%s/%04d/%02d/", base, y, m)
          body = begin
            http.get!(dir)
          rescue StandardError
            ""
          end
          files = body.scan(/routeviews-rv[26]-\d{8}-\d{4}\.pfx2as\.gz/).uniq.sort
          return dir + files.last unless files.empty?
        end
        nil
      end

      # Fetch+cache both AF files -> [[af, gz_path], ...] (a dead AF is skipped).
      def route_files(http: Http.new)
        DIRS.keys.filter_map do |af|
          url = latest_url(http, af) or next
          [af, http.fetch(url, "quant/prefix2as-#{af}.gz")]
        rescue StandardError => e
          Env.warn("quant/prefixes: #{af} fetch failed (#{e.message}); continuing")
          nil
        end
      end

      # "1.0.0.0\t24\t13335" -> [v6?, prefixlen, [origin_asns]] (MOAS split, ASN0 dropped); nil if junk.
      def parse_line(line)
        pfx, len, asf = line.split("\t")
        return nil unless asf
        origins = asf.strip.split(/[,_]/).map(&:to_i).reject(&:zero?)
        return nil if origins.empty?
        [pfx.include?(":"), len.to_i, origins]
      end

      # Accumulate counts from an enumerable of pfx2as lines into `acc` (numeric, no stringify).
      # Each AS's announced ranges are collected in `spans` ({asn => {v4: [[first, last], ...], v6: [...]}});
      # `finalize` then turns them into de-duplicated address counts.
      def accumulate(lines, acc, spans = {})
        lines.each do |line|
          p = parse_line(line) or next
          v6, len, origins = p
          next if v6 ? (len > 128 || len < 1) : (len > 32 || len < 1)
          first = address_int(line.split("\t", 2).first, v6) or next
          size = 1 << ((v6 ? 128 : 32) - len)
          first &= ~(size - 1) # a non-canonical "10.0.0.1/24" counts as its network 10.0.0.0/24
          origins.each do |asn|
            x = (acc[asn] ||= { "prefixes_v4" => 0, "prefixes_v6" => 0, "ipv4_addresses" => 0, "ipv6_addresses" => 0 })
            x[v6 ? "prefixes_v6" : "prefixes_v4"] += 1
            ((spans[asn] ||= { v4: [], v6: [] })[v6 ? :v6 : :v4]) << [first, first + size - 1]
          end
        end
        acc
      end

      # Set each AS's address counts in `acc` to the size of the union of its announced ranges.
      def finalize(acc, spans)
        spans.each do |asn, by_af|
          acc[asn]["ipv4_addresses"] = union_size(by_af[:v4])
          acc[asn]["ipv6_addresses"] = union_size(by_af[:v6])
        end
        acc
      end

      # Distinct addresses covered by inclusive [first, last] ranges (overlaps and duplicates counted once).
      def union_size(ranges)
        total = 0
        cur_first = cur_last = nil
        ranges.sort.each do |f, l|
          if cur_last && f <= cur_last + 1
            cur_last = l if l > cur_last
          else
            total += cur_last - cur_first + 1 if cur_last
            cur_first = f
            cur_last = l
          end
        end
        total += cur_last - cur_first + 1 if cur_last
        total
      end

      # "1.2.3.0" / "2001:db8::" -> Integer, nil if unparseable.
      def address_int(text, v6)
        IPAddr.new(text, v6 ? Socket::AF_INET6 : Socket::AF_INET).to_i
      rescue IPAddr::Error, ArgumentError
        nil
      end

      # Pure test helper: full text blob -> counts (with ipv6 stringified).
      def tally(text)
        acc = {}
        spans = {}
        accumulate(text.each_line, acc, spans)
        finalize(acc, spans)
        acc.each_value { |a| a["ipv6_addresses"] = a["ipv6_addresses"].to_s }
        acc
      end

      def fetch_all(http: Http.new)
        acc = {}
        spans = {}
        route_files(http: http).each do |_af, path|
          Zlib::GzipReader.open(path) { |gz| accumulate(gz, acc, spans) }
        end
        finalize(acc, spans)
        acc.each_value { |a| a["ipv6_addresses"] = a["ipv6_addresses"].to_s } # bignum -> string
        acc
      end
    end
  end
end
