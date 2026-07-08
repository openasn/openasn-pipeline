# frozen_string_literal: true

require "zlib"
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
    # each listed origin. Files are DATED snapshots, so we discover the newest file in
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
      def accumulate(lines, acc)
        lines.each do |line|
          p = parse_line(line) or next
          v6, len, origins = p
          next if v6 ? (len > 128 || len < 1) : (len > 32 || len < 1)
          origins.each do |asn|
            x = (acc[asn] ||= { "prefixes_v4" => 0, "prefixes_v6" => 0, "ipv4_addresses" => 0, "ipv6_addresses" => 0 })
            if v6
              x["prefixes_v6"] += 1
              x["ipv6_addresses"] += (1 << (128 - len))
            else
              x["prefixes_v4"] += 1
              x["ipv4_addresses"] += (1 << (32 - len))
            end
          end
        end
        acc
      end

      # Pure test helper: full text blob -> counts (with ipv6 stringified).
      def tally(text)
        acc = {}
        accumulate(text.each_line, acc)
        acc.each_value { |a| a["ipv6_addresses"] = a["ipv6_addresses"].to_s }
        acc
      end

      def fetch_all(http: Http.new)
        acc = {}
        route_files(http: http).each do |_af, path|
          Zlib::GzipReader.open(path) { |gz| accumulate(gz, acc) }
        end
        acc.each_value { |a| a["ipv6_addresses"] = a["ipv6_addresses"].to_s } # bignum -> string
        acc
      end
    end
  end
end
