# frozen_string_literal: true

# Stage 2: parse every cached input into canonical in-memory structures.
# No policy decisions happen here - this stage is pure parsing + shaping.
# (Corrections/overrides semantics are applied in compile.rb; drift
# analysis in crosscheck.rb.)
#
# Canonical shapes produced:
#   base_v4 / base_v6 : sorted arrays of [start_int, end_int, asn]
#   asn_meta          : { asn => AsJson::Record }
#   vpn_v4 / dc_v4    : sorted merged arrays of [start_int, end_int], with
#                       X4B's third-party feeds removed (lib/x4b_first_party.rb)
#   bad_asns          : Set[Integer]
#   x4b_vpn_asns / x4b_dc_asns : Set[Integer] (crosscheck reference + seeds)
#   wikidata_names    : { asn => { "name", "qid" } } (CC0 org names, D-SRC-2)
#   wikidata_stats    : admissibility counts (manifest stats)
#   wikidata_countries: { qid => { "cc", "via" } } (CC0 country, D-SRC-2 country)
#   wikidata_country_stats : statement-rule counts (manifest stats)

require "set"
require_relative "lib/env"
require_relative "lib/ipmath"
require_relative "lib/asjson"
require_relative "lib/x4b_first_party"
require_relative "lib/wikidata_names"
require_relative "lib/wikidata_countries"
require_relative "fetch"

module OpenASNPipeline
  module Normalize
    module_function

    def run(paths)
      out = {}
      # :backbone_v4/_v6 are rib2origin's output (RouteViews, default) or, with
      # OPENASN_BACKBONE=sapics, sapics' origin-asn files in the same shape (fetch.rb).
      out[:base_v4] = parse_origin_asn(paths[:backbone_v4], IPMath::V4_MAX, "origin-asn ipv4")
      out[:base_v6] = parse_origin_asn(paths[:backbone_v6], IPMath::V6_MAX, "origin-asn ipv6")

      out[:asn_meta] = parse_as_metadata(paths[:as_json])

      out[:bad_asns]     = parse_bad_asn_csv(paths[:bad_asn])
      out[:x4b_vpn_asns] = parse_x4b_asn_file(paths[:x4b_vpn_asn])
      out[:x4b_dc_asns]  = parse_x4b_asn_file(paths[:x4b_dc_asn])

      # X4B's published overlays merge third-party feeds (Apple relay,
      # Mullvad, PIA, Proton) that are Tier B for us. vpn keeps only what
      # X4B's own first-party inputs justify; dc has the named feed file
      # stripped (lib/x4b_first_party.rb says why the methods differ;
      # data-repo DECISIONS.md D-SRC-3). dc is justified by BOTH ASN lists
      # because X4B's build-list.yml expands input/vpn/ASN.txt into it too.
      vpn_published = parse_cidr_list(paths[:x4b_vpn], "x4b vpn")
      res = X4BFirstParty.restrict(vpn_published, base_rows: out[:base_v4], asns: out[:x4b_vpn_asns],
                                                  manual: parse_cidr_list(paths[:x4b_vpn_manual], "x4b vpn Manual.txt"))
      X4BFirstParty.log("x4b vpn", res)
      out[:vpn_v4] = res.ranges

      dc_published = parse_cidr_list(paths[:x4b_dc], "x4b datacenter")
      dc_feeds = IPMath.merge_ranges(paths[:x4b_dc_feeds].flat_map { |p| parse_cidr_list(p, "x4b dc feed #{File.basename(p)}") })
      res = X4BFirstParty.strip_feeds(dc_published, feeds: dc_feeds, base_rows: out[:base_v4],
                                                    asns: out[:x4b_dc_asns] | out[:x4b_vpn_asns],
                                                    manual: parse_cidr_list(paths[:x4b_dc_manual], "x4b datacenter Manual.txt"))
      X4BFirstParty.log("x4b datacenter", res)
      out[:dc_v4] = res.ranges

      out[:wikidata_names], out[:wikidata_stats] = parse_wikidata(paths[:wikidata])
      out[:wikidata_countries], out[:wikidata_country_stats] = parse_wikidata_countries(paths[:wikidata_countries])

      out
    end

    # sapics -num CSVs: start_int,end_int,asn,"AS Name". We take the integers
    # and the ASN only. The AS-name column has undisclosed provenance and is
    # never read (published org names: org_names.txt + Wikidata, D-SRC-2).
    # The 4th column may contain commas inside quotes - split with a limit
    # so we never pay CSV-quote parsing for 559k rows we don't read.
    def parse_origin_asn(path, max_addr, label)
      rows = []
      bad = 0
      File.foreach(path) do |line|
        s, e, asn, _name = line.split(",", 4)
        s = s.to_i
        e = e.to_i
        asn = asn.to_i
        # to_i on garbage returns 0; a real range never starts and ends at 0.
        if e < s || e > max_addr || (s.zero? && e.zero?) || asn <= 0
          bad += 1
          next
        end
        rows << [s, e, asn]
      end
      Env.fail_stage!("#{label}: #{bad} malformed rows (>0.1%) - upstream format changed?") if bad > rows.length / 1000
      rows.sort_by!(&:first)
      sanitize_overlaps!(rows, label)
      Env.log("#{label}: #{rows.length} ranges" + (bad.positive? ? " (#{bad} skipped)" : ""))
      rows
    end

    # origin-asn is documented as non-overlapping, but we do not trust that
    # blindly: a torn upstream write or a compiler bug there would otherwise
    # corrupt binary search silently. Contained duplicates are dropped,
    # partial overlaps clipped; anything structural fails the build.
    def sanitize_overlaps!(rows, label)
      fixed = 0
      prev_end = -1
      rows.reject! do |row|
        if row[0] <= prev_end
          fixed += 1
          if row[1] <= prev_end
            true # fully contained in previous range - drop
          else
            row[0] = prev_end + 1
            prev_end = row[1]
            false
          end
        else
          prev_end = row[1]
          false
        end
      end
      return if fixed.zero?

      Env.warn("#{label}: repaired #{fixed} overlapping ranges")
      Env.fail_stage!("#{label}: #{fixed} overlaps is structural breakage, not noise - investigate upstream") if fixed > 1000
    end

    def parse_as_metadata(path)
      meta = {}
      AsJson.each_record(path) { |rec| meta[rec.asn] = rec }
      Env.log("as-metadata: #{meta.size} ASNs " \
              "(hosting=#{meta.count { |_, r| r.category == 'hosting' }}, " \
              "isp=#{meta.count { |_, r| r.category == 'isp' }})")
      meta
    end

    # A body that is not SPARQL JSON is breakage, not an empty answer: fail
    # loudly. HTTP errors were already absorbed at fetch time (keep-last-good).
    def parse_wikidata(path)
      names, stats = WikidataNames.parse(File.read(path))
      dropped = stats.except("statements", "admitted_asns").map { |k, v| "#{k}=#{v}" }.join(", ")
      Env.log("wikidata P3797: #{stats['statements']} statements -> #{names.size} admissible named ASNs (dropped: #{dropped})")
      [names, stats]
    rescue JSON::ParserError, ArgumentError => e
      Env.fail_stage!("wikidata P3797: unparseable response (#{e.message}) - did the endpoint return an error page?")
    end

    # Same failure policy as parse_wikidata.
    def parse_wikidata_countries(path)
      items, stats = WikidataCountries.parse(File.read(path))
      dropped = stats.except("statements", "items_with_country", "sar", "territory").map { |k, v| "#{k}=#{v}" }.join(", ")
      Env.log("wikidata P17/P159: #{stats['statements']} statements -> #{items.size} items with one country " \
              "(HK/MO refined: #{stats['sar'].to_i}, territory -> recognised state: #{stats['territory'].to_i}; dropped: #{dropped})")
      [items, stats]
    rescue JSON::ParserError, ArgumentError => e
      Env.fail_stage!("wikidata P17/P159: unparseable response (#{e.message}) - did the endpoint return an error page?")
    end

    def parse_cidr_list(path, label)
      ranges = []
      bad = 0
      File.foreach(path) do |line|
        stripped = line.strip
        next if stripped.empty? || stripped.start_with?("#")

        # First token only, like X4B's own build (`grep -v '^#' | awk
        # '{print $1}'`): hand-curated files carry `CIDR # reason` lines.
        stripped = stripped.split(/[\s#]/, 2).first
        begin
          s, e, family = IPMath.cidr_to_range(stripped)
          # X4B is IPv4-only; skip any future v6 lines rather than corrupt the v4 layer.
          ranges << [s, e] if family == :ipv4
        rescue IPAddr::Error
          bad += 1
        end
      end
      # A handful of malformed lines is upstream noise; a flood is breakage.
      Env.fail_stage!("#{label}: #{bad} unparseable lines - upstream format changed?") if bad > 20
      merged = IPMath.merge_ranges(ranges)
      Env.log("#{label}: #{ranges.length} cidrs -> #{merged.length} merged ranges" + (bad.positive? ? " (#{bad} skipped)" : ""))
      merged
    end

    # bad-asn-list.csv: header row `ASN,Entity`, then `1442,"Surehosting..."`.
    def parse_bad_asn_csv(path)
      asns = Set.new
      File.foreach(path).with_index do |line, i|
        next if i.zero? # header

        asn = line.split(",", 2).first.to_i
        asns << asn if asn.positive?
      end
      Env.log("bad-asn-list: #{asns.size} ASNs")
      asns
    end

    # X4B input files: `AS262978 # Centro de Tecnologia...` per line.
    def parse_x4b_asn_file(path)
      asns = Set.new
      File.foreach(path) do |line|
        asns << Regexp.last_match(1).to_i if line =~ /\AAS(\d+)\b/
      end
      asns
    end
  end
end

if $PROGRAM_NAME == __FILE__
  paths = OpenASNPipeline::Fetch.run(offline: true)
  OpenASNPipeline::Normalize.run(paths)
end
