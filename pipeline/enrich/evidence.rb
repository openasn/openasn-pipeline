# frozen_string_literal: true

# Evidence packets: the per-ASN facts handed to the LLM.
#
# Two layers, deliberately separable so the pilot can A/B them:
#   * LOCAL — everything already in build/cache + the data repo: ipverse
#     description/category/role (CC0), announced-space stats computed from
#     the sapics backbone (PDDL), X4B/bad-asn membership (MIT), our own
#     override flags, and the %-of-space-inside-the-X4B-dc-overlay
#     corroboration signal. Zero network, zero new legal surface.
#   * EXTERNAL — Fetchers (RIPEstat/PeeringDB/RDAP/rDNS/website), merged in
#     when the caller passes them. Inputs-unrestricted per the curation
#     policy documented in fetchers.rb.
#
# Packets are compact on purpose (~120 tokens local, ~300-500 enriched):
# Linnaeus classified 120k ASNs on ~$25 of inference because its packets were
# lean (arXiv:2603.13649 §7.1 "the model does not need 50KB per ASN").
# Field names are part of PROMPT_VERSION's contract — the preamble references
# them (existing_openasn_flags, in_bad_asn_list, ipverse_network_role...);
# renaming a field means bumping the prompt version.

require "set"
require_relative "../lib/env"
require_relative "../lib/asjson"
require_relative "../lib/overrides"
require_relative "../fetch"
require_relative "../normalize"

module OpenASNPipeline
  module Enrich
    module Evidence
      # Everything local evidence needs, built once per run.
      #   meta            {asn => AsJson::Record}
      #   ranges_v4       {asn => [[start,end],...]} (announced v4 ranges)
      #   v6_asns         Set[Integer] (announces any IPv6)
      #   dc_ranges       sorted merged [[s,e],...] (X4B datacenter overlay)
      #   bad_asns / x4b_vpn_asns / x4b_dc_asns   Set[Integer]
      #   override_flags  {asn => ["vpn_provider", ...]} from data/overrides/
      #   routed_asns     Set[Integer] (announces v4 or v6)
      LocalContext = Struct.new(
        :meta, :ranges_v4, :v6_asns, :dc_ranges,
        :bad_asns, :x4b_vpn_asns, :x4b_dc_asns,
        :override_flags, :routed_asns,
        keyword_init: true
      )

      # Which override flags packets carry. eyeball_confirm and
      # corrections.yml are omitted on purpose: eyeball_confirm entries are
      # eval GOLD (leaking them into packets would let the model read the
      # answer), and corrections.yml is empty today.
      PACKET_FLAGS = %i[vpn_provider mobile_carrier cdn enterprise_gateway hosting_extra].freeze

      module_function

      # offline: true (default) builds from the existing build/cache — the
      # pilot must not silently re-download 100MB of Tier A data. Pass
      # offline: false (rake enrich:pilot FETCH=1) to refresh first.
      def build_context(offline: true)
        paths = Fetch.run(offline: offline)
        normalized = Normalize.run(paths)

        ranges_v4 = Hash.new { |h, k| h[k] = [] }
        normalized[:base_v4].each { |(s, e, asn)| ranges_v4[asn] << [s, e] }
        ranges_v4.default_proc = nil

        v6_asns = Set.new
        normalized[:base_v6].each { |(_s, _e, asn)| v6_asns << asn }

        LocalContext.new(
          meta: normalized[:asn_meta],
          ranges_v4: ranges_v4,
          v6_asns: v6_asns,
          dc_ranges: normalized[:dc_v4],
          bad_asns: normalized[:bad_asns],
          x4b_vpn_asns: normalized[:x4b_vpn_asns],
          x4b_dc_asns: normalized[:x4b_dc_asns],
          override_flags: load_override_flags,
          routed_asns: Set.new(ranges_v4.keys) | v6_asns
        )
      end

      # Loaded via the compiler's own strict loader (lib/overrides.rb): a line
      # the real build would reject must not leak a flag into packets, and the
      # file list + line syntax stay single-sourced with compile.rb/gold.rb.
      def load_override_flags(dir = Env.overrides_dir)
        flags = {}
        Overrides.load(dir).sets.each do |flag, asns|
          next unless PACKET_FLAGS.include?(flag)

          asns.each { |asn| (flags[asn] ||= []) << flag.to_s }
        end
        flags
      end

      # The evidence packet. Key order matters for humans reading dumps, not
      # for the model; keep stable anyway (diffable JSONL).
      def packet(asn, ctx, external: nil)
        rec = ctx.meta[asn]
        ranges = ctx.ranges_v4[asn] || []
        p = {
          asn: asn,
          description: rec&.description,
          country: rec&.country,
          ipverse_category: rec&.category,
          ipverse_network_role: rec&.network_role,
          announced_ipv4_ranges: ranges.size,
          announced_ipv4_addresses: ranges.sum { |(s, e)| e - s + 1 },
          announces_ipv6: ctx.v6_asns.include?(asn),
          pct_ipv4_space_in_x4b_dc_overlay: dc_overlay_pct(ranges, ctx.dc_ranges),
          in_bad_asn_list: ctx.bad_asns.include?(asn),
          in_x4b_vpn_asns: ctx.x4b_vpn_asns.include?(asn),
          in_x4b_dc_asns: ctx.x4b_dc_asns.include?(asn),
          existing_openasn_flags: ctx.override_flags[asn] || []
        }
        p.merge!(external_fields(external)) if external
        p
      end

      # Flatten the Fetchers hash into prompt-friendly fields; drop nils and
      # the errors map (a dead upstream is not evidence). String keys because
      # the cache round-trips through JSON.
      def external_fields(ext)
        out = {}
        if (holder = ext.dig("ripestat_overview", "holder"))
          out[:ripestat_holder] = holder
        end
        if (n = ext["ripestat_neighbours"])
          out[:bgp_neighbours] = {
            left: n["left_count"], right: n["right_count"], uncertain: n["uncertain_count"]
          }
        end
        if (pdb = ext["peeringdb"])
          out[:peeringdb] = if pdb["present"]
                              pdb.slice("name", "aka", "website", "info_types",
                                        "info_traffic", "info_scope", "policy_general").compact
                            else
                              { "present" => false }
                            end
        end
        if (rdap = ext["rdap"]) && !rdap.empty?
          out[:rdap] = rdap
        end
        if (rdns = ext["rdns"]) && !rdns.empty?
          out[:rdns_samples] = rdns
        end
        if (site = ext["website"])
          out[:website] = site
        end
        out
      end

      # % of the ASN's announced v4 addresses that sit inside the X4B
      # datacenter overlay. Two-pointer intersection over sorted range lists —
      # both sides are sorted and non-overlapping (backbone sanitized in
      # normalize.rb, overlay merged there too).
      def dc_overlay_pct(asn_ranges, dc_ranges)
        return 0.0 if asn_ranges.empty? || dc_ranges.empty?

        total = asn_ranges.sum { |(s, e)| e - s + 1 }
        sorted = asn_ranges.sort_by(&:first)
        covered = 0
        # bsearch the STARTING position: walking di up from 0 costs
        # O(|dc_ranges|) per call — across a 95k-ASN backfill with a ~30k
        # range overlay that's billions of pointless comparisons. After the
        # jump the two-pointer advances amortized as before.
        di = dc_ranges.bsearch_index { |r| r[1] >= sorted.first[0] } || dc_ranges.size
        sorted.each do |(s, e)|
          di += 1 while di < dc_ranges.size && dc_ranges[di][1] < s
          j = di
          while j < dc_ranges.size && dc_ranges[j][0] <= e
            lo = [s, dc_ranges[j][0]].max
            hi = [e, dc_ranges[j][1]].min
            covered += hi - lo + 1 if hi >= lo
            j += 1
          end
        end
        ((covered.to_f / total) * 100).round(1)
      end
    end
  end
end
