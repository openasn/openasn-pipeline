# frozen_string_literal: true

# Gold/eval set assembly for the enrichment pilot.
#
# THE CHEAT THIS PROJECT GETS FOR FREE: Linnaeus had to hand-annotate 1,870
# ASNs to evaluate anything (arXiv:2603.13649 §6.2). We already own curated
# labels — data/overrides/*.txt (every line human-reviewed + sourced),
# brianhama/bad-asn-list (MIT, first-party curation), X4BNet's hand-curated
# ASN input lists (MIT) — plus ipverse categories as weak gold for the
# categories the overrides don't cover.
#
# PROVENANCE MATTERS FOR SCORING (eval.rb splits on it):
#   :independent — gold from sources the model cannot see in the packet
#     answer-key style. NOTE the honest caveat: override/X4B/bad-asn
#     membership DOES appear in packets as boolean flags (in_bad_asn_list,
#     existing_openasn_flags...) because production packets will carry them.
#     The flag says "this list contains the ASN", not which label is gold —
#     but for these classes the model gets a strong hint. The eval therefore
#     measures "can the model apply our curation policy", not "can it
#     rediscover it blind". eyeball_confirm entries are the exception: that
#     file is EXCLUDED from packets (evidence.rb) so tier1-eyeball rescue is
#     measured blind.
#   :ipverse — gold sampled from as-metadata category fields; the same field
#     sits verbatim in the packet, so arm-local metrics on these classes are
#     inflated by construction. Reported separately, never headline.
#   :pinned — hand-pinned famous ASNs. EVERY pin carries a desc_regex guard:
#     assemble-time we check it against the live ipverse description and DROP
#     (loudly) any pin whose description doesn't match — a misremembered ASN
#     must weaken the eval, not poison it.
#
# Multi-label gold + acceptable-extras: `labels` must all be predicted
# (recall); predicted labels outside labels+acceptable count as false
# positives (precision). Acceptable-extras encode defensible adjacency
# (cdn⊂hosting-ish, NREN=education+transit) so the eval doesn't punish
# correct-but-richer answers.

require "set"
require_relative "../lib/env"
require_relative "../lib/overrides"
require_relative "schema"

module OpenASNPipeline
  module Enrich
    module Gold
      Entry = Struct.new(:asn, :labels, :acceptable, :source, :provenance, keyword_init: true)

      SEED = 42 # fixed sampling seed: the eval set must be reproducible run-to-run

      # Provenance tiers, single-sourced (eval.rb filters/counts read these
      # too). WEAK provenances share a field with the evidence packet — the
      # model can read the answer — so they never headline and lose merges.
      # Adding a tier means touching exactly this pair, nothing else.
      PROVENANCE_STRENGTH = { independent: 2, pinned: 1, ipverse: 0 }.freeze
      WEAK_PROVENANCES = %i[ipverse].freeze

      # data/overrides/<file>.txt -> gold labels. acceptable reflects real
      # adjacency in those lists (e.g. cdn.txt entries are hosting-adjacent by
      # nature; vpn_provider.txt has hosting-company entries like M247).
      OVERRIDE_GOLD = {
        "vpn_provider"       => { labels: %w[vpn_provider], acceptable: %w[hosting_provider] },
        "mobile_carrier"     => { labels: %w[mobile_carrier], acceptable: %w[access_eyeball] },
        "cdn"                => { labels: %w[cdn], acceptable: %w[hosting_provider cloud_provider] },
        "enterprise_gateway" => { labels: %w[enterprise_gateway], acceptable: %w[business hosting_provider] },
        "hosting_extra"      => { labels: %w[hosting_provider], acceptable: %w[cloud_provider cdn] },
        "eyeball_confirm"    => { labels: %w[access_eyeball], acceptable: %w[pure_transit_backbone mobile_carrier] }
      }.freeze

      # Pure tier-1 backbone ASNs from DECISIONS.md D-IMPL-1 (the data repo):
      # the measured 2026-07-04 list of isp+tier1_transit ASNs that are
      # genuinely backbone-only (the 4 consumer giants live in
      # eyeball_confirm.txt instead). desc_regex guards each one.
      TIER1_PURE_TRANSIT = [
        { asn: 174,   desc_regex: /cogent/i },
        { asn: 3356,  desc_regex: /lumen|level ?3/i },
        { asn: 3257,  desc_regex: /gtt/i },
        { asn: 2914,  desc_regex: /ntt/i },
        { asn: 6461,  desc_regex: /zayo/i },
        { asn: 3491,  desc_regex: /pccw|bics/i },
        { asn: 6453,  desc_regex: /tata/i },
        { asn: 1299,  desc_regex: /arelion|telia/i },
        { asn: 5511,  desc_regex: /orange|opentransit/i },
        { asn: 6762,  desc_regex: /sparkle|telecom italia/i },
        { asn: 12956, desc_regex: /telefonica|telxius/i }
      ].freeze

      # Famous pins for classes our overrides don't cover. Each: labels +
      # acceptable + guard regex + src note. Kept SMALL — these are weak gold
      # (world knowledge), the guard only protects against a wrong ASN number,
      # not a wrong belief about the org.
      PINNED = [
        # education / research networking
        { asn: 3,     labels: %w[education], acceptable: [], desc_regex: /massachusetts|mit/i,
          src: "MIT (Linnaeus Appendix A example)" },
        { asn: 11164, labels: %w[education pure_transit_backbone], acceptable: [],
          desc_regex: /internet2/i, src: "Internet2 — the paper's own multi-label example (§1)" },
        { asn: 2200,  labels: %w[education], acceptable: %w[pure_transit_backbone],
          desc_regex: /renater/i, src: "Renater, French NREN (Linnaeus Appendix A)" },
        { asn: 786,   labels: %w[education], acceptable: %w[pure_transit_backbone],
          desc_regex: /jisc|janet/i, src: "JANET/Jisc, UK NREN" },
        # IXPs
        { asn: 6695,  labels: %w[ixp], acceptable: [], desc_regex: /de-?cix/i, src: "DE-CIX" },
        # Guard lesson (pilot run 2026-07-05): ipverse descriptions use LEGAL
        # names, not brands — "Amsterdam Internet Exchange B.V." not "AMS-IX",
        # "Internet Systems Consortium Inc." not "ISC". Guards must cover both.
        { asn: 1200,  labels: %w[ixp], acceptable: [],
          desc_regex: /ams-?ix|amsterdam internet exchange/i, src: "AMS-IX" },
        { asn: 5459,  labels: %w[ixp], acceptable: [], desc_regex: /linx|london internet/i, src: "LINX" },
        # DNS infrastructure
        { asn: 25152, labels: %w[dns_infrastructure], acceptable: [],
          desc_regex: /ripe|k-?root/i, src: "RIPE NCC K-root" },
        { asn: 3557,  labels: %w[dns_infrastructure], acceptable: %w[education],
          desc_regex: /\bisc\b|f-?root|internet systems consortium/i, src: "ISC F-root" },
        { asn: 8674,  labels: %w[dns_infrastructure], acceptable: %w[ixp],
          desc_regex: /netnod/i, src: "Netnod (i-root + IXP operator)" },
        # satellite access
        { asn: 14593, labels: %w[satellite], acceptable: %w[access_eyeball],
          desc_regex: /space ?exploration|starlink|spacex/i, src: "SpaceX Starlink" },
        { asn: 22351, labels: %w[satellite], acceptable: [], desc_regex: /intelsat/i, src: "Intelsat" },
        { asn: 7155,  labels: %w[satellite], acceptable: %w[access_eyeball],
          desc_regex: /viasat/i, src: "Viasat" },
        # personal (the paper's own example of a one-person ASN, §1)
        { asn: 200556, labels: %w[personal], acceptable: [], desc_regex: /./,
          src: "hobbyist ASN cited in Linnaeus §1 — weakest pin, no regex guard possible" },
        # big-4 consumer clouds as hosting/cloud sanity anchors
        { asn: 16509, labels: %w[cloud_provider hosting_provider], acceptable: %w[cdn business],
          desc_regex: /amazon/i, src: "AWS" },
        { asn: 8075,  labels: %w[cloud_provider hosting_provider], acceptable: %w[cdn business],
          desc_regex: /microsoft/i, src: "Microsoft/Azure" },
        # consumer eyeball anchors beyond eyeball_confirm.txt
        { asn: 7922,  labels: %w[access_eyeball], acceptable: %w[pure_transit_backbone cdn],
          desc_regex: /comcast/i, src: "Comcast" },
        { asn: 12322, labels: %w[access_eyeball], acceptable: [],
          desc_regex: /free|proxad/i, src: "Free SAS (Iliad), FR consumer ISP" }
      ].freeze

      # Per-class caps for sampled sources (pins/overrides are never capped).
      SAMPLE_SIZES = {
        bad_asn: 22, x4b_vpn: 12,
        ipverse_education: 8, ipverse_government: 8, ipverse_business: 10, ipverse_access: 10
      }.freeze

      module_function

      # ctx = Evidence::LocalContext. Returns [Entry] with merged duplicates.
      def build(ctx)
        rng = Random.new(SEED)
        entries = []
        entries.concat(from_overrides(ctx))
        entries.concat(from_pins(ctx))
        entries.concat(from_bad_asn(ctx, rng))
        entries.concat(from_x4b_vpn(ctx, rng))
        entries.concat(from_ipverse(ctx, rng))
        merged = merge_by_asn(entries)
        # Evidence packets need announced space; unrouted gold is unusable.
        merged.select { |e| ctx.routed_asns.include?(e.asn) }
      end

      # Loaded via the compiler's own strict loader (lib/overrides.rb) so the
      # gold can never contain a line the real build would reject, and the
      # file list + line syntax stay single-sourced (a hand-rolled parser
      # here had already drifted to a laxer regex than the build enforces).
      def from_overrides(_ctx)
        sets = Overrides.load(Env.overrides_dir).sets
        OVERRIDE_GOLD.flat_map do |file, spec|
          (sets[file.to_sym] || Set.new).map do |asn|
            Entry.new(asn: asn, labels: spec[:labels].dup, acceptable: spec[:acceptable].dup,
                      source: "overrides/#{file}.txt", provenance: :independent)
          end
        end
      end

      def from_pins(ctx)
        pins = TIER1_PURE_TRANSIT.map do |p|
          { asn: p[:asn], labels: %w[pure_transit_backbone], acceptable: %w[access_eyeball],
            desc_regex: p[:desc_regex], src: "DECISIONS.md D-IMPL-1 tier1 backbone list" }
        end + PINNED
        dropped = []
        kept = pins.filter_map do |p|
          desc = ctx.meta[p[:asn]]&.description.to_s
          unless desc.match?(p[:desc_regex])
            dropped << "AS#{p[:asn]} (#{p[:src]}; guard #{p[:desc_regex].inspect} vs live #{desc.inspect[0, 60]})"
            next
          end
          Entry.new(asn: p[:asn], labels: p[:labels].dup, acceptable: p[:acceptable] || [],
                    source: "pinned: #{p[:src]}", provenance: :pinned)
        end
        # ONE aggregate warn, not one per pin: the offline tests drive this
        # against tiny fake meta where every pin drops, and per-pin warns
        # buried every `rake test` run under ~28 lines of noise.
        unless dropped.empty?
          Env.warn("gold: dropped #{dropped.size} pins failing description guards " \
                   "(misremembered?): #{dropped.join('; ')}")
        end
        kept
      end

      def from_bad_asn(ctx, rng)
        sample(ctx.bad_asns.to_a, SAMPLE_SIZES[:bad_asn], rng, ctx).map do |asn|
          Entry.new(asn: asn, labels: %w[hosting_provider],
                    acceptable: %w[cloud_provider cdn vpn_provider business],
                    source: "brianhama/bad-asn-list", provenance: :independent)
        end
      end

      def from_x4b_vpn(ctx, rng)
        sample(ctx.x4b_vpn_asns.to_a, SAMPLE_SIZES[:x4b_vpn], rng, ctx).map do |asn|
          Entry.new(asn: asn, labels: %w[vpn_provider], acceptable: %w[hosting_provider],
                    source: "X4BNet input/vpn/ASN.txt", provenance: :independent)
        end
      end

      # Weak gold from ipverse categories (the same field the packet carries —
      # see file header). access additionally requires role=access_provider.
      def from_ipverse(ctx, rng)
        pools = { ipverse_education: [], ipverse_government: [], ipverse_business: [], ipverse_access: [] }
        ctx.meta.each_value do |rec|
          case rec.category
          when "education_research" then pools[:ipverse_education] << rec.asn
          when "government_admin"   then pools[:ipverse_government] << rec.asn
          when "business"           then pools[:ipverse_business] << rec.asn
          when "isp"
            pools[:ipverse_access] << rec.asn if rec.network_role == "access_provider"
          end
        end
        spec = {
          ipverse_education:  { labels: %w[education], acceptable: %w[pure_transit_backbone government] },
          ipverse_government: { labels: %w[government], acceptable: %w[business education] },
          ipverse_business:   { labels: %w[business], acceptable: %w[hosting_provider education government] },
          ipverse_access:     { labels: %w[access_eyeball],
                                acceptable: %w[mobile_carrier pure_transit_backbone business] }
        }
        pools.flat_map do |pool, asns|
          sample(asns, SAMPLE_SIZES[pool], rng, ctx).map do |asn|
            Entry.new(asn: asn, labels: spec[pool][:labels].dup, acceptable: spec[pool][:acceptable].dup,
                      source: pool.to_s, provenance: :ipverse)
          end
        end
      end

      def sample(asns, n, rng, ctx)
        asns.select { |a| ctx.routed_asns.include?(a) }.sort.sample(n, random: rng)
      end

      # An ASN can arrive from several sources (M247 is in vpn_provider.txt AND
      # bad-asn-list). Merge: union labels + acceptable (minus promoted
      # labels), join sources, keep the strongest provenance.
      def merge_by_asn(entries)
        entries.group_by(&:asn).map do |asn, group|
          labels = group.flat_map(&:labels).uniq
          acceptable = group.flat_map(&:acceptable).uniq - labels
          Entry.new(
            asn: asn, labels: labels, acceptable: acceptable,
            source: group.map(&:source).uniq.join(" + "),
            # fetch, not []: an unknown provenance symbol must fail loudly
            # here, not surface later as a nil-comparison inside max_by.
            provenance: group.map(&:provenance).max_by { |p| PROVENANCE_STRENGTH.fetch(p) }
          )
        end
      end
    end
  end
end
