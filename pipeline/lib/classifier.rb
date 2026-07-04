# frozen_string_literal: true

# Reference classifier over compiled artifacts - the PRD §9 precedence
# ladder, restricted to what the canonical artifact contains (Tier A).
# Tier B overlays (Apple relay, Tor, cloud provider ranges, ...) are fetched
# and applied CLIENT-side by the gem; rules 3, 4 and 8 therefore cannot fire
# here, and that is correct: this classifier exists to validate artifacts
# (spot panel, round-trip gates), not to serve lookups. The production
# implementation lives in the `openasn` gem and covers the full ladder.
#
# Returned verdicts (closed enum, §9):
#   :residential_isp :mobile :business :hosting :vpn :tor_exit :relay
#   :enterprise_gateway :education :government :cgnat :private :unknown

require "ipaddr"
require_relative "env"
require_relative "binary"
require_relative "asjson"

module OpenASNPipeline
  module Classifier
    Verdict = Struct.new(:verdict, :rule, :asn, :category, :network_role, :flags, keyword_init: true)

    # IPv4 special ranges, checked before any data layer (PRD §9 step 2).
    # [start, end, verdict, rule]
    V4_SPECIALS = [
      ["0.0.0.0/8",      :private, :special_reserved],
      ["10.0.0.0/8",     :private, :special_rfc1918],
      ["100.64.0.0/10",  :cgnat,   :special_cgnat],      # RFC 6598 shared address space
      ["127.0.0.0/8",    :private, :special_loopback],
      ["169.254.0.0/16", :private, :special_link_local],
      ["172.16.0.0/12",  :private, :special_rfc1918],
      ["192.168.0.0/16", :private, :special_rfc1918],
      ["224.0.0.0/4",    :private, :special_multicast],
      ["240.0.0.0/4",    :private, :special_reserved]
    ].map { |cidr, verdict, rule| r = IPAddr.new(cidr).to_range; [r.first.to_i, r.last.to_i, verdict, rule] }.freeze

    V6_SPECIALS = [
      ["::1/128",   :private, :special_loopback],
      ["fc00::/7",  :private, :special_ula],
      ["fe80::/10", :private, :special_link_local]
    ].map { |cidr, verdict, rule| r = IPAddr.new(cidr).to_range; [r.first.to_i, r.last.to_i, verdict, rule] }.freeze

    # RESOLVED DEVIATION from PRD §9 rules 12/16 (documented in
    # DECISIONS.md D-IMPL-1 and the README): the PRD carved ALL transit roles
    # out of :residential_isp, but live data (2026-07-04) shows ipverse
    # assigns major/midsize_transit to virtually every national consumer
    # telco (Comcast, Telefónica, Vodafone DE, Orange, BT, TIM, ... —
    # 40.2% of routed IPv4 would have become :unknown, and the PRD's own
    # §13 acceptance panel would fail). Only tier1_transit is treated as
    # pure-backbone ambiguity (19 ASNs worldwide; the four consumer giants
    # among them are confirmed via data/overrides/eyeball_confirm.txt).
    AMBIGUOUS_TRANSIT_ROLES = %w[tier1_transit].freeze

    module_function

    def special_for(ip_int, family)
      table = family == :ipv4 ? V4_SPECIALS : V6_SPECIALS
      table.each do |(s, e, verdict, rule)|
        return [verdict, rule] if ip_int >= s && ip_int <= e
      end
      nil
    end

    # artifact: Binary::Artifact. ip_int must match the artifact family.
    def classify(artifact, ip_int)
      if (sp = special_for(ip_int, artifact.family))
        return Verdict.new(verdict: sp[0], rule: sp[1])
      end

      base = artifact.find_base(ip_int)
      asn = base&.[](2)
      flags = base&.[](3) || 0
      category = AsJson::CATEGORY_NAMES[flags & Binary::CATEGORY_MASK]
      role     = AsJson::ROLE_NAMES[(flags & Binary::ROLE_MASK) >> Binary::ROLE_SHIFT]

      verdict, rule =
        if artifact.in_vpn?(ip_int)                     then [:vpn, :x4b_vpn]
        elsif flags.anybits?(Binary::FLAG_VPN_PROVIDER) then [:vpn, :asn_vpn_provider]
        elsif flags.anybits?(Binary::FLAG_ENTERPRISE_GW) then [:enterprise_gateway, :asn_enterprise_gw]
        elsif artifact.in_dc?(ip_int)                   then [:hosting, :x4b_dc]
        elsif flags.anybits?(Binary::FLAG_BAD_ASN | Binary::FLAG_HOSTING_EXTRA | Binary::FLAG_CDN) ||
              category == "hosting"                     then [:hosting, :asn_category]
        elsif flags.anybits?(Binary::FLAG_MOBILE)       then [:mobile, :asn_mobile]
        elsif category == "isp" && !AMBIGUOUS_TRANSIT_ROLES.include?(role) then [:residential_isp, :asn_category]
        elsif category == "business"                    then [:business, :asn_category]
        elsif category == "education_research"          then [:education, :asn_category]
        elsif category == "government_admin"            then [:government, :asn_category]
        elsif category == "isp"                         then [:unknown, :isp_transit_ambiguous]
        elsif base                                      then [:unknown, :no_category]
        else                                                 [:unknown, :unrouted]
        end

      Verdict.new(verdict: verdict, rule: rule, asn: asn,
                  category: category, network_role: role, flags: flags)
    end
  end
end
