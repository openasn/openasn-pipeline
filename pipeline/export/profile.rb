# frozen_string_literal: true

# core-v1: the frozen Tier A classification profile the portable exports
# materialize (PRD §7 / EXPORT_FORMATS.md).
#
# This is a PURE function of already-decoded evidence. It never sees an IP,
# so it cannot do special-address handling, and that separation is the
# point: an exported row describes an interval, while `private`/`cgnat` are
# properties of an address that the consumer helper decides BEFORE it
# searches the database. Baking specials into rows would also mean shipping
# policy-version-1 decisions inside schema-version-1 bytes.
#
# WHY IT IS NOT lib/classifier.rb: the pipeline's classifier is the
# independent oracle that validates the artifacts (spot panel, round-trip
# gates), and its rule labels (:asn_mobile, :no_category, coarse
# :asn_category) are its own contract. The exports must speak the PUBLIC
# names the `openasn` gem returns (asn_mobile_carrier, asn_no_category, and
# the itemized hosting list), because a consumer reading core_sources out of
# SQLite and a consumer calling the gem must see the same explanation. Two
# implementations of one ladder is the cheap way to notice when one of them
# drifts; sharing a function would delete that signal.
#
# The verdicts here are the nine record verdicts. :relay and :tor_exit are
# Tier B and cannot arise from these bytes.

require_relative "../lib/env"
require_relative "contract"

module OpenASNPipeline
  module Export
    module Profile
      Result = Struct.new(:verdict, :sources)

      module_function

      # asn:          nil (no base row) or Integer 0..4294967295
      # category:     nil or Contract::CATEGORIES member
      # network_role: nil or Contract::NETWORK_ROLES member
      # signals:      all eight booleans, keyed by symbol
      def call(asn:, category:, network_role:, signals:)
        validate!(asn, category, network_role, signals)

        verdict, sources =
          if signals[:vpn_range]        then ["vpn", ["x4b_vpn"]]
          elsif signals[:vpn_provider]  then ["vpn", ["asn_vpn_provider"]]
          elsif signals[:enterprise_gw] then ["enterprise_gateway", ["asn_enterprise_gw"]]
          elsif signals[:datacenter_range] then ["hosting", ["x4b_dc"]]
          elsif hosting?(category, signals) then ["hosting", hosting_sources(category, signals)]
          elsif signals[:mobile_carrier] then ["mobile", ["asn_mobile_carrier"]]
          elsif category == "isp" && network_role != "tier1_transit" then ["residential_isp", ["asn_category"]]
          elsif category == "business"           then ["business", ["asn_category"]]
          elsif category == "education_research" then ["education", ["asn_category"]]
          elsif category == "government_admin"   then ["government", ["asn_category"]]
          elsif category == "isp"                then ["unknown", ["isp_transit_ambiguous"]]
          elsif !asn.nil?                        then ["unknown", ["asn_no_category"]]
          else                                        ["unknown", ["unrouted"]]
          end

        Result.new(verdict, sources.freeze)
      end

      def hosting?(category, signals)
        signals[:bad_asn] || signals[:hosting_extra] || signals[:cdn] || category == "hosting"
      end

      # Every true reason, in this exact order - consumers diff these lists
      # across builds, so the order is part of the frozen contract. Reasons
      # for a LOWER-precedence rule are never collected: a datacenter-overlay
      # hit says x4b_dc and nothing else, even when the ASN also reads
      # hosting, because the overlay is what decided it.
      def hosting_sources(category, signals)
        sources = []
        sources << "asn_bad_asn"       if signals[:bad_asn]
        sources << "asn_hosting_extra" if signals[:hosting_extra]
        sources << "asn_cdn"           if signals[:cdn]
        sources << "asn_category"      if category == "hosting"
        sources
      end

      # A canonical export input is narrower than what the bits can express.
      # Rejecting here (rather than emitting a guess) is what keeps the
      # published vocabulary equal to the documented one.
      def validate!(asn, category, network_role, signals)
        unless asn.nil? || (asn.is_a?(Integer) && asn >= 0 && asn <= Contract::ASN_MAX)
          Env.fail_stage!("asn #{asn.inspect} is not nil or a uint32")
        end
        unless category.nil? || Contract::CATEGORIES.include?(category)
          Env.fail_stage!("unknown category #{category.inspect}")
        end
        unless network_role.nil? || Contract::NETWORK_ROLES.include?(network_role)
          Env.fail_stage!("unknown network_role #{network_role.inspect}")
        end

        missing = Contract::SIGNALS - signals.keys
        Env.fail_stage!("missing signal(s) #{missing.inspect}") unless missing.empty?
        extra = signals.keys - Contract::SIGNALS
        Env.fail_stage!("unknown signal(s) #{extra.inspect}") unless extra.empty?
        Contract::SIGNALS.each do |name|
          value = signals[name]
          Env.fail_stage!("signal #{name} is #{value.inspect}, not a boolean") unless [true, false].include?(value)
        end

        return unless asn.nil?

        # No base row means no ASN-level evidence, full stop. AS0 is a real
        # ASN with real flags; only a genuinely absent row reaches here, and
        # a row with flags but no ASN is a corrupt record, not a hint.
        unless category.nil? && network_role.nil? && Contract::ASN_SIGNALS.none? { |s| signals[s] }
          Env.fail_stage!("record has no ASN but carries ASN evidence " \
                          "(category=#{category.inspect} role=#{network_role.inspect} " \
                          "signals=#{signals.select { |k, v| v && Contract::ASN_SIGNALS.include?(k) }.keys.inspect})")
        end
      end
    end
  end
end
