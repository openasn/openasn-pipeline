# frozen_string_literal: true

# Frozen identity and vocabularies for the portable exports (SQLite / CSV /
# MMDB), schema 1 revision 0, classification profile core-v1.
#
# Every token an export writer may emit is named here exactly once. That is
# D-FMT-1's whole point: a data refresh may change WHICH verdict an address
# gets, but it may never introduce a new token or reinterpret a field,
# because consumers pin `classification_profile` and switch on these exact
# strings. A vocabulary copied into a second file is a vocabulary that will
# drift, so writers, validators and tests all read it from here.
#
# The flag BIT POSITIONS below are not ours to choose: they are byte law in
# lib/binary.rb and the data repo's FORMAT.md. This file only maps export
# field names onto them, and decode_flags refuses anything the canonical
# writer is not supposed to have produced - a reserved category code or a
# set reserved bit is evidence we cannot name, and guessing at it would
# silently invent a meaning that no profile version documented.

require_relative "../lib/env"
require_relative "../lib/binary"
require_relative "../lib/asjson"

module OpenASNPipeline
  module Export
    module Contract
      SCHEMA_VERSION         = 1
      SCHEMA_REVISION        = 0
      CLASSIFICATION_PROFILE = "core-v1"
      LOOKUP_POLICY_VERSION  = 1
      EDITION                = "core"
      SCOPE                  = "tier_a"
      TIER_B_INCLUDED        = false
      EXPORTER_VERSION       = "1.0.0"

      # Which exports a build is allowed to produce. `portable` is the
      # SQLite+CSV milestone; `all` adds MMDB once its toolchain is pinned.
      EXPORT_MODES = %w[none portable all].freeze

      # Raw upstream evidence, exactly as bits 0-3 / 4-7 encode it. These are
      # NOT verdicts: `isp` is a category, `residential_isp` is a conclusion.
      CATEGORIES     = %w[isp hosting business education_research government_admin].freeze
      NETWORK_ROLES  = %w[tier1_transit major_transit midsize_transit
                          access_provider content_network stub].freeze

      # Code -> name, mirroring FORMAT.md. Declared here rather than derived
      # from AsJson so that an upstream category appearing in a future
      # release fails the export loudly instead of widening core-v1's
      # vocabulary behind the profile version (export_profile_test asserts
      # the two agree today).
      CATEGORY_BY_CODE = { 0 => nil, 1 => "isp", 2 => "hosting", 3 => "business",
                           4 => "education_research", 5 => "government_admin" }.freeze
      ROLE_BY_CODE     = { 0 => nil, 1 => "tier1_transit", 2 => "major_transit",
                           3 => "midsize_transit", 4 => "access_provider",
                           5 => "content_network", 6 => "stub" }.freeze

      # Export field name -> flag bit. Ordered as the record is serialized.
      ASN_SIGNAL_BITS = {
        bad_asn:        Binary::FLAG_BAD_ASN,
        vpn_provider:   Binary::FLAG_VPN_PROVIDER,
        mobile_carrier: Binary::FLAG_MOBILE,
        enterprise_gw:  Binary::FLAG_ENTERPRISE_GW,
        cdn:            Binary::FLAG_CDN,
        hosting_extra:  Binary::FLAG_HOSTING_EXTRA
      }.freeze

      ASN_SIGNALS   = ASN_SIGNAL_BITS.keys.freeze
      # Overlay membership, decided by the projection rather than by a bit.
      RANGE_SIGNALS = %i[vpn_range datacenter_range].freeze
      SIGNALS       = (ASN_SIGNALS + RANGE_SIGNALS).freeze

      RESERVED_BITS_MASK = 0xC000 # bits 14-15
      FLAGS_MAX          = 0xFFFF
      ASN_MAX            = (1 << 32) - 1

      VERDICTS = %w[residential_isp mobile business hosting vpn
                    enterprise_gateway education government unknown].freeze

      # Every explanation core-v1 can emit. `relay`/`tor_exit` sources cannot
      # appear: they are Tier B, fetched client-side, never in these bytes.
      SOURCES = %w[x4b_vpn asn_vpn_provider asn_enterprise_gw x4b_dc
                   asn_bad_asn asn_hosting_extra asn_cdn asn_category
                   asn_mobile_carrier isp_transit_ambiguous asn_no_category
                   unrouted].freeze

      # Serialization order for the logical record, shared by the JSONL
      # spool and the CSV header (the CSV names its endpoints start_ip/end_ip
      # instead, being textual addresses rather than fixed-width hex).
      PAYLOAD_FIELDS = (%i[asn as_org category network_role] + SIGNALS +
                        %i[core_verdict core_sources]).freeze
      SPOOL_FIELDS   = (%i[ip_version start_hex end_hex] + PAYLOAD_FIELDS).freeze
      CSV_HEADER     = (%w[ip_version start_ip end_ip] +
                        PAYLOAD_FIELDS.map(&:to_s)).join(",").freeze

      FAMILIES     = %i[ipv4 ipv6].freeze
      IP_VERSIONS  = { ipv4: 4, ipv6: 6 }.freeze
      # 2**32 / 2**128 are legitimate internal end-sentinels in the sweep;
      # only these maxima may ever be serialized.
      ADDRESS_MAX  = { ipv4: (1 << 32) - 1, ipv6: (1 << 128) - 1 }.freeze
      HEX_WIDTH    = { ipv4: 8, ipv6: 32 }.freeze

      module_function

      # u16 flags -> [category, network_role, {signal => bool}] for the six
      # ASN-level signals. Raises on anything outside the profile.
      def decode_flags(flags)
        unless flags.is_a?(Integer) && flags >= 0 && flags <= FLAGS_MAX
          Env.fail_stage!("flags #{flags.inspect} is not a u16")
        end
        unless (flags & RESERVED_BITS_MASK).zero?
          Env.fail_stage!(format("flags 0x%04x sets reserved bits 14-15; core-v1 cannot name that " \
                                 "evidence - allocate it in a new profile rather than dropping it", flags))
        end

        category_code = flags & Binary::CATEGORY_MASK
        role_code     = (flags & Binary::ROLE_MASK) >> Binary::ROLE_SHIFT
        category = CATEGORY_BY_CODE.fetch(category_code) do
          Env.fail_stage!(format("flags 0x%04x has reserved category code %d", flags, category_code))
        end
        role = ROLE_BY_CODE.fetch(role_code) do
          Env.fail_stage!(format("flags 0x%04x has reserved network_role code %d", flags, role_code))
        end

        signals = {}
        ASN_SIGNAL_BITS.each { |name, bit| signals[name] = flags.anybits?(bit) }
        [category, role, signals]
      end

      # A complete signal set with every range flag explicit - the profile
      # refuses a partial hash, so callers never get a default-false bug.
      def signals(vpn_range: false, datacenter_range: false, **asn_signals)
        base = ASN_SIGNALS.to_h { |name| [name, false] }
        unknown = asn_signals.keys - ASN_SIGNALS
        Env.fail_stage!("unknown signal(s) #{unknown.inspect}") unless unknown.empty?
        base.merge(asn_signals).merge(vpn_range: vpn_range, datacenter_range: datacenter_range)
      end
    end
  end
end
