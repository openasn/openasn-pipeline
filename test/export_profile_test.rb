# frozen_string_literal: true

# core-v1 acceptance (PRD ids P01-P04).
#
# The matrix is the vendored hand-written contract fixture, not a recording
# of what Export::Profile currently returns - see fixtures/export-v1/
# PROVENANCE. Expected verdicts and source lists are only ever read from
# that file.

require_relative "test_helper"
require "json"
require_relative "../pipeline/export/contract"
require_relative "../pipeline/export/profile"

module OpenASNPipeline
  class ExportProfileTest < Minitest::Test
    FIXTURE = JSON.parse(File.read(File.expand_path("fixtures/export-v1/profile-fixtures.json", __dir__))).freeze

    # P01
    def test_every_fixture_case_produces_the_hand_specified_verdict_and_ordered_sources
      defaults = FIXTURE.fetch("defaults")
      assert_operator FIXTURE.fetch("cases").length, :>=, 26, "the contract matrix lost cases"

      FIXTURE.fetch("cases").each do |c|
        result = call_case(c, defaults)
        assert_equal c.fetch("verdict"), result.verdict, "verdict for #{c['id']}"
        assert_equal c.fetch("sources"), result.sources, "sources for #{c['id']}"
      end
    end

    def test_every_fixture_verdict_and_source_belongs_to_the_frozen_vocabulary
      FIXTURE.fetch("cases").each do |c|
        result = call_case(c, FIXTURE.fetch("defaults"))
        assert_includes Export::Contract::VERDICTS, result.verdict, c["id"]
        result.sources.each { |s| assert_includes Export::Contract::SOURCES, s, c["id"] }
      end
    end

    # The export must speak the PUBLIC client's explanation names. These
    # three are exactly where the pipeline's internal classifier says
    # something else (:asn_mobile, :no_category, a coarse :asn_category for
    # every hosting reason), which is why the two stay separate implementations.
    def test_sources_use_the_public_client_names_not_the_pipeline_classifier_labels
      mobile = call(flags: 1024)
      assert_equal ["asn_mobile_carrier"], mobile.sources

      no_category = call(flags: 0)
      assert_equal ["asn_no_category"], no_category.sources

      every_hosting_reason = call(flags: 12_546)
      assert_equal %w[asn_bad_asn asn_hosting_extra asn_cdn asn_category], every_hosting_reason.sources
    end

    def test_a_lower_precedence_reason_is_never_collected_after_another_rule_wins
      # DC overlay over an ASN that also reads hosting/cdn: the overlay is
      # what decided it, so x4b_dc is the whole explanation.
      dc_over_hosting = call(flags: 4098, datacenter_range: true)
      assert_equal "hosting", dc_over_hosting.verdict
      assert_equal ["x4b_dc"], dc_over_hosting.sources

      # VPN and DC can both cover an address; VPN explains it.
      both = call(flags: 0, vpn_range: true, datacenter_range: true)
      assert_equal ["x4b_vpn"], both.sources
    end

    # P02
    def test_reserved_category_role_codes_and_reserved_bits_are_rejected_not_guessed
      reserved = FIXTURE.fetch("invalid_inputs").reject { |c| c["id"] == "missing-asn-with-flags" }
      assert_equal %w[reserved-category reserved-role reserved-bit14 reserved-bit15], reserved.map { |c| c["id"] }

      reserved.each do |c|
        error = assert_raises(StageFailure, c["id"]) { Export::Contract.decode_flags(c.fetch("flags")) }
        assert_match(/reserved/, error.message, c["id"])
      end
    end

    def test_the_export_category_and_role_vocabulary_matches_the_compiled_flag_codes
      # Contract declares its own code tables so an upstream addition fails
      # the export instead of widening core-v1 silently. Today they agree.
      assert_equal AsJson::CATEGORY_CODES.invert, Export::Contract::CATEGORY_BY_CODE
      assert_equal AsJson::ROLE_CODES.invert, Export::Contract::ROLE_BY_CODE
      assert_equal AsJson::CATEGORY_CODES.keys.compact.sort, Export::Contract::CATEGORIES.sort
      assert_equal AsJson::ROLE_CODES.keys.compact.sort, Export::Contract::NETWORK_ROLES.sort
    end

    # P03
    def test_a_record_with_no_asn_but_asn_evidence_is_rejected
      invalid = FIXTURE.fetch("invalid_inputs").find { |c| c["id"] == "missing-asn-with-flags" }
      category, role, signals = Export::Contract.decode_flags(invalid.fetch("flags"))
      error = assert_raises(StageFailure) do
        Export::Profile.call(asn: nil, category: category, network_role: role,
                             signals: signals.merge(vpn_range: false, datacenter_range: false))
      end
      assert_match(/no ASN but carries ASN evidence/, error.message)

      assert_raises(StageFailure) { call(asn: nil, flags: Binary::FLAG_CDN) }
      assert_raises(StageFailure) { call(asn: nil, flags: Binary::FLAG_VPN_PROVIDER) }
    end

    def test_an_incomplete_or_unknown_signal_set_is_rejected_rather_than_defaulted
      full = Export::Contract.signals

      assert_raises(StageFailure) do
        Export::Profile.call(asn: 1, category: nil, network_role: nil, signals: full.reject { |k, _| k == :cdn })
      end
      assert_raises(StageFailure) do
        Export::Profile.call(asn: 1, category: nil, network_role: nil, signals: full.merge(tor_exit: false))
      end
      assert_raises(StageFailure) do
        Export::Profile.call(asn: 1, category: nil, network_role: nil, signals: full.merge(cdn: nil))
      end
      assert_raises(StageFailure) do
        Export::Profile.call(asn: 1, category: "residential_isp", network_role: nil, signals: full)
      end
      assert_raises(StageFailure) do
        Export::Profile.call(asn: 1, category: nil, network_role: "transit", signals: full)
      end
    end

    # P04
    def test_as_zero_and_the_maximum_asn_are_real_asns_not_missing_ones
      zero = call(asn: 0, flags: 0)
      assert_equal "unknown", zero.verdict
      assert_equal ["asn_no_category"], zero.sources, "AS0 must not fall through to unrouted"

      max = call(asn: Export::Contract::ASN_MAX, flags: 65)
      assert_equal "residential_isp", max.verdict

      assert_raises(StageFailure) { call(asn: Export::Contract::ASN_MAX + 1, flags: 0) }
      assert_raises(StageFailure) { call(asn: -1, flags: 0) }
    end

    def test_an_isp_with_no_role_is_residential_and_only_tier1_transit_is_ambiguous
      assert_equal "residential_isp", call(flags: 1).verdict # category isp, role nil
      assert_equal "unknown", call(flags: 17).verdict        # tier1_transit
      assert_equal ["isp_transit_ambiguous"], call(flags: 17).sources
      assert_equal "residential_isp", call(flags: 33).verdict # major_transit
    end

    private

    def call_case(fixture_case, defaults)
      asn = fixture_case.key?("asn") ? fixture_case["asn"] : defaults.fetch("asn")
      call(asn: asn,
           flags: fixture_case.fetch("flags"),
           vpn_range: fixture_case.fetch("vpn_range", defaults.fetch("vpn_range")),
           datacenter_range: fixture_case.fetch("datacenter_range", defaults.fetch("datacenter_range")))
    end

    def call(flags:, asn: 123, vpn_range: false, datacenter_range: false)
      category, role, signals = Export::Contract.decode_flags(flags)
      Export::Profile.call(asn: asn, category: category, network_role: role,
                           signals: signals.merge(vpn_range: vpn_range, datacenter_range: datacenter_range))
    end
  end
end
