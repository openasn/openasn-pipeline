# frozen_string_literal: true

# Effective-interval projection and validated input acceptance
# (PRD ids I01-I11 and O01-O03).
#
# The ten-row fixture is vendored and hand-written (fixtures/export-v1/
# PROVENANCE); everything it does not reach - zero starts, the maximum
# address, empty layers, same-position deactivate/activate, every rejection
# path, and the org-name byte edges - is a synthetic case here.
#
# The rejection tests pack OASN/OORG bytes directly instead of going through
# Binary.write/Orgs.write, because the point is precisely that the adapter
# must not trust the writer: Binary.write only verifies sorted/disjoint for
# the base layer, so a vpn layer that no writer would ever emit is exactly
# what an input adapter has to survive.

require_relative "test_helper"
require "json"
require_relative "../pipeline/export/contract"
require_relative "../pipeline/export/inputs"
require_relative "../pipeline/export/project"
require_relative "../pipeline/export/spool"

module OpenASNPipeline
  class ExportProjectionTest < Minitest::Test
    FIXTURE = JSON.parse(File.read(File.expand_path("fixtures/export-v1/projection-fixture.json", __dir__))).freeze
    ORIGIN  = IPAddr.new("1.0.0.0").to_i
    V4_MAX  = Export::Contract::ADDRESS_MAX.fetch(:ipv4)
    V6_MAX  = Export::Contract::ADDRESS_MAX.fetch(:ipv6)
    ISP_ACCESS = 65    # category isp, role access_provider
    HOSTING    = 2     # category hosting, no role

    def setup
      @dir = File.join(WORK_DIR, "test-#{name}")
      FileUtils.mkdir_p(@dir)
    end

    def teardown
      FileUtils.rm_rf(@dir)
    end

    # --- I01 -----------------------------------------------------------

    def test_the_contract_fixture_projects_to_its_ten_hand_specified_intervals
      records = records_for_fixture

      assert_equal FIXTURE.fetch("expected_effective_rows"), records.length
      FIXTURE.fetch("expected").each_with_index do |want, i|
        got = records[i]
        label = "row #{i} (offset #{want['start']})"
        assert_equal ORIGIN + want.fetch("start"), got.start, label
        assert_equal ORIGIN + want.fetch("end"), got.end, label
        if want.fetch("asn").nil?
          assert_nil got.payload.asn, label
        else
          assert_equal want.fetch("asn"), got.payload.asn, label
        end
        assert_equal want.fetch("vpn_range"), got.payload.vpn_range, label
        assert_equal want.fetch("datacenter_range"), got.payload.datacenter_range, label
        assert_equal want.fetch("core_verdict"), got.payload.core_verdict, label
        assert_equal want.fetch("core_sources"), got.payload.core_sources, label

        # The fixture's flags are test context; the export decodes them into
        # the named fields, which is what a consumer actually reads.
        category, role, signals = Export::Contract.decode_flags(want.fetch("flags"))
        assert_equal [category, role], [got.payload.category, got.payload.network_role], label
        Export::Contract::ASN_SIGNALS.each { |s| assert_equal signals.fetch(s), got.payload[s], "#{label} #{s}" }
      end
    end

    def test_the_fixture_covers_exactly_its_stated_address_counts_and_leaves_its_gaps_empty
      records = records_for_fixture

      covered = records.sum(&:addresses)
      assert_equal FIXTURE.fetch("expected_covered_addresses"), covered
      overlay_only = records.reject { |r| r.payload.asn }.sum(&:addresses)
      assert_equal FIXTURE.fetch("expected_overlay_only_addresses"), overlay_only

      FIXTURE.fetch("miss_offsets").each do |offset|
        address = ORIGIN + offset
        refute records.any? { |r| r.start <= address && address <= r.end },
               "offset #{offset} is in a gap and must not be covered"
      end
    end

    def test_the_fixture_orgs_reach_the_payload_and_an_overlay_only_row_has_none
      records = records_for_fixture
      assert_equal "Access A", records.first.payload.as_org
      assert_equal "Gateway C", records.find { |r| r.payload.asn == 300 }.payload.as_org
      assert_nil records.last.payload.as_org
    end

    # --- I02, I03, I04 -------------------------------------------------

    def test_adjacent_rows_with_an_identical_payload_coalesce_into_one_interval
      records = project(base: [[0, 9, 100, ISP_ACCESS], [10, 19, 100, ISP_ACCESS]], orgs: { 100 => "Access A" })

      assert_equal 1, records.length
      assert_equal [0, 19], [records[0].start, records[0].end]
    end

    def test_adjacent_rows_with_different_asns_are_kept_even_when_verdict_and_org_agree
      records = project(base: [[0, 9, 100, ISP_ACCESS], [10, 19, 200, ISP_ACCESS]],
                        orgs: { 100 => "Same Org", 200 => "Same Org" })

      assert_equal 2, records.length
      assert_equal [100, 200], records.map { |r| r.payload.asn }
      assert_equal %w[residential_isp residential_isp], records.map { |r| r.payload.core_verdict }
      assert_equal ["Same Org", "Same Org"], records.map { |r| r.payload.as_org }
    end

    def test_an_identical_payload_across_a_gap_is_never_bridged
      records = project(base: [[0, 9, 100, ISP_ACCESS], [20, 29, 100, ISP_ACCESS]], orgs: { 100 => "Access A" })

      assert_equal 2, records.length
      assert_equal [[0, 9], [20, 29]], records.map { |r| [r.start, r.end] }
    end

    def test_a_redundant_base_boundary_between_identical_payloads_disappears
      # Two different ASNs would keep the boundary; the same ASN with the
      # same flags and the same name makes the boundary unobservable, and an
      # unobservable boundary is not worth a published row.
      records = project(base: [[0, 4, 100, ISP_ACCESS], [5, 9, 100, ISP_ACCESS], [10, 14, 100, ISP_ACCESS]],
                        orgs: { 100 => "Access A" })
      assert_equal 1, records.length
      assert_equal [0, 14], [records[0].start, records[0].end]
    end

    # --- I05 -----------------------------------------------------------

    def test_overlay_boundaries_inside_a_base_row_split_it_with_independent_flags
      records = project(base: [[0, 99, 100, ISP_ACCESS]], vpn: [[50, 59]], dc: [[55, 64]],
                        orgs: { 100 => "Access A" })

      assert_equal [[0, 49], [50, 54], [55, 59], [60, 64], [65, 99]], records.map { |r| [r.start, r.end] }
      assert_equal [false, true, true, false, false], records.map { |r| r.payload.vpn_range }
      assert_equal [false, false, true, true, false], records.map { |r| r.payload.datacenter_range }
      assert_equal %w[residential_isp vpn vpn hosting residential_isp], records.map { |r| r.payload.core_verdict }
      assert(records.all? { |r| r.payload.asn == 100 }, "the base evidence survives every overlay split")
    end

    # --- I06 -----------------------------------------------------------

    def test_an_overlay_in_a_base_gap_is_exported_with_a_null_asn
      records = project(base: [[0, 9, 100, ISP_ACCESS], [40, 49, 100, ISP_ACCESS]], dc: [[20, 29]],
                        orgs: { 100 => "Access A" })

      overlay_only = records.find { |r| r.payload.asn.nil? }
      assert_equal [20, 29], [overlay_only.start, overlay_only.end]
      assert_nil overlay_only.payload.as_org
      assert_nil overlay_only.payload.category
      assert_nil overlay_only.payload.network_role
      assert_equal "hosting", overlay_only.payload.core_verdict
      assert_equal ["x4b_dc"], overlay_only.payload.core_sources
      assert(Export::Contract::ASN_SIGNALS.none? { |s| overlay_only.payload[s] }, "no base row means no ASN signals")
    end

    # --- I07 -----------------------------------------------------------

    def test_a_layer_starting_at_zero_and_ending_at_the_maximum_address_emits_one_final_row
      records = project(base: [[0, V4_MAX, 100, ISP_ACCESS]], orgs: { 100 => "Access A" })

      assert_equal 1, records.length
      assert_equal 0, records[0].start
      assert_equal V4_MAX, records[0].end
      assert_equal 1 << 32, records[0].addresses
    end

    def test_the_end_sentinel_one_past_the_last_address_is_never_serialized
      records = project(base: [[V4_MAX - 1, V4_MAX, 100, ISP_ACCESS]], orgs: { 100 => "Access A" })
      line = JSON.parse(Export::Spool.line_for(records[0]))

      assert_equal "fffffffe", line.fetch("start_hex")
      assert_equal "ffffffff", line.fetch("end_hex")
    end

    def test_the_ipv6_maximum_address_survives_as_an_integer_not_a_float
      records = project(family: :ipv6, base: [[V6_MAX - 1, V6_MAX, 100, ISP_ACCESS]], orgs: { 100 => "Access A" })
      line = JSON.parse(Export::Spool.line_for(records[0]))

      assert_equal V6_MAX, records[0].end
      assert_equal "f" * 32, line.fetch("end_hex")
      assert_equal 32, line.fetch("start_hex").length
    end

    # --- I08 -----------------------------------------------------------

    def test_an_empty_base_with_overlays_yields_overlay_only_rows_and_an_empty_input_yields_none
      records = project(vpn: [[10, 19]], dc: [[15, 24]])
      assert_equal [[10, 14], [15, 19], [20, 24]], records.map { |r| [r.start, r.end] }
      assert(records.all? { |r| r.payload.asn.nil? })
      assert_equal %w[vpn vpn hosting], records.map { |r| r.payload.core_verdict }

      assert_empty project
    end

    # --- I09 -----------------------------------------------------------

    def test_unsorted_inverted_or_overlapping_ranges_are_rejected_before_the_sweep
      {
        "base unsorted" => { base: [[100, 199, 1, 0], [0, 99, 1, 0]] },
        "base overlapping" => { base: [[0, 99, 1, 0], [50, 149, 1, 0]] },
        "base touching" => { base: [[0, 99, 1, 0], [99, 149, 1, 0]] },
        "base inverted" => { base: [[99, 0, 1, 0]] },
        "vpn unsorted" => { vpn: [[100, 199], [0, 99]] },
        "vpn overlapping" => { vpn: [[0, 99], [50, 149]] },
        "vpn inverted" => { vpn: [[99, 0]] },
        "dc unsorted" => { dc: [[100, 199], [0, 99]] },
        "dc overlapping" => { dc: [[0, 99], [50, 149]] },
        "dc inverted" => { dc: [[99, 0]] }
      }.each do |label, layers|
        error = assert_raises(StageFailure, label) { load_written(**layers) }
        assert_match(/unsorted or overlapping|inverted/, error.message, label)
      end
    end

    # --- I10 -----------------------------------------------------------

    def test_a_deactivation_and_an_activation_at_the_same_position_lose_no_interval
      records = project(base: [[0, 9, 100, ISP_ACCESS], [10, 19, 200, HOSTING]],
                        vpn: [[5, 9], [10, 14]], orgs: { 100 => "Access A", 200 => "Host B" })

      # Position 10 carries four simultaneous events (base row 0 ends, base
      # row 1 starts, vpn row 0 ends, vpn row 1 starts). Nothing collapses.
      assert_equal [[0, 4], [5, 9], [10, 14], [15, 19]], records.map { |r| [r.start, r.end] }
      assert_equal [100, 100, 200, 200], records.map { |r| r.payload.asn }
      assert_equal [false, true, true, false], records.map { |r| r.payload.vpn_range }
      assert_equal 20, records.sum(&:addresses)
    end

    def test_adjacent_rows_in_one_layer_are_not_mistaken_for_an_overlap
      records = project(vpn: [[0, 9], [10, 19]])
      assert_equal 1, records.length, "adjacent overlay rows describe one continuous covered interval"
      assert_equal [0, 19], [records[0].start, records[0].end]
    end

    # --- I11 -----------------------------------------------------------

    def test_a_nonzero_relay_layer_fails_the_export_with_an_explanatory_error
      error = assert_raises(StageFailure) { load_written(base: [[0, 9, 100, ISP_ACCESS]], relay: [[20, 29]]) }

      assert_match(/relay overlay layer has 1 rows/, error.message)
      assert_match(/Tier B/, error.message)
    end

    # --- input adapter: header, evidence, timestamps --------------------

    def test_reserved_category_role_codes_and_reserved_bits_fail_the_input_adapter
      [6, 112, 1 << 14, 1 << 15].each do |flags|
        assert_raises(StageFailure, "flags #{flags}") { load_written(base: [[0, 9, 100, flags]]) }
      end
    end

    def test_mismatched_build_timestamps_fail_because_they_are_not_one_build
      v4 = write_oasn("a4.bin", family: :ipv4, build_ts: 1_789_755_195, base: [[0, 9, 100, ISP_ACCESS]])
      v6 = write_oasn("a6.bin", family: :ipv6, build_ts: 1_789_755_196, base: [])
      orgs = write_orgs("o.bin", { 100 => "Access A" })

      error = assert_raises(StageFailure) { Export::Inputs.load(v4_path: v4, v6_path: v6, orgs_path: orgs) }
      assert_match(/build timestamps differ/, error.message)
    end

    def test_a_header_whose_counts_do_not_match_the_file_length_is_rejected
      path = write_oasn("short.bin", family: :ipv4, base: [[0, 9, 100, ISP_ACCESS]])
      File.binwrite(path, File.binread(path)[0..-3])
      v6 = write_oasn("s6.bin", family: :ipv6)

      error = assert_raises(StageFailure) do
        Export::Inputs.load(v4_path: path, v6_path: v6, orgs_path: write_orgs("o.bin", { 100 => "Access A" }))
      end
      assert_match(/describe \d+ bytes, file is/, error.message)
    end

    def test_a_swapped_family_artifact_is_rejected_rather_than_read_as_the_other_family
      v4 = write_oasn("x4.bin", family: :ipv6)
      v6 = write_oasn("x6.bin", family: :ipv6)

      error = assert_raises(StageFailure) do
        Export::Inputs.load(v4_path: v4, v6_path: v6, orgs_path: write_orgs("o.bin", { 1 => "A" }))
      end
      assert_match(/address_family/, error.message)
    end

    def test_the_input_descriptors_record_every_artifact_name_size_and_digest
      snapshot = load_written(base: [[0, 9, 100, ISP_ACCESS]], orgs: { 100 => "Access A" })

      assert_equal %w[openasn-ipv4.bin openasn-ipv6.bin openasn-orgs.bin], snapshot.artifacts.map(&:name)
      snapshot.artifacts.each do |descriptor|
        assert_equal 64, descriptor.sha256.length
        assert_equal Digest::SHA256.file(File.join(@dir, descriptor.name)).hexdigest, descriptor.sha256
        assert_equal File.size(File.join(@dir, descriptor.name)), descriptor.bytes
      end
      assert_equal({ base: 1, vpn: 0, dc: 0, relay: 0 }, snapshot.layers(:ipv4).counts)
    end

    # --- O01, O02 ------------------------------------------------------

    def test_an_asn_with_no_org_entry_keeps_its_asn_and_gets_a_null_name
      snapshot = load_written(base: [[0, 9, 100, ISP_ACCESS], [10, 19, 200, ISP_ACCESS]], orgs: { 100 => "Access A" })
      records = Export::Project.each(snapshot, family: :ipv4).to_a

      assert_equal [100, 200], records.map { |r| r.payload.asn }
      assert_equal ["Access A", nil], records.map { |r| r.payload.as_org }
    end

    def test_a_missing_or_corrupt_orgs_file_fails_the_export
      v4 = write_oasn("openasn-ipv4.bin", family: :ipv4, base: [[0, 9, 100, ISP_ACCESS]])
      v6 = write_oasn("openasn-ipv6.bin", family: :ipv6)
      load = ->(orgs_path) { Export::Inputs.load(v4_path: v4, v6_path: v6, orgs_path: orgs_path) }

      missing = File.join(@dir, "absent.bin")
      assert_match(/missing/, assert_raises(StageFailure) { load.call(missing) }.message)

      bad_magic = write_orgs("magic.bin", { 100 => "Access A" })
      File.binwrite(bad_magic, "OOPS#{File.binread(bad_magic)[4..]}")
      assert_match(/bad magic/, assert_raises(StageFailure) { load.call(bad_magic) }.message)

      truncated = write_orgs("truncated.bin", { 100 => "Access A" })
      File.binwrite(truncated, File.binread(truncated)[0..-2])
      assert_match(/describes \d+ bytes/, assert_raises(StageFailure) { load.call(truncated) }.message)

      # index offset pointing past the blob
      out_of_bounds = write_orgs("oob.bin", { 100 => "Access A" })
      bytes = File.binread(out_of_bounds)
      bytes[Orgs::HEADER_SIZE + 4, 4] = [9_999].pack("N")
      File.binwrite(out_of_bounds, bytes)
      assert_match(/past the \d+-byte blob/, assert_raises(StageFailure) { load.call(out_of_bounds) }.message)

      invalid_utf8 = write_orgs("utf8.bin", { 100 => "Access A" })
      bytes = File.binread(invalid_utf8)
      bytes[-1] = "\xC3".b
      File.binwrite(invalid_utf8, bytes)
      assert_match(/not valid UTF-8/, assert_raises(StageFailure) { load.call(invalid_utf8) }.message)

      unsorted = write_orgs("unsorted.bin", { 100 => "Access A", 200 => "Host B" }, sort: false)
      assert_match(/unsorted or has duplicates/, assert_raises(StageFailure) { load.call(unsorted) }.message)
    end

    # --- O03 -----------------------------------------------------------

    def test_org_names_round_trip_byte_for_byte_at_the_96_byte_boundary_and_through_punctuation
      boundary = "あ" * 32 # exactly 96 bytes, the OORG cap, on a character boundary
      assert_equal Orgs::MAX_NAME, boundary.bytesize
      punctuated = %(Acme, "Net" Ltd.\nSecond line)

      snapshot = load_written(base: [[0, 9, 100, ISP_ACCESS], [10, 19, 200, ISP_ACCESS]],
                              orgs: { 100 => boundary, 200 => punctuated })
      records = Export::Project.each(snapshot, family: :ipv4).to_a

      assert_equal boundary, records[0].payload.as_org
      assert_equal Encoding::UTF_8, records[0].payload.as_org.encoding
      assert_equal punctuated, records[1].payload.as_org

      # Through the spool the name is escaped, not altered: the newline is one
      # JSON escape on one physical line, so a line-counting consumer and a
      # parsing consumer agree.
      lines = spool_lines(snapshot)
      assert_equal 2, lines.length
      assert_equal punctuated, JSON.parse(lines[1]).fetch("as_org")
      assert_includes lines[1], '\n'
      assert_equal boundary, JSON.parse(lines[0]).fetch("as_org")
    end

    # --- spool canonical form ------------------------------------------

    def test_the_spool_writes_fixed_key_order_ipv4_before_ipv6_and_ascending_endpoints
      snapshot = load_written(base: [[0, 9, 100, ISP_ACCESS], [20, 29, 200, HOSTING]],
                              v6_base: [[0, 9, 300, ISP_ACCESS]],
                              orgs: { 100 => "Access A", 200 => "Host B", 300 => "Six C" })
      lines = spool_lines(snapshot)

      assert_equal 3, lines.length
      assert_equal [4, 4, 6], lines.map { |l| JSON.parse(l).fetch("ip_version") }
      assert_equal Export::Contract::SPOOL_FIELDS.map(&:to_s), JSON.parse(lines[0]).keys
      assert_equal %w[00000000 00000014], lines.first(2).map { |l| JSON.parse(l).fetch("start_hex") }
      assert_equal 32, JSON.parse(lines[2]).fetch("start_hex").length
      assert_equal "residential_isp", JSON.parse(lines[0]).fetch("core_verdict")
      assert_equal ["asn_category"], JSON.parse(lines[0]).fetch("core_sources")
    end

    def test_the_spool_returns_per_family_counts_and_the_digest_of_the_bytes_it_wrote
      snapshot = load_written(base: [[0, 9, 100, ISP_ACCESS]], v6_base: [[0, 9, 300, HOSTING]],
                              orgs: { 100 => "Access A", 300 => "Six C" })
      path = File.join(@dir, "records.jsonl")
      counts = Export::Spool.write(snapshot, path: path)

      assert_equal 1, counts.ipv4
      assert_equal 1, counts.ipv6
      assert_equal 2, counts.total
      assert_equal File.size(path), counts.bytes
      assert_equal Digest::SHA256.file(path).hexdigest, counts.sha256
    end

    private

    def records_for_fixture
      base = FIXTURE.fetch("base").map { |r| [ORIGIN + r["start"], ORIGIN + r["end"], r["asn"], r["flags"]] }
      snapshot = load_written(
        base: base,
        vpn: FIXTURE.fetch("vpn").map { |(s, e)| [ORIGIN + s, ORIGIN + e] },
        dc: FIXTURE.fetch("dc").map { |(s, e)| [ORIGIN + s, ORIGIN + e] },
        relay: FIXTURE.fetch("relay"),
        orgs: FIXTURE.fetch("orgs").to_h { |asn, name| [asn.to_i, name] }
      )
      Export::Project.each(snapshot, family: :ipv4).to_a
    end

    # In-memory snapshot: the sweep's own behaviour, without file plumbing.
    def project(family: :ipv4, base: [], vpn: [], dc: [], orgs: {})
      layers = Export::Inputs::Layers.new(family, base, vpn, dc)
      empty  = Export::Inputs::Layers.new(family == :ipv4 ? :ipv6 : :ipv4, [], [], [])
      snapshot = Export::Inputs::Snapshot.new(
        build_ts: 1_789_755_195,
        ipv4: family == :ipv4 ? layers : empty,
        ipv6: family == :ipv6 ? layers : empty,
        orgs: Export::Inputs::OrgIndex.new(orgs),
        artifacts: []
      )
      Export::Project.each(snapshot, family: family).to_a
    end

    def spool_lines(snapshot)
      path = File.join(@dir, "records.jsonl")
      Export::Spool.write(snapshot, path: path)
      File.binread(path).lines
    end

    # Writes a real artifact set into the scratch dir and loads it through
    # the validated adapter.
    def load_written(base: [], vpn: [], dc: [], relay: [], v6_base: [], orgs: {})
      v4 = write_oasn("openasn-ipv4.bin", family: :ipv4, base: base, vpn: vpn, dc: dc, relay: relay)
      v6 = write_oasn("openasn-ipv6.bin", family: :ipv6, base: v6_base)
      Export::Inputs.load(v4_path: v4, v6_path: v6, orgs_path: write_orgs("openasn-orgs.bin", orgs))
    end

    # Deliberately unchecked packers - see the file header.
    def write_oasn(name, family:, build_ts: 1_789_755_195, base: [], vpn: [], dc: [], relay: [])
      path = File.join(@dir, name)
      File.open(path, "wb") do |io|
        io.write(MAGIC.b, [FORMAT_VERSION, family == :ipv4 ? 0x04 : 0x06, 0].pack("CCn"), [build_ts].pack("Q>"),
                 [base.length, vpn.length, dc.length, relay.length].pack("NNNN"))
        base.each do |(s, e, asn, flags)|
          io.write(Binary.pack_addr(s, family), Binary.pack_addr(e, family), [asn, flags].pack("Nn"))
        end
        [vpn, dc, relay].each do |rows|
          rows.each { |(s, e)| io.write(Binary.pack_addr(s, family), Binary.pack_addr(e, family)) }
        end
      end
      path
    end

    def write_orgs(name, names, sort: true)
      path = File.join(@dir, name)
      entries = names.to_a
      entries = entries.sort_by(&:first) if sort
      entries = entries.reverse unless sort
      blob = +"".b
      index = +"".b
      entries.each do |(asn, org)|
        index << [asn, blob.bytesize].pack("NN")
        blob << org.b
      end
      File.open(path, "wb") do |io|
        io.write(Orgs::MAGIC.b, [Orgs::VERSION, 0, 0].pack("CCn"),
                 [entries.length, blob.bytesize].pack("NN"), index, blob)
      end
      path
    end
  end
end
