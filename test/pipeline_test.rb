# frozen_string_literal: true

# Unit tests for the pipeline's pure logic. The heavyweight correctness
# checks (spot panel, round-trip, delta gates) run inside every real build
# (pipeline/validate.rb); these tests cover the algorithms and parsers that
# gates depend on, so a bug can't hide inside the gate machinery itself.

require_relative "test_helper"

module OpenASNPipeline
  class IPMathTest < Minitest::Test
    def test_cidr_to_range_v4
      assert_equal [0x01020300, 0x010203FF, :ipv4], IPMath.cidr_to_range("1.2.3.0/24")
      assert_equal [0x08080808, 0x08080808, :ipv4], IPMath.cidr_to_range("8.8.8.8")
    end

    def test_cidr_to_range_v6
      s, e, fam = IPMath.cidr_to_range("2a00::/16")
      assert_equal :ipv6, fam
      assert_equal 0x2a00 << 112, s
      assert_equal ((0x2a00 << 112) | ((1 << 112) - 1)), e
    end

    def test_v4_to_int_fast_path_agrees_with_ipaddr
      %w[0.0.0.0 255.255.255.255 8.8.8.8 100.64.0.1 192.168.1.254].each do |ip|
        assert_equal IPAddr.new(ip).to_i, IPMath.v4_to_int(ip), ip
      end
      assert_nil IPMath.v4_to_int("300.1.2.3")
      assert_nil IPMath.v4_to_int("1.2.3")
      assert_nil IPMath.v4_to_int("::1")
    end

    def test_merge_ranges_merges_overlapping_and_adjacent
      assert_equal [[1, 12]], IPMath.merge_ranges([[1, 5], [6, 9], [8, 12]])
      assert_equal [[1, 5], [7, 9]], IPMath.merge_ranges([[7, 9], [1, 5]])
      assert_equal [], IPMath.merge_ranges([])
    end

    def test_subtract_covered_returns_gaps_only
      covered = [[10, 20], [30, 40]]
      assert_equal [[5, 9], [21, 29], [41, 45]], IPMath.subtract_covered(5, 45, covered)
      assert_equal [], IPMath.subtract_covered(12, 18, covered)
      assert_equal [[50, 60]], IPMath.subtract_covered(50, 60, covered)
    end
  end

  class BinaryTest < Minitest::Test
    def setup
      @dir = File.join(WORK_DIR, "test-#{name}")
      FileUtils.mkdir_p(@dir)
    end

    def teardown
      FileUtils.rm_rf(@dir)
    end

    def test_ipv4_round_trip_and_lookup
      path = File.join(@dir, "t4.bin")
      base = [[100, 200, 65_001, 0x0102], [300, 400, 65_002, Binary::FLAG_VPN_PROVIDER]]
      Binary.write(path, family: :ipv4, build_ts: 1_751_000_000,
                   base_rows: base, vpn_rows: [[150, 160]], dc_rows: [[300, 350]])

      a = Binary::Artifact.new(path)
      assert_equal :ipv4, a.family
      assert_equal({ base: 2, vpn: 1, dc: 1, relay: 0 }, a.counts)
      assert_equal [100, 200, 65_001, 0x0102], a.find_base(100)
      assert_equal [100, 200, 65_001, 0x0102], a.find_base(200)
      assert_nil a.find_base(250)
      assert a.in_vpn?(155)
      refute a.in_vpn?(165)
      assert a.in_dc?(320)
    end

    def test_ipv6_round_trip_with_128bit_values
      path = File.join(@dir, "t6.bin")
      s = IPAddr.new("2a00:1450::").to_i
      e = IPAddr.new("2a00:1450:ffff:ffff:ffff:ffff:ffff:ffff").to_i
      Binary.write(path, family: :ipv6, build_ts: 1, base_rows: [[s, e, 15_169, 0x52]])

      a = Binary::Artifact.new(path)
      assert_equal [s, e, 15_169, 0x52], a.find_base(IPAddr.new("2a00:1450::8888").to_i)
      assert_nil a.find_base(IPAddr.new("2a01::1").to_i)
    end

    def test_header_is_byte_exact_per_format_md
      path = File.join(@dir, "hdr.bin")
      Binary.write(path, family: :ipv4, build_ts: 0x0102030405060708,
                   base_rows: [[1, 2, 3, 4]])
      bytes = File.binread(path)
      assert_equal "OASN", bytes[0, 4]
      assert_equal [0x01, 0x04], bytes[4, 2].unpack("CC")
      assert_equal 0, bytes[6, 2].unpack1("n")
      assert_equal 0x0102030405060708, bytes[8, 8].unpack1("Q>")
      assert_equal [1, 0, 0, 0], bytes[16, 16].unpack("NNNN")
      assert_equal 32 + 14, bytes.bytesize
    end

    def test_writer_rejects_overlapping_base_rows
      path = File.join(@dir, "bad.bin")
      assert_raises(StageFailure) do
        Binary.write(path, family: :ipv4, build_ts: 1,
                     base_rows: [[1, 10, 1, 0], [5, 20, 2, 0]])
      end
    end
  end

  class LicenseExtractionTest < Minitest::Test
    def test_x4b_license_section_extraction
      readme = <<~MD
        # Usage
        blah blah stats table that churns daily

        # License

        Software in the below license corresponds to the scripts, automation, and the list itself (source files and generated output).

        ```
        MIT License
        Copyright (c) 2024 X4B (Mathew Heard)
        ```

        # Contributing
        more churn
      MD
      extracted = LicenseGate.extract(readme, :license_heading_section, "x4b")
      assert_includes extracted, "source files and generated output"
      assert_includes extracted, "Copyright (c) 2024 X4B"
      refute_includes extracted, "stats table"
      refute_includes extracted, "Contributing"
    end

    def test_extraction_failure_is_loud
      assert_raises(StageFailure) do
        LicenseGate.extract("# Totally Different README", :license_heading_section, "x4b")
      end
    end
  end

  class OverridesTest < Minitest::Test
    def setup
      @dir = File.join(WORK_DIR, "test-overrides-#{name}")
      FileUtils.mkdir_p(@dir)
    end

    def teardown
      FileUtils.rm_rf(@dir)
    end

    def write(file, content) = File.write(File.join(@dir, file), content)

    def test_parses_sourced_lines_and_rejects_unsourced
      write("vpn_provider.txt", <<~TXT)
        # header comment
        AS9009  # M247 - src: https://example.com/evidence (2026-07-04)
      TXT
      o = Overrides.load(@dir)
      assert_equal Set[9009], o.sets[:vpn_provider]

      write("vpn_provider.txt", "AS1234  # no source here\n")
      assert_raises(StageFailure) { Overrides.load(@dir) }
    end

    def test_eyeball_infra_conflict_fails_build
      write("vpn_provider.txt", "AS1  # x src: https://e (d)\n")
      write("eyeball_confirm.txt", "AS1  # y src: https://e (d)\n")
      assert_raises(StageFailure) { Overrides.load(@dir) }
    end

    def test_corrections_yaml_validation
      write("corrections.yml", <<~YAML)
        64496:
          category: hosting
          reason: "verified mislabel"
          source_url: "https://example.com"
          date: 2026-07-04
      YAML
      o = Overrides.load(@dir)
      assert_equal "hosting", o.corrections[64_496]["category"]

      write("corrections.yml", <<~YAML)
        64497:
          category: not_a_category
          reason: "r"
          source_url: "u"
          date: 2026-07-04
      YAML
      assert_raises(StageFailure) { Overrides.load(@dir) }
    end
  end

  class ClassifierSpecialsTest < Minitest::Test
    def test_v4_special_ranges
      assert_equal [:private, :special_loopback], Classifier.special_for(IPAddr.new("127.0.0.1").to_i, :ipv4)
      assert_equal [:cgnat, :special_cgnat], Classifier.special_for(IPAddr.new("100.64.0.0").to_i, :ipv4)
      assert_equal [:cgnat, :special_cgnat], Classifier.special_for(IPAddr.new("100.127.255.255").to_i, :ipv4)
      # boundary: first public IP above CGNAT space is NOT special
      assert_nil Classifier.special_for(IPAddr.new("100.128.0.0").to_i, :ipv4)
      assert_equal [:private, :special_rfc1918], Classifier.special_for(IPAddr.new("172.16.0.1").to_i, :ipv4)
      assert_nil Classifier.special_for(IPAddr.new("172.32.0.1").to_i, :ipv4)
    end

    def test_v6_special_ranges
      assert_equal [:private, :special_loopback], Classifier.special_for(IPAddr.new("::1").to_i, :ipv6)
      assert_equal [:private, :special_ula], Classifier.special_for(IPAddr.new("fd00::1").to_i, :ipv6)
      assert_nil Classifier.special_for(IPAddr.new("2a00::1").to_i, :ipv6)
    end
  end
end
