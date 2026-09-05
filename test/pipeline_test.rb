# frozen_string_literal: true

# Unit tests for the pipeline's pure logic. The heavyweight correctness
# checks (spot panel, round-trip, delta gates) run inside every real build
# (pipeline/validate.rb); these tests cover the algorithms and parsers that
# gates depend on, so a bug can't hide inside the gate machinery itself.

require_relative "test_helper"
require "stringio"
require_relative "../pipeline/crosscheck"
require_relative "../pipeline/validate"

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

  # Shared helpers for the drift-gate suites: quiet, capturable logging and
  # fixture builders. The gates log through Env.logger (memoized on $stdout
  # at creation), so Minitest's capture_io cannot see them; we swap the
  # memoized logger for one on a StringIO and restore the memo afterwards.
  module DriftTestHelpers
    def setup
      DriftGate.reset!
      @log = StringIO.new
      logger = Logger.new(@log)
      logger.formatter = proc { |sev, _t, _p, msg| "[#{sev}] #{msg}\n" }
      Env.instance_variable_set(:@logger, logger)
    end

    def teardown
      DriftGate.reset!
      Env.instance_variable_set(:@logger, nil)
    end

    def log = @log.string

    def pin(label, stats) = Crosscheck::Pin.new(label: label, stats: stats)
    def hosting_pin(label, hosting) = pin(label, { "hosting_asns" => hosting })
    def baselines(*pairs) = pairs.map { |label, value| DriftGate::Baseline.new(label: label, value: value) }

    def ev(now:, prev:, baselines: [], ack: nil, policy: DriftGate::HOSTING_POLICY)
      DriftGate.evaluate(metric: "hosting_asns", now: now, prev: prev, baselines: baselines, policy: policy, ack: ack)
    end

    def enforce(now:, prev:, baselines: [], ack: nil, policy: DriftGate::HOSTING_POLICY, gate: "crosscheck")
      DriftGate.enforce!(gate: gate, metric: "hosting_asns", now: now, prev: prev, baselines: baselines,
                         policy: policy, ack: ack)
    end
  end

  # lib/drift_gate.rb - the policy behind the 2026-08-24 -> 09-05 deadlock
  # fix (drift_gate.rb header; data-repo DECISIONS.md D-GATE-1). Numbers in
  # these tests are the real incident numbers: hosting ASNs 12,393 (Aug 23
  # pin) -> 9,342 (Aug 24 degraded build, published) -> 12,442 (Aug 25+).
  class DriftGateTest < Minitest::Test
    include DriftTestHelpers

    def test_deadlock_scenario_passes_as_recovery
      # Aug 25 as the task states it: prev = degraded latest, pin = Aug 16.
      r = ev(now: 12_442, prev: 9_342, baselines: baselines(["v2026.08.16", 12_377]))
      assert_equal :recovery, r.status
      refute r.blocking?
      assert_in_delta 0.332, r.drift, 0.001
      assert_equal "v2026.08.16", r.baseline.label
      assert_in_delta 0.0053, r.baseline_drift, 0.0005
      assert_equal "hosting_asns: 9342 -> 12442 (+33.2% vs previous build); within +0.5% of weekly pin v2026.08.16 (12377)",
                   r.summary

      # ...and against the actual most recent pin (v2026.08.23 = 12,393).
      r = enforce(now: 12_442, prev: 9_342, baselines: baselines(["v2026.08.23", 12_393], ["v2026.08.16", 12_377]))
      assert_equal :recovery, r.status
      assert_equal "v2026.08.23", r.baseline.label
      assert_match(/\[WARN\] crosscheck: drift RECOVERY hosting_asns: 9342 -> 12442 \(\+33\.2% vs previous build\); within \+0\.4% of weekly pin v2026\.08\.23 \(12393\)/, log)
      assert_match(/PASSING/, log)
      assert_equal [:recovery], DriftGate.events.map(&:status)
      assert_equal 1, DriftGate.manifest_stamp[:drift_recovery].size
      refute DriftGate.manifest_stamp.key?(:drift_ack)
    end

    def test_genuine_catastrophe_fails_even_with_a_pin
      r = ev(now: 6_000, prev: 12_400, baselines: baselines(["v2026.08.16", 12_377]))
      assert_equal :fail, r.status
      assert r.blocking?
      err = assert_raises(StageFailure) do
        enforce(now: 6_000, prev: 12_400, baselines: baselines(["v2026.08.16", 12_377]))
      end
      assert_match(/drift FAIL hosting_asns: 12400 -> 6000 \(-51\.6% vs previous build\)/, err.message)
      assert_match(/beyond the 10% drop line/, err.message)
      assert_match(/v2026\.08\.16=12377/, err.message)
      assert_match(/OPENASN_ACK_DRIFT="<reason>"/, err.message) # the unblock instruction travels with the failure
      assert_empty DriftGate.events
      assert_equal({}, DriftGate.manifest_stamp)
    end

    def test_ack_turns_a_fail_into_a_stamped_warn
      reason = "ipverse reclassified 6k ASNs on purpose, see ipverse/as-metadata#123"
      r = enforce(now: 6_000, prev: 12_400, baselines: baselines(["v2026.08.16", 12_377]), ack: reason)
      assert_equal :acked, r.status
      refute r.blocking?
      assert_match(/\[WARN\] crosscheck: drift ACKED hosting_asns: 12400 -> 6000 \(-51\.6% vs previous build\) - acknowledged: "ipverse reclassified/, log)
      stamp = DriftGate.manifest_stamp
      assert_equal reason, stamp[:drift_ack][:reason]
      assert_equal 1, stamp[:drift_ack][:gates].size
      assert_match(/\Ahosting_asns: 12400 -> 6000 \(-51\.6% vs previous build\) - acknowledged:/, stamp[:drift_ack][:gates].first)

      # A blank ack is no ack; whitespace is not a reason.
      assert_equal :fail, ev(now: 6_000, prev: 12_400, ack: "   ").status
      assert_equal :fail, ev(now: 6_000, prev: 12_400, ack: nil).status
      # An ack never touches a passing gate (nothing to stamp).
      DriftGate.reset!
      assert_equal :pass, enforce(now: 12_442, prev: 12_400, ack: reason).status
      assert_equal({}, DriftGate.manifest_stamp)
    end

    def test_drop_and_rise_lines_are_asymmetric
      # The 2026-08-24 drop (12,393 -> 9,342, -24.6%) only WARNED under the
      # old symmetric 30% line and shipped. It FAILS now.
      assert_equal :fail, ev(now: 9_342, prev: 12_393).status
      # Drop of 11.3% fails; the same-sized rise only warns.
      assert_equal :fail, ev(now: 11_000, prev: 12_400).status
      assert_equal :warn, ev(now: 13_800, prev: 12_400).status
      # A 21% rise fails; a 19% rise warns.
      assert_equal :fail, ev(now: 15_000, prev: 12_400).status
      assert_equal :warn, ev(now: 14_750, prev: 12_400).status
      # Exactly on the lines: <= is inside.
      assert_equal :warn, ev(now: 11_160, prev: 12_400).status # -10.0%
      assert_equal :pass, ev(now: 11_780, prev: 12_400).status # -5.0%
      assert_equal :pass, ev(now: 12_393, prev: 12_377).status # the real Aug 16 -> 23 move (+0.13%)
      assert_equal "warn>5%, fail: drop>10% rise>20%, recovery band +-5% of a weekly pin", DriftGate::HOSTING_POLICY.describe
    end

    def test_every_status_logs_one_engagement_line_with_numbers
      enforce(now: 12_393, prev: 12_377)                                             # pass
      enforce(now: 11_650, prev: 12_400)                                             # warn (-6.0%)
      enforce(now: 12_442, prev: 9_342, baselines: baselines(["v2026.08.23", 12_393])) # recovery
      enforce(now: 6_000, prev: 12_400, ack: "x")                                    # acked
      enforce(now: 12_442, prev: nil)                                                # skipped
      lines = log.lines.grep(/drift (PASS|WARN|RECOVERY|ACKED|SKIP) hosting_asns:/)
      assert_equal 5, lines.size, log
      assert_match(/\[INFO\] crosscheck: drift PASS hosting_asns: 12377 -> 12393 \(\+0\.1% vs previous build\); warn>5%/, lines[0])
      assert_match(/\[WARN\] crosscheck: drift WARN hosting_asns: 12400 -> 11650 \(-6\.0% vs previous build\) - beyond the 5% warn line/, lines[1])
      assert_match(/\[WARN\] crosscheck: drift RECOVERY/, lines[2])
      assert_match(/\[WARN\] crosscheck: drift ACKED/, lines[3])
      assert_match(/\[INFO\] crosscheck: drift SKIP hosting_asns: no previous build stats and no weekly pin/, lines[4])
    end

    def test_no_previous_stats_paths
      # Nothing to compare against: SKIP, never raises, nothing stamped.
      r = enforce(now: 12_442, prev: nil)
      assert_equal :skipped, r.status
      refute r.blocking?
      assert_empty DriftGate.events
      assert_equal :skipped, ev(now: 12_442, prev: 0).status # a zero prev is "absent", not a division by zero

      # No previous build but pins exist (e.g. the `latest` asset failed to
      # download): the most recent pin stands in - the gate stays armed.
      r = ev(now: 12_442, prev: nil, baselines: baselines(["v2026.08.23", 12_393]))
      assert_equal :pass, r.status
      assert_equal "weekly pin v2026.08.23", r.prev_label
      assert_equal 12_393, r.prev
      assert_equal :fail, ev(now: 6_000, prev: nil, baselines: baselines(["v2026.08.23", 12_393])).status

      # No prev, a degraded newest pin, a healthy older pin: recovery via the older one.
      r = ev(now: 12_442, prev: nil, baselines: baselines(["v2026.08.30", 9_342], ["v2026.08.23", 12_393]))
      assert_equal :recovery, r.status
      assert_equal "v2026.08.23", r.baseline.label

      # Pins without the metric (older manifest shape) are ignored, not crashed on.
      assert_equal :skipped, ev(now: 12_442, prev: nil, baselines: baselines(["v2026.07.05", nil])).status
    end

    def test_two_pins_protect_against_a_drop_that_got_pinned_on_a_sunday
      r = ev(now: 12_442, prev: 9_342, baselines: baselines(["v2026.08.30", 9_350], ["v2026.08.23", 12_393]))
      assert_equal :recovery, r.status
      assert_equal "v2026.08.23", r.baseline.label
    end

    def test_recovery_band_is_tight_so_a_real_shift_still_needs_an_ack
      # +5.7% above the only pin: not a snap-back, a new state -> FAIL.
      r = ev(now: 13_100, prev: 9_342, baselines: baselines(["v2026.08.23", 12_393]))
      assert_equal :fail, r.status
      assert_nil r.baseline
      # ...but the ack still works there.
      assert_equal :acked, ev(now: 13_100, prev: 9_342, baselines: baselines(["v2026.08.23", 12_393]), ack: "ok").status
    end

    def test_layer_policy_keeps_the_founding_20pct_lines_and_gains_a_warn_tier
      p = DriftGate::LAYER_POLICY
      assert_equal [0.05, 0.20, 0.20, 0.05], [p.warn, p.fail_drop, p.fail_rise, p.recovery_band]
      assert_equal :pass, ev(now: 439_214, prev: 439_199, policy: p).status
      assert_equal :warn, ev(now: 400_000, prev: 439_199, policy: p).status # -8.9%
      assert_equal :fail, ev(now: 350_000, prev: 439_199, policy: p).status # -20.3%
      assert_equal :fail, ev(now: 530_000, prev: 439_199, policy: p).status # +20.7%
    end
  end

  # Crosscheck.run end to end with a synthetic as-metadata table: the drift
  # gate, the count floor and the returned stats, using the incident numbers.
  class CrosscheckDriftTest < Minitest::Test
    include DriftTestHelpers

    # `hosting` hosting-labelled ASNs plus 500 ISPs; the reference set is 900
    # ASNs of which 820 are hosting -> coverage 91.1%, like live data.
    def normalized(hosting)
      meta = {}
      (1..hosting).each { |i| meta[i] = AsJson::Record.new(i, "host #{i}", "US", "hosting", "stub") }
      (1..500).each { |i| meta[900_000 + i] = AsJson::Record.new(900_000 + i, "isp #{i}", "ES", "isp", "access_provider") }
      reference = Set.new((1..820).to_a + (900_001..900_080).to_a)
      { asn_meta: meta, x4b_dc_asns: reference, bad_asns: Set.new }
    end

    def test_the_deadlock_night_passes_as_a_recovery_and_returns_stats
      stats = Crosscheck.run(normalized(12_442), previous_stats: { "hosting_asns" => 9_342 },
                                                 baseline_stats: [hosting_pin("v2026.08.23", 12_393), hosting_pin("v2026.08.16", 12_377)])
      assert_equal 12_442, stats[:hosting_asns]
      assert_equal 900, stats[:reference_dc_asns]
      assert_in_delta 0.9111, stats[:reference_coverage], 0.0001
      assert_equal [:recovery], DriftGate.events.map(&:status)
      assert_match(/crosscheck: as-metadata hosting=12442 ASNs; reference dc set=900; coverage=91\.1%/, log)
      assert_match(/drift RECOVERY hosting_asns: 9342 -> 12442/, log)
    end

    def test_the_aug_24_build_can_no_longer_ship
      # 9,342 trips the raised count floor before the drift gate even runs...
      err = assert_raises(StageFailure) do
        Crosscheck.run(normalized(9_342), previous_stats: { "hosting_asns" => 12_393 }, baseline_stats: [])
      end
      assert_match(/hosting count 9342 < floor 10000/, err.message)
      # ...and the floor is NOT ackable: it means the category field broke.
      ENV[DriftGate::ACK_ENV] = "trying to force it through"
      err = assert_raises(StageFailure) do
        Crosscheck.run(normalized(9_342), previous_stats: { "hosting_asns" => 12_393 }, baseline_stats: [])
      end
      assert_match(/< floor 10000/, err.message)
      ENV.delete(DriftGate::ACK_ENV)
      # A milder drop (-11.2%) clears the floor and fails on the drop line.
      err = assert_raises(StageFailure) do
        Crosscheck.run(normalized(11_000), previous_stats: { "hosting_asns" => 12_393 },
                                           baseline_stats: [hosting_pin("v2026.08.23", 12_393)])
      end
      assert_match(/crosscheck: drift FAIL hosting_asns: 12393 -> 11000 \(-11\.2% vs previous build\)/, err.message)
    ensure
      ENV.delete(DriftGate::ACK_ENV)
    end

    def test_ack_env_var_flows_through_run_into_the_manifest_stamp
      ENV[DriftGate::ACK_ENV] = "operator verified: ipverse merged 1.4k hosting ASNs into parents"
      stats = Crosscheck.run(normalized(11_000), previous_stats: { "hosting_asns" => 12_393 },
                                                 baseline_stats: [hosting_pin("v2026.08.23", 12_393)])
      assert_equal 11_000, stats[:hosting_asns]
      stamp = DriftGate.manifest_stamp
      assert_equal "operator verified: ipverse merged 1.4k hosting ASNs into parents", stamp[:drift_ack][:reason]
      assert_match(/hosting_asns: 12393 -> 11000 \(-11\.2% vs previous build\) - acknowledged:/, stamp[:drift_ack][:gates].first)
    ensure
      ENV.delete(DriftGate::ACK_ENV)
    end

    def test_no_previous_stats_is_skipped_loudly_not_silently
      stats = Crosscheck.run(normalized(12_442), previous_stats: nil, baseline_stats: [])
      assert_equal 12_442, stats[:hosting_asns]
      assert_match(/drift SKIP hosting_asns: no previous build stats and no weekly pin/, log)
      assert_empty DriftGate.events
      # previous manifest present but from before the stats existed
      Crosscheck.run(normalized(12_442), previous_stats: { "layer_counts" => {} }, baseline_stats: [])
      assert_equal 2, log.scan(/drift SKIP/).size
    end
  end

  # Operational helpers in crosscheck.rb: stale-latest tripwire + pin discovery.
  class CrosscheckFreshnessTest < Minitest::Test
    include DriftTestHelpers

    def test_stale_latest_tripwire_warns_with_the_age
      now = Time.utc(2026, 9, 5, 4, 0, 0)
      age = Crosscheck.check_latest_freshness("2026-08-24T04:05:04Z", now: now)
      assert_in_delta 287.9, age, 0.1
      assert_match(/\[WARN\] STALE LATEST: previous published build 2026-08-24T04:05:04Z is 12\.0 days old \(288h > 48h\)/, log)

      age = Crosscheck.check_latest_freshness("2026-09-04T04:05:04Z", now: now)
      assert_in_delta 23.9, age, 0.1
      refute_match(/STALE/, log.lines.last)
      assert_match(/previous published build 2026-09-04T04:05:04Z \(23\.9h old\)/, log)

      assert_nil Crosscheck.check_latest_freshness(nil, now: now)
      assert_nil Crosscheck.check_latest_freshness("not-a-time", now: now)
    end

    def test_sunday_probe_fallback_lists_recent_pin_tags_newest_first
      tags = Crosscheck.recent_sunday_tags(today: Time.utc(2026, 9, 5, 12))
      assert_equal %w[v2026.08.30 v2026.08.23 v2026.08.16 v2026.08.09], tags.first(4)
      assert_equal 8, tags.size
      assert(tags.all? { |t| t.match?(Crosscheck::WEEKLY_TAG) })
      # A Sunday counts as itself (the pin is cut that morning).
      assert_equal "v2026.09.06", Crosscheck.recent_sunday_tags(today: Time.utc(2026, 9, 6, 23)).first
    end

    def test_weekly_tag_pattern_matches_only_dated_pins
      assert "v2026.08.23".match?(Crosscheck::WEEKLY_TAG)
      refute "latest".match?(Crosscheck::WEEKLY_TAG)
      refute "2026-07-05".match?(Crosscheck::WEEKLY_TAG) # the renamed pre-standard tag form
      refute "v2026.08.23-rc1".match?(Crosscheck::WEEKLY_TAG)
    end
  end

  # validate.rb G4 through the same machinery: recovery, catastrophe, ack, skip.
  class ValidateDeltaGateTest < Minitest::Test
    include DriftTestHelpers

    FakeArtifact = Struct.new(:counts)

    def artifacts(base4: 439_214, vpn: 6_565, dc: 29_064, base6: 126_073)
      { ipv4: FakeArtifact.new({ base: base4, vpn: vpn, dc: dc, relay: 0 }),
        ipv6: FakeArtifact.new({ base: base6, vpn: 0, dc: 0, relay: 0 }) }
    end

    def counts(base4: 439_199, vpn: 6_565, dc: 29_070, base6: 126_053)
      { "base_ipv4" => base4, "vpn_ipv4" => vpn, "dc_ipv4" => dc, "base_ipv6" => base6 }
    end

    def test_normal_night_passes_and_logs_every_layer
      Validate.check_deltas!(artifacts, { "layer_counts" => counts }, [pin("v2026.08.23", { "layer_counts" => counts })])
      assert_equal 4, log.scan(/G4: drift PASS/).size
      assert_match(/G4: deltas gate done, 4\/4 layers within ±5% of previous build \(base_ipv4 439199→439214, vpn_ipv4 6565→6565, dc_ipv4 29070→29064, base_ipv6 126053→126073\)/, log)
      assert_empty DriftGate.events
    end

    def test_deadlock_shape_recovers_via_the_weekly_pin
      degraded = { "layer_counts" => counts(dc: 20_000) } # a -31% dc overlay night that got published
      Validate.check_deltas!(artifacts, degraded, [pin("v2026.08.23", { "layer_counts" => counts })])
      assert_equal [:recovery], DriftGate.events.map(&:status)
      assert_match(/G4: drift RECOVERY dc_ipv4: 20000 -> 29064 \(\+45\.3% vs previous build\); within -0\.0% of weekly pin v2026\.08\.23 \(29070\)/, log)
      assert_match(/dc_ipv4 20000→29064 \[RECOVERY\]/, log)
    end

    def test_catastrophe_fails_and_ack_rescues_with_a_stamp
      err = assert_raises(StageFailure) do
        Validate.check_deltas!(artifacts(base4: 200_000), { "layer_counts" => counts }, [pin("v2026.08.23", { "layer_counts" => counts })])
      end
      assert_match(/G4: drift FAIL base_ipv4: 439199 -> 200000 \(-54\.5% vs previous build\)/, err.message)

      DriftGate.reset!
      ENV[DriftGate::ACK_ENV] = "sapics rebuilt the v4 table, verified"
      Validate.check_deltas!(artifacts(base4: 200_000), { "layer_counts" => counts }, [])
      assert_equal "sapics rebuilt the v4 table, verified", DriftGate.manifest_stamp[:drift_ack][:reason]
      assert_match(/\Abase_ipv4: 439199 -> 200000/, DriftGate.manifest_stamp[:drift_ack][:gates].first)
    ensure
      ENV.delete(DriftGate::ACK_ENV)
    end

    def test_skip_paths
      Validate.check_deltas!(artifacts, nil, [])
      assert_match(/G4: no previous build stats and no weekly pin - delta gate skipped/, log)
      # No previous build, but a pin: the pin stands in.
      Validate.check_deltas!(artifacts, nil, [pin("v2026.08.23", { "layer_counts" => counts })])
      assert_match(/G4: drift PASS base_ipv4: 439199 -> 439214 \(\+0\.0% vs weekly pin v2026\.08\.23\)/, log)
      # A layer new since the previous build is SKIP for that layer only, never a division by zero.
      Validate.check_deltas!(artifacts, { "layer_counts" => counts.merge("base_ipv6" => 0) }, [])
      assert_match(/G4: drift SKIP base_ipv6/, log)
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
