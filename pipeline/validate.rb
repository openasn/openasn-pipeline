# frozen_string_literal: true

# Stage 5: validation gates. A build that reaches publish.rb has passed ALL
# of these; there is no "publish with warnings" path for gate failures.
#
#   G1. Artifact structure round-trip: reparse both .bin files, verify
#       header counts match byte sizes exactly and layers are sorted.
#   G2. Record re-find: for a sample of base records, binary search over the
#       packed artifact returns exactly that record (search-correctness
#       against the same bytes users will download).
#   G3. Size sanity: ipv4 within 2-20MB (PRD acceptance), ipv6 within
#       1-40MB.
#   G4. Layer-count deltas vs the previous published build within ±20%
#       (skipped with a log line on the first build ever).
#   G5. Spot-check panel (spotchecks.yml) passes 100%. The panel is a
#       tripwire, not gospel: update expectations only via reviewed PR with
#       a reason (routing changes happen - e.g. an IP moving providers).

require "yaml"
require "ipaddr"
require_relative "lib/env"
require_relative "lib/binary"
require_relative "lib/classifier"
require_relative "lib/orgs"

module OpenASNPipeline
  module Validate


    SIZE_BOUNDS = {
      ipv4: (2_000_000..20_000_000),
      ipv6: (1_000_000..40_000_000)
    }.freeze

    DELTA_TOLERANCE = 0.20
    REFIND_SAMPLES  = 2_000

    module_function

    def run(compiled, previous_stats: nil)
      artifacts = {
        ipv4: Binary::Artifact.new(compiled[:v4_path]),
        ipv6: Binary::Artifact.new(compiled[:v6_path])
      }

      artifacts.each do |family, artifact|
        check_size!(family, compiled)
        check_refind!(family, artifact, compiled)
      end
      check_deltas!(artifacts, previous_stats)
      run_spotchecks!(artifacts)
      check_orgs!(compiled)

      Env.log("validate: all gates green")
      artifacts
    end

    # G6: the orgs sidecar must resolve well-known ASNs to plausible names.
    def check_orgs!(compiled)
      path = compiled[:orgs_path]
      Env.fail_stage!("G6: orgs artifact missing") unless path && File.exist?(path)

      { 15_169 => /google/i, 13_335 => /cloudflare/i, 3352 => /telefonica/i }.each do |asn, pattern|
        name = Orgs.read(path, asn)
        next if name&.match?(pattern)

        Env.fail_stage!("G6: orgs lookup for AS#{asn} returned #{name.inspect}, expected #{pattern.inspect}")
      end
    end

    def check_size!(family, compiled)
      path = compiled[family == :ipv4 ? :v4_path : :v6_path]
      size = File.size(path)
      bounds = SIZE_BOUNDS[family]
      return if bounds.cover?(size)

      Env.fail_stage!("G3: #{File.basename(path)} is #{size} bytes, outside sanity bounds #{bounds}")
    end

    # G1 is implicit in Binary::Artifact.new (it raises on bad magic, count
    # mismatches, or trailing bytes). G2 samples evenly across the keyspace.
    def check_refind!(family, artifact, compiled)
      rows = compiled[family == :ipv4 ? :base_v4 : :base_v6]
      step = [rows.length / REFIND_SAMPLES, 1].max
      (0...rows.length).step(step) do |i|
        s, e, asn, flags = rows[i]
        # Probe start, end and midpoint - binary-search edge cases live at
        # range boundaries.
        [s, e, s + ((e - s) / 2)].each do |probe|
          found = artifact.find_base(probe)
          next if found == [s, e, asn, flags]

          Env.fail_stage!("G2: re-find mismatch at #{probe} (#{family}): " \
                          "expected #{[s, e, asn, flags].inspect}, got #{found.inspect}")
        end
      end
    end

    def check_deltas!(artifacts, previous_stats)
      unless previous_stats && previous_stats["layer_counts"]
        Env.log("G4: no previous build stats - delta gate skipped (expected on first build)")
        return
      end

      current = layer_counts(artifacts)
      previous_stats["layer_counts"].each do |layer, prev|
        prev = prev.to_i
        next if prev.zero? # layer introduced after the previous build

        now = current.fetch(layer, 0)
        delta = (now - prev).abs / prev.to_f
        next if delta <= DELTA_TOLERANCE

        Env.fail_stage!(format("G4: layer %s moved %.1f%% (%d -> %d), tolerance ±%.0f%% - " \
                               "either upstream broke or the world changed; investigate before publishing",
                               layer, delta * 100, prev, now, DELTA_TOLERANCE * 100))
      end
    end

    def layer_counts(artifacts)
      {
        "base_ipv4" => artifacts[:ipv4].counts[:base],
        "vpn_ipv4" => artifacts[:ipv4].counts[:vpn],
        "dc_ipv4" => artifacts[:ipv4].counts[:dc],
        "base_ipv6" => artifacts[:ipv6].counts[:base]
      }
    end

    # spotchecks.yml rows: ip / expect / rule (optional) / asn (optional) /
    # note. Tier-B-dependent rows (tor, relay) carry `context: gem` and are
    # asserted in the gem's test suite instead - the canonical artifact
    # cannot see Tier B overlays by design.
    def run_spotchecks!(artifacts)
      panel = YAML.safe_load_file(Env.spotchecks_path)["checks"]
      failures = []

      panel.each do |row|
        next if row["context"] == "gem"

        ip = IPAddr.new(row["ip"])
        artifact = artifacts[ip.ipv4? ? :ipv4 : :ipv6]
        got = Classifier.classify(artifact, ip.to_i)

        failures << "#{row['ip']}: expected #{row['expect']}, got #{got.verdict} (rule=#{got.rule}, asn=#{got.asn.inspect}) — #{row['note']}" if got.verdict.to_s != row["expect"]
        failures << "#{row['ip']}: expected rule #{row['rule']}, got #{got.rule}" if row["rule"] && got.rule.to_s != row["rule"]
        failures << "#{row['ip']}: expected AS#{row['asn']}, got AS#{got.asn.inspect}" if row["asn"] && got.asn != row["asn"]
      end

      if failures.any?
        Env.fail_stage!("G5: spot-check panel failed:\n  - #{failures.join("\n  - ")}\n" \
                        "If routing genuinely changed, update spotchecks.yml in a reviewed PR with the reason.")
      end
      Env.log("G5: spot panel green (#{panel.count { |r| r['context'] != 'gem' }} checks)")
    end
  end
end
