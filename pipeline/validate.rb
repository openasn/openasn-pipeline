# frozen_string_literal: true

# Stage 5: validation gates. A build that reaches publish.rb has passed ALL
# of these; there is no "publish with warnings" path for gate failures.
#
#   G1. Artifact structure round-trip: reparse both .bin files, verify
#       header counts match byte sizes exactly and layers are sorted.
#   G2. Record re-find: for a sample of base records, binary search over the
#       packed artifact returns exactly that record (search-correctness
#       against the same bytes users will download).
#   G3. Size sanity: ipv4 within 2-20MB (founding acceptance bound), ipv6 within
#       1-40MB.
#   G4. Layer-count deltas vs the previous published build within ±20%
#       (warn above 5%). Baseline-aware since 2026-09-05: a move that fails
#       vs the previous build but sits within ±5% of a weekly pin passes as
#       a recovery, and OPENASN_ACK_DRIFT="<reason>" downgrades a FAIL to a
#       stamped WARN - the same machinery as the crosscheck drift gate
#       (lib/drift_gate.rb), because G4 had the same deadlock shape.
#       Skipped with a log line on the first build ever.
#   G6. Org-names sidecar: sentinel ASNs resolve, and its entry count is
#       drift-gated (LAYER_POLICY) against the previous build and weekly pins.
#   G7. Per-ASN country (asn-categories.csv): sentinel ASNs carry their
#       curated country, and the count of non-empty countries is drift-gated
#       (LAYER_POLICY) like G6. D-SRC-2 (country).
#   G5. Spot-check panel (spotchecks.yml) passes 100%. The panel is a
#       tripwire, not gospel: update expectations only via reviewed PR with
#       a reason (routing changes happen - e.g. an IP moving providers).

require "yaml"
require "ipaddr"
require_relative "lib/env"
require_relative "lib/binary"
require_relative "lib/classifier"
require_relative "lib/orgs"
require_relative "lib/drift_gate"

module OpenASNPipeline
  module Validate
    SIZE_BOUNDS = {
      ipv4: (2_000_000..20_000_000),
      ipv6: (1_000_000..40_000_000)
    }.freeze

    # G4 policy: the founding ±20% fail lines are kept (layer counts move
    # ~0.2%/week: base_ipv4 433,550 -> 439,199 over Jul 5 - Aug 23 2026);
    # the 5% WARN tier, weekly-pin recovery and ack path are new.
    LAYER_POLICY    = DriftGate::LAYER_POLICY
    DELTA_TOLERANCE = LAYER_POLICY.fail_drop
    REFIND_SAMPLES  = 2_000

    module_function

    def run(compiled, previous_stats: nil, baseline_stats: [])
      artifacts = {
        ipv4: Binary::Artifact.new(compiled[:v4_path]),
        ipv6: Binary::Artifact.new(compiled[:v6_path])
      }

      artifacts.each do |family, artifact|
        check_size!(family, compiled)
        check_refind!(family, artifact, compiled)
      end
      check_deltas!(artifacts, previous_stats, baseline_stats)
      run_spotchecks!(artifacts)
      check_orgs!(compiled, previous_stats, baseline_stats)
      check_countries!(compiled, previous_stats, baseline_stats)

      Env.log("validate: all gates green")
      artifacts
    end

    # G6: the orgs sidecar must resolve well-known ASNs to plausible names,
    # and its entry count is drift-gated like the layer counts (D-GATE-1).
    # Since D-SRC-2 the names are CC0-only (org_names.txt + Wikidata), so the
    # sentinels are ASNs whose names come from our own sourced org_names.txt;
    # a missing sentinel means that file failed to load, not an upstream blip.
    # The Telefonica pattern accepts the accented spelling, which is what the
    # operator itself uses.
    ORG_SENTINELS = { 15_169 => /google/i, 13_335 => /cloudflare/i, 3352 => /telef[oó]nica/i }.freeze

    def check_orgs!(compiled, previous_stats = nil, baseline_stats = [])
      path = compiled[:orgs_path]
      Env.fail_stage!("G6: orgs artifact missing") unless path && File.exist?(path)

      ORG_SENTINELS.each do |asn, pattern|
        name = Orgs.read(path, asn)
        next if name&.match?(pattern)

        Env.fail_stage!("G6: orgs lookup for AS#{asn} returned #{name.inspect}, expected #{pattern.inspect}")
      end

      # A metric the previous manifest does not carry (first build after
      # D-SRC-2) is a SKIP, loudly, inside DriftGate - never a -100% FAIL.
      pins = baseline_stats.select { |p| p.stats["org_names"] }
      DriftGate.enforce!(
        gate: "G6",
        metric: "org_names",
        now: File.binread(path, 16)[8, 4].unpack1("N"),
        prev: previous_stats && previous_stats["org_names"],
        baselines: DriftGate.baselines_from(pins) { |s| s["org_names"] },
        policy: LAYER_POLICY
      )
    end

    # G7: since D-SRC-2 (country) the `country` column is CC0-only
    # (asn_country.txt, then Wikidata). The sentinels come from the
    # hand-curated head of asn_country.txt, so a miss means that file failed
    # to load or lost its head, not an upstream blip. The count is drift-gated
    # like the org names; a metric absent from the previous manifest SKIPs.
    COUNTRY_SENTINELS = { 15_169 => "US", 13_335 => "US", 3352 => "ES" }.freeze

    def check_countries!(compiled, previous_stats = nil, baseline_stats = [])
      countries = compiled[:countries] || {}
      COUNTRY_SENTINELS.each do |asn, cc|
        got = countries.dig(asn, "cc")
        Env.fail_stage!("G7: country for AS#{asn} is #{got.inspect}, expected #{cc.inspect}") unless got == cc
      end

      pins = baseline_stats.select { |p| p.stats["countries"] }
      DriftGate.enforce!(
        gate: "G7",
        metric: "countries",
        now: countries.size,
        prev: previous_stats && previous_stats["countries"],
        baselines: DriftGate.baselines_from(pins) { |s| s["countries"] },
        policy: LAYER_POLICY
      )
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

    # `previous_stats` is the previous published manifest's stats (or nil);
    # `baseline_stats` the weekly pins as Crosscheck::Pin structs. Per layer,
    # DriftGate does the comparison, the log line, the recovery/ack logic
    # and the raise - see lib/drift_gate.rb for the policy and its evidence.
    def check_deltas!(artifacts, previous_stats, baseline_stats = [])
      prev_counts = previous_stats && previous_stats["layer_counts"]
      pins = baseline_stats.select { |p| p.stats["layer_counts"] }
      current = layer_counts(artifacts)

      # Evaluate the UNION of what we build now, what the previous build had,
      # and what the pins have - never just the previous manifest's keys.
      # Otherwise a layer we add later is silently ungated until the next
      # publish, and an empty/degenerate `layer_counts: {}` in the previous
      # manifest turns the whole gate into a no-op that still logs a
      # reassuring line ("0/0 layers"). A layer missing on one side is a
      # SKIP (new layer) or a -100% FAIL (vanished layer), both loud.
      layers = current.keys |
               (prev_counts&.keys || []) |
               pins.flat_map { |p| p.stats["layer_counts"].keys }
      if layers.empty? || (prev_counts.nil? && pins.empty?)
        Env.log("G4: no previous build stats and no weekly pin - delta gate skipped (expected on first build)")
        return
      end

      results = layers.map do |layer|
        DriftGate.enforce!(
          gate: "G4",
          metric: layer,
          now: current[layer], # nil (layer gone) reads as 0 -> -100% FAIL, see DriftGate.evaluate
          prev: prev_counts && prev_counts[layer],
          baselines: DriftGate.baselines_from(pins) { |s| s.dig("layer_counts", layer) },
          policy: LAYER_POLICY
        )
      end
      # Log the PASS too: a silent gate is indistinguishable from a skipped
      # one, which makes "did the delta gate actually run?" unanswerable
      # from a green CI log (cost us a log-archaeology session 2026-07-04).
      summary = results.map { |r| "#{r.metric} #{r.prev || '?'}→#{r.now}#{r.status == :pass ? '' : " [#{r.status.upcase}]"}" }.join(", ")
      Env.log("G4: deltas gate done, #{results.count { |r| r.status == :pass }}/#{results.size} layers within " \
              "±#{(LAYER_POLICY.warn * 100).to_i}% of #{results.first&.prev_label || 'previous build'} (#{summary})")
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
