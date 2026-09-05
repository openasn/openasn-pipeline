# frozen_string_literal: true

# Baseline-aware, asymmetric, operator-ackable drift gates. Shared by
# crosscheck.rb (hosting-ASN count) and validate.rb (G4 layer counts), so
# both gates have one policy, one log format, one unblock procedure.
#
# INCIDENT 2026-08-24 -> 2026-09-05 (why this file exists)
#
#   The original gates compared each night ONLY against the previous
#   PUBLISHED manifest, with one symmetric threshold pair (warn 5%, fail 30%).
#   On 2026-08-24 ipverse's hosting-ASN count fell 12,393 -> 9,342 (-24.6%):
#   inside the 30% line, so it only WARNED and the degraded build was
#   published as `latest`. On 2026-08-25 upstream recovered to 12,442, which
#   is +33.2% against the degraded 9,342 -> FAIL. A failed build publishes
#   nothing, so every following night compared against the same 9,342 and
#   failed identically: a deadlock with no self-heal, 12 nights long, while
#   production served data in which ~3,000 hosting ASNs had lost their
#   label (they classify `unknown`, rule `no_category`).
#
#   Two defects, two fixes:
#   1. NO LONG-RUN BASELINE. The weekly dated pins (vYYYY.MM.DD releases)
#      are frozen, tag-addressed, and survive a deadlock untouched (nothing
#      publishes during one). A move that fails against the previous night
#      but lands within RECOVERY_BAND of a weekly pin is a RECOVERY: the
#      previous build was the anomaly. Logged loudly, stamped into the
#      manifest (stats.drift_recovery), and PASSED. Two pins are consulted
#      so a drop that got pinned on a Sunday still has a healthy reference.
#   2. NO OPERATOR PATH. OPENASN_ACK_DRIFT="<reason>" turns a drift FAIL into
#      a loud WARN for that run only, and the reason is stamped into
#      manifest.json (stats.drift_ack) so the unblock is auditable forever.
#      The nightly workflow exposes it as the `ack_drift` dispatch input.
#
# THRESHOLD POLICY (asymmetric, evidence 2026-09-05)
#
#   Observed variance of the hosting count: weekly pins 12,256 (07-05) ->
#   12,316 (07-12) -> 12,363 (08-09) -> 12,377 (08-16) -> 12,393 (08-23):
#   at most +0.5% per week; the nightly series (CI logs) moves well under 1%
#   per night. Any overnight move of 5% is therefore already >10x noise,
#   and the only >5% move ever observed was a defect.
#
#   DROPS fail at 10%. Hosting labels vanishing is exactly the failure this
#   project's crosscheck exists for ("the D8 tripwire": a classifier input
#   goes missing upstream and a slice of ASNs silently turns `unknown`). A
#   -24.6% drop shipped under the old 30% line; 10% catches it with margin
#   and is still 20x the observed noise. Note the reference-coverage gate
#   stayed at 91.1% throughout the incident - the lost labels were long-tail
#   ASNs outside the X4B/bad-asn reference set - so the COUNT is the only
#   signal for that tail.
#   RISES fail at 20%. A rise means non-hosting ASNs became `hosting`, which
#   can turn real eyeballs into blocked traffic - bad, but no upstream
#   mechanism produces it by accident (a missing input yields blanks, not
#   labels), the spot panel independently guards the big eyeballs, and the
#   recovery rule means a legitimate snap-back to baseline never trips it.
#   Both directions WARN above 5%.
#   A false FAIL costs one lost night plus a one-command ack; a false PASS
#   cost twelve days of degraded production data. The lines lean strict.
#
#   SLOW SLIDES are the blind spot every night-vs-night threshold shares: a
#   move small enough to clear the warn line each night accumulates freely,
#   and 4%/night for a week is the same -25% that, in one step, is the
#   2026-08-24 defect. So every evaluation ALSO measures the total distance
#   from the best value the weekly pins have seen, and warns loudly (status
#   :warn, `slide` set) when that exceeds the drop line. Warn, not fail, on
#   purpose - see check_slide for why a fail there would mint a new deadlock.
#
#   The same machinery guards G4 (per-layer artifact record counts), which
#   had the identical deadlock shape; its founding +-20% lines are kept
#   (layer counts move ~0.2%/week) and it gains the WARN tier, the weekly
#   baseline recovery, and the ack path.
#
# LOG ENGAGEMENT: every evaluation logs exactly one line beginning with
# "drift <STATUS> <metric>:" carrying the numbers and the thresholds, so a
# green CI log always answers "did this gate run, and against what?".

require_relative "env"

module OpenASNPipeline
  module DriftGate
    ACK_ENV = "OPENASN_ACK_DRIFT"

    # Per-metric policy. Fractions of the previous value. `warn` applies in
    # both directions; `fail_drop` / `fail_rise` are direction-specific;
    # `recovery_band` is the +-band around a weekly-pin baseline inside
    # which a would-be FAIL is reclassified as a recovery.
    Policy = Struct.new(:warn, :fail_drop, :fail_rise, :recovery_band, keyword_init: true) do
      def fail_for(drift) = drift.negative? ? fail_drop : fail_rise

      def describe
        format("warn>%.0f%%, fail: drop>%.0f%% rise>%.0f%%, recovery band +-%.0f%% of a weekly pin",
               warn * 100, fail_drop * 100, fail_rise * 100, recovery_band * 100)
      end
    end

    HOSTING_POLICY = Policy.new(warn: 0.05, fail_drop: 0.10, fail_rise: 0.20, recovery_band: 0.05).freeze
    LAYER_POLICY   = Policy.new(warn: 0.05, fail_drop: 0.20, fail_rise: 0.20, recovery_band: 0.05).freeze

    # A long-run reference point: label is human-facing (the weekly pin tag),
    # value is the metric at that pin (nil when the pin lacks the metric).
    Baseline = Struct.new(:label, :value, keyword_init: true)

    # What one evaluation concluded. `status` is one of
    #   :skipped  - nothing to compare against (first build ever)
    #   :pass     - |drift| <= policy.warn
    #   :warn     - inside the fail line for its direction
    #   :recovery - beyond the fail line vs `prev`, but within recovery_band
    #               of `baseline` (so `prev` was the anomaly): gate PASSES
    #   :acked    - beyond the fail line, operator ack present: gate PASSES
    #   :fail     - beyond the fail line, no rescue: gate FAILS the build
    # `slide` marks the boiled-frog case: night-over-night was fine, but the
    # value has drifted more than the drop line below the best weekly pin.
    Result = Struct.new(:metric, :status, :now, :prev, :prev_label, :drift, :baseline,
                        :baseline_drift, :slide, :ack, :policy, keyword_init: true) do
      def blocking? = status == :fail

      # One-line, number-bearing account of the comparison - used verbatim
      # in logs, failure messages, and manifest stamps.
      def summary
        return "#{metric}: no previous build stats and no weekly pin - nothing to compare" if status == :skipped

        s = format("%s: %d -> %d (%s vs %s)", metric, prev, now, pct(drift), prev_label)
        if slide
          s += format("; but %s from the best weekly pin %s (%d) - a SLOW SLIDE no single night tripped",
                      pct(baseline_drift), baseline.label, baseline.value)
        elsif baseline
          s += format("; within %s of weekly pin %s (%d)", pct(baseline_drift), baseline.label, baseline.value)
        end
        s += %( - acknowledged: "#{ack}") if status == :acked
        s
      end

      def pct(f) = format("%+.1f%%", f * 100)
    end

    module_function

    # Pure: no logging, no raising, no state. `prev` is the previous
    # published build's value (nil if none), `baselines` the weekly pins
    # (most recent first). When `prev` is nil the most recent baseline
    # stands in for it - a missing `latest` asset must not disarm the gate
    # while pins exist.
    def evaluate(metric:, now:, prev:, baselines: [], policy:, ack: ENV[ACK_ENV])
      # A metric the build did not produce is ZERO, not nil: a layer that
      # vanishes must read as a -100% FAIL, never crash the gate with a
      # NoMethodError (which CI would report as "the pipeline broke", not
      # "the data broke" - a very different, much slower investigation).
      now = now.to_i
      baselines = baselines.select { |b| b.value.to_i.positive? }
      # The best value the pinned history has seen, kept before `prev`
      # substitution consumes the newest pin. This is the anchor for the
      # slow-slide check below.
      anchor = baselines.max_by(&:value)
      prev_label = "previous build"
      if prev.to_i.zero? && baselines.any?
        prev_label = "weekly pin #{baselines.first.label}"
        prev = baselines.first.value
        baselines = baselines.drop(1)
      end
      return Result.new(metric: metric, status: :skipped, now: now, policy: policy) if prev.to_i.zero?

      drift = (now - prev) / prev.to_f
      result = Result.new(metric: metric, now: now, prev: prev, prev_label: prev_label,
                          drift: drift, policy: policy, ack: normalize_ack(ack))
      result.status =
        if drift.abs <= policy.warn then :pass
        elsif drift.abs <= policy.fail_for(drift) then :warn
        else :fail
        end
      return check_slide(result, anchor) unless result.status == :fail

      # Recovery: the world snapped back to where the pinned history says
      # it belongs, so the PREVIOUS build was the outlier, not this one.
      rescue_by = baselines.find { |b| ((now - b.value) / b.value.to_f).abs <= policy.recovery_band }
      if rescue_by
        result.baseline = rescue_by
        result.baseline_drift = (now - rescue_by.value) / rescue_by.value.to_f
        result.status = :recovery
      elsif result.ack
        result.status = :acked
      end
      result
    end

    # THE BOILED-FROG GUARD. Every night-vs-night threshold shares one blind
    # spot: a slide small enough to clear the warn line each night accumulates
    # without a single night ever tripping. 4% a night for a week is -25% and
    # the gate never says a word - the same -25% that, taken in one step, is
    # the 2026-08-24 defect. The weekly pins are the fix here too: measure the
    # TOTAL distance from the best value the pinned history has seen.
    #
    # Deliberately a WARN, not a FAIL, and this is the one place the "lines
    # lean strict" rule is knowingly not applied. A FAIL here would publish
    # nothing; publishing nothing cuts no new pin; the anchor would therefore
    # never move, and every subsequent night would fail against it - a NEW
    # deadlock of exactly the shape D-GATE-1 exists to forbid. The hard stop
    # for a slide that actually reaches dangerous territory is the absolute
    # floor (crosscheck.rb MIN_HOSTING_ASNS), which does not move and cannot
    # be acked. So: this warns early and loudly, `rake gates:status` reports
    # it as an action item, and the floor is what refuses to build.
    def check_slide(result, anchor)
      return result if anchor.nil? || result.status == :skipped

      slide = (result.now - anchor.value) / anchor.value.to_f
      return result unless slide.negative? && slide.abs > result.policy.fail_drop

      result.baseline = anchor
      result.baseline_drift = slide
      result.slide = true
      result.status = :warn if result.status == :pass
      result
    end

    # Evaluate, log with numbers, record ack/recovery events for the
    # manifest, and raise StageFailure on :fail. Returns the Result.
    def enforce!(metric:, now:, prev:, baselines: [], policy:, ack: ENV[ACK_ENV], gate: nil)
      result = evaluate(metric: metric, now: now, prev: prev, baselines: baselines, policy: policy, ack: ack)
      prefix = gate ? "#{gate}: " : ""
      case result.status
      when :skipped
        Env.log("#{prefix}drift SKIP #{result.summary} (expected on first build)")
      when :pass
        Env.log("#{prefix}drift PASS #{result.summary}; #{policy.describe}")
      when :warn
        if result.slide
          Env.warn("#{prefix}drift WARN(SLIDE) #{result.summary} - the cumulative move is past the " \
                   "#{(policy.fail_for(-1.0) * 100).to_i}% drop line even though no single night was. " \
                   "Investigate upstream NOW: this is how a silent degradation reaches production. " \
                   "The absolute floor is the hard stop, not this warning")
        else
          Env.warn("#{prefix}drift WARN #{result.summary} - beyond the #{(policy.warn * 100).to_i}% warn line; " \
                   "keep an eye on upstream (#{policy.describe})")
        end
      when :recovery
        events << result
        Env.warn("#{prefix}drift RECOVERY #{result.summary} - the move fails the " \
                 "#{(policy.fail_for(result.drift) * 100).to_i}% line against the previous build, but this " \
                 "value sits inside the weekly-pin baseline, so the PREVIOUS build was the anomaly. PASSING; " \
                 "this build supersedes degraded published data (stamped in manifest stats.drift_recovery)")
      when :acked
        events << result
        Env.warn("#{prefix}drift ACKED #{result.summary} - FAIL overridden for this run by " \
                 "#{ACK_ENV}; stamped into manifest stats.drift_ack")
      when :fail
        Env.fail_stage!("#{prefix}drift FAIL #{result.summary} - beyond the " \
                        "#{(policy.fail_for(result.drift) * 100).to_i}% #{result.drift.negative? ? 'drop' : 'rise'} line " \
                        "and not within +-#{(policy.recovery_band * 100).to_i}% of any weekly pin " \
                        "(#{baselines.map { |b| "#{b.label}=#{b.value}" }.join(', ').then { |s| s.empty? ? 'no pins found' : s }}). " \
                        "Investigate upstream; if the new value is genuine, re-run with " \
                        "#{ACK_ENV}=\"<reason>\" (nightly-build.yml dispatch input `ack_drift`) to publish with the reason on record")
      end
      result
    end

    # Ack/recovery events accumulated during this run, in gate order. Read by
    # publish.rb to stamp manifest.json; reset by tests.
    def events = (@events ||= [])
    def reset! = (@events = [])

    # The manifest fragment: present ONLY when something happened, so a
    # normal night's manifest is byte-identical in shape to before.
    def manifest_stamp
      acks = events.select { |e| e.status == :acked }
      recoveries = events.select { |e| e.status == :recovery }
      stamp = {}
      stamp[:drift_ack] = { reason: acks.first.ack, gates: acks.map(&:summary) } if acks.any?
      stamp[:drift_recovery] = recoveries.map(&:summary) if recoveries.any?
      stamp
    end

    # Build Baseline structs from pinned manifests. `pins` are
    # {label:, stats:} pairs (Crosscheck::Pin); the block extracts the metric.
    def baselines_from(pins)
      pins.filter_map do |pin|
        value = yield(pin.stats)
        Baseline.new(label: pin.label, value: value) if value.to_i.positive?
      end
    end

    def normalize_ack(ack)
      s = ack.to_s.strip
      s.empty? ? nil : s
    end
  end
end
