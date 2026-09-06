# frozen_string_literal: true

# Operator tooling: "is the nightly healthy, and what would tonight's gates
# compare against?" — answered WITHOUT building anything.
#
# Why this exists. The 2026-08/09 drift deadlock ran for twelve nights, and
# answering the two questions that would have ended it on night one —
#   * how old is the data `latest` is serving?
#   * what number is the drift gate comparing tonight's build against?
# — required reading CI logs and hand-fetching release assets. Both are two
# HTTP GETs. This makes them one command:
#
#   rake gates:status
#
# It fetches the rolling `latest` manifest and the most recent weekly dated
# pins (tag-addressed URLs only — D-REL-1), prints their ages and metrics,
# restates the live thresholds, and then answers the operational question
# directly: if tonight's value matched the newest healthy pin, would the
# gate PASS, RECOVER, or FAIL? A stale `latest` or a pending deadlock is
# visible in the first ten lines of output.
#
# Read-only. Fetches nothing but manifests, writes nothing, never publishes.
# Exit code is 0 for a healthy nightly and 1 when it finds something an
# operator must act on (stale latest, or a deadlock the recovery rule would
# NOT clear), so it can be dropped into a monitor.

require "json"
require "time"
require_relative "../lib/env"
require_relative "../lib/http"
require_relative "../lib/drift_gate"
require_relative "../crosscheck"
# run.rb owns the release-URL contract (OPENASN_RELEASE_URL / _ROOT); requiring
# it keeps one source of truth. It is guarded and runs nothing on require.
require_relative "../run"

module OpenASNPipeline
  module GatesStatus
    module_function

    def call(out: $stdout)
      problems = []
      out.puts "OpenASN gate status — #{Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')}"
      out.puts "repo: #{PUBLISH_REPO}"
      out.puts

      # Fetch and report in order, so the pin-discovery log lines land after
      # the `latest` block rather than on top of it.
      latest = Crosscheck.fetch_manifest("#{Run.release_base_url}manifest.json", "latest")
      problems.concat(report_latest(latest, out))
      out.puts
      pins = Crosscheck.baseline_stats(Run.release_root_url)
      report_pins(pins, out)
      out.puts
      report_policy(out)
      out.puts
      problems.concat(report_forecast(latest, pins, out))

      out.puts
      if problems.empty?
        out.puts "OK — nothing needs an operator."
      else
        out.puts "ACTION NEEDED:"
        problems.each { |p| out.puts "  * #{p}" }
      end
      problems.empty?
    end

    # The rolling `latest` release: what production is actually serving.
    def report_latest(latest, out)
      unless latest
        out.puts "latest: NOT AVAILABLE — no rolling release could be fetched."
        return ["`latest` release is unreachable: consumers have no data source."]
      end

      build_id = latest["build_id"]
      age_h = age_hours(build_id)
      out.puts "latest: build #{build_id}#{age_h ? format(' (%.1fh / %.1f days old)', age_h, age_h / 24) : ''}"
      stats = latest["stats"] || {}
      out.puts "  hosting_asns: #{stats['hosting_asns'] || '?'}   reference_coverage: #{stats['reference_coverage'] || '?'}"
      out.puts "  layer_counts: #{(stats['layer_counts'] || {}).map { |k, v| "#{k}=#{v}" }.join(' ')}"
      out.puts "  drift_ack: #{stats['drift_ack'].to_json}" if stats["drift_ack"]
      out.puts "  drift_recovery: #{stats['drift_recovery'].to_json}" if stats["drift_recovery"]

      return [] unless age_h && age_h > Crosscheck::STALE_LATEST_HOURS

      [format("`latest` is %.1f days old (> %dh): the nightly has not published since %s. " \
              "Check the open pipeline-failure issue and the gate lines in the last run.",
              age_h / 24, Crosscheck::STALE_LATEST_HOURS, build_id)]
    end

    # The weekly dated pins: the drift gate's frozen long-run baseline.
    def report_pins(pins, out)
      if pins.empty?
        out.puts "weekly pins: NONE FOUND — the recovery rule is disarmed (a deadlock could not self-heal)."
        return
      end
      out.puts "weekly pins (drift baseline, newest first):"
      pins.each do |pin|
        stats = pin.stats
        out.puts format("  %-14s build %-22s hosting=%-7s %s", pin.label, pin.build_id || "?",
                        stats["hosting_asns"] || "?",
                        (stats["layer_counts"] || {}).map { |k, v| "#{k}=#{v}" }.join(" "))
      end
    end

    def report_policy(out)
      out.puts "policy:"
      out.puts "  hosting_asns  #{DriftGate::HOSTING_POLICY.describe}"
      out.puts "  layer counts  #{DriftGate::LAYER_POLICY.describe}"
      out.puts "  absolute floor: hosting_asns >= #{Crosscheck::MIN_HOSTING_ASNS} (NOT ackable)"
      out.puts "  reference coverage floor: #{(Crosscheck::MIN_REFERENCE_COVERAGE * 100).to_i}%"
      ack = DriftGate.normalize_ack(ENV[DriftGate::ACK_ENV])
      out.puts "  #{DriftGate::ACK_ENV}: #{ack ? "SET — #{ack.inspect}" : 'not set (normal)'}"
    end

    # The two questions an operator actually has:
    #
    #   1. If upstream is healthy tonight, can the build publish? Simulated
    #      TWICE — day-over-day only (what the pre-2026-09-05 gate did, and
    #      what we fall back to when no pin is reachable) and with the weekly
    #      pins. A deadlock shows up as "would FAIL alone / RECOVERY with
    #      pins", which is exactly the state this tool exists to name.
    #   2. Is the data `latest` is serving right now still buildable — i.e.
    #      does it clear today's absolute floor? A published build below the
    #      floor means production is degraded even though nothing is failing.
    def report_forecast(latest, pins, out)
      prev = latest && latest.dig("stats", "hosting_asns")
      problems = []
      unless prev
        out.puts "forecast: no published `latest` hosting count — tonight's drift gate would SKIP."
        return problems
      end

      healthy = pins.map { |p| p.stats["hosting_asns"] }.compact.max
      if healthy.nil?
        problems.concat(check_published_floor(prev, nil, out))
        out.puts "forecast: no weekly pin reachable — the recovery rule is DISARMED this run."
        return problems << "No weekly dated pin is reachable, so the drift gate has no frozen baseline and a bad " \
                           "night could deadlock again. Check `gh release list` / cut a pin (run the nightly " \
                           "workflow with dated_tag=true)."
      end

      simulate = lambda do |baselines|
        DriftGate.evaluate(metric: "hosting_asns", now: healthy, prev: prev, baselines: baselines,
                           policy: DriftGate::HOSTING_POLICY, ack: nil)
      end
      pin_baselines = DriftGate.baselines_from(pins) { |s| s["hosting_asns"] }
      bare = simulate.call([])
      with = simulate.call(pin_baselines)

      # Is the CURRENTLY PUBLISHED value itself sliding away from the pins?
      # (`now: prev` - we are grading latest, not a hypothetical tonight.)
      published = DriftGate.evaluate(metric: "hosting_asns", now: prev, prev: prev,
                                     baselines: pin_baselines, policy: DriftGate::HOSTING_POLICY, ack: nil)
      if published.slide
        problems << "SLOW SLIDE: the published hosting count is #{format('%+.1f%%', published.baseline_drift * 100)} " \
                    "from the best weekly pin #{published.baseline.label} (#{published.baseline.value}) — a " \
                    "cumulative degradation no single night tripped. Check upstream before it reaches the floor."
      end

      out.puts "forecast: a healthy upstream tonight (hosting=#{healthy}) vs latest (#{prev}):"
      out.puts "  day-over-day only: #{bare.status.to_s.upcase} — #{bare.summary}"
      out.puts "  with weekly pins:  #{with.status.to_s.upcase} — #{with.summary}"
      if bare.blocking? && with.status == :recovery
        out.puts "  DEADLOCK DETECTED, and the recovery rule clears it automatically on the next run."
        out.puts "  (before 2026-09-05 this state was unrecoverable without a human editing the pipeline)"
      end
      problems.concat(check_published_floor(prev, healthy, out))
    end

    # Is the data production is serving right now still buildable? A
    # published count under today's floor means consumers are being served a
    # build that could not pass the gates — degraded, but silently so,
    # because nothing is failing on the degraded side of a deadlock.
    def check_published_floor(published, healthy, out)
      floor = Crosscheck::MIN_HOSTING_ASNS
      return [] if published >= floor

      # Report the gap to a KNOWN-GOOD value (the newest healthy pin) rather
      # than to the floor, but state it as what it is: a shortfall in an
      # upstream METRIC. It is not a count of degraded verdicts — most
      # hosting-category ASNs have no routed IPv4 presence, so the
      # consumer-visible damage is typically far smaller (2026-08-24:
      # -24.6% on this metric, ~-2.8% on hosting verdicts in the artifact).
      # Overstating this in an alert teaches operators to discount alerts.
      gap = healthy ? healthy - published : nil
      out.puts "  the published hosting count (#{published}) is BELOW today's floor (#{floor}) — " \
               "consumers are on a build that could not pass the gates."
      [format("Production is serving degraded data: `latest` has %d hosting ASNs, under the %d floor%s. " \
              "Getting a green build published is urgent, not routine. (This is the upstream metric, " \
              "not a verdict count — measure the artifacts before quoting user impact.)",
              published, floor,
              gap ? format(" and %d short of the last healthy build (%d)", gap, healthy) : "")]
    end

    def age_hours(build_id, now: Time.now.utc)
      build_id && (now - Time.parse(build_id)) / 3600.0
    rescue ArgumentError
      nil
    end
  end
end

OpenASNPipeline::GatesStatus.call || exit(1) if $PROGRAM_NAME == __FILE__
