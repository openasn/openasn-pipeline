# frozen_string_literal: true

# Stage 3: paranoia gates over ipverse as-metadata's categorization.
#
# WHY THIS EXISTS: the entire base-layer classification leans on ipverse's
# `category` field, which (a) has only existed since 2026-02-08, (b) comes
# from a single-maintainer project, and (c) is self-described as "useful
# default, not gospel". If it silently degrades - fields renamed, the
# hosting labels vanish, the repo goes stale - we must find out in CI, not
# from a user issue three weeks later.
#
# Reference set: the union of X4BNet's hand-curated datacenter ASN inputs
# and brianhama/bad-asn-list - two INDEPENDENT first-party curations of
# "definitely hosting/datacenter" ASNs. We measure how much of that
# reference as-metadata's hosting category covers.
#
# Baseline measured 2026-07-04 on live data: see the constants below, which
# were set from that measurement with alarm margin. Update them consciously,
# in a reviewed PR, if the upstream reality shifts.
#
# DRIFT GATE (rewritten 2026-09-05 after the 12-night deadlock; full
# write-up in lib/drift_gate.rb and data-repo DECISIONS.md D-GATE-1):
#   * compares against the previous published build AND the two most
#     recent weekly pins (vYYYY.MM.DD releases, tag-addressed URLs only);
#   * asymmetric lines: drop >10% fails, rise >20% fails, both warn >5%;
#   * a move that fails vs the previous build but sits within +-5% of a
#     weekly pin is a RECOVERY (the previous build was the anomaly): PASS;
#   * OPENASN_ACK_DRIFT="<reason>" downgrades a FAIL to WARN for one run and
#     stamps the reason into manifest.json (stats.drift_ack).
# LESSON from the incident: the reference-coverage gate stayed at 91.1%
# while 3,051 hosting labels vanished - the lost ASNs were long-tail, not in
# the X4B/bad-asn reference. The absolute COUNT is the only tripwire for
# that tail, which is why the count floor and the drop line are strict.

require "set"
require "date"
require_relative "lib/env"
require_relative "lib/http"
require_relative "lib/drift_gate"

module OpenASNPipeline
  module Crosscheck
    # Reference-coverage floor: fraction of {X4B dc ∪ bad-asn} ASNs that
    # as-metadata must label `hosting`. Measured 2026-07-04 on live data:
    # 91.3% (899-ASN reference set). Floor set at 0.60: low enough to
    # tolerate reference-list churn, high enough that "categories are
    # gone/garbage" cannot pass.
    MIN_REFERENCE_COVERAGE = 0.60

    # Absolute count floor for hosting-category ASNs. Measured 12,257 on
    # 2026-07-04 and 12,442 on 2026-09-05; every observation since the field
    # existed sits in 12.2k-12.5k. Raised 8,000 -> 10,000 on 2026-09-05: the
    # 2026-08-24 defect (9,342, -24.6%) cleared the old floor, and this
    # floor is the ONLY guard on a night with no previous manifest and no
    # pins. A build below it means >19% of the hosting labels are gone
    # relative to every known-good state; that is never a same-night
    # legitimate change. If upstream ever consolidates for real, bump this
    # in a reviewed PR with the evidence (this floor is deliberately NOT
    # ackable via OPENASN_ACK_DRIFT).
    MIN_HOSTING_ASNS = 10_000

    # Day-over-day drift policy: see DriftGate::HOSTING_POLICY (warn 5%,
    # fail on drop >10% / rise >20%, recovery within 5% of a weekly pin).
    HOSTING_POLICY = DriftGate::HOSTING_POLICY

    # Weekly dated pins to consult as the long-run baseline. Two, so a drop
    # that itself got pinned on a Sunday still leaves a healthy reference.
    WEEKLY_TAG    = /\Av\d{4}\.\d{2}\.\d{2}\z/
    BASELINE_PINS = 2

    # If the previous published manifest is older than this at build start,
    # the nightly has been failing (or the schedule is dead): say so in the
    # log, in hours, so the age is visible on the very first green run.
    STALE_LATEST_HOURS = 48

    # A pinned manifest's stats plus its human label (the release tag) and
    # the build it froze.
    Pin = Struct.new(:label, :stats, :build_id, keyword_init: true)

    module_function

    def run(normalized, previous_stats: nil, baseline_stats: [])
      meta = normalized[:asn_meta]
      hosting = meta.each_pair.select { |_, r| r.category == "hosting" }.map(&:first).to_set
      reference = normalized[:x4b_dc_asns] | normalized[:bad_asns]

      coverage = (reference & hosting).size / reference.size.to_f
      Env.log(format("crosscheck: as-metadata hosting=%d ASNs; reference dc set=%d; coverage=%.1f%%",
                     hosting.size, reference.size, coverage * 100))

      if hosting.size < MIN_HOSTING_ASNS
        Env.fail_stage!("as-metadata hosting count #{hosting.size} < floor #{MIN_HOSTING_ASNS} - " \
                        "category field likely broken upstream (see this file header: the D8 tripwire)")
      end
      if coverage < MIN_REFERENCE_COVERAGE
        Env.fail_stage!(format("as-metadata covers only %.1f%% of the X4B∪bad-asn reference dc set " \
                               "(floor %.0f%%) - categorization quality collapsed", coverage * 100,
                               MIN_REFERENCE_COVERAGE * 100))
      end

      DriftGate.enforce!(
        gate: "crosscheck",
        metric: "hosting_asns",
        now: hosting.size,
        prev: previous_stats && previous_stats["hosting_asns"],
        baselines: DriftGate.baselines_from(baseline_stats) { |s| s["hosting_asns"] },
        policy: HOSTING_POLICY
      )

      # Uncovered reference ASNs are exactly the candidates for
      # data/overrides/hosting_extra.txt - write them out for curators.
      uncovered = (reference - hosting).to_a.sort
      report = File.join(WORK_DIR, "crosscheck-uncovered-dc-asns.txt")
      FileUtils.mkdir_p(WORK_DIR)
      File.write(report, uncovered.map { |a| "AS#{a}" }.join("\n") + "\n")
      Env.log("crosscheck: #{uncovered.size} reference dc ASNs NOT hosting-categorized " \
              "(curation candidates -> #{report})")

      { hosting_asns: hosting.size, reference_dc_asns: reference.size,
        reference_coverage: coverage.round(4) }
    end

    # The previous build's stats come from the previous published manifest -
    # the release asset is the only state that survives between CI runs.
    # Plain HTTP works once the data repo is public; while it's private
    # (pre-launch incubation) we fall back to an authenticated `gh` download
    # so the delta gates are armed from day one, not from launch day.
    def previous_stats(release_base_url)
      manifest = fetch_manifest("#{release_base_url}manifest.json", "latest")
      unless manifest
        Env.log("no previous manifest available - delta gates fall back to the weekly pins " \
                "(or are skipped on a first build)")
        return nil
      end
      check_latest_freshness(manifest["build_id"])
      manifest["stats"]
    end

    # Stale-latest tripwire. A rolling release whose build is days old means
    # nights have been failing (or the cron died); log the age loudly so the
    # first green run after an outage records how long it lasted.
    def check_latest_freshness(build_id, now: Time.now.utc)
      return unless build_id

      age_h = (now - Time.parse(build_id)) / 3600.0
      if age_h > STALE_LATEST_HOURS
        Env.warn(format("STALE LATEST: previous published build %s is %.1f days old (%.0fh > %dh) - " \
                        "the nightly has not published recently; check the pipeline-failure issue",
                        build_id, age_h / 24, age_h, STALE_LATEST_HOURS))
      else
        Env.log(format("previous published build %s (%.1fh old)", build_id, age_h))
      end
      age_h
    rescue ArgumentError
      Env.warn("previous manifest build_id #{build_id.inspect} is not a timestamp - freshness unknown")
      nil
    end

    # Weekly pins as Pin structs, most recent first. Discovery goes through
    # `gh release list` (authenticated, works while the repo is private);
    # downloads use the TAG-addressed URL form only (D-REL-1). If gh is
    # missing, fall back to probing the last few Sundays' tags directly -
    # pins are cut on Sundays by nightly-build.yml. Never the Latest badge.
    def baseline_stats(release_root_url)
      tags = weekly_pin_tags
      tags = recent_sunday_tags if tags.empty?
      pins = []
      tags.each do |tag|
        break if pins.size >= BASELINE_PINS

        manifest = fetch_manifest("#{release_root_url}#{tag}/manifest.json", tag, quiet: true)
        next unless manifest && manifest["stats"]

        pins << Pin.new(label: tag, stats: manifest["stats"], build_id: manifest["build_id"])
      end
      if pins.empty?
        Env.log("weekly baseline: no dated pins found - recovery rule disarmed this run " \
                "(#{tags.empty? ? 'no tags discovered' : "tried #{tags.first(BASELINE_PINS + 2).join(', ')}"})")
      else
        Env.log("weekly baseline: #{pins.map { |p| "#{p.label} (build #{p.build_id || '?'}, hosting #{p.stats['hosting_asns']})" }.join('; ')}")
      end
      pins
    end

    def weekly_pin_tags
      out = IO.popen(["gh", "release", "list", "--repo", PUBLISH_REPO, "--limit", "200",
                      "--json", "tagName", "--jq", ".[].tagName"], err: File::NULL, &:read)
      return [] if out.nil? || !$?.success? # rubocop:disable Style/SpecialGlobalVars

      # vYYYY.MM.DD sorts lexicographically == chronologically (D-IMPL-NAMING).
      out.split.grep(WEEKLY_TAG).sort.reverse
    rescue StandardError
      []
    end

    # Last 8 Sundays (UTC) as candidate tags, newest first.
    def recent_sunday_tags(today: Time.now.utc)
      date = today.to_date
      date -= 1 until date.sunday?
      Array.new(8) { |i| (date - (7 * i)).strftime("v%Y.%m.%d") }
    end

    # Fetch + parse a manifest by tag-addressed URL, with the `gh release
    # download` fallback for a private repo. nil (never raises) on any miss.
    def fetch_manifest(url, tag, quiet: false)
      http = Http.new
      JSON.parse(http.get!(url))
    rescue StandardError => e
      via_gh = manifest_via_gh(tag)
      return via_gh if via_gh

      Env.log("manifest for #{tag} unavailable (#{e.message.lines.first&.strip})") unless quiet
      nil
    end

    def manifest_via_gh(tag)
      out = IO.popen(["gh", "release", "download", tag, "--repo", PUBLISH_REPO,
                      "--pattern", "manifest.json", "--output", "-"], err: File::NULL, &:read)
      return nil if out.nil? || out.empty? || !$?.success? # rubocop:disable Style/SpecialGlobalVars

      Env.log("manifest for #{tag} fetched via gh (private-repo fallback)")
      JSON.parse(out)
    rescue StandardError
      nil
    end
  end
end
