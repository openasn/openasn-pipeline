# frozen_string_literal: true

# Stage 3: paranoia gates over ipverse as-metadata's categorization (PRD D8).
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

require "set"
require_relative "lib/env"
require_relative "lib/http"

module OpenASNPipeline
  module Crosscheck
    # Reference-coverage floor: fraction of {X4B dc ∪ bad-asn} ASNs that
    # as-metadata must label `hosting`. Measured 2026-07-04 on live data:
    # 91.3% (899-ASN reference set). Floor set at 0.60: low enough to
    # tolerate reference-list churn, high enough that "categories are
    # gone/garbage" cannot pass.
    MIN_REFERENCE_COVERAGE = 0.60

    # Absolute count floor for hosting-category ASNs (measured 2026-07-04:
    # 12,257). A drop below 8,000 (~-35%) means the category field broke.
    MIN_HOSTING_ASNS = 8_000

    # Day-over-day drift alarm (compares against the previous published
    # manifest's stats): warn above WARN, fail above FAIL.
    HOSTING_DRIFT_WARN = 0.05
    HOSTING_DRIFT_FAIL = 0.30

    module_function

    def run(normalized, previous_stats: nil)
      meta = normalized[:asn_meta]
      hosting = meta.each_pair.select { |_, r| r.category == "hosting" }.map(&:first).to_set
      reference = normalized[:x4b_dc_asns] | normalized[:bad_asns]

      coverage = (reference & hosting).size / reference.size.to_f
      Env.log(format("crosscheck: as-metadata hosting=%d ASNs; reference dc set=%d; coverage=%.1f%%",
                     hosting.size, reference.size, coverage * 100))

      if hosting.size < MIN_HOSTING_ASNS
        Env.fail_stage!("as-metadata hosting count #{hosting.size} < floor #{MIN_HOSTING_ASNS} - " \
                        "category field likely broken upstream (PRD D8 tripwire)")
      end
      if coverage < MIN_REFERENCE_COVERAGE
        Env.fail_stage!(format("as-metadata covers only %.1f%% of the X4B∪bad-asn reference dc set " \
                               "(floor %.0f%%) - categorization quality collapsed", coverage * 100,
                               MIN_REFERENCE_COVERAGE * 100))
      end

      if previous_stats && previous_stats["hosting_asns"]
        prev = previous_stats["hosting_asns"].to_f
        drift = (hosting.size - prev).abs / prev
        if drift > HOSTING_DRIFT_FAIL
          Env.fail_stage!(format("hosting ASN count moved %.1f%% day-over-day (%d -> %d) - " \
                                 "catastrophic upstream shift", drift * 100, prev, hosting.size))
        elsif drift > HOSTING_DRIFT_WARN
          Env.warn(format("hosting ASN count moved %.1f%% day-over-day (%d -> %d) - keep an eye on ipverse",
                          drift * 100, prev, hosting.size))
        else
          # Log engagement: silence must never be ambiguous between
          # "compared and fine" and "had nothing to compare against".
          Env.log(format("crosscheck: day-over-day drift OK (hosting %d -> %d, %.2f%%)",
                         prev, hosting.size, drift * 100))
        end
      else
        Env.log("crosscheck: no previous stats - drift comparison skipped (expected on first build)")
      end

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
      http = Http.new
      body = http.get!("#{release_base_url}manifest.json")
      JSON.parse(body)["stats"]
    rescue StandardError => e
      gh_fallback = previous_stats_via_gh
      return gh_fallback if gh_fallback

      Env.log("no previous manifest available (#{e.message.lines.first&.strip}) - " \
              "delta gates will be skipped (expected on first build)")
      nil
    end

    def previous_stats_via_gh
      out = IO.popen(["gh", "release", "download", "latest", "--repo", PUBLISH_REPO,
                      "--pattern", "manifest.json", "--output", "-"], err: File::NULL, &:read)
      return nil if out.nil? || out.empty? || !$?.success? # rubocop:disable Style/SpecialGlobalVars

      Env.log("previous manifest fetched via gh (private-repo fallback)")
      JSON.parse(out)["stats"]
    rescue StandardError
      nil
    end
  end
end
