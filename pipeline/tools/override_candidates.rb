# frozen_string_literal: true

# Curation aid: mine the cached Tier A data for data/overrides/ CANDIDATES.
#
# This tool never writes to data/overrides/ itself - it produces evidence
# files under build/work/candidates/ for a human (or an LLM drafting for a
# human) to review line by line. Every line that graduates into
# data/overrides/ must carry a source comment; the generated files
# pre-format that comment with the evidence found.
#
# Method (the "assisted taxonomy" loop):
#   1. Authoritative seeds: X4BNet's hand-curated input ASN lists (MIT).
#   2. Keyword sweeps over ipverse as-metadata descriptions (CC0) - high
#      recall, deliberately over-broad; the human pass provides precision.
#   3. The crosscheck gap: reference-dc ASNs that as-metadata does not call
#      hosting (candidates for hosting_extra.txt).
# Review discipline: prefer false negatives over false positives. A missed
# VPN ASN degrades recall slightly; a wrongly flagged eyeball ISP hurts
# real users. When in doubt, leave it out (or corrections.yml + :unknown).
#
# Usage: rake overrides:candidates   (needs a warm build/cache)

require "set"
require_relative "../lib/env"
require_relative "../fetch"
require_relative "../normalize"

module OpenASNPipeline
  module OverrideCandidates
    OUT_DIR = File.join(WORK_DIR, "candidates")

    # Keyword sweeps are RECALL tools. Keep patterns specific enough that a
    # human can clear a file in minutes, not hours.
    SWEEPS = {
      "vpn_provider" => /\b(vpn|anonymi[sz]er|proxy network)\b/i,
      "cdn" => /\b(cdn|content delivery|cloudflare|fastly|akamai|edgecast|cachefly|bunnyway|keycdn|cdn77|gcore)\b/i,
      "mobile_carrier" => /\b(mobile|wireless|cellular|telecom.*mobile|movil|3g|4g|5g|lte|umts)\b/i,
      "enterprise_gateway" => /\b(zscaler|iboss|netskope|forcepoint|secure web gateway|swg|menlo security|broadcom.*web)\b/i
    }.freeze

    module_function

    def run
      FileUtils.mkdir_p(OUT_DIR)
      paths = Fetch.run(offline: true)
      normalized = Normalize.run(paths)
      meta = normalized[:asn_meta]

      write_x4b_seed(paths)
      SWEEPS.each { |name, pattern| sweep(name, pattern, meta) }
      write_hosting_gap(normalized, meta)

      Env.log("candidates written to #{OUT_DIR} - review and graduate lines into data/overrides/")
    end

    def write_x4b_seed(paths)
      # X4B input/vpn/ASN.txt is first-party curation (MIT): straight seed.
      lines = File.readlines(paths[:x4b_vpn_asn], chomp: true).filter_map do |line|
        next unless line =~ /\AAS(\d+)\s*#?\s*(.*)\z/

        "AS#{$1}  # #{$2.strip} — src: https://raw.githubusercontent.com/X4BNet/lists_vpn/main/input/vpn/ASN.txt"
      end
      File.write(File.join(OUT_DIR, "vpn_provider.from-x4b.txt"), lines.join("\n") + "\n")
    end

    def sweep(name, pattern, meta)
      hits = meta.values.select { |r| r.description&.match?(pattern) }
      lines = hits.sort_by(&:asn).map do |r|
        "AS#{r.asn}  # #{r.description} (#{r.country}) cat=#{r.category || '-'} role=#{r.network_role || '-'} " \
          "— src: ipverse as-metadata description match"
      end
      File.write(File.join(OUT_DIR, "#{name}.sweep.txt"), lines.join("\n") + "\n")
      Env.log("sweep #{name}: #{hits.size} candidates")
    end

    def write_hosting_gap(normalized, meta)
      hosting = meta.each_pair.select { |_, r| r.category == "hosting" }.map(&:first).to_set
      gap = (normalized[:x4b_dc_asns] | normalized[:bad_asns]) - hosting
      lines = gap.to_a.sort.map do |asn|
        rec = meta[asn]
        src = normalized[:x4b_dc_asns].include?(asn) ? "X4B input/datacenter/ASN.txt" : "brianhama/bad-asn-list"
        "AS#{asn}  # #{rec&.description || 'NOT IN as-metadata'} (#{rec&.country || '?'}) " \
          "cat=#{rec&.category || '-'} — src: #{src}"
      end
      File.write(File.join(OUT_DIR, "hosting_extra.gap.txt"), lines.join("\n") + "\n")
      Env.log("hosting gap: #{gap.size} candidates")
    end
  end
end

OpenASNPipeline::OverrideCandidates.run if $PROGRAM_NAME == __FILE__
