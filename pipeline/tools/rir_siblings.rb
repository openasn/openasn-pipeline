# frozen_string_literal: true

# Curation aid: SIBLING candidates for data/overrides/ from RIR holder
# clusters (lib/rir_stats.rb; DECISIONS.md D-SRC-1).
#
# For every ASN already listed in an override file, the RIR delegated-extended
# stats name the other ASNs registered to the same holder (per-RIR opaque-id).
# Those siblings are CANDIDATES only: a holder often runs very different
# networks (a mobile carrier's fixed-line ASN, a hoster's corporate ASN), so
# every line needs the same human review and its own evidence as any other
# override. Prefer false negatives: a missed sibling costs a little recall, a
# wrongly flagged eyeball network hurts real users.
#
# Nothing here is published. Output goes to build/work/candidates/ and cites
# the RIR file URL + fetch time; a line that graduates into data/overrides/
# is the curator's own sourced conclusion (D-CUR-1), not RIR data.
#
# Holders larger than RirStats::POOL_THRESHOLD are registry pools (APNIC NIRs)
# and never produce candidates.
#
# Usage: rake overrides:rir_siblings   (OFFLINE=1 to reuse build/cache)

require "set"
require_relative "../lib/env"
require_relative "../lib/http"
require_relative "../lib/overrides"
require_relative "../lib/rir_stats"
require_relative "../lib/license_gate"

module OpenASNPipeline
  module RirSiblings
    OUT_DIR = File.join(WORK_DIR, "candidates")

    # eyeball_confirm is deliberately absent: it asserts "this specific ASN is
    # an eyeball network", which a holder relationship cannot establish.
    FILES = %i[vpn_provider hosting_extra mobile_carrier enterprise_gateway cdn].freeze

    module_function

    def run(http: Http.new, offline: ENV["OFFLINE"] == "1", out_dir: OUT_DIR)
      LicenseGate.run(http: http, offline: offline, scope: :curation)
      reg = RirStats.build(http: http, offline: offline)
      overrides = Overrides.load
      FileUtils.mkdir_p(out_dir)
      summary = {}
      FILES.each do |name|
        listed = overrides.sets.fetch(name)
        cands = candidates(listed, reg[:rows], reg[:clusters])
        summary[name] = { "listed" => listed.size, "candidates" => cands.size }
        File.write(File.join(out_dir, "#{name}.rir-siblings.txt"),
                   render(name, cands, reg[:rows], reg[:stats]["rirs"]))
      end
      Env.log("rir siblings: #{summary.inspect} -> #{out_dir}")
      summary
    end

    # Pure. { sibling_asn => [listed_asn, ...] } for siblings NOT already
    # listed, never crossing a pool.
    def candidates(listed, rows, clusters)
      out = Hash.new { |h, k| h[k] = [] }
      listed.each do |asn|
        RirStats.siblings(asn, rows, clusters).each do |sib|
          out[sib] << asn unless listed.include?(sib)
        end
      end
      out.transform_values(&:sort).sort.to_h
    end

    def render(name, cands, rows, rirs)
      header = [
        "# #{name}: RIR sibling CANDIDATES - review every line; NOT an override file.",
        "# A sibling shares a registrant with a listed ASN; that alone is NOT evidence of the class.",
        "# Source: RIR delegated-extended stats (per-RIR opaque-id), D-SRC-1; RIPE #{rirs.key?('ripencc') ? 'INCLUDED (research only - never cite into a published line)' : 'excluded'}."
      ]
      lines = cands.map do |sib, via|
        r = rows[sib]
        url = RirStats::REGISTRIES.dig(r["rir"], :url)
        fetched = rirs.dig(r["rir"], "fetched_at") || "cache"
        "AS#{sib}  # sibling of #{via.map { "AS#{_1}" }.join(',')} (holder #{r['holder']}, #{r['cc'] || '??'}, " \
          "registered #{r['registered'] || '?'}) - src: #{url} (fetched #{fetched})"
      end
      (header + lines).join("\n") + "\n"
    end
  end
end

OpenASNPipeline::RirSiblings.run if $PROGRAM_NAME == __FILE__
