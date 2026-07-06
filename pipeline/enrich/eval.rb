# frozen_string_literal: true

# Scoring + report for the enrichment pilot.
#
# METRICS (multi-label, per label L over the gold set):
#   TP: gold requires L, prediction has L
#   FN: gold requires L, prediction lacks L
#   FP: prediction has L, gold neither requires nor accepts L
# Acceptable-extras (gold.rb) don't count anywhere — they exist so a
# defensible richer answer (cdn on a hosting ASN) isn't punished as FP.
# We also report exact-match (prediction ⊇ required and ⊆ required+acceptable)
# and confidence calibration (precision by confidence bucket) — calibration
# is what decides the production auto-queue thresholds, so it's a
# first-class output of the pilot, not a curiosity.
#
# THE INDEPENDENT/IPVERSE SPLIT: gold sampled from ipverse categories shares a
# field with the packet (the model can read the answer), so those classes are
# reported separately and never headline. See gold.rb header for the finer
# caveat on override-derived gold (packets carry membership FLAGS).
#
# Paper comparison: Linnaeus (arXiv:2603.13649) Table 3 numbers are hardcoded
# below for the overlapping classes. It is NOT apples-to-apples — different
# taxonomy, different gold, they were blind while our packets carry curation
# flags — the row exists to sanity-check ORDER OF MAGNITUDE, not to win.

require "json"
require_relative "schema"
require_relative "gold"

module OpenASNPipeline
  module Enrich
    module Eval
      # Linnaeus top-level per-tag precision/recall (arXiv:2603.13649 Table 3,
      # fine-tuned GPT-4o-mini + SVM + stacking, 1,870-ASN gold), for the
      # classes that roughly map onto ours.
      PAPER_BASELINE = {
        "access_eyeball"        => { paper_tag: "Access",            p: 0.85, r: 0.72 },
        "pure_transit_backbone" => { paper_tag: "Transit",           p: 0.80, r: 0.69 },
        "mobile_carrier"        => { paper_tag: "Mobile",            p: 0.73, r: 0.77 },
        "hosting_provider"      => { paper_tag: "Content Providers", p: 0.79, r: 0.63 },
        "education"             => { paper_tag: "Edu & Research",    p: 0.92, r: 0.83 },
        "government"            => { paper_tag: "Government",        p: 0.83, r: 0.82 },
        "business"              => { paper_tag: "Enterprise",        p: 0.66, r: 0.49 },
        "ixp"                   => { paper_tag: "IXP",               p: 0.95, r: 0.84 },
        "dns_infrastructure"    => { paper_tag: "DNS",               p: 0.87, r: 0.79 },
        "satellite"             => { paper_tag: "Satellite",         p: 0.89, r: 0.67 },
        "personal"              => { paper_tag: "Personal",          p: 0.88, r: 0.78 }
      }.freeze

      CONFIDENCE_BUCKETS = [[0.9, 1.01], [0.7, 0.9], [0.0, 0.7]].freeze

      module_function

      # gold: [Gold::Entry], preds: {asn => Schema::Result}
      # subset: :all | :independent (independent = not Gold::WEAK_PROVENANCES)
      def score(gold, preds, subset: :all)
        rows = gold.select { |g| subset == :all || !Gold::WEAK_PROVENANCES.include?(g.provenance) }
        per_label = Hash.new { |h, k| h[k] = { tp: 0, fp: 0, fn: 0, support: 0 } }
        exact = 0
        errors = []

        rows.each do |g|
          pred = preds[g.asn]
          next unless pred # skipped/failed batch — excluded rather than counted against

          allowed = g.labels + g.acceptable
          g.labels.each do |l|
            per_label[l][:support] += 1
            pred.labels.include?(l) ? per_label[l][:tp] += 1 : per_label[l][:fn] += 1
          end
          (pred.labels - allowed).each { |l| per_label[l][:fp] += 1 }

          ok = (g.labels - pred.labels).empty? && (pred.labels - allowed).empty?
          exact += 1 if ok
          errors << { gold: g, pred: pred } unless ok
        end

        per_label.each_value do |m|
          m[:precision] = ratio(m[:tp], m[:tp] + m[:fp])
          m[:recall]    = ratio(m[:tp], m[:tp] + m[:fn])
          m[:f1] = if m[:precision] && m[:recall] && (m[:precision] + m[:recall]).positive?
                     (2 * m[:precision] * m[:recall] / (m[:precision] + m[:recall])).round(3)
                   end
        end

        scored = rows.count { |g| preds.key?(g.asn) }
        { n: scored, per_label: per_label.sort.to_h,
          exact_match: ratio(exact, scored),
          macro_precision: macro(per_label, :precision), macro_recall: macro(per_label, :recall),
          errors: errors, calibration: calibration(rows, preds) }
      end

      def ratio(num, den) = den.positive? ? (num.to_f / den).round(3) : nil

      def macro(per_label, key)
        vals = per_label.values.map { |m| m[key] }.compact
        vals.empty? ? nil : (vals.sum / vals.size).round(3)
      end

      # Precision of the whole label-set by the model's own confidence: the
      # empirical basis for the graduation thresholds (fast-track ≥0.90 etc.).
      def calibration(rows, preds)
        CONFIDENCE_BUCKETS.map do |(lo, hi)|
          # NOT filter_map: a wrong-but-confident prediction maps to `false`
          # and filter_map would silently drop it from the bucket, inflating
          # calibration. map+compact keeps false, drops only out-of-bucket nils.
          bucket = rows.map do |g|
            pred = preds[g.asn]
            next unless pred && pred.confidence >= lo && pred.confidence < hi

            allowed = g.labels + g.acceptable
            (g.labels - pred.labels).empty? && (pred.labels - allowed).empty?
          end.compact
          { range: "#{lo}–#{hi > 1 ? 1.0 : hi}", n: bucket.size,
            exact_match: ratio(bucket.count(true), bucket.size) }
        end
      end

      # arms: {arm_name => {preds: {asn=>Result}, stats: llm.stats}}
      def report_markdown(gold, arms, meta)
        md = +"# OpenASN enrichment pilot — run #{meta[:run_id]}\n\n"
        md << "Backend `#{meta[:backend]}`, model `#{meta[:model]}`, prompt `#{Prompt::PROMPT_VERSION}`, "
        md << "batch size #{meta[:batch_size]}. Gold set: #{gold.size} ASNs "
        md << "(#{gold.count { |g| !Gold::WEAK_PROVENANCES.include?(g.provenance) }} independent/pinned, "
        md << "#{gold.count { |g| Gold::WEAK_PROVENANCES.include?(g.provenance) }} weak/ipverse-derived).\n\n"
        md << "> Scoring: gold labels must all be predicted (recall); predictions outside\n"
        md << "> gold+acceptable count as FP (precision). ipverse-derived gold shares a field\n"
        md << "> with the packet, so the **independent** table is the headline. Override-derived\n"
        md << "> gold still exposes membership *flags* in packets (production parity — see gold.rb).\n\n"

        arms.each do |arm, data|
          %i[independent all].each do |subset|
            s = score(gold, data[:preds], subset: subset)
            md << "## Arm `#{arm}` — #{subset} gold (n=#{s[:n]})\n\n"
            md << "Exact-match **#{pct(s[:exact_match])}** · macro P **#{s[:macro_precision]}** · " \
                  "macro R **#{s[:macro_recall]}**\n\n"
            md << label_table(s[:per_label], with_paper: subset == :independent)
            md << "\nCalibration (exact-match by model confidence): " \
                  "#{s[:calibration].map { |b| "#{b[:range]}: #{pct(b[:exact_match])} (n=#{b[:n]})" }.join(' · ')}\n\n"
          end
          st = data[:stats]
          md << "Cost/latency: #{st[:requests]} requests (#{st[:retries]} retries), " \
                "#{st[:input_tokens]} in / #{st[:output_tokens]} out tokens " \
                "(#{st[:cache_read_tokens]} cache-read), ~$#{st[:cost_usd].round(3)}, " \
                "#{st[:wall_seconds].round(1)}s LLM wall time.\n\n"
        end

        if arms.size == 2
          md << arm_delta(gold, arms)
        end

        md << error_listing(gold, arms)
        md << "\n---\n*Paper baseline: Linnaeus, arXiv:2603.13649 Table 3 (fine-tuned GPT-4o-mini + " \
              "SVM stack, their 1,870-ASN gold). Different taxonomy and gold — order-of-magnitude " \
              "context only.*\n"
        md
      end

      def label_table(per_label, with_paper:)
        header = "| label | P | R | F1 | support | FP |"
        header += " paper P/R |" if with_paper
        md = +"#{header}\n|---|---|---|---|---|---|#{'---|' if with_paper}\n"
        per_label.each do |label, m|
          next if m[:support].zero? && m[:fp].zero?

          row = "| #{label} | #{fmt(m[:precision])} | #{fmt(m[:recall])} | #{fmt(m[:f1])} " \
                "| #{m[:support]} | #{m[:fp]} |"
          if with_paper
            p = PAPER_BASELINE[label]
            row += p ? " #{p[:p]}/#{p[:r]} (#{p[:paper_tag]}) |" : " — |"
          end
          md << row << "\n"
        end
        md
      end

      def arm_delta(gold, arms)
        names = arms.keys
        a = score(gold, arms[names[0]][:preds], subset: :independent)
        b = score(gold, arms[names[1]][:preds], subset: :independent)
        md = +"## Arm delta (#{names[1]} − #{names[0]}, independent gold)\n\n"
        md << "Exact-match #{pct(a[:exact_match])} → #{pct(b[:exact_match])}; " \
              "macro P #{a[:macro_precision]} → #{b[:macro_precision]}; " \
              "macro R #{a[:macro_recall]} → #{b[:macro_recall]}.\n\n"
        md
      end

      # The qualitative half: every miss with the model's own evidence line.
      # This is what actually teaches us what to fix (prompt, packet, or gold).
      def error_listing(gold, arms)
        md = +"## Misses (worth reading, every one)\n\n"
        arms.each do |arm, data|
          s = score(gold, data[:preds], subset: :all)
          md << "### #{arm} — #{s[:errors].size} misses\n\n"
          s[:errors].sort_by { |e| -e[:pred].confidence }.each do |e|
            g = e[:gold]
            p = e[:pred]
            md << "- **AS#{g.asn}** gold `#{g.labels.join(',')}`#{" (+ok: #{g.acceptable.join(',')})" unless g.acceptable.empty?} " \
                  "← pred `#{p.labels.join(',')}` conf #{p.confidence} " \
                  "(#{g.provenance}; #{g.source})\n" \
                  "  - evidence: #{p.evidence}#{p.needs_review ? ' · needs_review' : ''}\n"
          end
          md << "\n"
        end
        md
      end

      def fmt(v) = v.nil? ? "—" : v
      def pct(v) = v.nil? ? "—" : "#{(v * 100).round(1)}%"
    end
  end
end
