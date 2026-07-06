# frozen_string_literal: true

# The enrichment pilot: measure LLM ASN classification against our own gold
# BEFORE trusting it anywhere (nothing auto-graduates until dangerous-label
# precision clears the bar).
#
# WHAT IT DOES
#   1. Build the local Tier A context (from build/cache; FETCH=1 refreshes).
#   2. Assemble the gold set (gold.rb; LIMIT=N for a stratified cut).
#   3. Fetch external evidence for every gold ASN (fetchers.rb, cached,
#      4-way concurrent, PeeringDB globally throttled).
#   4. Classify each arm (ARM=local|enriched|both) in batches (BATCH, default
#      DEFAULT_BATCH — run and resume share the constant so a resumed run
#      keeps the same batch size unless BATCH is set explicitly).
#   5. Score + write build/work/enrich/pilot-<runid>/ containing report.md,
#      gold.jsonl, packets+predictions per arm (full audit trail).
#
# INVARIANTS (violations are bugs, not style):
#   * never touches data/overrides/ or anything the nightly reads;
#   * everything lands under gitignored build/ (raw LLM output must not enter
#     the public repo);
#   * the nightly build never calls an LLM — this file is operator tooling,
#     invoked by hand via `rake enrich:pilot`.
#
# Usage:
#   rake enrich:pilot                        # both arms, full gold, claude CLI
#   ARM=enriched LIMIT=40 rake enrich:pilot  # quicker iteration
#   BATCH=5 OPENASN_ENRICH_MODEL=sonnet rake enrich:pilot
#
# The LLM spend guard lives in LlmClient (OPENASN_ENRICH_MAX_CALLS). One
# Budget is shared across every arm's client, so the cap bounds the whole
# run; exhausting it stops further batches but still scores + writes the
# report from everything classified so far.

require "fileutils"
require "json"
require_relative "../lib/env"
require_relative "evidence"
require_relative "fetchers"
require_relative "gold"
require_relative "llm_client"
require_relative "eval"

module OpenASNPipeline
  module Enrich
    module Pilot
      FETCH_THREADS = 4 # RIPEstat guideline is ≤8 concurrent; PeeringDB has its own throttle
      DEFAULT_BATCH = 12 # one shared default — run and resume MUST agree

      module_function

      def run
        run_id = Time.now.utc.strftime("%Y%m%d-%H%M%S")
        out_dir = File.join(WORK_DIR, "enrich", "pilot-#{run_id}")
        FileUtils.mkdir_p(out_dir)

        arms = case ENV.fetch("ARM", "both")
               when "local" then [:local]
               when "enriched" then [:enriched]
               else %i[local enriched]
               end
        batch_size = Integer(ENV.fetch("BATCH", DEFAULT_BATCH))

        Env.log("enrich pilot #{run_id}: arms=#{arms.join(',')} batch=#{batch_size}")
        ctx = Evidence.build_context(offline: ENV["FETCH"] != "1")

        gold = Gold.build(ctx)
        gold = stratified_limit(gold, Integer(ENV["LIMIT"])) if ENV["LIMIT"]
        dump_jsonl(File.join(out_dir, "gold.jsonl"), gold.map(&:to_h))
        Env.log("enrich pilot: gold set #{gold.size} ASNs " \
                "(#{gold.group_by(&:provenance).transform_values(&:size).inspect})")

        external = arms.include?(:enriched) ? fetch_external(gold, ctx) : {}

        llm = LlmClient.new
        Env.log("enrich pilot: LLM backend=#{llm.backend} model=#{llm.model}")

        # The local fields (incl. the dc-overlay scan) are identical across
        # arms — build them once; the enriched arm merges externals on top.
        local_packets = gold.map { |g| Evidence.packet(g.asn, ctx) }

        results = {}
        arms.each do |arm|
          packets = if arm == :enriched
                      local_packets.map do |p|
                        (ext = external[p[:asn]]) ? p.merge(Evidence.external_fields(ext)) : p
                      end
                    else
                      local_packets
                    end
          dump_jsonl(File.join(out_dir, "packets-#{arm}.jsonl"), packets)
          # Fresh stats per arm (report attributes cost per arm) but ONE
          # shared budget — ARM=both must not double the operator's cap.
          arm_llm = LlmClient.new(backend: llm.backend, model: llm.model, budget: llm.budget)
          pred_path = File.join(out_dir, "predictions-#{arm}.jsonl")
          preds = classify(packets, arm_llm, batch_size, arm, checkpoint_path: pred_path)
          results[arm] = { preds: preds, stats: arm_llm.stats }
        end

        finish(out_dir, gold, results,
               { run_id: run_id, backend: llm.backend, model: llm.model, batch_size: batch_size })
      end

      # Keep every provenance AND source represented when cutting down — a
      # LIMIT run must not silently drop whole classes. Entries arrive in
      # file order (all vpn, then all mobile, ...), so a bare take() would do
      # exactly that; seeded shuffle first (same seed as gold sampling so a
      # LIMIT run is reproducible too).
      def stratified_limit(gold, n)
        rng = Random.new(Gold::SEED)
        share = (n.to_f / gold.size)
        groups = gold.group_by(&:provenance).transform_values do |entries|
          entries.shuffle(random: rng).take([1, (entries.size * share).round].max)
        end
        # Per-group rounding can overshoot n. Trim from the LARGEST groups —
        # a bare `.take(n)` here would delete whole trailing groups for small
        # LIMIT, the exact failure this method exists to prevent. If n is
        # smaller than the number of groups, we keep one entry per group and
        # deliberately exceed n (logged) rather than lose a class.
        total = groups.each_value.sum(&:size)
        while total > n
          largest = groups.each_value.max_by(&:size)
          break if largest.size <= 1

          largest.pop
          total -= 1
        end
        Env.warn("enrich pilot: LIMIT=#{n} < #{groups.size} provenance classes; keeping #{total}") if total > n
        groups.values.flatten
      end

      def fetch_external(gold, ctx)
        Env.log("enrich pilot: fetching external evidence for #{gold.size} ASNs " \
                "(#{FETCH_THREADS} threads; cached under build/cache/enrich/)")
        queue = Queue.new
        gold.each { |g| queue << g }
        done = 0
        mutex = Mutex.new
        out = {}
        threads = FETCH_THREADS.times.map do
          Thread.new do
            loop do
              g = begin
                queue.pop(true)
              rescue ThreadError
                break
              end
              ext = Fetchers.enrich(g.asn, ranges_v4: ctx.ranges_v4[g.asn] || [])
              mutex.synchronize do
                out[g.asn] = ext
                done += 1
                Env.log("enrich pilot: evidence #{done}/#{gold.size}") if (done % 20).zero?
              end
            end
          end
        end
        threads.each(&:join)
        errs = out.values.sum { |e| e["errors"].size }
        Env.log("enrich pilot: external evidence done (#{errs} per-source failures across " \
                "#{out.size} ASNs — keep-partial, see cache files)")
        out
      end

      # Classify packets in batches, CHECKPOINTING after every batch to
      # checkpoint_path. This makes the LLM phase resumable at batch
      # granularity: a multi-hour run WILL eventually be SIGTERMed from
      # outside (supervisor/CI timeouts, Ctrl-C — observed in practice), and
      # without per-batch checkpointing a kill at batch 14/15 loses
      # everything. On entry we load any predictions already in the
      # checkpoint and SKIP those ASNs — so re-invoking `enrich:resume` just
      # continues. A batch is the only unit ever lost.
      def classify(packets, llm, batch_size, arm, checkpoint_path: nil)
        preds = {}
        if checkpoint_path && File.exist?(checkpoint_path)
          read_jsonl(checkpoint_path).each { |h| preds[h["asn"]] = result_from_h(h) }
          Env.log("enrich pilot: [#{arm}] checkpoint has #{preds.size} predictions; skipping those")
        end
        todo = packets.reject { |p| preds.key?(p[:asn]) }
        return preds if todo.empty?

        total = (todo.size / batch_size.to_f).ceil
        todo.each_slice(batch_size).with_index do |batch, i|
          Env.log("enrich pilot: [#{arm}] batch #{i + 1}/#{total} (#{batch.size} ASNs)")
          begin
            batch_results = llm.classify_batch(batch)
            batch_results.each { |r| preds[r.asn] = r }
            append_checkpoint(checkpoint_path, batch_results) if checkpoint_path
          rescue LlmClient::BudgetExceeded => e
            # Budget exhaustion stops further batches but must NOT abort the
            # run: the caller still scores + reports everything classified so
            # far. The budget is shared across arms, so any later arm fails
            # fast into this same break on its first batch.
            Env.warn("enrich pilot: [#{arm}] budget exhausted at batch #{i + 1}/#{total} — #{e.message}")
            break
          rescue LlmClient::BackendError => e
            # A lost batch shouldn't kill the run — eval excludes those ASNs
            # (score() skips gold without predictions).
            Env.warn("enrich pilot: [#{arm}] batch #{i + 1} FAILED: #{e.message}")
          end
        end
        preds
      end

      # Append-only checkpoint: one JSONL line per result, written after each
      # batch. Appending keeps each checkpoint O(batch); rewriting the whole
      # file every batch would be O(n²) total write volume over a long run
      # (tens of GB at backfill scale). A kill can only tear the FINAL line,
      # which read_jsonl skips — that one prediction is re-classified on
      # resume, matching the "a batch is the only unit ever lost" contract.
      def append_checkpoint(path, results)
        File.open(path, "a") { |f| results.each { |r| f.puts(JSON.generate(r.to_h_compact)) } }
      end

      def dump_jsonl(path, rows)
        File.open(path, "w") { |f| rows.each { |r| f.puts(JSON.generate(r)) } }
      end

      def read_jsonl(path)
        rows = []
        File.foreach(path) do |line|
          rows << JSON.parse(line)
        rescue JSON::ParserError
          # Torn trailing line from a kill mid-append (see append_checkpoint).
          Env.warn("enrich pilot: skipping torn JSONL line in #{File.basename(path)}")
        end
        rows
      end

      # Resume a killed run (rake 'enrich:resume[pilot-<id>]'). Reuses the
      # FROZEN gold.jsonl + packets-*.jsonl from that dir — so predictions
      # already saved (a fully-classified arm) are kept, and only missing arms
      # are re-classified. Cheap because external evidence is already baked
      # into the saved enriched packets (no re-fetch). This is the recovery
      # path for a long two-arm run getting killed mid-arm.
      def resume(dir_name)
        out_dir = File.join(WORK_DIR, "enrich", dir_name)
        Env.fail_stage!("no such pilot dir: #{out_dir}") unless File.directory?(out_dir)

        gold = read_jsonl(File.join(out_dir, "gold.jsonl")).map do |h|
          Gold::Entry.new(asn: h["asn"], labels: h["labels"], acceptable: h["acceptable"],
                          source: h["source"], provenance: h["provenance"].to_sym)
        end
        Env.log("enrich resume: #{dir_name}, gold #{gold.size} ASNs")

        llm = LlmClient.new
        batch_size = Integer(ENV.fetch("BATCH", DEFAULT_BATCH))
        results = {}
        %i[local enriched].each do |arm|
          pred_path = File.join(out_dir, "predictions-#{arm}.jsonl")
          pkt_path  = File.join(out_dir, "packets-#{arm}.jsonl")
          next unless File.exist?(pkt_path)

          packets = read_jsonl(pkt_path).map { |h| symbolize(h) }
          pred_rows = File.exist?(pred_path) ? read_jsonl(pred_path) : []
          # An arm is "done" only when its checkpoint covers every packet.
          # A PARTIAL predictions file (killed mid-arm) is resumed, not reused
          # as final — classify() loads it and continues from the gap.
          if pred_rows.map { |h| h["asn"] }.to_set.superset?(packets.map { |p| p[:asn] }.to_set)
            preds = pred_rows.to_h { |h| [h["asn"], Schema::Result.from_h(h)] }
            Env.log("enrich resume: [#{arm}] complete — reusing #{preds.size} saved predictions")
            # NOTE: reloaded arms report zero stats — per-arm spend is not
            # persisted, so a resumed report's cost line covers NEW spend only.
            results[arm] = { preds: preds, stats: LlmClient::EMPTY_STATS.dup }
          else
            arm_llm = LlmClient.new(backend: llm.backend, model: llm.model, budget: llm.budget)
            Env.log("enrich resume: [#{arm}] classifying #{packets.size} saved packets " \
                    "(checkpoint-resumable)")
            preds = classify(packets, arm_llm, batch_size, arm, checkpoint_path: pred_path)
            results[arm] = { preds: preds, stats: arm_llm.stats }
          end
        end

        finish(out_dir, gold, results,
               { run_id: "#{dir_name}-resumed", backend: llm.backend, model: llm.model,
                 batch_size: batch_size })
      end

      # Shared tail of run/resume: score, write report.md, print the headline.
      def finish(out_dir, gold, results, meta)
        report_path = File.join(out_dir, "report.md")
        File.write(report_path, Eval.report_markdown(gold, results, meta))
        Env.log("enrich pilot: report at #{report_path}")
        print_headline(gold, results)
        report_path
      end

      # One ASN's packet exactly as the pilot sends it — the single owner of
      # the fetch-external-then-build-packet incantation. The enrich:evidence
      # and enrich:classify rake tasks call this so their debug output can
      # never drift from what enrich:pilot actually feeds the model.
      def build_packet(asn, ctx: nil, external: true)
        ctx ||= Evidence.build_context(offline: ENV["FETCH"] != "1")
        ext = external ? Fetchers.enrich(asn, ranges_v4: ctx.ranges_v4[asn] || []) : nil
        Evidence.packet(asn, ctx, external: ext)
      end

      # Saved packets round-tripped through JSON have string keys; the model
      # only sees the serialized JSON so nesting can stay strings, but
      # classify_batch/Prompt index p[:asn], so top-level keys must be symbols.
      def symbolize(hash)
        hash.transform_keys(&:to_sym)
      end

      def print_headline(gold, results)
        results.each do |arm, data|
          s = Eval.score(gold, data[:preds], subset: :independent)
          Env.log("enrich pilot: [#{arm}] independent gold n=#{s[:n]} " \
                  "exact=#{Eval.pct(s[:exact_match])} macroP=#{s[:macro_precision]} " \
                  "macroR=#{s[:macro_recall]} cost=$#{data[:stats][:cost_usd].round(3)}")
        end
      end
    end
  end
end

OpenASNPipeline::Enrich::Pilot.run if $PROGRAM_NAME == __FILE__
