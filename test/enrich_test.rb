# frozen_string_literal: true

# Offline unit tests for the LLM enrichment module (pipeline/enrich/).
# NO network, NO data-repo checkout, NO LLM calls — pure logic only, same
# doctrine as pipeline_test.rb. The live paths are exercised by the manual
# rake tasks (enrich:evidence / enrich:classify / enrich:pilot).

require_relative "test_helper"
require "tmpdir"
require_relative "../pipeline/enrich/schema"
require_relative "../pipeline/enrich/prompt"
require_relative "../pipeline/enrich/evidence"
require_relative "../pipeline/enrich/gold"
require_relative "../pipeline/enrich/eval"
require_relative "../pipeline/enrich/llm_client"
require_relative "../pipeline/enrich/fetchers"
require_relative "../pipeline/enrich/pilot"

module OpenASNPipeline
  module Enrich
    class SchemaTest < Minitest::Test
      def valid_row(asn, labels: ["hosting_provider"], action: "none", conf: 0.9)
        { "asn" => asn, "labels" => labels, "openasn_action" => action,
          "correction" => nil, "confidence" => conf, "evidence" => "e",
          "evidence_url" => nil, "needs_review" => false, "risk_note" => nil }
      end

      def test_extract_json_plain
        assert_equal({ "a" => 1 }, Schema.extract_json('{"a": 1}'))
      end

      def test_extract_json_fenced
        text = "Here you go:\n```json\n{\"a\": 1}\n```\nDone."
        assert_equal({ "a" => 1 }, Schema.extract_json(text))
      end

      def test_extract_json_prose_wrapped
        text = "Sure! {\"results\": []} hope that helps"
        assert_equal({ "results" => [] }, Schema.extract_json(text))
      end

      def test_extract_json_garbage_raises
        assert_raises(Schema::ValidationError) { Schema.extract_json("no json here") }
      end

      def test_validate_orders_results_to_expected_asns
        parsed = { "results" => [valid_row(2), valid_row(1)] }
        results = Schema.validate_results!(parsed, [1, 2])
        assert_equal [1, 2], results.map(&:asn)
      end

      def test_validate_rejects_missing_and_foreign_asns
        parsed = { "results" => [valid_row(1), valid_row(99)] }
        err = assert_raises(Schema::ValidationError) { Schema.validate_results!(parsed, [1, 2]) }
        assert_match(/missing: 2/, err.message)
        assert_match(/unexpected: 99/, err.message)
      end

      def test_validate_rejects_duplicates_unknown_labels_and_bad_confidence
        assert_raises(Schema::ValidationError) do
          Schema.validate_results!({ "results" => [valid_row(1), valid_row(1)] }, [1])
        end
        assert_raises(Schema::ValidationError) do
          Schema.validate_results!({ "results" => [valid_row(1, labels: ["made_up"])] }, [1])
        end
        assert_raises(Schema::ValidationError) do
          Schema.validate_results!({ "results" => [valid_row(1, conf: 1.7)] }, [1])
        end
      end

      def test_action_without_matching_label_is_coerced_to_none_and_flagged
        parsed = { "results" => [valid_row(1, labels: ["business"], action: "vpn_provider")] }
        result = Schema.validate_results!(parsed, [1]).first
        assert_equal "none", result.openasn_action
        assert result.needs_review
      end

      def test_correction_action_without_object_is_coerced
        row = valid_row(1, labels: ["education"], action: "correction")
        result = Schema.validate_results!({ "results" => [row] }, [1]).first
        assert_equal "none", result.openasn_action
        assert result.needs_review
      end
    end

    class PromptTest < Minitest::Test
      def test_full_prompt_carries_preamble_and_packets
        packets = [{ asn: 3352, description: "TELEFONICA" }]
        prompt = Prompt.full_prompt(packets)
        assert_includes prompt, "WORKED TRAPS"
        assert_includes prompt, "AS3352"
        assert_includes prompt, "TELEFONICA"
      end

      def test_prompt_version_is_stamped
        refute_nil Prompt::PROMPT_VERSION
        assert_match(/\Av\d+/, Prompt::PROMPT_VERSION)
      end
    end

    class EvidenceTest < Minitest::Test
      def fake_ctx(meta: {}, ranges: {}, dc: [])
        Evidence::LocalContext.new(
          meta: meta, ranges_v4: ranges, v6_asns: Set.new([9]), dc_ranges: dc,
          bad_asns: Set.new([7]), x4b_vpn_asns: Set.new([8]), x4b_dc_asns: Set.new,
          override_flags: { 7 => ["hosting_extra"] }, routed_asns: Set.new(ranges.keys)
        )
      end

      def test_packet_local_fields
        meta = { 7 => AsJson::Record.new(7, "Example Hosting", "US", "hosting", "stub") }
        ctx = fake_ctx(meta: meta, ranges: { 7 => [[0, 9], [100, 149]] }, dc: [[0, 4]])
        p = Evidence.packet(7, ctx)
        assert_equal "Example Hosting", p[:description]
        assert_equal 2, p[:announced_ipv4_ranges]
        assert_equal 60, p[:announced_ipv4_addresses]
        assert_in_delta 8.3, p[:pct_ipv4_space_in_x4b_dc_overlay], 0.1 # 5 of 60 addresses
        assert p[:in_bad_asn_list]
        assert_equal ["hosting_extra"], p[:existing_openasn_flags]
        refute p[:announces_ipv6]
      end

      def test_dc_overlay_pct_edges
        assert_equal 0.0, Evidence.dc_overlay_pct([], [[0, 10]])
        assert_equal 0.0, Evidence.dc_overlay_pct([[0, 9]], [])
        assert_equal 100.0, Evidence.dc_overlay_pct([[5, 14]], [[0, 100]])
        # partial: [10,19] ∩ [15,30] = 5 of 10 addresses
        assert_equal 50.0, Evidence.dc_overlay_pct([[10, 19]], [[15, 30]])
      end

      def test_external_fields_flattening_drops_dead_sources
        ext = {
          "ripestat_overview" => { "holder" => "EXAMPLE-AS" },
          "ripestat_neighbours" => { "left_count" => 2, "right_count" => 0, "uncertain_count" => 1 },
          "peeringdb" => { "present" => true, "name" => "Example", "info_types" => ["Content"] },
          "rdap" => nil, "rdns" => {}, "errors" => { "rdap" => "boom" }
        }
        out = Evidence.external_fields(ext)
        assert_equal "EXAMPLE-AS", out[:ripestat_holder]
        assert_equal({ left: 2, right: 0, uncertain: 1 }, out[:bgp_neighbours])
        refute out.key?(:rdap)
        refute out.key?(:rdns_samples)
        refute out.key?(:errors)
      end

      def test_load_override_flags_parses_as_lines
        Dir.mktmpdir do |dir|
          File.write(File.join(dir, "vpn_provider.txt"), <<~TXT)
            # comment line
            AS9009    # M247 — src: ...
            AS197141  # Mullvad — src: ...
          TXT
          flags = Evidence.load_override_flags(dir)
          assert_equal ["vpn_provider"], flags[9009]
          assert_equal ["vpn_provider"], flags[197_141]
          assert_nil flags[12_345]
        end
      end
    end

    class GoldTest < Minitest::Test
      def test_merge_by_asn_unions_labels_and_keeps_strongest_provenance
        entries = [
          Gold::Entry.new(asn: 9009, labels: ["vpn_provider"], acceptable: ["hosting_provider"],
                          source: "overrides/vpn_provider.txt", provenance: :independent),
          Gold::Entry.new(asn: 9009, labels: ["hosting_provider"], acceptable: ["cdn"],
                          source: "bad-asn-list", provenance: :ipverse)
        ]
        merged = Gold.merge_by_asn(entries)
        assert_equal 1, merged.size
        m = merged.first
        assert_equal %w[vpn_provider hosting_provider].sort, m.labels.sort
        # hosting_provider was promoted to a required label -> leaves acceptable
        assert_equal ["cdn"], m.acceptable
        assert_equal :independent, m.provenance
      end

      def test_pins_are_dropped_when_description_fails_guard
        meta = {
          174 => AsJson::Record.new(174, "Cogent Communications", "US", "isp", "tier1_transit"),
          3356 => AsJson::Record.new(3356, "SOMETHING ELSE ENTIRELY", "US", "isp", "tier1_transit")
        }
        ctx = Evidence::LocalContext.new(
          meta: meta, ranges_v4: {}, v6_asns: Set.new, dc_ranges: [],
          bad_asns: Set.new, x4b_vpn_asns: Set.new, x4b_dc_asns: Set.new,
          override_flags: {}, routed_asns: Set.new
        )
        pins = Gold.from_pins(ctx)
        assert_includes pins.map(&:asn), 174
        refute_includes pins.map(&:asn), 3356 # guard regex /lumen|level ?3/ fails
      end
    end

    class EvalTest < Minitest::Test
      def gold(asn, labels, acceptable = [], provenance = :independent)
        Gold::Entry.new(asn: asn, labels: labels, acceptable: acceptable,
                        source: "t", provenance: provenance)
      end

      def pred(asn, labels, conf: 0.95)
        Schema::Result.new(asn: asn, labels: labels, openasn_action: "none", correction: nil,
                           confidence: conf, evidence: "e", evidence_url: nil,
                           needs_review: false, risk_note: nil)
      end

      def test_scoring_with_acceptable_extras
        g = [
          gold(1, ["hosting_provider"], ["cdn"]),          # pred adds cdn -> NOT an FP
          gold(2, ["vpn_provider"]),                       # pred misses vpn, adds hosting -> FN + FP
          gold(3, ["education"], [], :ipverse)             # excluded from :independent
        ]
        preds = {
          1 => pred(1, %w[hosting_provider cdn]),
          2 => pred(2, ["hosting_provider"], conf: 0.6),
          3 => pred(3, ["education"])
        }
        s = Eval.score(g, preds, subset: :independent)
        assert_equal 2, s[:n]

        hosting = s[:per_label]["hosting_provider"]
        assert_equal 0.5, hosting[:precision] # 1 TP (AS1) vs 1 FP (AS2)
        assert_equal 1, hosting[:tp]
        assert_equal 1, hosting[:fp] # hosting predicted on AS2 where gold is vpn-only
        vpn = s[:per_label]["vpn_provider"]
        assert_equal 1, vpn[:fn]
        assert_equal 0.5, s[:exact_match]

        all = Eval.score(g, preds, subset: :all)
        assert_equal 3, all[:n]
        assert_equal 1, all[:per_label]["education"][:tp]
      end

      def test_missing_predictions_are_excluded_not_penalized
        g = [gold(1, ["hosting_provider"]), gold(2, ["vpn_provider"])]
        s = Eval.score(g, { 1 => pred(1, ["hosting_provider"]) }, subset: :all)
        assert_equal 1, s[:n]
        assert_equal 1.0, s[:exact_match]
      end

      def test_calibration_buckets
        g = [gold(1, ["hosting_provider"]), gold(2, ["vpn_provider"])]
        preds = { 1 => pred(1, ["hosting_provider"], conf: 0.95),
                  2 => pred(2, ["hosting_provider"], conf: 0.95) }
        cal = Eval.score(g, preds, subset: :all)[:calibration]
        top = cal.find { |b| b[:range].start_with?("0.9") }
        assert_equal 2, top[:n]
        assert_equal 0.5, top[:exact_match]
      end

      def test_report_renders
        g = [gold(1, ["hosting_provider"])]
        arms = { local: { preds: { 1 => pred(1, ["hosting_provider"]) },
                          stats: { requests: 1, retries: 0, input_tokens: 10, output_tokens: 5,
                                   cache_read_tokens: 0, cost_usd: 0.01, wall_seconds: 1.0 } } }
        md = Eval.report_markdown(g, arms, { run_id: "t", backend: :claude_cli, model: "opus", batch_size: 10 })
        assert_includes md, "# OpenASN enrichment pilot"
        assert_includes md, "hosting_provider"
        assert_includes md, "arXiv:2603.13649"
      end
    end

    class LlmClientTest < Minitest::Test
      def with_env(vars)
        saved = vars.keys.to_h { |k| [k, ENV[k]] }
        vars.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
        yield
      ensure
        saved.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
      end

      def test_backend_autodetect_prefers_api_keys_then_cli
        with_env("ANTHROPIC_API_KEY" => "x", "OPENAI_API_KEY" => nil,
                 "OPENASN_ENRICH_BACKEND" => nil, "OPENASN_ENRICH_MODEL" => nil) do
          assert_equal :anthropic, LlmClient.new.backend
        end
        with_env("ANTHROPIC_API_KEY" => nil, "OPENAI_API_KEY" => nil,
                 "OPENASN_ENRICH_BACKEND" => nil, "OPENASN_ENRICH_MODEL" => nil) do
          client = LlmClient.new
          assert_equal :claude_cli, client.backend
          assert_equal "opus", client.model
        end
      end

      def test_openai_backend_requires_explicit_model
        with_env("OPENASN_ENRICH_BACKEND" => "openai", "OPENASN_ENRICH_MODEL" => nil) do
          assert_raises(LlmClient::BackendError) { LlmClient.new }
        end
      end

      def test_forced_api_backend_without_key_fails_at_construction
        # NOT at request 1 of a long run with a bare KeyError.
        with_env("OPENASN_ENRICH_BACKEND" => "anthropic", "ANTHROPIC_API_KEY" => nil,
                 "OPENASN_ENRICH_MODEL" => nil) do
          e = assert_raises(LlmClient::BackendError) { LlmClient.new }
          assert_match(/ANTHROPIC_API_KEY/, e.message)
        end
      end

      def test_budget_is_shared_and_caps_the_run
        budget = LlmClient::Budget.new(2)
        budget.consume!
        budget.consume!
        assert_raises(LlmClient::BudgetExceeded) { budget.consume! }
      end
    end

    # Regression tests for the pre-publication review fixes (2026-07-06).
    class ReviewFixesSchemaTest < Minitest::Test
      def valid_row(asn, extra = {})
        { "asn" => asn, "labels" => ["hosting_provider"], "openasn_action" => "none",
          "correction" => nil, "confidence" => 0.9, "evidence" => "e",
          "evidence_url" => nil, "needs_review" => false, "risk_note" => nil }.merge(extra)
      end

      def test_result_from_h_round_trips_to_h_compact
        result = Schema.validate_results!({ "results" => [valid_row(9)] }, [9]).first
        json = JSON.parse(JSON.generate(result.to_h_compact))
        assert_equal result, Schema::Result.from_h(json)
      end

      def test_out_of_enum_correction_category_is_a_hard_error
        # The claude-CLI backend has no server-side schema enforcement; a
        # bogus category must never reach a review queue looking legitimate.
        row = valid_row(9, "openasn_action" => "correction",
                           "correction" => { "category" => "cdn" })
        e = assert_raises(Schema::ValidationError) { Schema.validate_results!({ "results" => [row] }, [9]) }
        assert_match(/correction category/, e.message)
      end

      def test_valid_correction_category_passes
        row = valid_row(9, "openasn_action" => "correction",
                           "correction" => { "category" => "hosting" })
        result = Schema.validate_results!({ "results" => [row] }, [9]).first
        assert_equal "correction", result.openasn_action
        assert_equal({ "category" => "hosting" }, result.correction)
      end
    end

    class PilotCheckpointTest < Minitest::Test
      def make_result(asn)
        Schema::Result.new(asn: asn, labels: ["hosting_provider"], openasn_action: "none",
                           correction: nil, confidence: 0.9, evidence: "e", evidence_url: nil,
                           needs_review: false, risk_note: nil)
      end

      def test_append_checkpoint_appends_and_read_skips_torn_tail
        Dir.mktmpdir do |dir|
          path = File.join(dir, "preds.jsonl")
          Pilot.append_checkpoint(path, [make_result(1)])
          Pilot.append_checkpoint(path, [make_result(2)])
          File.open(path, "a") { |f| f.write('{"asn": 3, "labels"') } # kill mid-append
          rows = Pilot.read_jsonl(path)
          assert_equal [1, 2], rows.map { |h| h["asn"] }
        end
      end

      def test_budget_exhaustion_returns_partial_preds_instead_of_raising
        fake = Class.new do
          def initialize(results)
            @results = results
            @calls = 0
          end

          def classify_batch(_batch)
            @calls += 1
            raise LlmClient::BudgetExceeded, "cap" if @calls > 1

            @results
          end
        end
        preds = Pilot.classify([{ asn: 1 }, { asn: 2 }], fake.new([make_result(1)]), 1, :local)
        assert_equal [1], preds.keys # batch 2 hit the cap: no raise, report still gets batch 1
      end

      def test_stratified_limit_never_drops_a_provenance_class
        gold = []
        30.times { |i| gold << Gold::Entry.new(asn: i, labels: ["business"], acceptable: [], source: "t", provenance: :independent) }
        4.times { |i| gold << Gold::Entry.new(asn: 100 + i, labels: ["business"], acceptable: [], source: "t", provenance: :pinned) }
        4.times { |i| gold << Gold::Entry.new(asn: 200 + i, labels: ["business"], acceptable: [], source: "t", provenance: :ipverse) }
        cut = Pilot.stratified_limit(gold, 10)
        assert_equal 10, cut.size
        assert_equal %i[independent ipverse pinned], cut.map(&:provenance).uniq.sort
        # A LIMIT below the class count keeps ≥1 per class (documented overshoot)
        tiny = Pilot.stratified_limit(gold, 2)
        assert_equal %i[independent ipverse pinned], tiny.map(&:provenance).uniq.sort
      end
    end

    class SsrfGuardTest < Minitest::Test
      # Hand-rolled Resolv stub (stdlib only — this suite must run without
      # any gems): DNS resolution swapped for a fixed answer, restored after.
      def with_resolved(addr)
        original = Resolv.method(:getaddresses)
        Resolv.singleton_class.send(:define_method, :getaddresses) { |_host| [addr] }
        yield
      ensure
        Resolv.singleton_class.send(:define_method, :getaddresses, original)
      end

      def assert_blocked(addr)
        with_resolved(addr) do
          assert Fetchers.private_host?("attacker-controlled.example"), "#{addr} must be blocked"
        end
      end

      def test_beyond_rfc1918_blocked_ranges
        assert_blocked("0.0.0.0")          # "this host" — routes to localhost on Linux
        assert_blocked("100.64.0.1")       # CGNAT
        assert_blocked("::ffff:127.0.0.1") # IPv4-mapped loopback dodges plain checks
        assert_blocked("224.0.0.251")      # multicast
      end

      def test_public_addresses_still_allowed
        with_resolved("93.184.216.34") do
          refute Fetchers.private_host?("example.com")
        end
      end
    end
  end
end
