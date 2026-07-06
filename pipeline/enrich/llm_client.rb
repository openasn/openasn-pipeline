# frozen_string_literal: true

# Provider-neutral LLM client for the enrichment loop. Stdlib only (net/http,
# open3, json) — this repo deliberately has zero runtime gem dependencies, so
# we speak raw HTTP instead of pulling the vendor SDKs.
#
# BACKEND SELECTION (env OPENASN_ENRICH_BACKEND, else auto):
#   1. "anthropic"  — ANTHROPIC_API_KEY set. Real structured outputs
#      (server-enforced JSON schema) + prompt caching on the stable preamble.
#   2. "openai"     — OPENAI_API_KEY set. Structured outputs via
#      response_format json_schema strict:true.
#   3. "claude_cli" — the `claude` CLI in headless mode (-p), authenticated by
#      the operator's existing Claude subscription. No key management, works
#      on the reference dev machine today; no server-side schema enforcement,
#      so Schema.extract_json + validate_results! carry the weight. This is
#      the PILOT backend; API backends are for the 95k backfill.
#
# GOTCHAS baked in (each verified against the claude-api reference 2026-07-05
# or observed live; do not "fix" them away):
#   * NO temperature/top_p/top_k on claude-opus-4-8 — the params were REMOVED
#     and return HTTP 400 (drift from older models where temperature:0 was
#     the classification idiom). Determinism comes from the schema + prompt.
#   * Structured outputs shape is output_config.format (the older top-level
#     output_format is deprecated).
#   * The stable preamble carries cache_control {type: ephemeral}: batches
#     after the first read it at ~0.1x price. Min cacheable prefix on Opus
#     4.8 is 4096 tokens — our preamble is ~1.6k tokens, so the cache may not
#     engage until packets push the prefix over the floor; harmless either way.
#   * 429/529 honor Retry-After; both are retryable per
#     https://platform.claude.com/docs/en/api/errors.md
#   * The claude CLI json envelope is {type:"result", subtype:"success",
#     is_error:false, result:"...", total_cost_usd:..., usage:{...}} —
#     verified live against claude CLI 2.1.201 on 2026-07-05.
#   * FOR THE 95k BACKFILL use the async batch APIs instead of this
#     synchronous client (50% price, 24h turnaround, separate rate pools):
#     https://platform.claude.com/docs/en/build-with-claude/batch-processing.md
#     https://platform.openai.com/docs/guides/batch
#
# COST GUARD: a run is capped at MAX_CALLS LLM requests (env
# OPENASN_ENRICH_MAX_CALLS). This tool spends the operator's money/quota
# autonomously; a runaway retry loop must hit a wall, not a credit card.
# The cap is enforced by a Budget object that can be SHARED across clients:
# a two-arm pilot builds one client per arm (for per-arm stats attribution)
# but hands them the same Budget, so the cap bounds the RUN, not each arm.

require "json"
require "net/http"
require "open3"
require "uri"
require_relative "../lib/env"
require_relative "schema"
require_relative "prompt"

module OpenASNPipeline
  module Enrich
    class LlmClient
      class BudgetExceeded < StandardError; end
      class BackendError < StandardError; end

      # One request-count budget for a whole run. Thread-safe; share one
      # instance across every client of the run (`LlmClient.new(budget:
      # other.budget)`) or ARM=both silently doubles the operator's cap.
      class Budget
        attr_reader :max

        def initialize(max)
          @max = max
          @used = 0
          @mutex = Mutex.new
        end

        def consume!
          @mutex.synchronize do
            if @used >= @max
              raise BudgetExceeded,
                    "LLM call budget (#{@max}) exhausted — raise OPENASN_ENRICH_MAX_CALLS if intended"
            end
            @used += 1
          end
        end
      end

      DEFAULT_MAX_CALLS = 120
      # Skill-verified current default (claude-api reference, cached
      # 2026-06-24): claude-opus-4-8, $5/$25 per MTok. Override with
      # OPENASN_ENRICH_MODEL (e.g. "claude-sonnet-5", or a CLI alias like
      # "opus"/"sonnet" for the claude_cli backend).
      ANTHROPIC_DEFAULT_MODEL = "claude-opus-4-8"
      CLI_DEFAULT_MODEL       = "opus"

      # Identify ourselves to the API hosts, same etiquette as the fetchers
      # (defined locally — this file must not depend on fetchers.rb loading).
      USER_AGENT = "openasn-enrich/0.1 (+https://github.com/openasn/openasn)"

      # Approximate $/MTok (input, output) for the report's cost line.
      # claude_cli reports its own authoritative cost envelope instead.
      # Models absent here accumulate tokens but $0 — record_usage warns once
      # and the operator can set OPENASN_ENRICH_PRICE_PER_MTOK="in,out".
      # The hard spend guard is the request Budget, never this estimate.
      PRICES_PER_MTOK = {
        "claude-opus-4-8" => [5.0, 25.0].freeze,
        "claude-sonnet-5" => [3.0, 15.0].freeze,
        "claude-haiku-4-5-20251001" => [1.0, 5.0].freeze
      }.freeze

      # The stats shape, single-sourced: pilot.rb reuses it when it needs a
      # zeroed row for arms whose predictions were reloaded from checkpoint.
      EMPTY_STATS = { requests: 0, retries: 0, input_tokens: 0, output_tokens: 0,
                      cache_read_tokens: 0, cost_usd: 0.0, wall_seconds: 0.0 }.freeze

      attr_reader :backend, :model, :stats, :budget

      def initialize(backend: nil, model: nil, budget: nil)
        @backend = (backend || ENV["OPENASN_ENRICH_BACKEND"] || autodetect_backend).to_sym
        @model   = model || ENV["OPENASN_ENRICH_MODEL"] || default_model
        @budget  = budget || Budget.new(Integer(ENV.fetch("OPENASN_ENRICH_MAX_CALLS", DEFAULT_MAX_CALLS)))
        @api_key = fetch_api_key # fail HERE, not on request 1 of a long run
        @stats = EMPTY_STATS.dup
      end

      # Classify one batch of evidence packets. Returns [Schema::Result].
      # One retry on schema/echo failure with the validator error appended —
      # models fix echo/enum mistakes reliably when told what broke; two
      # consecutive failures mean the batch (or prompt) is wrong, so raise.
      def classify_batch(packets)
        expected = packets.map { |p| p[:asn] }
        attempt_note = nil
        begin
          parsed = request_json(packets, attempt_note)
          Schema.validate_results!(parsed, expected)
        rescue Schema::ValidationError => e
          raise BackendError, "batch failed twice: #{e.message}" if attempt_note

          @stats[:retries] += 1
          Env.warn("enrich llm: batch invalid (#{e.message}); retrying once with corrective note")
          attempt_note = "PREVIOUS ATTEMPT WAS REJECTED: #{e.message}. " \
                         "Return the exact JSON object shape with one result per input ASN."
          retry
        end
      end

      private

      def autodetect_backend
        return "anthropic" if ENV["ANTHROPIC_API_KEY"] && !ENV["ANTHROPIC_API_KEY"].empty?
        return "openai"    if ENV["OPENAI_API_KEY"] && !ENV["OPENAI_API_KEY"].empty?

        "claude_cli"
      end

      # Autodetection only picks an API backend when its key exists; this
      # guards the FORCED path (OPENASN_ENRICH_BACKEND=anthropic with no key),
      # which would otherwise die mid-run with a bare KeyError.
      def fetch_api_key
        case @backend
        when :anthropic
          ENV["ANTHROPIC_API_KEY"] || raise(BackendError, "backend anthropic needs ANTHROPIC_API_KEY set")
        when :openai
          ENV["OPENAI_API_KEY"] || raise(BackendError, "backend openai needs OPENAI_API_KEY set")
        end
      end

      def default_model
        case @backend
        when :anthropic then ANTHROPIC_DEFAULT_MODEL
        when :openai
          # Deliberately NO hardcoded OpenAI default: their model lineup
          # rotates and a stale guess here would silently pin old behavior.
          # (initialize only calls us when OPENASN_ENRICH_MODEL was unset,
          # so there is nothing to fall back to — fail with instructions.)
          raise(BackendError, "openai backend needs OPENASN_ENRICH_MODEL set explicitly " \
                              "(no default hardcoded on purpose; see platform.openai.com/docs/models)")
        else CLI_DEFAULT_MODEL
        end
      end

      # One usage record per request, whatever the backend calls its fields.
      # `cost` nil means "estimate from PRICES_PER_MTOK" (API backends);
      # claude_cli passes its envelope's authoritative total_cost_usd.
      def record_usage(input, output, cache_read, cost = nil)
        @stats[:input_tokens]      += input
        @stats[:output_tokens]     += output
        @stats[:cache_read_tokens] += cache_read
        @stats[:cost_usd] += cost || estimate_cost(input, output)
      end

      def estimate_cost(input, output)
        rates = price_per_mtok
        unless rates
          unless @warned_unpriced
            @warned_unpriced = true
            Env.warn("enrich llm: no $/MTok known for #{@model}; report cost will read low — " \
                     "set OPENASN_ENRICH_PRICE_PER_MTOK=\"input,output\" to fix")
          end
          return 0.0
        end
        (input * rates[0] + output * rates[1]) / 1_000_000.0
      end

      def price_per_mtok
        return @price_per_mtok if defined?(@price_per_mtok)

        @price_per_mtok = if (pair = ENV["OPENASN_ENRICH_PRICE_PER_MTOK"])
                            pair.split(",").map { |x| Float(x) }
                          else
                            PRICES_PER_MTOK[@model]
                          end
      end

      def request_json(packets, attempt_note)
        @budget.consume!
        @stats[:requests] += 1
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        text = case @backend
               when :claude_cli then call_claude_cli(packets, attempt_note)
               when :anthropic  then call_anthropic(packets, attempt_note)
               when :openai     then call_openai(packets, attempt_note)
               else raise BackendError, "unknown backend #{@backend}"
               end
        @stats[:wall_seconds] += Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
        Schema.extract_json(text)
      end

      # ---- backend: claude CLI (headless) ------------------------------------
      # `claude -p --output-format json` reads the prompt from stdin and prints
      # a JSON envelope; auth rides the operator's existing CLI login. Prompt
      # goes via stdin (not argv) to dodge ARG_MAX on fat enriched batches.
      def call_claude_cli(packets, attempt_note)
        prompt = Prompt.full_prompt(packets)
        prompt += "\n\n#{attempt_note}" if attempt_note
        cmd = ["claude", "-p", "--output-format", "json", "--model", @model]
        out, err, status = Open3.capture3(*cmd, stdin_data: prompt)
        raise BackendError, "claude CLI exit #{status.exitstatus}: #{err.strip[0, 300]}" unless status.success?

        envelope = JSON.parse(out)
        raise BackendError, "claude CLI reported error: #{envelope['result'].to_s[0, 300]}" if envelope["is_error"]

        u = envelope["usage"] || {}
        record_usage(u["input_tokens"].to_i, u["output_tokens"].to_i,
                     u["cache_read_input_tokens"].to_i, envelope["total_cost_usd"].to_f)
        envelope.fetch("result")
      rescue JSON::ParserError
        raise BackendError, "claude CLI emitted non-JSON envelope (starts: #{out.to_s[0, 120].inspect})"
      end

      # ---- backend: Anthropic Messages API ------------------------------------
      # POST /v1/messages with output_config.format (structured outputs) and a
      # cache_control breakpoint on the preamble. Auth: x-api-key header.
      # Docs: https://platform.claude.com/docs/en/build-with-claude/structured-outputs.md
      def call_anthropic(packets, attempt_note)
        user = Prompt.batch_message(packets)
        user += "\n\n#{attempt_note}" if attempt_note
        body = {
          model: @model,
          max_tokens: 8192, # ~40 results × ~120 output tokens + headroom; <16k so non-streaming is safe
          system: [{ type: "text", text: Prompt::PREAMBLE, cache_control: { type: "ephemeral" } }],
          messages: [{ role: "user", content: user }],
          output_config: { format: { type: "json_schema", schema: Schema::BATCH_JSON_SCHEMA } }
          # NOTE: no temperature/top_p — removed params, 400 on opus-4-8/fable.
        }
        response = post_json_with_retries(
          "https://api.anthropic.com/v1/messages",
          body,
          { "x-api-key" => @api_key,
            "anthropic-version" => "2023-06-01" }
        )
        if (u = response["usage"])
          # Estimated via PRICES_PER_MTOK — approximate (cache reads/writes
          # bill differently). Good enough for the report's cost line.
          record_usage(u["input_tokens"].to_i, u["output_tokens"].to_i,
                       u["cache_read_input_tokens"].to_i)
        end
        # Guard before reading content: a refusal returns 200 with an empty
        # content array (relevant if the model is ever switched to fable).
        raise BackendError, "anthropic stop_reason=#{response['stop_reason']}" if response["stop_reason"] == "refusal"

        block = Array(response["content"]).find { |b| b["type"] == "text" }
        raise BackendError, "anthropic response had no text block" unless block

        block["text"]
      end

      # ---- backend: OpenAI Chat Completions -----------------------------------
      # response_format json_schema strict:true (schema already complies with
      # strict-mode rules: required-all + additionalProperties:false).
      # Docs: https://platform.openai.com/docs/guides/structured-outputs
      def call_openai(packets, attempt_note)
        user = Prompt.batch_message(packets)
        user += "\n\n#{attempt_note}" if attempt_note
        body = {
          model: @model,
          messages: [
            { role: "system", content: Prompt::PREAMBLE },
            { role: "user", content: user }
          ],
          response_format: {
            type: "json_schema",
            json_schema: { name: "asn_classification", strict: true, schema: Schema::BATCH_JSON_SCHEMA }
          }
        }
        response = post_json_with_retries(
          "https://api.openai.com/v1/chat/completions",
          body,
          { "Authorization" => "Bearer #{@api_key}" }
        )
        if (u = response["usage"])
          record_usage(u["prompt_tokens"].to_i, u["completion_tokens"].to_i,
                       u.dig("prompt_tokens_details", "cached_tokens").to_i)
        end
        message = response.dig("choices", 0, "message") || {}
        raise BackendError, "openai refusal: #{message['refusal']}" if message["refusal"]

        message.fetch("content")
      end

      # Shared HTTP POST with retry-on-retryable (429/5xx/timeouts). 4xx other
      # than 429 raises immediately — those are our bugs, retrying spends money
      # to repeat them.
      def post_json_with_retries(url, body, headers, attempts: 4)
        uri = URI(url)
        (1..attempts).each do |attempt|
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = true
          http.open_timeout = 15
          http.read_timeout = 300 # a fat enriched batch on a big model takes a while
          request = Net::HTTP::Post.new(uri, headers.merge("Content-Type" => "application/json",
                                                           "User-Agent" => USER_AGENT))
          request.body = JSON.generate(body)
          response = begin
            http.request(request)
          rescue StandardError => e
            raise BackendError, "#{uri.host}: #{e.class}: #{e.message}" if attempt == attempts

            sleep(2**attempt)
            next
          end

          case response.code.to_i
          when 200
            begin
              return JSON.parse(response.body)
            rescue JSON::ParserError
              # A 200 with a non-JSON body (proxy/WAF interstitial, truncated
              # stream) must fail as a survivable batch error, not crash the
              # run — pilot.classify only catches BackendError.
              raise BackendError,
                    "#{uri.host} HTTP 200 with non-JSON body (starts: #{response.body.to_s[0, 120].inspect})"
            end
          when 429, 500..599
            raise BackendError, "#{uri.host} HTTP #{response.code}: #{response.body.to_s[0, 200]}" if attempt == attempts

            delay = (response["retry-after"]&.to_i&.nonzero? || 2**attempt)
            Env.warn("enrich llm: HTTP #{response.code}, retrying in #{delay}s (attempt #{attempt}/#{attempts})")
            sleep(delay)
          else
            raise BackendError, "#{uri.host} HTTP #{response.code}: #{response.body.to_s[0, 400]}"
          end
        end
      end
    end
  end
end
