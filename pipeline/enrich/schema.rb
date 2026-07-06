# frozen_string_literal: true

# The label taxonomy + output contract for the LLM enrichment loop.
#
# DESIGN: we do NOT adopt Linnaeus's 18/38 academic taxonomy
# (arXiv:2603.13649). We ask for labels that map to ACTIONS OpenASN can take —
# override-file candidates, corrections, or traits-only rows. Multi-label on
# purpose: AS7018 (AT&T) is access_eyeball AND pure_transit_backbone; that
# multi-label insight is the one thing we do take from the paper wholesale.
#
# CONTRACT RULES (violations here are bugs, not style):
#   * LLM output NEVER writes to data/overrides/ — it lands in review queues.
#   * These labels are pipeline-internal. They are NOT the gem's verdict enum
#     (which is an append-only cross-language contract, DECISIONS.md D-IMPL-6)
#     and must never leak into artifacts or client APIs.
#   * The JSON schema below is written for STRICT structured outputs on both
#     major APIs. Compat constraints (verified against provider docs 2026-07):
#       - every property listed in `required` (OpenAI strict:true mandates
#         required-all; Anthropic tolerates but we keep one shape)
#       - additionalProperties: false on every object
#       - nullable via {"anyOf": [X, {"type":"null"}]} (union types like
#         ["string","null"] are less portable)
#       - NO minimum/maximum/minLength (unsupported by Anthropic structured
#         outputs; enforced in validate_results! instead)
#     Anthropic docs: https://platform.claude.com/docs/en/build-with-claude/structured-outputs.md
#     OpenAI docs:    https://platform.openai.com/docs/guides/structured-outputs

require "json"

module OpenASNPipeline
  module Enrich
    module Schema
      # Multi-label classification vocabulary. Keep the one-line meanings in
      # prompt.rb in sync — the prompt text IS the operational definition.
      LABELS = %w[
        access_eyeball
        mobile_carrier
        pure_transit_backbone
        hosting_provider
        cloud_provider
        cdn
        vpn_provider
        enterprise_gateway
        education
        government
        business
        ixp
        dns_infrastructure
        satellite
        personal
      ].freeze

      # What OpenASN should DO with the classification. Maps 1:1 to curation
      # destinations: override files, corrections.yml, or none (traits-only).
      # "none" is the common case and that is fine.
      ACTIONS = %w[
        none
        eyeball_confirm
        mobile_carrier
        hosting_extra
        cdn
        vpn_provider
        enterprise_gateway
        correction
      ].freeze

      # action -> label that must be present for the action to make sense.
      # Mismatches are soft-coerced to "none" + needs_review (a wrong action
      # suggestion must never survive into a review queue silently).
      ACTION_REQUIRES_LABEL = {
        "eyeball_confirm"    => "access_eyeball",
        "mobile_carrier"     => "mobile_carrier",
        "hosting_extra"      => "hosting_provider",
        "cdn"                => "cdn",
        "vpn_provider"       => "vpn_provider",
        "enterprise_gateway" => "enterprise_gateway"
      }.freeze

      # ipverse as-metadata category vocabulary (for `correction` proposals).
      # Mirrors AsJson::CATEGORY_CODES keys; "none" = upstream should have no
      # category at all.
      CORRECTION_CATEGORIES = %w[isp hosting business education_research government_admin none].freeze

      # One classified ASN, normalized.
      Result = Struct.new(
        :asn, :labels, :openasn_action, :correction, :confidence,
        :evidence, :evidence_url, :needs_review, :risk_note,
        keyword_init: true
      ) do
        def to_h_compact
          { asn: asn, labels: labels, openasn_action: openasn_action,
            correction: correction, confidence: confidence, evidence: evidence,
            evidence_url: evidence_url, needs_review: needs_review,
            risk_note: risk_note }
        end

        # Inverse of to_h_compact, for the checkpoint/resume JSONL round-trip.
        # Kept HERE, next to to_h_compact, so a new field gets added to both
        # or neither — keyword_init silently nils a field forgotten on either
        # side, and a resumed report would quietly compute on lossy rows.
        def self.from_h(h)
          new(asn: h["asn"], labels: h["labels"], openasn_action: h["openasn_action"],
              correction: h["correction"], confidence: h["confidence"],
              evidence: h["evidence"], evidence_url: h["evidence_url"],
              needs_review: h["needs_review"], risk_note: h["risk_note"])
        end
      end

      RESULT_JSON_SCHEMA = {
        "type" => "object",
        "additionalProperties" => false,
        "required" => %w[asn labels openasn_action correction confidence evidence evidence_url needs_review risk_note],
        "properties" => {
          "asn" => { "type" => "integer" },
          "labels" => { "type" => "array", "items" => { "type" => "string", "enum" => LABELS } },
          "openasn_action" => { "type" => "string", "enum" => ACTIONS },
          "correction" => {
            "anyOf" => [
              { "type" => "null" },
              {
                "type" => "object",
                "additionalProperties" => false,
                "required" => %w[category],
                "properties" => { "category" => { "type" => "string", "enum" => CORRECTION_CATEGORIES } }
              }
            ]
          },
          "confidence" => { "type" => "number" },
          "evidence" => { "type" => "string" },
          "evidence_url" => { "anyOf" => [{ "type" => "string" }, { "type" => "null" }] },
          "needs_review" => { "type" => "boolean" },
          "risk_note" => { "anyOf" => [{ "type" => "string" }, { "type" => "null" }] }
        }
      }.freeze

      # Root must be an object (both providers reject top-level arrays for
      # structured outputs).
      BATCH_JSON_SCHEMA = {
        "type" => "object",
        "additionalProperties" => false,
        "required" => %w[results],
        "properties" => {
          "results" => { "type" => "array", "items" => RESULT_JSON_SCHEMA }
        }
      }.freeze

      class ValidationError < StandardError; end

      module_function

      # Validate + normalize a parsed batch response against the ASNs we sent.
      #
      # HARD errors (raise -> caller retries the batch once with the error
      # text appended; models fix echo/enum mistakes reliably on retry):
      #   * missing/duplicated/foreign ASNs (echo integrity — result rows must
      #     be attributable to inputs or the whole batch is worthless)
      #   * unknown labels / actions (enum drift)
      #   * confidence outside [0,1] (schema can't enforce ranges, we do)
      # SOFT fixes (normalize + flag, never raise):
      #   * action whose required label is absent -> action "none",
      #     needs_review true (a suggestion the model itself didn't label
      #     must not reach a human queue looking legitimate)
      #
      # Returns Results ordered to match expected_asns.
      def validate_results!(parsed, expected_asns)
        raise ValidationError, "response is not a JSON object" unless parsed.is_a?(Hash)

        rows = parsed["results"]
        raise ValidationError, "missing 'results' array" unless rows.is_a?(Array)

        by_asn = {}
        rows.each do |row|
          raise ValidationError, "result row is not an object: #{row.inspect[0, 120]}" unless row.is_a?(Hash)

          asn = row["asn"]
          raise ValidationError, "row asn is not an integer: #{asn.inspect}" unless asn.is_a?(Integer)
          raise ValidationError, "duplicate result for AS#{asn}" if by_asn.key?(asn)

          by_asn[asn] = row
        end

        missing = expected_asns - by_asn.keys
        foreign = by_asn.keys - expected_asns
        unless missing.empty? && foreign.empty?
          raise ValidationError,
                "asn echo mismatch (missing: #{missing.take(5).join(',')}#{'…' if missing.size > 5}; " \
                "unexpected: #{foreign.take(5).join(',')}#{'…' if foreign.size > 5})"
        end

        expected_asns.map { |asn| normalize_row(asn, by_asn[asn]) }
      end

      def normalize_row(asn, row)
        labels = Array(row["labels"]).map(&:to_s)
        unknown = labels - LABELS
        raise ValidationError, "AS#{asn}: unknown labels #{unknown.join(',')}" unless unknown.empty?

        action = (row["openasn_action"] || "none").to_s
        raise ValidationError, "AS#{asn}: unknown action #{action}" unless ACTIONS.include?(action)

        confidence = row["confidence"]
        raise ValidationError, "AS#{asn}: confidence not a number" unless confidence.is_a?(Numeric)
        raise ValidationError, "AS#{asn}: confidence #{confidence} outside [0,1]" if confidence.negative? || confidence > 1

        # The JSON schema's correction-category enum is only server-enforced
        # on the API backends; the claude-CLI backend has none, so re-check
        # here. Enum drift is a HARD error like unknown labels/actions — the
        # retry-with-note fixes it; a bogus category must never reach a
        # review queue looking legitimate.
        correction = row["correction"]
        if correction.is_a?(Hash) && !CORRECTION_CATEGORIES.include?(correction["category"])
          raise ValidationError,
                "AS#{asn}: unknown correction category #{correction['category'].inspect}"
        end

        needs_review = row["needs_review"] ? true : false
        # Soft-coerce inconsistent action suggestions (see method comment).
        if (required = ACTION_REQUIRES_LABEL[action]) && !labels.include?(required)
          action = "none"
          needs_review = true
        end
        if action == "correction" && !correction.is_a?(Hash)
          action = "none"
          needs_review = true
        end

        Result.new(
          asn: asn, labels: labels, openasn_action: action,
          correction: correction, confidence: confidence.to_f.round(3),
          evidence: row["evidence"].to_s[0, 300], evidence_url: row["evidence_url"],
          needs_review: needs_review, risk_note: row["risk_note"]
        )
      end

      # Pull a JSON object out of model text that may carry prose or code
      # fences around it. Used by the claude-CLI backend (no server-side
      # structured outputs there); the API backends normally return pure JSON
      # but go through this too — belt and suspenders costs nothing.
      def extract_json(text)
        raise ValidationError, "empty model output" if text.nil? || text.strip.empty?

        candidates = []
        candidates << text.strip
        # ```json ... ``` fence (models add these despite instructions)
        text.scan(/```(?:json)?\s*(\{.*?\})\s*```/m) { |m| candidates << m[0] }
        # widest {...} span as last resort (prose before/after the object)
        first = text.index("{")
        last  = text.rindex("}")
        candidates << text[first..last] if first && last && last > first

        candidates.each do |cand|
          return JSON.parse(cand)
        rescue JSON::ParserError
          next
        end
        raise ValidationError, "no parseable JSON object in model output (starts: #{text.strip[0, 120].inspect})"
      end
    end
  end
end
