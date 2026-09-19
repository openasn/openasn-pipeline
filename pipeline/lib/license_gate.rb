# frozen_string_literal: true

# The license gate (data-repo README "Legal design" rule 4): every build re-downloads each upstream
# license-declaring file, extracts the license-bearing text, and compares its
# SHA-256 against the pinned hash in data/licenses/pins.json.
#
# ANY mismatch fails the build. That is the point: licenses have changed
# underneath projects before (MaxMind, Dec 2019), and continuing to ship data
# under a revoked or altered grant is legal exposure, not a build hiccup.
# When the gate trips: read the new text, decide with a human (and if the
# grant genuinely changed, likely with a lawyer) whether the source is still
# eligible, then re-pin via `rake licenses:pin` in the same reviewed PR.
#
# In GitHub Actions, a trip additionally opens an issue automatically
# (see nightly-build.yml in the data repo, which runs this pipeline).
#
# SCOPES. `:tier_a` (Sources.license_urls: LICENSE_URLS for the selected backbone) is what the nightly checks: the
# inputs of the published artifact. `:curation` (Sources::CURATION_TERMS_URLS)
# pins the terms of inputs read only as build-time curation evidence (RIR
# delegated stats, D-SRC-1); the tools that read them check that scope, and it
# never blocks a publish that does not contain them. Curation pins carry
# "scope": "curation" in pins.json; Tier A entries keep their original shape.

require "digest"
require_relative "env"
require_relative "sources"

module OpenASNPipeline
  module LicenseGate
    SCOPES = %i[tier_a curation].freeze

    module_function

    # Pins live in the DATA repo (they are provenance receipts for the
    # published data, and belong next to it) — resolved lazily.
    def pins_path = File.join(Env.licenses_dir, "pins.json")

    # { source_id => spec } for the requested scope(s); spec gains :scope.
    def specs(scope = :tier_a)
      scopes = scope == :all ? SCOPES : [scope]
      unknown = scopes - SCOPES
      raise ArgumentError, "unknown license scope #{unknown.inspect}" if unknown.any?

      out = {}
      out.merge!(Sources.license_urls.transform_values { _1.merge(scope: :tier_a) }) if scopes.include?(:tier_a)
      out.merge!(Sources::CURATION_TERMS_URLS.transform_values { _1.merge(scope: :curation) }) if scopes.include?(:curation)
      out
    end

    def run(http: Http.new, offline: ENV["OFFLINE"] == "1", scope: :tier_a)
      if offline
        Env.warn("license gate (#{scope}) SKIPPED (offline mode) - never publish an offline build")
        return
      end

      pins = load_pins
      failures = []

      specs(scope).each do |source_id, spec|
        live_text = extract(http.get!(spec[:url]), spec[:extract], source_id)
        live_sha  = Digest::SHA256.hexdigest(live_text)
        pinned    = pins.dig(source_id, "sha256")

        if pinned.nil?
          failures << "#{source_id}: no pin recorded - run `rake licenses:pin` and review data/licenses/"
        elsif live_sha != pinned
          # Save what we saw so the failure is diagnosable from CI logs alone.
          drift_path = File.join(WORK_DIR, "license-drift-#{source_id}.txt")
          FileUtils.mkdir_p(WORK_DIR)
          File.write(drift_path, live_text)
          failures << "#{source_id}: LICENSE TEXT CHANGED (pinned #{pinned[0, 12]}…, live #{live_sha[0, 12]}…). " \
                      "Live copy saved to #{drift_path}. Review before re-pinning."
        else
          Env.log("license gate: #{source_id} OK (#{live_sha[0, 12]}…)")
        end
      end

      Env.fail_stage!("LICENSE GATE FAILED:\n  - #{failures.join("\n  - ")}") if failures.any?
    end

    # Re-pin sources to whatever is live right now, and store the full
    # human-readable text alongside. Only ever run this deliberately, inside
    # a reviewed PR that states why the license text changed.
    #
    # only: an Array of source ids to (re-)pin; every other existing pin and
    # its .txt copy is left byte-for-byte untouched. Use it when ADDING a
    # source, so the review is not asked to re-approve pins nobody re-read.
    # nil (the default) re-pins everything, as before.
    def pin!(http: Http.new, only: nil)
      all = specs(:all)
      if only
        unknown = only - all.keys
        raise ArgumentError, "licenses:pin ONLY= names unknown source ids: #{unknown.join(', ')}" if unknown.any?
      end

      FileUtils.mkdir_p(Env.licenses_dir)
      pins = only ? load_pins : {}
      all.each do |source_id, spec|
        next if only && !only.include?(source_id)

        text = extract(http.get!(spec[:url]), spec[:extract], source_id)
        pins[source_id] = pin_entry(spec, text)
        File.binwrite(File.join(Env.licenses_dir, "#{source_id}.txt"), text)
        Env.log("pinned #{source_id} (#{pins[source_id]['sha256'][0, 12]}…)")
      end
      File.write(pins_path, JSON.pretty_generate(pins) + "\n")
    end

    def pin_entry(spec, text)
      entry = {
        "url" => spec[:url],
        "extract" => spec[:extract].to_s,
        "sha256" => Digest::SHA256.hexdigest(text),
        "pinned_at" => Time.now.utc.iso8601
      }
      entry["scope"] = spec[:scope].to_s unless spec[:scope] == :tier_a
      entry
    end

    def load_pins
      return {} unless File.exist?(pins_path)

      JSON.parse(File.read(pins_path))
    end

    # X4BNet declares MIT inside README.md under "# License" (they have no
    # LICENSE file - verified 2026-07-04). We pin from that heading through
    # the fenced block that contains the license text, so routine README
    # churn (stats tables, usage docs) can't trip the gate but any edit to
    # the grant or to the crucial "source files and generated output"
    # sentence does.
    #
    # APNIC/AFRINIC README-EXTENDED: section "2. CONDITIONS OF USE" up to the
    # "3. STATISTICS FORMAT" heading (verified 2026-09-19), whitespace kept
    # verbatim - a reworded grant must trip the gate.
    def extract(body, mode, source_id)
      case mode
      when :whole_file
        body
      when :license_heading_section
        m = body.match(/^#+\s*License\s*$(.*?^```.*?^```)/m)
        Env.fail_stage!("#{source_id}: could not extract License section - README structure changed, INVESTIGATE") unless m

        "# License#{m[1]}"
      when :wp_json_rendered_text
        # RouteViews: WordPress REST rendering of the licence page. Tags are
        # stripped and whitespace collapsed so only the words are pinned.
        html = JSON.parse(body).dig("content", "rendered")
        Env.fail_stage!("#{source_id}: licence JSON has no content.rendered - endpoint changed, INVESTIGATE") unless html.is_a?(String)

        "#{html.gsub(/<[^>]+>/, ' ').gsub(/\s+/, ' ').strip}\n"
      when :conditions_of_use_section
        text = body.dup.force_encoding("UTF-8").scrub
        m = text.match(/^(2\.[ \t]+CONDITIONS OF USE[ \t]*\r?\n.*?)^3\.[ \t]+STATISTICS FORMAT/m)
        Env.fail_stage!("#{source_id}: could not extract CONDITIONS OF USE section - README structure changed, INVESTIGATE") unless m

        m[1]
      else
        Env.fail_stage!("unknown license extract mode #{mode.inspect} for #{source_id}")
      end
    end
  end
end
