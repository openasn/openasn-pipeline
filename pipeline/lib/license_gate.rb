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

require "digest"
require_relative "env"
require_relative "sources"

module OpenASNPipeline
  module LicenseGate
    module_function

    # Pins live in the DATA repo (they are provenance receipts for the
    # published data, and belong next to it) — resolved lazily.
    def pins_path = File.join(Env.licenses_dir, "pins.json")

    def run(http: Http.new, offline: ENV["OFFLINE"] == "1")
      if offline
        Env.warn("license gate SKIPPED (offline mode) - never publish an offline build")
        return
      end

      pins = load_pins
      failures = []

      Sources::LICENSE_URLS.each do |source_id, spec|
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

    # Re-pin all sources to whatever is live right now, and store the full
    # human-readable text alongside. Only ever run this deliberately, inside
    # a reviewed PR that states why the license text changed.
    def pin!(http: Http.new)
      FileUtils.mkdir_p(Env.licenses_dir)
      pins = {}
      Sources::LICENSE_URLS.each do |source_id, spec|
        text = extract(http.get!(spec[:url]), spec[:extract], source_id)
        pins[source_id] = {
          "url" => spec[:url],
          "extract" => spec[:extract].to_s,
          "sha256" => Digest::SHA256.hexdigest(text),
          "pinned_at" => Time.now.utc.iso8601
        }
        File.write(File.join(Env.licenses_dir, "#{source_id}.txt"), text)
        Env.log("pinned #{source_id} (#{pins[source_id]['sha256'][0, 12]}…)")
      end
      File.write(pins_path, JSON.pretty_generate(pins) + "\n")
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
    def extract(body, mode, source_id)
      case mode
      when :whole_file
        body
      when :license_heading_section
        m = body.match(/^#+\s*License\s*$(.*?^```.*?^```)/m)
        Env.fail_stage!("#{source_id}: could not extract License section - README structure changed, INVESTIGATE") unless m

        "# License#{m[1]}"
      else
        Env.fail_stage!("unknown license extract mode #{mode.inspect} for #{source_id}")
      end
    end
  end
end
