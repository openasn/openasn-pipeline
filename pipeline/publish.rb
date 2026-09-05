# frozen_string_literal: true

# Stage 6: assemble the release payload in build/dist/ and (in CI) upload it
# to the rolling `latest` GitHub Release.
#
# dist/ contents = the complete, self-describing release:
#   openasn-ipv4.bin, openasn-ipv6.bin  - the artifacts (compile.rb)
#   manifest.json                       - build identity + file checksums +
#                                         source provenance + stats
#   SHA256SUMS                          - plain checksums (sha256sum -c compatible)
#   fetch-manifest.json                 - Tier B spec for clients (repo copy)
#   ATTRIBUTION.md                      - license attributions (repo copy)
#   asn-categories.csv                  - convenience CSV (CC0): the full
#                                         ASN -> category/role/flags table
#
# Upload model (founding decision; see data-repo README "What you get"): a rolling `latest` release updated nightly is the
# free-CDN distribution channel (precedent: sapics/ip-location-db,
# tn3w/IPBlocklist). A dated tag is cut weekly for pinning. Uploads happen
# via `gh` only when PUBLISH=1 - local builds never touch the network here.
#
# RubyGems noise rule: data moves through THESE releases;
# the gem never re-releases for data. Do not "helpfully" wire gem version
# bumps into this stage.

require "csv"
require "digest"
require_relative "lib/env"
require_relative "lib/asjson"
require_relative "lib/binary"
require_relative "lib/sources"
require_relative "lib/license_gate"
require_relative "lib/drift_gate"
require_relative "fetch"

module OpenASNPipeline
  module Publish
    RELEASE_TAG = "latest"

    module_function

    def run(compiled, normalized, crosscheck_stats, artifacts, http:)
      build_id = Time.at(compiled[:build_ts]).utc.iso8601

      write_asn_categories_csv(normalized, compiled)
      copy_repo_docs
      manifest = write_manifest(build_id, compiled, crosscheck_stats, artifacts, http)
      write_sha256sums

      Env.log("publish: dist/ assembled (build #{build_id})")
      upload!(manifest) if ENV["PUBLISH"] == "1"
      manifest
    end

    # The convenience CSV: everything an analyst needs without parsing
    # binary. CC0, same as the artifacts.
    def write_asn_categories_csv(normalized, compiled)
      flags_by_asn = compiled[:flags_by_asn]
      path = File.join(DIST_DIR, "asn-categories.csv")
      CSV.open("#{path}.tmp", "wb") do |csv|
        csv << %w[asn org country category network_role openasn_flags]
        normalized[:asn_meta].keys.sort.each do |asn|
          rec = normalized[:asn_meta][asn]
          flags = flags_by_asn[asn]
          csv << [asn, rec.description, rec.country,
                  AsJson::CATEGORY_NAMES[flags & Binary::CATEGORY_MASK],
                  AsJson::ROLE_NAMES[(flags & Binary::ROLE_MASK) >> Binary::ROLE_SHIFT],
                  flag_names(flags).join("|")]
        end
      end
      File.rename("#{path}.tmp", path)
    end

    def flag_names(flags)
      names = []
      names << "bad_asn"        if flags.anybits?(Binary::FLAG_BAD_ASN)
      names << "vpn_provider"   if flags.anybits?(Binary::FLAG_VPN_PROVIDER)
      names << "mobile_carrier" if flags.anybits?(Binary::FLAG_MOBILE)
      names << "enterprise_gw"  if flags.anybits?(Binary::FLAG_ENTERPRISE_GW)
      names << "cdn"            if flags.anybits?(Binary::FLAG_CDN)
      names << "hosting_extra"  if flags.anybits?(Binary::FLAG_HOSTING_EXTRA)
      names
    end

    def copy_repo_docs
      FileUtils.cp(Env.attribution_path, File.join(DIST_DIR, "ATTRIBUTION.md"))
      FileUtils.cp(Env.fetch_manifest_path, File.join(DIST_DIR, "fetch-manifest.json"))
    end

    def write_manifest(build_id, compiled, crosscheck_stats, artifacts, http)
      pins = LicenseGate.load_pins

      files = %w[openasn-ipv4.bin openasn-ipv6.bin openasn-orgs.bin asn-categories.csv fetch-manifest.json ATTRIBUTION.md].map do |name|
        path = File.join(DIST_DIR, name)
        {
          name: name,
          sha256: Digest::SHA256.file(path).hexdigest,
          bytes: File.size(path),
          records: records_for(name, artifacts, path)
        }
      end

      sources = Sources::CATALOG.map do |src|
        {
          id: src[:id], url: src[:url], license: src[:license],
          license_sha256: pins.dig(src[:id], "sha256"),
          fetched_at: fetched_at_for(src[:id], http, build_id)
        }
      end

      manifest = {
        format_version: FORMAT_VERSION,
        # Open-core contract (data-repo DECISIONS.md D-IMPL-5): the free edition is and stays "core".
        # Future signed Pro artifacts will use this same manifest shape plus
        # a real `signature` - keep the key present-but-null so clients can
        # feature-detect without a schema change.
        edition: "core",
        build_id: build_id,
        files: files,
        sources: sources,
        stats: manifest_stats(artifacts, crosscheck_stats),
        signature: nil
      }

      File.write(File.join(DIST_DIR, "manifest.json"), JSON.pretty_generate(manifest) + "\n")
      manifest
    end

    # stats = layer counts + crosscheck figures + (only when something
    # happened) the drift-gate audit trail: `drift_ack` carries the operator's
    # OPENASN_ACK_DRIFT reason and the gate(s) it overrode, `drift_recovery`
    # the gate(s) that passed as a snap-back to the weekly-pin baseline. Both
    # are absent on a normal night, so the usual manifest shape is unchanged.
    # (lib/drift_gate.rb; data-repo DECISIONS.md D-GATE-1)
    def manifest_stats(artifacts, crosscheck_stats)
      {
        layer_counts: {
          base_ipv4: artifacts[:ipv4].counts[:base],
          vpn_ipv4: artifacts[:ipv4].counts[:vpn],
          dc_ipv4: artifacts[:ipv4].counts[:dc],
          base_ipv6: artifacts[:ipv6].counts[:base]
        }
      }.merge(crosscheck_stats || {}).merge(DriftGate.manifest_stamp)
    end

    def records_for(name, artifacts, path)
      case name
      when "openasn-ipv4.bin" then artifacts[:ipv4].counts[:base]
      when "openasn-ipv6.bin" then artifacts[:ipv6].counts[:base]
      when "openasn-orgs.bin" then File.binread(path, 16)[8, 4].unpack1("N")
      when /\.csv\z/ then File.foreach(path).count - 1
      else 0
      end
    end

    # Manifest source id -> the fetch cache keys (Fetch::KEYS) whose bytes
    # feed that source's contribution to the build. Multi-file sources
    # report the OLDEST fetched_at among their files - "no input byte is
    # older than this" is the claim a provenance consumer actually needs.
    # (fetched_at values are ISO-8601 UTC strings, so String#min IS
    # chronological order.)
    SOURCE_FETCH_KEYS = {
      "sapics-origin-asn"      => %i[sapics_v4 sapics_v6],
      "ipverse-as-metadata"    => %i[as_json],
      "x4bnet-lists_vpn"       => %i[x4b_vpn x4b_dc x4b_vpn_asn x4b_dc_asn],
      "brianhama-bad-asn-list" => %i[bad_asn]
    }.freeze

    # Honest provenance only (this used to default to Time.now for anything
    # unmapped, which stamped fiction into manifest.json):
    #   * openasn-overrides    -> build_id: the data-repo checkout IS made at
    #     build time in CI (nightly-build.yml checks it out fresh each run).
    #   * ipverse-as-ip-blocks -> nil: fetched per-ASN on demand during
    #     compile (compile.rb gap-fill), so there is no single timestamp.
    #   * unknown ids          -> nil, so a future CATALOG addition surfaces
    #     as missing provenance instead of a silently wrong timestamp
    #     (test/publish_test.rb walks CATALOG to catch drift).
    def fetched_at_for(source_id, http, build_id)
      case source_id
      when "openasn-overrides" then build_id
      when "ipverse-as-ip-blocks" then nil
      else
        keys = SOURCE_FETCH_KEYS.fetch(source_id) { return nil }
        keys.filter_map { |k| http.fetched_at(Fetch::KEYS[k]) }.min
      end
    end

    # manifest.json is deliberately NOT in SHA256SUMS: it is the checksum
    # authority (the gem verifies .bin downloads against manifest hashes);
    # SHA256SUMS exists for humans and shell scripts.
    def write_sha256sums
      lines = Dir.children(DIST_DIR).sort.reject { |f| f == "SHA256SUMS" || f == "manifest.json" }.map do |f|
        "#{Digest::SHA256.file(File.join(DIST_DIR, f)).hexdigest}  #{f}"
      end
      File.write(File.join(DIST_DIR, "SHA256SUMS"), lines.join("\n") + "\n")
    end

    # ------------------------------------------------------------------
    # GitHub "Latest" badge semantics - THE gotcha of this stage.
    #
    # GitHub has two asset-URL shapes that look interchangeable but are not:
    #
    #   releases/download/<TAG>/<file>   - addressed by TAG. Stable. This is
    #                                      what we tell every consumer to use
    #                                      (our rolling tag is literally
    #                                      named "latest").
    #   releases/latest/download/<file>  - addressed by the "Latest" BADGE,
    #                                      i.e. whatever release GitHub
    #                                      currently marks as latest.
    #     https://docs.github.com/en/repositories/releasing-projects-on-github/linking-to-releases
    #
    # The badge is assigned at release creation: the REST param `make_latest`
    # DEFAULTS TO "true" for every newly published release
    # (https://docs.github.com/en/rest/releases/releases#create-a-release),
    # and `gh release create` sends nothing unless you pass --latest/
    # --latest=false (https://cli.github.com/manual/gh_release_create).
    #
    # INCIDENT 2026-07-05 (first Sunday after going public): the first weekly
    # dated snapshot was created without --latest=false, stole the badge from
    # the rolling release, and `releases/latest/download/...` began serving
    # the frozen snapshot - which would have gone up to 6 days stale before
    # anyone noticed. Hence, invariants enforced below and unit-tested in
    # test/publish_test.rb:
    #
    #   1. dated releases are ALWAYS created with --latest=false;
    #   2. every nightly re-asserts --latest on the rolling release
    #      (self-healing if a manual/human release ever steals the badge);
    #   3. all notes/docs point consumers at the TAG-addressed URL form.
    #
    # Data-repo record of this decision: DECISIONS.md D-REL-1.
    # ------------------------------------------------------------------

    # Release titles are re-stamped on every publish, because the title is
    # the only freshness signal the repo-home sidebar gives us: the sidebar's
    # relative time ("17 hours ago") is the release object's CREATION time,
    # which never advances for a rolling release whose assets are merely
    # re-uploaded - by design it looks ever-staler. The sidebar also truncates
    # titles at roughly 25-30 chars (observed 2026-07-05), so the date must
    # clear that cut. Both titles follow the cross-project "<Project>
    # <dotted-version>" standard shared with VehiclesDB (which titles releases
    # "VehiclesDB 2026.07.3"); here the version IS the date, so "OpenASN
    # 2026.07.07" is project-named AND date-led at once — the short "OpenASN "
    # lead (8 chars) keeps the full date inside the truncation window. The
    # " · <stream>" suffix disambiguates OpenASN's two streams (rolling vs
    # pinned) in the releases list — on Sundays both carry the same date.
    # Dates are dotted (never hyphenated) to match the vYYYY.MM.DD tag family.
    def rolling_title(manifest)
      "OpenASN #{manifest.fetch(:build_id)[0, 10].tr('-', '.')} · Nightly rolling"
    end

    def dated_title(tag)
      "OpenASN #{tag.delete_prefix('v')} · Weekly snapshot"
    end

    # The gh invocations are built by pure functions (unit-testable without
    # a gh binary or network; see test/publish_test.rb) and executed by gh!.

    def rolling_create_args(manifest)
      ["release", "create", RELEASE_TAG, "--repo", PUBLISH_REPO,
       "--title", rolling_title(manifest),
       "--notes", rolling_release_notes(manifest),
       "--latest"]
    end

    # `gh release edit` re-stamps the title + body with the current build
    # and re-asserts the badge (invariant 2 above) after every asset upload.
    def rolling_edit_args(manifest)
      ["release", "edit", RELEASE_TAG, "--repo", PUBLISH_REPO,
       "--title", rolling_title(manifest),
       "--notes", rolling_release_notes(manifest),
       "--latest"]
    end

    # "--latest=false" MUST be a single argv element: gh only accepts the
    # `=false` form for negating boolean flags ("--latest", "false" would be
    # parsed as a stray positional arg).
    def dated_create_args(tag, manifest, files)
      ["release", "create", tag, "--repo", PUBLISH_REPO,
       "--title", dated_title(tag),
       "--notes", dated_release_notes(tag, manifest),
       "--latest=false",
       *files]
    end

    # Releases live on the DATA repo (PUBLISH_REPO = openasn/openasn) — the
    # public flagship where users download from and the gem's default
    # release_url points. This pipeline repo only compiles.
    # Requires: gh CLI authenticated with write access to PUBLISH_REPO
    # (locally: your gh login; in the data repo's Actions: its own
    # GITHUB_TOKEN, since the workflow runs in that repo).
    def upload!(manifest)
      unless system("gh --version", out: File::NULL, err: File::NULL)
        Env.fail_stage!("PUBLISH=1 but gh CLI is not available")
      end

      repo_args = ["--repo", PUBLISH_REPO]
      unless system("gh", "release", "view", RELEASE_TAG, *repo_args, out: File::NULL, err: File::NULL)
        Env.log("creating rolling release '#{RELEASE_TAG}' on #{PUBLISH_REPO}")
        ok = system("gh", *rolling_create_args(manifest))
        Env.fail_stage!("could not create release #{RELEASE_TAG}") unless ok
      end

      files = Dir[File.join(DIST_DIR, "*")]
      ok = system("gh", "release", "upload", RELEASE_TAG, *repo_args, *files, "--clobber")
      Env.fail_stage!("release upload failed") unless ok
      Env.log("publish: uploaded #{files.size} assets to #{PUBLISH_REPO} release '#{RELEASE_TAG}'")

      # Assets are already uploaded, so a failure here cannot corrupt data -
      # but a lost "Latest" badge silently misroutes every badge-URL consumer
      # to stale bytes, so it still fails the nightly loudly (which opens the
      # pipeline-failure issue via nightly-build.yml).
      ok = system("gh", *rolling_edit_args(manifest))
      Env.fail_stage!("rolling release edit failed (notes stamp + Latest badge re-assert; note: assets DID upload)") unless ok
      Env.log("publish: rolling notes stamped (build #{manifest[:build_id]}), Latest badge asserted")

      # Weekly dated tag for version pinning (gem config: pin_version).
      # The workflow sets OPENASN_DATED_TAG on Sundays / manual dispatch.
      # Tag format vYYYY.MM.DD — the cross-project release-naming standard
      # (VehiclesDB uses vYYYY.MM.P for its monthly cadence): v-prefixed,
      # dot-separated, hyphen-free, lexicographic order == chronological.
      # (The one pre-standard 2026-07-05 tag was renamed to v2026.07.05.)
      return unless ENV["OPENASN_DATED_TAG"] == "1"

      tag = Time.now.utc.strftime("v%Y.%m.%d")
      if system("gh", "release", "view", tag, *repo_args, out: File::NULL, err: File::NULL)
        Env.log("dated release #{tag} already exists - skipping")
      else
        ok = system("gh", *dated_create_args(tag, manifest, files))
        Env.fail_stage!("could not create dated release #{tag}") unless ok
        Env.log("publish: cut dated release #{tag} (badge stays on '#{RELEASE_TAG}')")
      end
    end

    # Release bodies are HUMAN-facing convenience; machines must keep reading
    # manifest.json (build_id, per-file SHA-256, provenance). The build stamp
    # below is still deliberately grep-able (backticked ISO-8601) for quick
    # shell checks. KEEP the badge-form warning and its URL on one physical
    # line - test/publish_test.rb asserts any badge-form mention sits on a
    # "do not use" line, so a reflow here will fail the suite (that's the
    # point: the warning must never drift apart from the URL it warns about).
    def rolling_release_notes(manifest)
      counts = manifest.dig(:stats, :layer_counts) || {}
      <<~NOTES
        Nightly-updated OpenASN data artifacts.

        **Current build: `#{manifest[:build_id]}`** · #{counts[:base_ipv4]} IPv4 / #{counts[:base_ipv6]} IPv6 base records · IPv4 overlays: #{counts[:vpn_ipv4]} vpn, #{counts[:dc_ipv4]} dc

        **Always fetch via the tag-addressed form** `releases/download/latest/<file>`, e.g.
        `https://github.com/#{PUBLISH_REPO}/releases/download/latest/manifest.json` —
        assets here are replaced every night by CI.
        Do NOT use `releases/latest/download/<file>` — that shape resolves via GitHub's "Latest" badge, not this tag, and can silently serve a stale weekly snapshot (see the data repo's DECISIONS.md D-REL-1).

        | File | What |
        |---|---|
        | `openasn-ipv4.bin` / `openasn-ipv6.bin` | packed classification artifacts (format: FORMAT.md) |
        | `manifest.json` | build id, per-file SHA-256, source provenance |
        | `asn-categories.csv` | full ASN → category/role/flags table (CC0) |
        | `fetch-manifest.json` | Tier B source spec executed by clients |
        | `ATTRIBUTION.md` | upstream attributions |
        | `SHA256SUMS` | `sha256sum -c` compatible checksums |

        Need a build that never changes underneath you? Pin a weekly dated release (`vYYYY.MM.DD` tags).
        Data license: CC0-1.0. Code: MIT.
      NOTES
    end

    def dated_release_notes(tag, manifest)
      counts = manifest.dig(:stats, :layer_counts) || {}
      <<~NOTES
        Weekly pinnable snapshot — build `#{manifest[:build_id]}`. Assets on this tag are never rewritten.

        #{counts[:base_ipv4]} IPv4 / #{counts[:base_ipv6]} IPv6 base records · IPv4 overlays: #{counts[:vpn_ipv4]} vpn, #{counts[:dc_ipv4]} dc

        Pin it from the gem (`config.pin_version = "#{tag}"`) or download directly:
        `https://github.com/#{PUBLISH_REPO}/releases/download/#{tag}/<file>`

        For freshness prefer the rolling release — replaced nightly at the tag-addressed URL
        `https://github.com/#{PUBLISH_REPO}/releases/download/latest/<file>`.
      NOTES
    end
  end
end
