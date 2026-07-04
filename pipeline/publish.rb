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
# Upload model (PRD D3): a rolling `latest` release updated nightly is the
# free-CDN distribution channel (precedent: sapics/ip-location-db,
# tn3w/IPBlocklist). A dated tag is cut weekly for pinning. Uploads happen
# via `gh` only when PUBLISH=1 - local builds never touch the network here.
#
# RubyGems noise rule (PRD gotcha 19): data moves through THESE releases;
# the gem never re-releases for data. Do not "helpfully" wire gem version
# bumps into this stage.

require "csv"
require "digest"
require_relative "lib/env"
require_relative "lib/asjson"
require_relative "lib/binary"
require_relative "lib/sources"
require_relative "lib/license_gate"
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
      upload! if ENV["PUBLISH"] == "1"
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
          fetched_at: fetched_at_for(src[:id], http)
        }
      end

      manifest = {
        format_version: FORMAT_VERSION,
        # Open-core contract (PRD §16): the free edition is and stays "core".
        # Future signed Pro artifacts will use this same manifest shape plus
        # a real `signature` - keep the key present-but-null so clients can
        # feature-detect without a schema change.
        edition: "core",
        build_id: build_id,
        files: files,
        sources: sources,
        stats: {
          layer_counts: {
            base_ipv4: artifacts[:ipv4].counts[:base],
            vpn_ipv4: artifacts[:ipv4].counts[:vpn],
            dc_ipv4: artifacts[:ipv4].counts[:dc],
            base_ipv6: artifacts[:ipv6].counts[:base]
          }
        }.merge(crosscheck_stats || {}),
        signature: nil
      }

      File.write(File.join(DIST_DIR, "manifest.json"), JSON.pretty_generate(manifest) + "\n")
      manifest
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

    def fetched_at_for(source_id, http)
      key = {
        "sapics-origin-asn" => Fetch::KEYS[:sapics_v4],
        "ipverse-as-metadata" => Fetch::KEYS[:as_json],
        "x4bnet-lists_vpn" => Fetch::KEYS[:x4b_vpn],
        "brianhama-bad-asn-list" => Fetch::KEYS[:bad_asn]
      }[source_id]
      key ? http.fetched_at(key) : Time.now.utc.iso8601
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

    # Releases live on the DATA repo (PUBLISH_REPO = openasn/openasn) — the
    # public flagship where users download from and the gem's default
    # release_url points. This pipeline repo only compiles.
    # Requires: gh CLI authenticated with write access to PUBLISH_REPO
    # (locally: your gh login; in the data repo's Actions: its own
    # GITHUB_TOKEN, since the workflow runs in that repo).
    def upload!
      unless system("gh --version", out: File::NULL, err: File::NULL)
        Env.fail_stage!("PUBLISH=1 but gh CLI is not available")
      end

      repo_args = ["--repo", PUBLISH_REPO]
      unless system("gh", "release", "view", RELEASE_TAG, *repo_args, out: File::NULL, err: File::NULL)
        Env.log("creating rolling release '#{RELEASE_TAG}' on #{PUBLISH_REPO}")
        ok = system("gh", "release", "create", RELEASE_TAG, *repo_args,
                    "--title", "OpenASN data (rolling latest)",
                    "--notes", rolling_release_notes, "--latest")
        Env.fail_stage!("could not create release #{RELEASE_TAG}") unless ok
      end

      files = Dir[File.join(DIST_DIR, "*")]
      ok = system("gh", "release", "upload", RELEASE_TAG, *repo_args, *files, "--clobber")
      Env.fail_stage!("release upload failed") unless ok
      Env.log("publish: uploaded #{files.size} assets to #{PUBLISH_REPO} release '#{RELEASE_TAG}'")

      # Weekly dated tag for version pinning (gem config: pin_version).
      # The workflow sets OPENASN_DATED_TAG on Sundays / manual dispatch.
      return unless ENV["OPENASN_DATED_TAG"] == "1"

      tag = Time.now.utc.strftime("%Y-%m-%d")
      if system("gh", "release", "view", tag, *repo_args, out: File::NULL, err: File::NULL)
        Env.log("dated release #{tag} already exists - skipping")
      else
        ok = system("gh", "release", "create", tag, *repo_args,
                    "--title", "OpenASN data #{tag}",
                    "--notes", "Weekly pinnable snapshot. Prefer the rolling `latest` release for freshness.",
                    *files)
        Env.fail_stage!("could not create dated release #{tag}") unless ok
        Env.log("publish: cut dated release #{tag}")
      end
    end

    def rolling_release_notes
      <<~NOTES
        Nightly-updated OpenASN data artifacts. **Always fetch via
        `releases/latest/download/<file>`** - assets here are replaced every
        night by CI.

        | File | What |
        |---|---|
        | `openasn-ipv4.bin` / `openasn-ipv6.bin` | packed classification artifacts (format: FORMAT.md) |
        | `manifest.json` | build id, per-file SHA-256, source provenance |
        | `asn-categories.csv` | full ASN → category/role/flags table (CC0) |
        | `fetch-manifest.json` | Tier B source spec executed by clients |
        | `ATTRIBUTION.md` | upstream attributions |
        | `SHA256SUMS` | `sha256sum -c` compatible checksums |

        Data license: CC0-1.0. Code: MIT.
      NOTES
    end
  end
end
