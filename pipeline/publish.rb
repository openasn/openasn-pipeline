# frozen_string_literal: true

# Stage 6: assemble the release payload in the build's candidate directory
# and (in CI) upload it to the rolling `latest` GitHub Release.
#
# A candidate = the complete, self-describing release:
#   openasn-ipv4.bin, openasn-ipv6.bin  - the artifacts (compile.rb)
#   openasn-orgs.bin                    - the org-name sidecar (compile.rb)
#   manifest.json                       - build identity + file checksums +
#                                         source provenance + stats
#   SHA256SUMS                          - plain checksums (sha256sum -c compatible)
#   fetch-manifest.json                 - Tier B spec for clients (repo copy)
#   ATTRIBUTION.md                      - license attributions (repo copy)
#   asn-categories.csv                  - convenience CSV (CC0): the full
#                                         ASN -> category/role/flags table
#   openasn.sqlite.gz, openasn.csv.gz,
#   openasn.mmdb                        - the portable exports, when the
#                                         build's export mode selects them
#
# WHAT IS IN A RELEASE IS DECIDED BY A REGISTRY, NOT BY A DIRECTORY LISTING
# (PRD §15.2). This stage used to upload `Dir[File.join(DIST_DIR, "*")]` and
# checksum `Dir.children(DIST_DIR)`, which answers "what is lying in that
# folder" rather than "what did this build produce". With the exports
# writing intermediate files and tools leaving failed candidates behind,
# those two questions now have different answers, and only one of them is
# safe to publish. Every asset is registered by name with the size and
# digest its producing stage measured; nothing else is uploaded,
# checksummed or mirrored (lib/release_assets.rb).
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
require_relative "lib/orgs"
require_relative "lib/release_assets"
require_relative "lib/sources"
require_relative "lib/routeviews"
require_relative "lib/license_gate"
require_relative "lib/drift_gate"
require_relative "export/contract"
require_relative "export/metadata"
require_relative "fetch"

module OpenASNPipeline
  module Publish
    RELEASE_TAG = "latest"

    # The native release payloads, in manifest order. Unchanged since the
    # first release: the exports are ADDITIVE entries appended after these,
    # never a replacement, so an old client reading this manifest finds
    # exactly what it has always found (PRD §15.3).
    NATIVE_FILES = %w[openasn-ipv4.bin openasn-ipv6.bin openasn-orgs.bin
                      asn-categories.csv fetch-manifest.json ATTRIBUTION.md].freeze

    # The subset a native SDK actually downloads and reads. `native_client_view`
    # below is the old-client contract, exercised by the compatibility test.
    NATIVE_ARTIFACTS = %w[openasn-ipv4.bin openasn-ipv6.bin openasn-orgs.bin].freeze

    module_function

    # Stage 6a (PRD §15.1 "prepare native catalog/docs/provenance"): the
    # files that are derived from the build's own inputs rather than from
    # its artifacts. They exist before the exports run because the exports
    # embed the same attribution text the release ships.
    def prepare(normalized, compiled, dir:)
      write_asn_categories_csv(normalized, compiled, dir: dir)
      copy_repo_docs(dir: dir)
    end

    # The convenience CSV: everything an analyst needs without parsing
    # binary. CC0, same as the artifacts.
    #
    # `org` is the CC0 name from openasn-orgs.bin (org_names.txt, then
    # Wikidata; D-SRC-2) and is EMPTY when we hold no clean name. It is never
    # the ipverse description, which is bulk WHOIS. The header and column
    # order are unchanged on purpose, so positional readers keep working.
    def write_asn_categories_csv(normalized, compiled, dir: DIST_DIR)
      flags_by_asn = compiled[:flags_by_asn]
      org_names = compiled[:org_names] || {}
      path = File.join(dir, "asn-categories.csv")
      CSV.open("#{path}.tmp", "wb") do |csv|
        csv << %w[asn org country category network_role openasn_flags]
        normalized[:asn_meta].keys.sort.each do |asn|
          rec = normalized[:asn_meta][asn]
          flags = flags_by_asn[asn]
          csv << [asn, org_names.dig(asn, "name"), rec.country,
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

    def copy_repo_docs(dir: DIST_DIR)
      FileUtils.cp(Env.attribution_path, File.join(dir, "ATTRIBUTION.md"))
      FileUtils.cp(Env.fetch_manifest_path, File.join(dir, "fetch-manifest.json"))
    end

    # The source catalogue with its license pins and fetch timestamps. It is
    # a PURE function of the catalog, the pin file and the fetch state, and
    # it is extracted from write_manifest because the exports need the same
    # array BEFORE a manifest exists: SQLite's `meta.sources` must mean
    # exactly what manifest.json's `sources` means, and two constructions of
    # "the same" list are two lists (PRD §9). Shape and content are
    # unchanged - write_manifest calls this and embeds the result verbatim.
    def source_provenance(build_id, http)
      pins = LicenseGate.load_pins
      Sources.catalog.map do |src|
        {
          id: src[:id], url: src[:url], license: src[:license],
          license_sha256: pins.dig(src[:id], "sha256"),
          fetched_at: fetched_at_for(src[:id], http, build_id)
        }
      end
    end

    # Stage 6b: the explicit inventory, the manifest, the checksums. Returns
    # [manifest, registry]; the registry is the only thing the uploader and
    # the mirror are allowed to read.
    def assemble(context:, compiled:, artifacts:, crosscheck_stats:, exports: nil)
      dir = context.candidate_dir
      registry = ReleaseAssets.new(root: dir)

      NATIVE_FILES.each do |name|
        path = File.join(dir, name)
        registry.register(name: name, path: path, records: records_for(name, artifacts, path))
      end
      adopt_exports(registry, exports, dir: dir)
      # The mode's declared asset list is the dataset's promise to consumers;
      # a build that produced something else must not reach an uploader.
      registry.require_exports!(context.mode.assets)

      manifest = manifest_document(
        build_id: context.build_id, registry: registry, sources: context.sources,
        stats: manifest_stats(artifacts, crosscheck_stats, exports: exports, org_stats: org_stats(compiled)),
        export_producer: export_producer(context, exports)
      )
      write_manifest(manifest, dir: dir)
      registry.envelope(name: "SHA256SUMS", path: write_sha256sums(registry, dir: dir))
      registry.envelope(name: "manifest.json", path: File.join(dir, "manifest.json"))

      Env.log("publish: candidate assembled (build #{context.build_id}, #{registry.payloads.size} payloads: " \
              "#{registry.payload_names.join(', ')})")
      [manifest, registry]
    end

    # Export payloads are written in the export workspace (where their
    # intermediate files stay) and MOVED into the candidate here. They are
    # registered with the size and digest the export stage measured, so the
    # registry re-verifies after the move: bytes that changed in transit
    # cannot enter the inventory.
    def adopt_exports(registry, exports, dir:)
      return if exports.nil? || exports.outputs.empty?

      exports.outputs.each do |output|
        target = File.join(dir, output.name)
        Env.fail_stage!("#{output.name} already exists in the candidate") if File.exist?(target)

        FileUtils.mv(output.path, target)
        registry.register(name: output.name, path: target, records: output.records,
                          export: output.export, bytes: output.bytes, sha256: output.sha256)
      end
    end

    # The manifest, as a pure value. Existing keys keep their meaning and
    # their order; `export_producer` appears only when this build actually
    # produced exports, so a native-only build's manifest is byte-for-byte
    # the shape it has always been.
    def manifest_document(build_id:, registry:, sources:, stats:, export_producer: nil)
      manifest = {
        format_version: FORMAT_VERSION,
        # Open-core contract (data-repo DECISIONS.md D-IMPL-5): the free edition is and stays "core".
        # Future signed Pro artifacts will use this same manifest shape plus
        # a real `signature` - keep the key present-but-null so clients can
        # feature-detect without a schema change.
        edition: "core",
        build_id: build_id,
        files: registry.manifest_files,
        sources: sources,
        stats: stats,
        signature: nil
      }
      manifest[:export_producer] = export_producer if export_producer
      manifest
    end

    def write_manifest(manifest, dir:)
      path = File.join(dir, "manifest.json")
      File.write(path, JSON.pretty_generate(manifest) + "\n")
      path
    end

    # Exporter identity and the toolchain that actually wrote the bytes
    # (PRD §15.3). The tool versions come from the export metadata the
    # writers embedded, not from a fresh probe: the manifest must describe
    # the run that happened.
    def export_producer(context, exports)
      meta = export_metadata(exports)
      return nil unless meta

      {
        exporter_version: Export::Contract::EXPORTER_VERSION,
        mode: context.mode.selected,
        schema_version: Export::Contract::SCHEMA_VERSION,
        schema_revision: Export::Contract::SCHEMA_REVISION,
        classification_profile: Export::Contract::CLASSIFICATION_PROFILE,
        lookup_policy_version: Export::Contract::LOOKUP_POLICY_VERSION,
        data_repo_commit: meta.fetch("data_repo_commit"),
        pipeline_repo_commit: meta.fetch("pipeline_repo_commit"),
        working_tree_dirty: meta.fetch("working_tree_dirty") == "true",
        tools: JSON.parse(meta.fetch("producer"))
      }
    end

    # The export metadata as written (all values TEXT, per §10.2), or nil
    # when this build produced no exports.
    def export_metadata(exports)
      return nil if exports.nil? || exports.metadata_path.nil?

      JSON.parse(File.read(exports.metadata_path))
    end

    # stats = layer counts + crosscheck figures + (only when something
    # happened) the drift-gate audit trail: `drift_ack` carries the operator's
    # OPENASN_ACK_DRIFT reason and the gate(s) it overrode, `drift_recovery`
    # the gate(s) that passed as a snap-back to the weekly-pin baseline. Both
    # are absent on a normal night, so the usual manifest shape is unchanged.
    # (lib/drift_gate.rb; data-repo DECISIONS.md D-GATE-1)
    #
    # `layer_counts` counts NATIVE INPUT LAYERS and keeps doing so: the
    # export's effective-interval counts are a different measurement of a
    # different thing and live in `export_counts` (PRD §15.3). Swapping them
    # would silently rebase every drift gate that compares layer counts
    # across builds.
    # org_stats (D-SRC-2): `org_names` is the entry count of openasn-orgs.bin,
    # the metric G6's drift gate compares night over night;
    # `org_names_by_source` and `wikidata_p3797` say where the names came from
    # and what the Wikidata admissibility rules dropped. Omitted when nil.
    def manifest_stats(artifacts, crosscheck_stats, exports: nil, org_stats: nil)
      stats = {
        layer_counts: {
          base_ipv4: artifacts[:ipv4].counts[:base],
          vpn_ipv4: artifacts[:ipv4].counts[:vpn],
          dc_ipv4: artifacts[:ipv4].counts[:dc],
          base_ipv6: artifacts[:ipv6].counts[:base]
        }
      }
      stats[:export_counts] = export_counts(exports) if exports&.counts
      stats.merge(crosscheck_stats || {}).merge(org_stats || {}).merge(DriftGate.manifest_stamp).merge(RouteViews.manifest_stamp)
    end

    # Coalesced effective intervals, per family and in total, plus the
    # transport/decoded sizes per format. Diagnostics only: the authoritative
    # per-asset counts live in each file's manifest entry.
    def export_counts(exports)
      counts = exports.counts
      {
        mode: exports.mode,
        records_ipv4: counts.ipv4,
        records_ipv6: counts.ipv6,
        records_total: counts.total,
        formats: exports.outputs.to_h do |output|
          [output.export.fetch("format").to_sym,
           { bytes: output.bytes,
             uncompressed_bytes: output.export.dig("uncompressed", "bytes") }.compact]
        end
      }
    end

    def org_stats(compiled)
      counts = Orgs.source_counts(compiled[:org_names] || {})
      { org_names: counts["total"],
        org_names_by_source: counts.except("total"),
        wikidata_p3797: compiled[:wikidata_stats] }
    end

    def records_for(name, artifacts, path)
      case name
      when "openasn-ipv4.bin" then artifacts[:ipv4].counts[:base]
      when "openasn-ipv6.bin" then artifacts[:ipv6].counts[:base]
      when "openasn-orgs.bin" then File.binread(path, 16)[8, 4].unpack1("N")
      # A CSV record is not a physical line: a quoted org name containing a
      # newline spans two of them. Today's catalog has none, so this counts
      # exactly what `File.foreach(path).count - 1` counted, but it stays
      # correct the first night an upstream description carries a line break.
      when /\.csv\z/ then CSV.foreach(path, headers: true).count
      else 0
      end
    end

    # What a native client resolves out of a manifest: its own files, by
    # name, ignoring every entry it does not understand. Additive export
    # entries are invisible to it, which is the whole point of nesting
    # export metadata under `export` instead of adding top-level keys
    # (PRD §15.3, test id U22).
    def native_client_view(manifest)
      files = manifest[:files] || manifest["files"] || []
      index = files.to_h { |entry| [entry[:name] || entry["name"], entry] }
      NATIVE_ARTIFACTS.map do |name|
        index.fetch(name) do
          Env.fail_stage!("manifest has no entry for #{name}; a native client could not install this release")
        end
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
      "x4bnet-lists_vpn"       => %i[x4b_vpn x4b_dc x4b_vpn_asn x4b_dc_asn x4b_vpn_manual x4b_dc_manual],
      "brianhama-bad-asn-list" => %i[bad_asn],
      "wikidata-p3797"         => %i[wikidata]
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
      # RouteViews: the oldest RIB this build compiled from.
      when "routeviews"
        RouteViews.used_keys.filter_map { |k| http.fetched_at(k) }.min
      else
        keys = SOURCE_FETCH_KEYS.fetch(source_id) { return nil }
        keys.filter_map { |k| http.fetched_at(Fetch::KEYS[k]) }.min
      end
    end

    # manifest.json is deliberately NOT in SHA256SUMS: it is the checksum
    # authority (the gem verifies .bin downloads against manifest hashes);
    # SHA256SUMS exists for humans and shell scripts. SHA256SUMS does not
    # list itself either - a file cannot carry its own hash - and neither of
    # them is an entry in `manifest.files` (PRD §15.2).
    def write_sha256sums(registry, dir:)
      path = File.join(dir, "SHA256SUMS")
      File.write(path, registry.checksums)
      path
    end

    # Stage 6c: the only place in this system that uploads anything. It
    # refuses on provenance the export contract calls unpublishable
    # (Export::Metadata.nonpublishable_reasons: an unknown or malformed
    # commit id, or a dirty tracked tree), because a released file whose
    # provenance cannot be checked is worse than a missed night.
    def publish!(manifest, registry, context:, exports: nil, publishing: ENV["PUBLISH"] == "1")
      reasons = Export::Metadata.nonpublishable_reasons(export_metadata(exports) || context.provenance)

      if reasons.any?
        unless publishing
          Env.warn("publish: this build is NOT publishable (#{reasons.join('; ')}). It assembled fine; " \
                   "PUBLISH=1 would have refused it.")
          return nil
        end
        Env.fail_stage!("refusing to publish build #{context.build_id}: #{reasons.join('; ')}. A published " \
                        "release must record exactly which clean revisions produced it (PRD §10.2).")
      end
      return nil unless publishing

      # Recompute every hash against the files as they are NOW: validation
      # happened earlier, and an asset that changed since then would be
      # uploaded under a manifest that describes different bytes.
      registry.verify!
      upload!(manifest, registry)
      manifest
    end

    # Every gh invocation goes through this one seam, so the publisher tests
    # can assert the exact argv and the exact ORDER without a gh binary, a
    # token, or a network - and so that no test can accidentally upload
    # anything (PRD §19.4).
    DEFAULT_GH = lambda do |arguments, quiet|
      quiet ? system("gh", *arguments, out: File::NULL, err: File::NULL) : system("gh", *arguments)
    end

    def gh_runner = @gh_runner || DEFAULT_GH

    def gh_runner=(runner)
      @gh_runner = runner
    end

    def reset_gh_runner! = (@gh_runner = nil)
    def gh(*arguments, quiet: false) = gh_runner.call(arguments, quiet)

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
    # UPLOAD ORDER IS THE SAFETY PROPERTY (PRD §16.1): payloads first, then
    # SHA256SUMS, then manifest.json LAST, and only then the release body.
    # A consumer resolves a release through its manifest, so as long as the
    # manifest is replaced last, a failure part-way leaves consumers reading
    # the previous generation's manifest, which still names bytes that are
    # present. A single multi-asset `gh release upload` call is NOT
    # transactional and gives no ordering, which is why each asset is its
    # own checked call.
    #
    # This does not make the rolling release atomic and nothing here claims
    # it does: while payloads are being replaced, an old manifest can point
    # at new bytes, and caches lag. That is what the consumer retry protocol
    # in EXPORT_FORMATS.md §9 exists for.
    def upload!(manifest, registry)
      unless gh("--version", quiet: true)
        Env.fail_stage!("PUBLISH=1 but gh CLI is not available")
      end

      repo_args = ["--repo", PUBLISH_REPO]
      unless gh("release", "view", RELEASE_TAG, *repo_args, quiet: true)
        Env.log("creating rolling release '#{RELEASE_TAG}' on #{PUBLISH_REPO}")
        ok = gh(*rolling_create_args(manifest))
        Env.fail_stage!("could not create release #{RELEASE_TAG}") unless ok
      end

      uploaded = []
      registry.upload_sequence.each do |asset|
        ok = gh("release", "upload", RELEASE_TAG, *repo_args, asset.path, "--clobber")
        upload_failed!(asset, uploaded) unless ok

        uploaded << asset.name
        Env.log("publish: uploaded #{asset.name} (#{asset.bytes} bytes) [#{uploaded.size}/#{registry.upload_sequence.size}]")
      end
      Env.log("publish: uploaded #{uploaded.size} assets to #{PUBLISH_REPO} release '#{RELEASE_TAG}' " \
              "in order #{uploaded.join(' -> ')}")

      # Assets are already uploaded, so a failure here cannot corrupt data -
      # but a lost "Latest" badge silently misroutes every badge-URL consumer
      # to stale bytes, so it still fails the nightly loudly (which opens the
      # pipeline-failure issue via nightly-build.yml).
      ok = gh(*rolling_edit_args(manifest))
      Env.fail_stage!("rolling release edit failed (notes stamp + Latest badge re-assert; note: assets DID upload)") unless ok
      Env.log("publish: rolling notes stamped (build #{manifest[:build_id]}), Latest badge asserted")

      # Weekly dated tag for version pinning (gem config: pin_version).
      # The workflow sets OPENASN_DATED_TAG on Sundays / manual dispatch.
      # Tag format vYYYY.MM.DD — the cross-project release-naming standard
      # (VehiclesDB uses vYYYY.MM.P for its monthly cadence): v-prefixed,
      # dot-separated, hyphen-free, lexicographic order == chronological.
      # (The one pre-standard 2026-07-05 tag was renamed to v2026.07.05.)
      return unless ENV["OPENASN_DATED_TAG"] == "1"

      # A PIN MUST BE A KNOWN-GOOD BUILD. Dated pins are immutable and are the
      # drift gate's only frozen reference — the one thing that can break a
      # publish deadlock (lib/drift_gate.rb; data-repo DECISIONS.md D-GATE-1).
      # Freezing a build the gates warned about poisons exactly that reference:
      # a -8.8% Sunday WARN publishes and gets pinned at 11,300, a second WARN
      # a week later pins 10,300, and when upstream finally recovers to 12,400
      # the move is +20.4% against the degraded `latest` with no surviving pin
      # inside the recovery band — an identical FAIL every night, forever,
      # with good data in hand. Skipping the pin costs one week of baseline
      # freshness and cannot itself deadlock, because the pin set only ages.
      unless DriftGate.clean?
        Env.warn("publish: NOT cutting a dated pin — this build is not clean " \
                 "(#{DriftGate.events.map(&:summary).join('; ')}). Pins are the drift gate's frozen " \
                 "known-good reference; pinning a warned build would poison it. The rolling " \
                 "'#{RELEASE_TAG}' release still published; the next clean build cuts the pin.")
        return
      end

      tag = Time.now.utc.strftime("v%Y.%m.%d")
      if gh("release", "view", tag, *repo_args, quiet: true)
        Env.log("dated release #{tag} already exists - skipping")
      else
        ok = gh(*dated_create_args(tag, manifest, registry.upload_paths))
        Env.fail_stage!("could not create dated release #{tag}") unless ok
        Env.log("publish: cut dated release #{tag} (badge stays on '#{RELEASE_TAG}')")
      end
    end

    # An upload failure has two very different meanings and the log must not
    # blur them. Nothing uploaded means the remote release is untouched;
    # something uploaded means the release now mixes two generations until a
    # later build replaces every asset. There is NO automatic rollback -
    # GitHub release assets are replaced in place, this stage does not
    # re-upload the previous generation, and claiming otherwise would send an
    # operator looking for a recovery that never happened.
    def upload_failed!(asset, uploaded)
      if uploaded.empty?
        Env.fail_stage!("release upload failed on the first asset (#{asset.name}). Nothing was uploaded, so " \
                        "the '#{RELEASE_TAG}' release still serves the previous generation complete.")
      end

      Env.fail_stage!("release upload failed at #{asset.name}, AFTER #{uploaded.size} asset(s) were already " \
                      "uploaded (#{uploaded.join(', ')}). manifest.json was not replaced, so consumers still " \
                      "resolve the previous generation - but the remote release now holds a mix of two " \
                      "generations. Nothing was rolled back: this stage performs no remote rollback. Re-run " \
                      "the build to replace every asset.")
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

        #{asset_table(manifest)}
        Need a build that never changes underneath you? Pin a weekly dated release (`vYYYY.MM.DD` tags).
        Data license: CC0-1.0. Code: MIT.
      NOTES
    end

    # One line per asset this build actually published, read from the
    # manifest the body is being stamped with (PRD §15.4). A hardcoded table
    # would be wrong in both directions now that the export mode decides how
    # many assets a release carries: it would advertise files a `none` build
    # never produced, and hide the exports from the night they appear.
    # Unknown names still get a row, because a release must never contain a
    # file the release body pretends is not there.
    ASSET_BLURBS = {
      "openasn-ipv4.bin" => "packed classification artifact, IPv4 (format: FORMAT.md)",
      "openasn-ipv6.bin" => "packed classification artifact, IPv6 (format: FORMAT.md)",
      "openasn-orgs.bin" => "packed ASN → organization names",
      "asn-categories.csv" => "full ASN → category/role/flags table (CC0)",
      "fetch-manifest.json" => "Tier B source spec executed by clients",
      "ATTRIBUTION.md" => "upstream attributions",
      "openasn.sqlite.gz" => "portable export: SQLite, gzipped (EXPORT_FORMATS.md)",
      "openasn.csv.gz" => "portable export: one row per IP range, gzipped (EXPORT_FORMATS.md)",
      "openasn.mmdb" => "portable export: MaxMind DB, read as-is by any MMDB reader (EXPORT_FORMATS.md)",
      "manifest.json" => "build id, per-file SHA-256, source provenance",
      "SHA256SUMS" => "`sha256sum -c` compatible checksums"
    }.freeze

    def asset_table(manifest)
      files = manifest[:files] || manifest["files"] || []
      names = files.map { |entry| entry[:name] || entry["name"] } + ReleaseAssets::ENVELOPE_NAMES
      return "" if files.empty?

      rows = names.map { |name| "| `#{name}` | #{ASSET_BLURBS.fetch(name, 'release asset')} |" }
      (["| File | What |", "|---|---|"] + rows).join("\n") + "\n"
    end

    def dated_release_notes(tag, manifest)
      counts = manifest.dig(:stats, :layer_counts) || {}
      <<~NOTES
        Weekly pinnable snapshot — build `#{manifest[:build_id]}`. Assets on this tag are never rewritten.

        #{counts[:base_ipv4]} IPv4 / #{counts[:base_ipv6]} IPv6 base records · IPv4 overlays: #{counts[:vpn_ipv4]} vpn, #{counts[:dc_ipv4]} dc

        Pin it from the gem (`config.pin_version = "#{tag}"`) or download directly:
        `https://github.com/#{PUBLISH_REPO}/releases/download/#{tag}/<file>`

        #{asset_table(manifest)}

        For freshness prefer the rolling release — replaced nightly at the tag-addressed URL
        `https://github.com/#{PUBLISH_REPO}/releases/download/latest/<file>`.
      NOTES
    end
  end
end
