# frozen_string_literal: true

# Publish-stage invariants. These exist because of the 2026-07-05 badge
# incident (see the "Latest badge semantics" block in pipeline/publish.rb):
# the first weekly dated release stole GitHub's "Latest" badge from the
# rolling release, silently redirecting every `releases/latest/download/...`
# consumer to a frozen snapshot. The gh invocations are built by pure
# functions precisely so these tests can pin the flags without a gh binary,
# network, or a real build.
#
# The second half of this file (PRD 19.4, ids U19-U22) covers the rest of the
# publisher the same way: the release inventory, the upload order, and the
# three production failures that must never end in a published generation.
# Every `gh` call in this file goes through Publish.gh_runner, which the tests
# replace with a recorder, so the suite has no way to upload a test asset to
# anything - which is itself a requirement of 19.4.

require_relative "test_helper"
require "json"
require_relative "../pipeline/lib/build_context"
require_relative "../pipeline/lib/orgs"
require_relative "../pipeline/export/mode"
require_relative "../pipeline/publish"
require_relative "../pipeline/run"

module OpenASNPipeline
  class PublishReleaseArgsTest < Minitest::Test
    MANIFEST = {
      build_id: "2026-07-05T06:50:27Z",
      stats: { layer_counts: { base_ipv4: 433_550, vpn_ipv4: 6_405,
                               dc_ipv4: 28_746, base_ipv6: 125_674 } }
    }.freeze

    def test_dated_release_never_takes_the_latest_badge
      args = Publish.dated_create_args("v2026.07.12", MANIFEST, ["a.bin", "b.bin"])
      # Must be the single-argv `=false` form: REST make_latest defaults to
      # "true" for new releases, so omitting the flag re-creates the incident.
      assert_includes args, "--latest=false"
      refute_includes args, "--latest"
      # Asset paths must survive as trailing args (gh: files are positional).
      assert_equal %w[a.bin b.bin], args.last(2)
    end

    def test_rolling_release_asserts_badge_on_create_and_edit
      create = Publish.rolling_create_args(MANIFEST)
      edit   = Publish.rolling_edit_args(MANIFEST)
      assert_includes create, "--latest"
      assert_includes edit, "--latest" # nightly self-heal of the badge
      assert_equal %w[release create latest], create.first(3)
      assert_equal %w[release edit latest], edit.first(3)
    end

    def test_titles_are_project_led_dotted_and_stream_disambiguated
      # Titles follow the cross-project "<Project> <dotted-version>" standard
      # (VehiclesDB titles "VehiclesDB 2026.07.3"); here the version IS the
      # date, so "OpenASN 2026.07.05" is project-named and date-led at once.
      # The short "OpenASN " lead keeps the date inside GitHub's ~25-char
      # sidebar cut (the release's relative time is frozen CREATION time, so
      # the title's date is the rolling release's only freshness signal).
      # Dotted, never hyphenated; suffixes disambiguate rolling vs pinned on
      # Sundays when both carry one date.
      rolling = Publish.rolling_title(MANIFEST)
      dated   = Publish.dated_title("v2026.07.12")
      assert_equal "OpenASN 2026.07.05 · Nightly rolling", rolling
      assert_equal "OpenASN 2026.07.12 · Weekly snapshot", dated
      refute_includes rolling, "-" # dotted dates only, matches vYYYY.MM.DD tags
      refute_includes dated, "-"
      refute_equal Publish.dated_title("v2026.07.05"), rolling
      # Titles ride inside the same argv the badge flags do - pin placement.
      assert_includes Publish.rolling_edit_args(MANIFEST), rolling
      assert_includes Publish.dated_create_args("v2026.07.12", MANIFEST, []), dated
    end

    def test_notes_are_stamped_with_build_identity
      [Publish.rolling_release_notes(MANIFEST),
       Publish.dated_release_notes("2026-07-12", MANIFEST)].each do |notes|
        assert_includes notes, "`2026-07-05T06:50:27Z`"
        assert_includes notes, "433550" # layer counts, grep-able
      end
    end

    def test_notes_recommend_only_tag_addressed_urls
      rolling = Publish.rolling_release_notes(MANIFEST)
      dated   = Publish.dated_release_notes("2026-07-12", MANIFEST)

      assert_includes rolling, "releases/download/latest/"
      assert_includes dated, "releases/download/2026-07-12/"

      # The badge-form URL may appear ONLY inside an explicit do-not-use
      # warning, on the same physical line (so the warning can never be
      # reflowed away from the URL it warns about).
      (rolling.lines + dated.lines).grep(%r{releases/latest/download}).each do |line|
        assert_match(/do not use|Do NOT use/i, line,
                     "badge-form URL outside a do-not-use warning: #{line.inspect}")
      end
    end

    def test_the_asset_table_lists_what_this_build_published_and_nothing_else
      # PRD 15.4: the body follows the manifest, so a `none` build cannot
      # advertise exports and an `all` build cannot hide them.
      native = MANIFEST.merge(files: [{ name: "openasn-ipv4.bin" }, { name: "asn-categories.csv" }])
      with_exports = MANIFEST.merge(files: native[:files] + [{ name: "openasn.sqlite.gz" },
                                                             { name: "openasn.mmdb" }])

      body = Publish.rolling_release_notes(native)
      assert_includes body, "| `openasn-ipv4.bin` |"
      assert_includes body, "| `manifest.json` |"
      assert_includes body, "| `SHA256SUMS` |"
      refute_includes body, "openasn.sqlite.gz"

      exported = Publish.rolling_release_notes(with_exports)
      assert_includes exported, "| `openasn.sqlite.gz` |"
      assert_includes exported, "| `openasn.mmdb` |"
      assert_includes Publish.dated_release_notes("v2026.07.12", with_exports), "| `openasn.mmdb` |"
    end

    def test_an_unknown_future_asset_is_still_listed_rather_than_hidden
      body = Publish.rolling_release_notes(MANIFEST.merge(files: [{ name: "openasn.futurefmt" }]))
      assert_includes body, "| `openasn.futurefmt` | release asset |"
    end

    def test_notes_survive_a_manifest_without_stats
      # First-ever build in a fork: crosscheck may contribute no stats. Notes
      # must degrade to blanks, not raise NoMethodError mid-publish.
      bare = { build_id: "2026-01-01T00:00:00Z", stats: {} }
      assert_includes Publish.rolling_release_notes(bare), "`2026-01-01T00:00:00Z`"
      assert_includes Publish.dated_release_notes("2026-01-01", bare), "`2026-01-01T00:00:00Z`"
    end
  end

  # The drift-gate audit trail reaches manifest.json through manifest_stats
  # (data-repo DECISIONS.md D-GATE-1): an operator ack or a baseline recovery
  # must be visible to anyone reading the published manifest, and a normal
  # night must keep the exact pre-incident stats shape.
  class PublishManifestStatsTest < Minitest::Test
    FakeArtifact = Struct.new(:counts)
    ARTIFACTS = { ipv4: FakeArtifact.new({ base: 439_214, vpn: 6_565, dc: 29_064 }),
                  ipv6: FakeArtifact.new({ base: 126_073 }) }.freeze
    CROSSCHECK = { hosting_asns: 12_442, reference_dc_asns: 902, reference_coverage: 0.9113 }.freeze

    def setup = DriftGate.reset!
    def teardown = DriftGate.reset!

    def quiet(&) = Env.logger.tap { |l| l.level = Logger::FATAL }.then { yield }.tap { Env.logger.level = Logger::INFO }

    def test_normal_night_keeps_the_pre_incident_shape
      stats = Publish.manifest_stats(ARTIFACTS, CROSSCHECK)
      assert_equal %i[layer_counts hosting_asns reference_dc_asns reference_coverage], stats.keys
      assert_equal({ base_ipv4: 439_214, vpn_ipv4: 6_565, dc_ipv4: 29_064, base_ipv6: 126_073 }, stats[:layer_counts])
    end

    def test_ack_and_recovery_are_stamped_and_survive_json
      quiet do
        DriftGate.enforce!(gate: "crosscheck", metric: "hosting_asns", now: 12_442, prev: 9_342,
                           baselines: [DriftGate::Baseline.new(label: "v2026.08.23", value: 12_393)],
                           policy: DriftGate::HOSTING_POLICY, ack: nil)
        DriftGate.enforce!(gate: "G4", metric: "dc_ipv4", now: 29_064, prev: 60_000, baselines: [],
                           policy: DriftGate::LAYER_POLICY, ack: "x4b dc list halved on purpose (X4BNet/lists_vpn#77)")
      end
      stats = JSON.parse(JSON.generate(Publish.manifest_stats(ARTIFACTS, CROSSCHECK)))
      assert_equal "x4b dc list halved on purpose (X4BNet/lists_vpn#77)", stats.dig("drift_ack", "reason")
      assert_equal ["dc_ipv4: 60000 -> 29064 (-51.6% vs previous build) - acknowledged: \"x4b dc list halved on purpose (X4BNet/lists_vpn#77)\""],
                   stats.dig("drift_ack", "gates")
      assert_equal ["hosting_asns: 9342 -> 12442 (+33.2% vs previous build); within +0.4% of weekly pin v2026.08.23 (12393)"],
                   stats["drift_recovery"]
      assert_equal 12_442, stats["hosting_asns"] # crosscheck figures untouched
    end
  end

  class PublishFetchedAtTest < Minitest::Test
    FakeHttp = Struct.new(:times) do
      def fetched_at(key) = times[key]
    end

    def test_multi_file_sources_report_their_oldest_input
      http = FakeHttp.new(
        { Fetch::KEYS[:sapics_v4] => "2026-07-05T06:00:00Z",
          Fetch::KEYS[:sapics_v6] => "2026-07-04T22:00:00Z" }
      )
      assert_equal "2026-07-04T22:00:00Z",
                   Publish.fetched_at_for("sapics-origin-asn", http, "BUILD_ID")
    end

    def test_overrides_stamp_build_time_and_on_demand_source_stamps_nil
      http = FakeHttp.new({})
      assert_equal "BUILD_ID", Publish.fetched_at_for("openasn-overrides", http, "BUILD_ID")
      assert_nil Publish.fetched_at_for("ipverse-as-ip-blocks", http, "BUILD_ID")
    end

    def test_unknown_source_id_yields_nil_not_a_fabricated_timestamp
      assert_nil Publish.fetched_at_for("some-future-source", FakeHttp.new({}), "BUILD_ID")
    end

    def test_every_catalog_source_resolves_without_raising
      # Drift tripwire: adding a source to Sources::CATALOG without wiring
      # SOURCE_FETCH_KEYS (or a special case) must degrade to nil provenance,
      # never to an exception inside write_manifest on a publish night.
      http = FakeHttp.new({})
      Sources::CATALOG.each do |src|
        value = Publish.fetched_at_for(src[:id], http, "BUILD_ID")
        assert(value.nil? || value.is_a?(String), src[:id])
      end
    end
  end

  # --- The candidate, the upload seam, and the four production failures ---
  #
  # PRD §19.4 U19-U22. Everything below drives the REAL assemble/publish code
  # with a stubbed `gh`, so the argument arrays and the call ORDER are the
  # assertions, and nothing can reach a network or a release. Each failure is
  # genuinely injected - a stray file really is written into the candidate, an
  # upload really does return false, an export writer really does raise -
  # because a test that simulates the failure by calling the error path
  # directly proves only that the error path exists.
  class PublishCandidateTest < Minitest::Test
    BUILD_TS = 1_789_755_195
    BUILD_ID = Time.at(BUILD_TS).utc.iso8601
    NATIVE = Publish::NATIVE_FILES
    ENVELOPES = %w[SHA256SUMS manifest.json].freeze

    FakeArtifact = Struct.new(:counts)
    ARTIFACTS = { ipv4: FakeArtifact.new({ base: 446_741, vpn: 6_631, dc: 29_301 }),
                  ipv6: FakeArtifact.new({ base: 125_616 }) }.freeze

    # Files a real build leaves in the workspace next to the release: the
    # export spool, both raw uncompressed exports, the categories CSV's
    # temporary name, the Go writer's abandoned candidate, and a log.
    STRAYS = %w[records.jsonl openasn.sqlite openasn.csv asn-categories.csv.tmp
                openasn.mmdb.candidate build.log].freeze

    def setup
      @dir = File.join(WORK_DIR, "test-#{name}")
      @candidate = File.join(@dir, "candidate")
      FileUtils.mkdir_p(@candidate)
      @gh = []
      @level = Env.logger.level
      Env.logger.level = Logger::FATAL
      DriftGate.reset!
    end

    def teardown
      Publish.reset_gh_runner!
      DriftGate.reset!
      Env.logger.level = @level
      ENV.delete("OPENASN_DATED_TAG")
      FileUtils.rm_rf(@dir)
    end

    # --- U19: an unregistered file is invisible to every downstream stage --

    def test_a_stray_file_in_the_candidate_is_never_registered_or_checksummed
      write_candidate(strays: STRAYS)
      manifest, registry = assemble

      assert_equal NATIVE, registry.payload_names
      assert_equal NATIVE, manifest[:files].map { |entry| entry[:name] }
      assert_equal NATIVE.sort, checksum_names
      # PRD §15.2: registration must not require the workspace to be tidy.
      # The stray files are still there; they are simply not the release.
      STRAYS.each { |stray| assert_path_exists File.join(@candidate, stray) }
    end

    def test_a_stray_file_in_the_candidate_is_never_uploaded_or_mirrored
      write_candidate(strays: STRAYS)
      manifest, registry = assemble
      stub_gh
      Publish.publish!(manifest, registry, context: context, publishing: true)

      assert_equal NATIVE + ENVELOPES, uploaded_names
      # The HuggingFace mirror stages the registered names and the two
      # envelopes, and nothing else reaches huggingface/push.sh.
      assert_equal NATIVE + ENVELOPES, registry.mirror_names
      STRAYS.each do |stray|
        refute_includes uploaded_names, stray
        refute_includes registry.mirror_names, stray
      end
    end

    # --- upload order and argument arrays (PRD §16.1) ----------------------

    def test_payloads_upload_first_checksums_next_and_the_manifest_last
      write_candidate
      manifest, registry = assemble
      stub_gh
      Publish.publish!(manifest, registry, context: context, publishing: true)

      assert_equal ["--version"], @gh.first
      assert_equal ["release", "view", "latest", "--repo", PUBLISH_REPO], @gh[1]
      # Manifest LAST is the property: a consumer resolving the release
      # through its manifest never sees it name bytes that are not up yet.
      assert_equal NATIVE + ENVELOPES, uploaded_names
      assert_equal "manifest.json", uploaded_names.last

      uploads.each do |argv|
        assert_equal ["release", "upload", "latest", "--repo", PUBLISH_REPO], argv.first(5)
        assert_equal "--clobber", argv.last
        # One asset per call: `gh release upload a b c` is not transactional
        # and gives no ordering, so a batched call would erase this test.
        assert_equal 7, argv.length
      end

      assert_equal %w[release edit latest], @gh.last.first(3)
      assert_includes @gh.last, "--latest"
    end

    def test_the_registry_re_verifies_the_candidate_immediately_before_upload
      write_candidate
      manifest, registry = assemble
      stub_gh
      # A file replaced after validation, which is exactly what the
      # "recompute final payload hashes" rule of PRD §16.1 exists to catch.
      File.binwrite(File.join(@candidate, "openasn-ipv4.bin"), "different bytes".b)

      error = assert_raises(StageFailure) do
        Publish.publish!(manifest, registry, context: context, publishing: true)
      end
      assert_match(/openasn-ipv4\.bin changed after it was registered/, error.message)
      assert_empty @gh, "nothing may be uploaded once the candidate no longer matches the manifest"
    end

    # --- U21: an upload that fails, before and after the first asset lands -

    def test_a_failure_on_the_first_asset_reports_that_nothing_reached_the_release
      write_candidate
      manifest, registry = assemble
      stub_gh(fail_upload_of: NATIVE.first)

      error = assert_raises(StageFailure) do
        Publish.publish!(manifest, registry, context: context, publishing: true)
      end
      assert_match(/failed on the first asset \(#{Regexp.escape(NATIVE.first)}\)/, error.message)
      assert_match(/Nothing was uploaded/, error.message)
      assert_equal [NATIVE.first], uploaded_names
    end

    def test_a_failure_after_some_assets_landed_promotes_no_manifest_and_claims_no_rollback
      write_candidate
      manifest, registry = assemble
      stub_gh(fail_upload_of: "openasn-orgs.bin") # the third payload

      error = assert_raises(StageFailure) do
        Publish.publish!(manifest, registry, context: context, publishing: true)
      end

      # The diagnostic must distinguish the two cases, because they call for
      # different operator action.
      assert_match(/AFTER 2 asset\(s\) were already uploaded/, error.message)
      assert_match(/openasn-ipv4\.bin, openasn-ipv6\.bin/, error.message)
      assert_match(/manifest\.json was not replaced/, error.message)
      # No rollback happened and none is claimed: GitHub replaces release
      # assets in place and this stage re-uploads nothing.
      assert_match(/performs no remote rollback/, error.message)
      refute_match(/rolled back automatically|restored the previous/i, error.message)

      refute_includes uploaded_names, "manifest.json"
      refute_includes uploaded_names, "SHA256SUMS"
      assert_empty @gh.select { |argv| argv.first(2) == %w[release edit] },
                   "a failed upload must not re-stamp the release body or the Latest badge"
    end

    # --- provenance: an unpublishable build never reaches an uploader ------

    def test_a_dirty_working_tree_refuses_to_publish_and_calls_gh_not_once
      write_candidate
      manifest, registry = assemble
      stub_gh

      error = assert_raises(StageFailure) do
        Publish.publish!(manifest, registry, context: context(dirty: true), publishing: true)
      end
      assert_match(/refusing to publish/, error.message)
      assert_match(/working_tree_dirty is true/, error.message)
      assert_empty @gh
    end

    def test_the_same_build_assembles_fine_without_publish_and_says_why_it_could_not
      write_candidate
      manifest, registry = assemble
      stub_gh

      assert_nil Publish.publish!(manifest, registry, context: context(dirty: true), publishing: false)
      assert_empty @gh
    end

    # --- the weekly pin keeps its flags and its cleanliness rule (D-GATE-1) -

    def test_a_clean_build_still_cuts_the_dated_pin_without_taking_the_badge
      write_candidate
      manifest, registry = assemble
      tag = Time.now.utc.strftime("v%Y.%m.%d")
      stub_gh(missing_tags: [tag])
      ENV["OPENASN_DATED_TAG"] = "1"

      Publish.publish!(manifest, registry, context: context, publishing: true)

      create = @gh.last
      assert_equal ["release", "create", tag], create.first(3)
      assert_includes create, "--latest=false"
      refute_includes create, "--latest"
      assert_equal registry.upload_paths, create.last(registry.upload_paths.length)
    end

    def test_a_warned_build_publishes_the_rolling_release_but_cuts_no_pin
      write_candidate
      manifest, registry = assemble
      ENV["OPENASN_DATED_TAG"] = "1"
      DriftGate.enforce!(gate: "G4", metric: "dc_ipv4", now: 29_064, prev: 60_000, baselines: [],
                         policy: DriftGate::LAYER_POLICY, ack: "x4b dc list halved on purpose")
      refute DriftGate.clean?
      stub_gh(missing_tags: [Time.now.utc.strftime("v%Y.%m.%d")])

      Publish.publish!(manifest, registry, context: context, publishing: true)

      # The rolling release still published; only the frozen pin is skipped.
      assert_equal NATIVE + ENVELOPES, uploaded_names
      assert_empty @gh.select { |argv| argv.first(2) == %w[release create] },
                   "pinning a warned build would poison the drift gate's only frozen baseline"
    end

    # --- U22: an old native client reading an additive manifest ------------

    def test_an_old_native_client_resolves_only_its_own_files_and_ignores_the_rest
      # A manifest from a future build: the three native artifacts, the
      # additive export entries with their nested metadata, and a file this
      # client has never heard of.
      manifest = {
        "build_id" => BUILD_ID,
        "files" => [
          { "name" => "openasn-ipv4.bin", "sha256" => "a" * 64, "bytes" => 10, "records" => 446_741 },
          { "name" => "openasn-ipv6.bin", "sha256" => "b" * 64, "bytes" => 11, "records" => 125_616 },
          { "name" => "openasn-orgs.bin", "sha256" => "c" * 64, "bytes" => 12, "records" => 3 },
          { "name" => "asn-categories.csv", "sha256" => "d" * 64, "bytes" => 13, "records" => 2 },
          { "name" => "openasn.sqlite.gz", "sha256" => "e" * 64, "bytes" => 14, "records" => 572_357,
            "export" => { "format" => "sqlite", "content_encoding" => "gzip",
                          "uncompressed" => { "name" => "openasn.sqlite", "bytes" => 99, "sha256" => "f" * 64 } } },
          { "name" => "openasn.mmdb", "sha256" => "1" * 64, "bytes" => 15, "records" => 572_357,
            "export" => { "format" => "mmdb", "content_encoding" => "identity" } },
          { "name" => "openasn.futurefmt", "sha256" => "2" * 64, "bytes" => 16, "records" => 1,
            "export" => { "format" => "futurefmt" } }
        ],
        "export_producer" => { "exporter_version" => "1.0.0" }
      }

      view = Publish.native_client_view(manifest)

      assert_equal %w[openasn-ipv4.bin openasn-ipv6.bin openasn-orgs.bin],
                   view.map { |entry| entry["name"] }
      assert_equal ["a" * 64, "b" * 64, "c" * 64], view.map { |entry| entry["sha256"] }
      # Nothing it resolved carries export metadata, and the unknown entry and
      # the new top-level key changed nothing about what it found.
      assert(view.none? { |entry| entry.key?("export") })
    end

    def test_the_old_client_view_fails_loudly_when_a_native_file_is_actually_gone
      manifest = { "files" => [{ "name" => "openasn.sqlite.gz", "sha256" => "e" * 64 }] }
      error = assert_raises(StageFailure) { Publish.native_client_view(manifest) }
      assert_match(/no entry for openasn-ipv4\.bin/, error.message)
    end

    def test_the_old_client_view_reads_the_manifest_as_this_build_holds_it
      # assemble returns symbol keys, the published file parses back to
      # string keys, and a native client must be resolvable from both.
      write_candidate
      manifest, = assemble
      on_disk = JSON.parse(File.read(File.join(@candidate, "manifest.json")))

      assert_equal Publish.native_client_view(on_disk).map { |e| e["sha256"] },
                   Publish.native_client_view(manifest).map { |e| e[:sha256] }
    end

    private

    # Every gh invocation is recorded and answered here, so no test can reach
    # a gh binary, a token, or a release. `fail_upload_of` makes exactly one
    # asset's upload return false - the way a real upload failure arrives.
    def stub_gh(fail_upload_of: nil, missing_tags: [])
      @gh = []
      Publish.gh_runner = lambda do |arguments, _quiet|
        @gh << arguments
        if arguments.first(2) == %w[release view]
          !missing_tags.include?(arguments[2])
        elsif arguments.first(2) == %w[release upload]
          fail_upload_of.nil? || File.basename(arguments[-2]) != fail_upload_of
        else
          true
        end
      end
    end

    def uploads = @gh.select { |argv| argv.first(2) == %w[release upload] }
    def uploaded_names = uploads.map { |argv| File.basename(argv[-2]) }

    def checksum_names
      File.read(File.join(@candidate, "SHA256SUMS")).lines.map { |line| line.split("  ", 2).last.chomp }
    end

    def context(dirty: false, assets: [], selected: "none")
      mode = Export::Mode::Resolved.new(selected: selected, required: "none",
                                        config_path: "(test fixture)", assets: assets)
      BuildContext.new(build_ts: BUILD_TS, mode: mode, candidate_dir: @candidate,
                       export_dir: File.join(@dir, "export"), data_repo_commit: "a" * 40,
                       pipeline_repo_commit: "b" * 40, working_tree_dirty: dirty).tap do |ctx|
        ctx.sources = [{ id: "sapics-origin-asn", url: "https://example.invalid", license: "PDDL-1.0",
                         license_sha256: "ab" * 32, fetched_at: "2026-09-01T00:00:00Z" }]
      end
    end

    def assemble(ctx = context)
      Publish.assemble(context: ctx, compiled: { build_ts: BUILD_TS }, artifacts: ARTIFACTS,
                       crosscheck_stats: { hosting_asns: 12_442 })
    end

    # A candidate as the native stages leave it, plus whatever else a real
    # workspace happens to contain.
    def write_candidate(strays: [])
      File.binwrite(File.join(@candidate, "openasn-ipv4.bin"), "OASN ipv4 payload".b)
      File.binwrite(File.join(@candidate, "openasn-ipv6.bin"), "OASN ipv6 payload".b)
      # records_for reads the OORG header's record count out of bytes 8..11.
      File.binwrite(File.join(@candidate, "openasn-orgs.bin"),
                    "OORG".b + [1, 0, 0].pack("CCn") + [3, 9].pack("NN"))
      File.write(File.join(@candidate, "asn-categories.csv"),
                 "asn,org,country,category,network_role,openasn_flags\n" \
                 "100,\"Access, A\",ES,isp,access_provider,\n" \
                 "200,Access B,US,hosting,stub,bad_asn\n")
      File.write(File.join(@candidate, "fetch-manifest.json"), %({"version":1}\n))
      File.write(File.join(@candidate, "ATTRIBUTION.md"), "Attribution for build #{BUILD_ID}\n")
      strays.each { |stray| File.write(File.join(@candidate, stray), "not a release asset\n") }
    end
  end

  # U20: an export writer that fails after a good native build must stop the
  # run before the publisher, not publish a generation missing an asset.
  #
  # This drives the real Run.assemble_and_publish sequence over real compiled
  # artifacts. The two stubs are the stages that need a data-repo checkout
  # (they have their own coverage and are not what this is about); the export
  # writer itself is real code, and it fails because it was made to fail.
  class PublishSequenceTest < Minitest::Test
    BUILD_TS = PublishCandidateTest::BUILD_TS
    BUILD_ID = Time.at(BUILD_TS).utc.iso8601
    ISP_ACCESS = 65 # category isp, role access_provider

    def setup
      @dir = File.join(WORK_DIR, "test-#{name}")
      @candidate = File.join(@dir, "candidate")
      @inputs = File.join(@dir, "inputs")
      FileUtils.mkdir_p([@candidate, @inputs])
      @attribution = File.join(@dir, "ATTRIBUTION.md")
      File.write(@attribution, "Attribution for build #{BUILD_ID}\n")
      @gh = []
      @level = Env.logger.level
      Env.logger.level = Logger::FATAL
    end

    def teardown
      Publish.reset_gh_runner!
      Env.logger.level = @level
      FileUtils.rm_rf(@dir)
    end

    def test_an_export_writer_failure_after_a_good_native_build_never_reaches_the_publisher
      compiled = write_native_artifacts

      error = assert_raises(StageFailure) do
        with_stubs(export_stubs + [[Export::Csv, :write, ->(*, **) { Env.fail_stage!("csv writer crashed") }]]) do
          run_sequence(compiled, mode: "portable", assets: %w[openasn.sqlite.gz openasn.csv.gz])
        end
      end

      assert_match(/csv writer crashed/, error.message)
      assert_empty @gh, "a failed export must not produce a single gh invocation"
      # Nothing that describes a release was written either: there is no
      # manifest naming an asset that does not exist.
      refute_path_exists File.join(@candidate, "manifest.json")
      refute_path_exists File.join(@candidate, "SHA256SUMS")
    end

    def test_the_same_sequence_does_reach_the_publisher_when_nothing_fails
      # The control the test above needs to mean anything: the same call,
      # the same stubs, an export mode that asks for no writer at all.
      compiled = write_native_artifacts

      with_stubs(export_stubs) { run_sequence(compiled, mode: "none", assets: []) }

      assert_equal ["--version"], @gh.first
      assert_equal "manifest.json", File.basename(@gh.select { |a| a.first(2) == %w[release upload] }.last[-2])
      assert_path_exists File.join(@candidate, "manifest.json")
    end

    private

    # Minitest 6 ships no mock/stub library, and these tests need exactly one
    # thing from one: replace a named module function for the duration of a
    # block and put the original back even when the block raises - which,
    # here, it is supposed to.
    def with_stubs(pairs)
      saved = pairs.map { |target, method_name, _| [target, method_name, target.method(method_name)] }
      pairs.each do |target, method_name, implementation|
        target.define_singleton_method(method_name) do |*args, **kwargs, &blk|
          implementation.respond_to?(:call) ? implementation.call(*args, **kwargs, &blk) : implementation
        end
      end
      yield
    ensure
      saved.each { |target, method_name, original| target.define_singleton_method(method_name, original) }
    end

    # The stages that read a data-repo checkout. `prepare` still writes the
    # three files it is responsible for, so the assembler downstream sees a
    # real candidate rather than a hole.
    def export_stubs
      [[Publish, :prepare, lambda { |_normalized, _compiled, dir:|
        File.write(File.join(dir, "asn-categories.csv"), "asn,org,country,category,network_role,openasn_flags\n")
        File.write(File.join(dir, "fetch-manifest.json"), %({"version":1}\n))
        FileUtils.cp(@attribution, File.join(dir, "ATTRIBUTION.md"))
      }],
       [Publish, :source_provenance, ->(_build_id, _http) { [] }],
       [Export::Run, :producer, ->(mode:) { { "ruby" => RUBY_VERSION, "mode" => mode } }],
       [Env, :attribution_path, @attribution]]
    end

    def run_sequence(compiled, mode:, assets:)
      Publish.gh_runner = lambda do |arguments, _quiet|
        @gh << arguments
        true
      end
      resolved = Export::Mode::Resolved.new(selected: mode, required: "none",
                                            config_path: "(test fixture)", assets: assets)
      ctx = BuildContext.new(build_ts: BUILD_TS, mode: resolved, candidate_dir: @candidate,
                             export_dir: File.join(@dir, "export"), data_repo_commit: "a" * 40,
                             pipeline_repo_commit: "b" * 40, working_tree_dirty: false)
      Run.assemble_and_publish(context: ctx, compiled: compiled, normalized: { asn_meta: {} },
                               artifacts: PublishCandidateTest::ARTIFACTS,
                               crosscheck_stats: {}, http: nil, publishing: true)
    end

    # Real OASN/OORG bytes, small enough to spool in milliseconds, so the
    # export stage runs for real up to the writer that was made to fail.
    def write_native_artifacts
      paths = {
        v4_path: File.join(@inputs, "openasn-ipv4.bin"),
        v6_path: File.join(@inputs, "openasn-ipv6.bin"),
        orgs_path: File.join(@inputs, "openasn-orgs.bin")
      }
      File.binwrite(paths[:v4_path], oasn(:ipv4, base: [[0x01000000, 0x01000004, 100, ISP_ACCESS]]))
      File.binwrite(paths[:v6_path], oasn(:ipv6, base: [[1, 9, 300, ISP_ACCESS]]))
      File.binwrite(paths[:orgs_path], orgs(100 => "Access A", 300 => "Six C"))
      # The candidate carries its own copy, the way compile.rb writes it.
      paths.each_value { |path| FileUtils.cp(path, File.join(@candidate, File.basename(path))) }
      paths.merge(build_ts: BUILD_TS, dest: @candidate, flags_by_asn: {})
    end

    def oasn(family, base: [])
      out = +"".b
      out << MAGIC.b << [FORMAT_VERSION, family == :ipv4 ? 0x04 : 0x06, 0].pack("CCn")
      out << [BUILD_TS].pack("Q>") << [base.length, 0, 0, 0].pack("NNNN")
      base.each do |(s, e, asn, flags)|
        out << Binary.pack_addr(s, family) << Binary.pack_addr(e, family) << [asn, flags].pack("Nn")
      end
      out
    end

    def orgs(names)
      index = +"".b
      blob = +"".b
      names.sort.each do |(asn, org)|
        index << [asn, blob.bytesize].pack("NN")
        blob << org.b
      end
      Orgs::MAGIC.b + [Orgs::VERSION, 0, 0].pack("CCn") + [names.length, blob.bytesize].pack("NN") + index + blob
    end
  end
end
