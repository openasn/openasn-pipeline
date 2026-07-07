# frozen_string_literal: true

# Publish-stage invariants. These exist because of the 2026-07-05 badge
# incident (see the "Latest badge semantics" block in pipeline/publish.rb):
# the first weekly dated release stole GitHub's "Latest" badge from the
# rolling release, silently redirecting every `releases/latest/download/...`
# consumer to a frozen snapshot. The gh invocations are built by pure
# functions precisely so these tests can pin the flags without a gh binary,
# network, or a real build.

require_relative "test_helper"
require_relative "../pipeline/publish"

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

    def test_notes_survive_a_manifest_without_stats
      # First-ever build in a fork: crosscheck may contribute no stats. Notes
      # must degrade to blanks, not raise NoMethodError mid-publish.
      bare = { build_id: "2026-01-01T00:00:00Z", stats: {} }
      assert_includes Publish.rolling_release_notes(bare), "`2026-01-01T00:00:00Z`"
      assert_includes Publish.dated_release_notes("2026-01-01", bare), "`2026-01-01T00:00:00Z`"
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
end
