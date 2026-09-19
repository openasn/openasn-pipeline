# frozen_string_literal: true

# The RouteViews backbone switch (default since D-SRC-2 (backbone); legacy sapics via
# OPENASN_BACKBONE=sapics). The derivation itself is tested in Go (tools/rib2origin);
# these cover the Ruby wiring: URLs, slot choice, and that licence pins and
# manifest sources follow the backbone actually compiled from.

require_relative "test_helper"
require "json"
require_relative "../pipeline/lib/sources"
require_relative "../pipeline/lib/license_gate"

module OpenASNPipeline
  class RouteViewsSourcesTest < Minitest::Test
    def with_env(vars)
      old = vars.to_h { |k, _| [k, ENV[k]] }
      vars.each { |k, v| ENV[k] = v }
      yield
    ensure
      old.each { |k, v| ENV[k] = v }
    end

    def test_default_backbone_is_routeviews
      [nil, "", " "].each do |unset|
        with_env("OPENASN_BACKBONE" => unset) do
          assert_equal "routeviews", Sources.backbone
          assert_same Sources::LICENSE_URLS, Sources.license_urls
          assert_same Sources::CATALOG, Sources.catalog
        end
      end
      # The default pins and sources carry RouteViews and never sapics: the
      # pins file is written from these (rake licenses:pin).
      refute Sources::LICENSE_URLS.key?("sapics-origin-asn")
      assert_equal :wp_json_rendered_text, Sources::LICENSE_URLS.fetch("routeviews")[:extract]
      ids = Sources::CATALOG.map { |s| s[:id] }
      assert_includes ids, "routeviews"
      refute_includes ids, "sapics-origin-asn"
    end

    def test_unknown_backbone_fails_loudly
      with_env("OPENASN_BACKBONE" => "ris") do
        assert_raises(StageFailure) { Sources.backbone }
      end
    end

    def test_legacy_sapics_backbone_swaps_pins_and_catalog_back
      with_env("OPENASN_BACKBONE" => "sapics") do
        refute Sources.routeviews?
        refute Sources.license_urls.key?("routeviews")
        assert_equal :whole_file, Sources.license_urls.fetch("sapics-origin-asn")[:extract]
        ids = Sources.catalog.map { |s| s[:id] }
        refute_includes ids, "routeviews"
        assert_equal "sapics-origin-asn", ids.first
        # Every other source is identical under either backbone.
        assert_equal Sources::LICENSE_URLS.keys - ["routeviews"], Sources.license_urls.keys - ["sapics-origin-asn"]
      end
    end

    def test_rib_urls_root_collector_vs_subdirectory
      assert_equal "https://archive.routeviews.org/bgpdata/2026.09/RIBS/rib.20260918.2000.bz2",
                   Sources.routeviews_rib_url("route-views2", "20260918.2000")
      assert_equal "https://archive.routeviews.org/route-views.linx/bgpdata/2026.09/RIBS/rib.20260918.2000.bz2",
                   Sources.routeviews_rib_url("route-views.linx", "20260918.2000")
    end

    def test_slot_is_even_hour_at_least_three_hours_old
      with_env("OPENASN_RV_RIB_SLOT" => nil) do
        assert_equal "20260919.0000", Sources.routeviews_slot(Time.utc(2026, 9, 19, 3, 17))
        assert_equal "20260918.2200", Sources.routeviews_slot(Time.utc(2026, 9, 19, 2, 59))
        assert_equal "20260919.1000", Sources.routeviews_slot(Time.utc(2026, 9, 19, 13, 0))
      end
      with_env("OPENASN_RV_RIB_SLOT" => "20260918.2000") do
        assert_equal "20260918.2000", Sources.routeviews_slot(Time.utc(2026, 9, 19, 3, 17))
      end
    end

    def test_licence_text_extraction_ignores_markup
      a = JSON.generate("content" => { "rendered" => "<p>Use of the data is licensed under\n<a href=\"x\">CC BY 4.0</a>.</p>" })
      b = JSON.generate("content" => { "rendered" => "<p class=\"new-theme\">Use of the data is licensed under <strong>CC BY 4.0</strong>.</p>" })
      assert_equal LicenseGate.extract(a, :wp_json_rendered_text, "routeviews"),
                   LicenseGate.extract(b, :wp_json_rendered_text, "routeviews")
      assert_raises(StageFailure) { LicenseGate.extract("{}", :wp_json_rendered_text, "routeviews") }
    end
  end
end

require "tmpdir"
require_relative "../pipeline/lib/http"
require_relative "../pipeline/lib/routeviews"

module OpenASNPipeline
  # RB-1 (review 2026-09-19): a collector's missing RIB must never be replaced
  # by a cached RIB of arbitrary age. The first version used one slot-less
  # cache key per collector, so Http#fetch's keep-last-good served whatever
  # RIB was last downloaded - from a collector retired months ago, forever.
  class RouteViewsRibResolutionTest < Minitest::Test
    SLOT = "20260919.0000"

    # An Http whose network answers only for `live` collectors.
    def http_with(dir, live:)
      http = Http.new(cache_dir: dir)
      http.define_singleton_method(:fetch) do |url, key, offline: false|
        path = path_for(key)
        return path if offline && File.exist?(path)
        raise StageFailure, "offline mode but no cached copy of #{key}" if offline
        raise StageFailure, "HTTP 404 for #{url}" unless live.any? { |c| url.include?("/#{c}/") || (c == "route-views2" && url.include?(".org/bgpdata/")) }

        FileUtils.mkdir_p(File.dirname(path))
        File.write(path, "fresh")
        path
      end
      http
    end

    def seed(dir, collector, slot)
      path = File.join(dir, RouteViews.cache_key(collector, slot))
      FileUtils.mkdir_p(File.dirname(path))
      File.write(path, "cached #{slot}")
      path
    end

    def all = Sources::ROUTEVIEWS_COLLECTORS

    def test_fresh_slot_is_used_and_older_cached_ribs_are_pruned
      Dir.mktmpdir do |dir|
        old = seed(dir, "route-views.linx", "20260918.0000")
        legacy = File.join(dir, RouteViews.legacy_cache_key("route-views.linx"))
        File.write(legacy, "pre-RB-1 slot-less cache")
        ribs = RouteViews.resolve_ribs(http: http_with(dir, live: all), offline: false, slot: SLOT)
        assert_equal all, ribs.keys
        assert(ribs.values.all? { |r| r[:slot] == SLOT })
        refute File.exist?(old), "yesterday's RIB is pruned once today's is in"
        refute File.exist?(legacy), "the slot-less pre-RB-1 file is pruned"
      end
    end

    def test_a_dead_collector_never_votes_with_an_old_rib
      Dir.mktmpdir do |dir|
        ancient = seed(dir, "route-views.linx", "20260619.0000") # a collector retired three months ago
        ribs = RouteViews.resolve_ribs(http: http_with(dir, live: all - ["route-views.linx"]), offline: false, slot: SLOT)
        refute ribs.key?("route-views.linx"), "a 92-day-old RIB must not stand in for today's"
        assert_equal all.size - 1, ribs.size
        refute File.exist?(ancient), "a RIB past the fallback window can never be used again: pruned"
      end
    end

    def test_one_nightly_back_is_a_stamped_fallback_not_a_silent_one
      Dir.mktmpdir do |dir|
        yesterday = seed(dir, "route-views6", "20260918.0000")
        ribs = RouteViews.resolve_ribs(http: http_with(dir, live: all - ["route-views6"]), offline: false, slot: SLOT)
        assert_equal "20260918.0000", ribs.dig("route-views6", :slot)
        assert_equal yesterday, ribs.dig("route-views6", :path)
        assert File.exist?(yesterday), "the RIB in use is kept"
        # 36h is the limit: 38h older is skipped.
        FileUtils.rm_f(yesterday)
        seed(dir, "route-views6", "20260917.1000")
        ribs = RouteViews.resolve_ribs(http: http_with(dir, live: all - ["route-views6"]), offline: false, slot: SLOT)
        refute ribs.key?("route-views6")
      end
    end

    def test_a_newer_cached_rib_never_stands_in_for_an_older_requested_slot
      Dir.mktmpdir do |dir|
        seed(dir, "route-views.sg", "20260919.0200")
        ribs = RouteViews.resolve_ribs(http: http_with(dir, live: all - ["route-views.sg"]), offline: false, slot: SLOT)
        refute ribs.key?("route-views.sg")
      end
    end

    def test_offline_takes_the_newest_cached_rib_of_any_age_and_reports_its_slot
      Dir.mktmpdir do |dir|
        all.each { |c| seed(dir, c, "20260801.2000") }
        seed(dir, "route-views2", "20260918.2000")
        ribs = RouteViews.resolve_ribs(http: http_with(dir, live: []), offline: true, slot: SLOT)
        assert_equal all, ribs.keys
        assert_equal "20260918.2000", ribs.dig("route-views2", :slot)
        assert_equal "20260801.2000", ribs.dig("route-views.linx", :slot)
        assert File.exist?(File.join(dir, RouteViews.cache_key("route-views2", "20260801.2000"))), "offline never prunes"
      end
    end
  end
end
