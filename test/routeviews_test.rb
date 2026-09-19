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
