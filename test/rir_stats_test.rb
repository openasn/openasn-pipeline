# frozen_string_literal: true

# RIR delegated-extended stats (lib/rir_stats.rb) + the curation-scope license
# pins that govern them (D-SRC-1). Fixture lines are real record shapes from
# the 2026-09-18 files of each RIR. No network.

require_relative "test_helper"
require "tmpdir"
require_relative "../pipeline/lib/rir_stats"
require_relative "../pipeline/tools/rir_siblings"

module OpenASNPipeline
  class RirStatsTest < Minitest::Test
    ARIN = <<~TXT
      2.3|arin|1789736421462|202816|19700101|20260918|-0400
      arin|*|asn|*|32959|summary
      arin|*|ipv4|*|80795|summary
      arin||asn|212|1||reserved|
      arin|US|asn|1|1|19840222|assigned|8f5d315929a560376b0b58b40a1932fa
      arin|US|asn|7|2|00000000|assigned|8f5d315929a560376b0b58b40a1932fa
      arin|US|asn|3356|1|20000310|assigned|589f9199b0aaaaaaaaaaaaaaaaaaaaaa
      arin|US|ipv4|8.0.0.0|16777216|19921201|allocated|589f9199b0aaaaaaaaaaaaaaaaaaaaaa
      arin|ZZ|asn|99999|1|20260101|available|
    TXT

    APNIC = <<~TXT
      ######################################################################
      #
      # 	CONDITIONS OF USE
      # The files are freely available for download and use on the condition
      2|apnic|20260919|190000|19830613|20260918|+1000
      apnic|*|asn|*|14750|summary
      apnic|JP|asn|2497|32|20020405|allocated|A91A7381
      apnic|AU|asn|4608|1|19930401|allocated|A9172506
      apnic|AU|asn|4739|1|19950101|allocated|A9172506
      apnic||asn|4800|1||available|
    TXT

    LACNIC_7FIELD = "lacnic||asn|27648|1||available\n"

    def rows_and_clusters(*bodies)
      ds = bodies.flat_map { |b, rir| RirStats.parse_delegations(b, rir: rir) }
      rows, conflicts = RirStats.expand(ds)
      [rows, RirStats.clusters(rows), conflicts]
    end

    def test_parse_skips_version_summary_comments_and_non_asn
      ds = RirStats.parse_delegations(ARIN, rir: "arin")
      assert_equal [212, 1, 7, 3356, 99_999], ds.map { _1["start"] }
      assert(ds.none? { _1["status"] == "summary" })
      assert_equal 4, RirStats.parse_delegations(APNIC, rir: "apnic").size # "#" header lines ignored
    end

    def test_sentinels_become_nil_never_fabricated
      ds = RirStats.parse_delegations(ARIN, rir: "arin").to_h { [_1["start"], _1] }
      assert_nil ds[7]["date"]            # 00000000
      assert_nil ds[212]["opaque_id"]     # empty opaque-id
      assert_nil ds[212]["cc"]            # empty cc
      assert_nil ds[99_999]["cc"]         # ZZ
      assert_equal "1984-02-22", ds[1]["date"]
      assert_nil RirStats.date("19700101")
      ds7 = RirStats.parse_delegations(LACNIC_7FIELD, rir: "lacnic").first
      assert_equal "available", ds7["status"]
      assert_nil ds7["opaque_id"]
    end

    def test_foreign_registry_line_is_rejected
      merged = ARIN + "ripencc|NL|asn|1101|1|19930901|allocated|8a5e4b44-5d1c-4f4c-9b2d-111111111111\n"
      err = assert_raises(RirStats::ParseError) { RirStats.parse_delegations(merged, rir: "arin") }
      assert_match(/merged\/NRO/, err.message)
    end

    def test_unknown_status_and_bad_count_are_loud
      assert_raises(RirStats::ParseError) { RirStats.parse_delegations("arin|US|asn|5|1|20200101|weird|x\n", rir: "arin") }
      assert_raises(RirStats::ParseError) { RirStats.parse_delegations("arin|US|asn|5|0|20200101|assigned|x\n", rir: "arin") }
    end

    def test_blocks_expand_and_holders_are_keyed_by_rir
      rows, cl, = rows_and_clusters([ARIN, "arin"], [APNIC, "apnic"])
      assert_equal "apnic:A91A7381", rows[2528]["holder"]   # last ASN of the 32-block
      refute rows.key?(2529)
      assert_equal [1, 7, 8], cl["arin:8f5d315929a560376b0b58b40a1932fa"] # 7|2 -> 7,8
      assert_equal [4608, 4739], cl["apnic:A9172506"]
      refute cl.key?("A9172506")                              # never an un-prefixed key
    end

    def test_clusters_count_delegated_rows_only
      body = "arin|US|asn|10|1|20200101|assigned|abc\narin||asn|11|1||reserved|abc\n"
      rows, cl, = rows_and_clusters([body, "arin"])
      assert_equal [10], cl["arin:abc"]
      assert_equal "reserved", rows[11]["status"]
    end

    def test_siblings_never_cross_a_pool
      rows, cl, = rows_and_clusters([ARIN, "arin"], [APNIC, "apnic"])
      assert_equal [7, 8], RirStats.siblings(1, rows, cl)
      assert_equal [4739], RirStats.siblings(4608, rows, cl)
      assert_equal [], RirStats.siblings(3356, rows, cl)       # single-ASN holder
      assert_equal [], RirStats.siblings(424_242, rows, cl)    # unknown ASN

      pool = "apnic|IN|asn|131072|#{RirStats::POOL_THRESHOLD + 1}|20100101|allocated|A918EDB2\n"
      prows, pcl, = rows_and_clusters([pool, "apnic"])
      assert_equal :pool, RirStats.cluster_kind(pcl["apnic:A918EDB2"].size)
      assert_equal [], RirStats.siblings(131_072, prows, pcl)
      assert_equal :siblings, RirStats.cluster_kind(RirStats::POOL_THRESHOLD)
    end

    def test_cross_rir_conflict_is_dropped_not_guessed
      a = "arin|US|asn|500|1|20200101|assigned|x\n"
      b = "lacnic|BR|asn|500|1|20210101|allocated|y\n"
      rows, _cl, conflicts = rows_and_clusters([a, "arin"], [b, "lacnic"])
      assert_equal [500], conflicts
      refute rows.key?(500)
    end

    def test_ripe_is_opt_in_and_nothing_is_publishable
      refute_includes RirStats.enabled_rirs({}), "ripencc"
      assert_includes RirStats.enabled_rirs(RirStats::INCLUDE_RIPE_ENV => "1"), "ripencc"
      assert_equal %w[afrinic apnic arin lacnic], RirStats.enabled_rirs({}).sort
      assert_equal false, RirStats::PUBLISHABLE
      assert_nil RirStats::REGISTRIES.dig("ripencc", :terms)
      RirStats::REGISTRIES.each_value { |spec| refute_match(/nro-stats|combined|merged/, spec[:url]) }
    end

    # Structural guard for D-SRC-1: the published build never reads RIR stats
    # and the manifest never lists them as a source.
    def test_published_build_path_does_not_touch_rir_stats
      root = File.expand_path("../pipeline", __dir__)
      %w[run.rb fetch.rb normalize.rb crosscheck.rb compile.rb validate.rb publish.rb].each do |f|
        refute_match(/rir_stats|RirStats|delegated-.*-extended/, File.read(File.join(root, f)), "#{f} must not use RIR stats")
      end
      refute(Sources::CATALOG.any? { _1[:id].match?(/rir|apnic|arin|lacnic|afrinic|ripe/) })
      refute(Sources::LICENSE_URLS.keys.any? { _1.include?("delegated-stats") })
    end

    def test_sibling_candidates_skip_already_listed_and_cite_the_rir_file
      rows, cl, = rows_and_clusters([ARIN, "arin"], [APNIC, "apnic"])
      cands = RirSiblings.candidates(Set[1, 7], rows, cl)
      assert_equal({ 8 => [1, 7] }, cands)
      text = RirSiblings.render(:hosting_extra, cands, rows, { "arin" => { "fetched_at" => "2026-09-19T05:00:00Z" } })
      line = text.lines.last
      assert_match(/\AAS8  # sibling of AS1,AS7 \(holder arin:8f5d/, line)
      assert_includes line, "src: #{RirStats::REGISTRIES['arin'][:url]} (fetched 2026-09-19T05:00:00Z)"
      assert_match(/NOT an override file/, text)
    end
  end

  class CurationLicenseScopeTest < Minitest::Test
    APNIC_README = <<~TXT
      1.	ABOUT THESE REPORTS
      blah

      2.    CONDITIONS OF USE
      ____________________________________________________________________


      The files are freely available for download and use on the condition
      that APNIC will not be held responsible for any loss or damage
      arising from the use of the information contained in these reports.



      3.    STATISTICS FORMAT
      ____________________________________________________________________
      3.1   File names  (this churns daily and must not trip the gate)
    TXT

    def test_conditions_of_use_extraction
      t = LicenseGate.extract(APNIC_README, :conditions_of_use_section, "apnic")
      assert t.start_with?("2.    CONDITIONS OF USE")
      assert_includes t, "freely available for download and use"
      refute_includes t, "STATISTICS FORMAT"
      refute_includes t, "ABOUT THESE REPORTS"
    end

    def test_conditions_extraction_failure_is_loud
      assert_raises(StageFailure) { LicenseGate.extract("no sections here", :conditions_of_use_section, "apnic") }
    end

    def test_nightly_scope_is_tier_a_only
      assert_equal Sources::LICENSE_URLS.keys.sort, LicenseGate.specs.keys.sort
      assert_equal Sources::CURATION_TERMS_URLS.keys.sort, LicenseGate.specs(:curation).keys.sort
      assert_equal (Sources::LICENSE_URLS.keys + Sources::CURATION_TERMS_URLS.keys).sort, LicenseGate.specs(:all).keys.sort
      assert_empty Sources::LICENSE_URLS.keys & Sources::CURATION_TERMS_URLS.keys
      assert_raises(ArgumentError) { LicenseGate.specs(:bogus) }
      # every RIR that is read has its terms pinned (ARIN: absence receipt)
      RirStats.enabled_rirs({}).each do |rir|
        assert_includes Sources::CURATION_TERMS_URLS.keys, RirStats::REGISTRIES[rir][:terms]
      end
    end

    FakeHttp = Struct.new(:bodies) do
      def get!(url) = bodies.fetch(url)
    end

    def test_pin_only_leaves_other_pins_byte_identical
      Dir.mktmpdir do |dir|
        lic = File.join(dir, "data", "licenses")
        FileUtils.mkdir_p(lic)
        FileUtils.mkdir_p(File.join(dir, "data", "overrides")) # Env.data_repo's marker dir
        before = { "sapics-origin-asn" => { "url" => "u", "extract" => "whole_file", "sha256" => "abc", "pinned_at" => "2026-07-04T20:25:49Z" } }
        File.write(File.join(lic, "pins.json"), JSON.pretty_generate(before) + "\n")
        File.write(File.join(lic, "sapics-origin-asn.txt"), "old text")
        http = FakeHttp.new({ Sources::CURATION_TERMS_URLS["lacnic-delegated-stats"][:url] => "[EN]\nfreely available\n" })
        with_env("OPENASN_DATA_REPO" => dir) do
          LicenseGate.pin!(http: http, only: ["lacnic-delegated-stats"])
          assert_raises(ArgumentError) { LicenseGate.pin!(http: http, only: ["nope"]) }
        end
        pins = JSON.parse(File.read(File.join(lic, "pins.json")))
        assert_equal before["sapics-origin-asn"], pins["sapics-origin-asn"]
        assert_equal "old text", File.read(File.join(lic, "sapics-origin-asn.txt"))
        assert_equal "curation", pins.dig("lacnic-delegated-stats", "scope")
        assert_equal Digest::SHA256.hexdigest("[EN]\nfreely available\n"), pins.dig("lacnic-delegated-stats", "sha256")
      end
    end

    def with_env(vars)
      old = vars.keys.to_h { [_1, ENV[_1]] }
      memo = Env.instance_variable_get(:@data_repo) # Env memoizes the data repo path
      Env.instance_variable_set(:@data_repo, nil)
      vars.each { ENV[_1] = _2 }
      yield
    ensure
      old.each { ENV[_1] = _2 }
      Env.instance_variable_set(:@data_repo, memo)
    end
  end
end
