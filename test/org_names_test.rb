# frozen_string_literal: true

# Org names after D-SRC-2 (data-repo DECISIONS.md): CC0 sources only.
# ipverse's `description` (bulk RIR WHOIS descr) must never reach
# openasn-orgs.bin or the asn-categories.csv `org` column. SPARQL JSON shapes
# are as returned by query.wikidata.org on 2026-09-19. No network.

require_relative "test_helper"
require "tmpdir"
require "csv"
require_relative "../pipeline/lib/wikidata_names"
require_relative "../pipeline/lib/orgs"
require_relative "../pipeline/publish"
require_relative "../pipeline/tools/org_names_from_dossiers"
require_relative "publish_test"

module OpenASNPipeline
  class WikidataNamesTest < Minitest::Test
    ARIN_BULK = "https://ftp.arin.net/pub/resource_registry_service/asns.csv"

    def b(qid, asn, label: nil, rank: "NormalRank", ended: false, refs: "")
      h = { "item" => { "value" => "http://www.wikidata.org/entity/#{qid}" }, "asn" => { "value" => asn },
            "rank" => { "value" => "http://wikiba.se/ontology##{rank}" }, "refs" => { "value" => refs } }
      h["en"] = { "value" => label } if label
      h["end"] = { "value" => "2019-01-01T00:00:00Z" } if ended
      h
    end

    def json(*bindings) = JSON.generate("head" => {}, "results" => { "bindings" => bindings })

    def test_statement_rules
      names, stats = WikidataNames.parse(json(
        b("Q95", "15169", label: "Google"), b("Q95", "AS396982", label: "Google"),
        b("Q1", "100", label: "Dep", rank: "DeprecatedRank"), b("Q2", "200", label: "Old", ended: true),
        b("Q3", "300", label: "A"), b("Q4", "300", label: "B"),   # two items claim one ASN
        b("Q5", "1-5", label: "Range"), b("Q6", "0", label: "Zero"), b("Q7", "400")  # junk, zero, no label
      ))
      assert_equal({ "name" => "Google", "qid" => "Q95" }, names[15_169])
      assert_equal "Q95", names[396_982]["qid"]
      [100, 200, 300, 400].each { |asn| refute names.key?(asn), "AS#{asn}" }
      assert_equal 1, stats["deprecated"]
      assert_equal 1, stats["ended"]
      assert_equal 1, stats["conflict"]
      assert_equal 2, stats["bad_asn"]
      assert_equal 1, stats["no_label"]
      assert_equal 2, stats["admitted_asns"]
    end

    # The measured 2026-09-19 case: 1,138 of 1,817 P3797 statements cite only
    # ARIN's bulk asns.csv. Wikidata's CC0 cannot launder ARIN's terms.
    def test_statements_resting_only_on_registry_or_aggregator_refs_are_dropped
      names, stats = WikidataNames.parse(json(
        b("Q10", "10", label: "Bulk only", refs: "r1|#{ARIN_BULK}"),
        b("Q11", "11", label: "Two bad refs", refs: "r1|https://rdap.arin.net/x r2|https://www.peeringdb.com/asn/11"),
        b("Q12", "12", label: "One good ref", refs: "r1|#{ARIN_BULK} r2|https://example.net/peering"),
        b("Q13", "13", label: "No refs at all"),
        b("Q14", "14", label: "Ref without URL", refs: "r1|"),
        b("Q15", "15", label: "CAIDA", refs: "r1|https://asrank.caida.org/asns/15")
      ))
      assert_equal [12, 13, 14], names.keys.sort
      assert_equal 3, stats["restricted_refs_only"]
    end

    # A ref with one restricted URL is restricted even if it also has a good
    # URL. Only a whole reference that avoids them counts.
    def test_admissibility_is_judged_per_reference
      refute WikidataNames.admissible?("r1|#{ARIN_BULK} r1|https://example.net/")
      assert WikidataNames.admissible?("r1|#{ARIN_BULK} r2|https://example.net/")
      assert WikidataNames.admissible?("")
    end

    def test_restricted_hosts_match_by_suffix_only
      assert WikidataNames.restricted_url?("https://whois.arin.net/rest/asn/AS1")
      assert WikidataNames.restricted_url?("https://apps.db.ripe.net/db-web-ui/query")
      refute WikidataNames.restricted_url?("https://notarin.net.example.com/")
      refute WikidataNames.restricted_url?("https://peering.ovh.net/")
    end

    def test_error_pages_raise_instead_of_publishing_nothing
      assert_raises(JSON::ParserError) { WikidataNames.parse("<html>502 Bad Gateway</html>") }
      assert_raises(ArgumentError) { WikidataNames.parse("{}") }
    end

    def test_mul_label_is_the_fallback_and_labels_are_single_line
      names, = WikidataNames.parse(json(b("Q180", "14907").merge("mul" => { "value" => "Wikimedia\nFoundation " })))
      assert_equal "Wikimedia Foundation", names[14_907]["name"]
    end
  end

  class OrgNamesOverridesTest < Minitest::Test
    def with_org_names(body)
      Dir.mktmpdir do |dir|
        File.write(File.join(dir, "org_names.txt"), body)
        yield Overrides.load(dir)
      end
    end

    def test_parses_name_and_src
      with_org_names("# header\nAS15169  Google  # src: https://support.google.com/interconnect/answer/10004057 (2026-09-19)\n" \
                     "AS3352  Telefónica de España (Movistar)  # src: https://www.telefonica.es/ (2026-09-19)\n") do |o|
        assert_equal({ "name" => "Google", "src" => "https://support.google.com/interconnect/answer/10004057" }, o.org_names[15_169])
        assert_equal "Telefónica de España (Movistar)", o.org_names[3352]["name"]
        refute o.all_asns.include?(15_169), "org names must not feed gap-fill / flag membership"
      end
    end

    def test_a_name_resting_on_whois_fails_the_build
      assert_raises(StageFailure) do
        with_org_names("AS1  Level 3  # src: https://rdap.arin.net/registry/autnum/1 (2026-09-19)\n") { nil }
      end
    end

    def test_unsourced_malformed_and_duplicate_lines_fail
      ["AS1  Name  # no url here\n", "AS1 # only a comment https://example.com\n",
       "AS1  A  # src: https://a.example/ (x)\nAS1  B  # src: https://b.example/ (x)\n"].each do |body|
        assert_raises(StageFailure, body) { with_org_names(body) { nil } }
      end
    end
  end

  class OrgsSidecarTest < Minitest::Test
    def test_overrides_win_over_wikidata
      merged = Orgs.merge({ 7922 => { "name" => "Comcast", "src" => "https://corporate.comcast.com/" } },
                          { 7922 => { "name" => "Xfinity", "qid" => "Q5151002" },
                            3320 => { "name" => "Deutsche Telekom", "qid" => "Q9396" } })
      assert_equal({ "name" => "Comcast", "source" => "override" }, merged[7922])
      assert_equal({ "name" => "Deutsche Telekom", "source" => "wikidata:Q9396" }, merged[3320])
      assert_equal({ "total" => 2, "override" => 1, "wikidata" => 1 }, Orgs.source_counts(merged))
    end

    def test_write_round_trips_through_the_reference_reader
      Dir.mktmpdir do |dir|
        path = File.join(dir, "openasn-orgs.bin")
        Env.logger.level = Logger::WARN
        Orgs.write(path, { 15_169 => { "name" => "Google" }, 3352 => { "name" => "Telefónica de España" },
                           1 => { "name" => "  " } })
        assert_equal "Google", Orgs.read(path, 15_169)
        assert_equal "Telefónica de España", Orgs.read(path, 3352)
        assert_nil Orgs.read(path, 1) # blank names get no entry
        assert_equal 2, File.binread(path, 16)[8, 4].unpack1("N")
      ensure
        Env.logger.level = Logger::INFO
      end
    end
  end

  # The legal guard itself: an ipverse description sitting in asn_meta must
  # not appear in the CSV. The CSV row set and the other columns are unchanged.
  class OrgColumnIsCc0OnlyTest < Minitest::Test
    def test_csv_org_column_uses_cc0_names_and_blanks_the_rest
      Dir.mktmpdir do |dir|
        old = OpenASNPipeline::DIST_DIR
        silence { OpenASNPipeline.const_set(:DIST_DIR, dir) }
        meta = { 15_169 => AsJson::Record.new(15_169, "GOOGLE - WHOIS DESCR", "US", "hosting", "content_network"),
                 64_500 => AsJson::Record.new(64_500, "SOME WHOIS DESCR", "DE", "isp", "access_provider") }
        Publish.write_asn_categories_csv({ asn_meta: meta },
                                         { flags_by_asn: Hash.new(0), org_names: { 15_169 => { "name" => "Google" } },
                                           base_v4: [[0, 255, 64_500, 0]], # routed, so written (CD-19d)
                                           countries: { 15_169 => { "cc" => "US", "source" => "override" } } })
        rows = CSV.read(File.join(dir, "asn-categories.csv"))
        assert_equal %w[asn org country category network_role openasn_flags], rows[0]
        assert_equal ["15169", "Google", "US"], rows[1][0, 3]
        assert_equal ["64500", nil, nil], rows[2][0, 3] # registry country "DE" never published (D-SRC-2, country)
        refute_includes File.read(File.join(dir, "asn-categories.csv")), "WHOIS DESCR"
      ensure
        silence { OpenASNPipeline.const_set(:DIST_DIR, old) }
      end
    end

    def silence
      verbose = $VERBOSE
      $VERBOSE = nil
      yield
    ensure
      $VERBOSE = verbose
    end
  end

  class WikidataLicensePinTest < Minitest::Test
    GRANT = "All structured data from the main, Property, Lexeme, and EntitySchema namespaces is available " \
            "under the [[Wikidata:Text of the Creative Commons Public Domain Dedication|Creative Commons CC0 License]]; ..."

    def test_pins_the_grant_sentence_only
      body = "#{GRANT}\n\n== Other ==\nchurn that must not trip the gate\n"
      assert_equal GRANT, LicenseGate.extract(body, :wikidata_cc0, "wikidata-p3797")
      assert_equal GRANT, LicenseGate.extract(body.sub("churn", "different churn"), :wikidata_cc0, "wikidata-p3797")
    end

    def test_a_missing_grant_fails_loudly
      assert_raises(StageFailure) { LicenseGate.extract("page rewritten", :wikidata_cc0, "wikidata-p3797") }
    end

    def test_pin_only_rejects_unknown_ids
      assert_raises(ArgumentError) { LicenseGate.pin!(http: nil, only: ["no-such-source"]) }
    end

    def test_org_stats_reach_the_manifest_shape
      stats = Publish.manifest_stats(PublishManifestStatsTest::ARTIFACTS, PublishManifestStatsTest::CROSSCHECK,
                                     org_stats: { org_names: 777, org_names_by_source: { "override" => 258, "wikidata" => 519 } })
      assert_equal 777, stats[:org_names]
      assert_equal %i[layer_counts hosting_asns reference_dc_asns reference_coverage org_names org_names_by_source], stats.keys
    end
  end

  class OrgNamesFromDossiersTest < Minitest::Test
    def dossier(asn, display, website:, evidence: [], qid: nil)
      { "asn" => asn, "org" => { "display_name" => display, "legal_name" => "#{display} Holdings Inc.", "website" => website },
        "evidence" => evidence, "external_ids" => { "wikidata_qid" => qid } }
    end

    def test_registry_and_aggregator_evidence_never_becomes_the_citation
      rec = dossier(209, "Lumen Technologies (CenturyLink) — AS209", website: "https://www.lumen.com/",
                    evidence: [{ "claim" => "AS209 registrant", "url" => "https://rdap.arin.net/registry/autnum/209" },
                               { "claim" => "AS209 rank", "url" => "https://asrank.caida.org/asns/209" }])
      row, = OrgNamesFromDossiers.draft(rec)
      assert_equal [209, "Lumen Technologies (CenturyLink)", "https://www.lumen.com/", "operator_website"], row
    end

    def test_first_party_page_naming_the_asn_is_preferred
      rec = dossier(2914, "NTT Global IP Network (AS2914)", website: "https://www.gin.ntt.net/",
                    evidence: [{ "claim" => "NTT operates AS2914", "url" => "https://www.gin.ntt.net/about/" }])
      assert_equal [2914, "NTT Global IP Network", "https://www.gin.ntt.net/about/", "evidence_names_asn"],
                   OrgNamesFromDossiers.draft(rec).first
    end

    def test_wikidata_item_is_the_last_resort_and_no_source_skips
      assert_equal "https://www.wikidata.org/wiki/Q1", OrgNamesFromDossiers.draft(dossier(1, "X", website: nil, qid: "Q1")).first[2]
      assert_equal [nil, "no_admissible_source"], OrgNamesFromDossiers.draft(dossier(1, "X", website: "https://peeringdb.com/x"))
    end
  end
end
