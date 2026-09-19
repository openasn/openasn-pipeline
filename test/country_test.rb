# frozen_string_literal: true

# Per-ASN country after D-SRC-2 (country) (data-repo DECISIONS.md): CC0
# sources only. ipverse's countryCode (sourced "from regional internet
# registries") must never reach the asn-categories.csv `country` column.
# SPARQL JSON shapes are as returned by query.wikidata.org on 2026-09-19.
# No network.

require_relative "test_helper"
require "tmpdir"
require "csv"
require_relative "../pipeline/lib/wikidata_names"
require_relative "../pipeline/lib/wikidata_countries"
require_relative "../pipeline/lib/countries"
require_relative "../pipeline/publish"
require_relative "../pipeline/validate"
require_relative "../pipeline/tools/asn_country_from_dossiers"
require_relative "publish_test"

module OpenASNPipeline
  class WikidataCountriesTest < Minitest::Test
    ARIN_BULK = "https://ftp.arin.net/pub/resource_registry_service/asns.csv"

    def b(qid, via, cc, rank: "NormalRank", ended: false, refs: "")
      h = { "item" => { "value" => "http://www.wikidata.org/entity/#{qid}" }, "via" => { "value" => via },
            "cc" => { "value" => cc }, "rank" => { "value" => "http://wikiba.se/ontology##{rank}" },
            "refs" => { "value" => refs } }
      h["end"] = { "value" => "2019-01-01T00:00:00Z" } if ended
      h
    end

    def json(*bindings) = JSON.generate("head" => {}, "results" => { "bindings" => bindings })

    def test_p17_wins_and_p159_is_the_fallback
      items, stats = WikidataCountries.parse(json(
        b("Q95", "P17", "US"), b("Q95", "P159", "IE"),       # P17 first
        b("Q1", "P159", "DE"),                                 # only HQ
        b("Q2", "P17", "US"), b("Q2", "P17", "GB"), b("Q2", "P159", "GB") # ambiguous P17 -> HQ
      ))
      assert_equal({ "cc" => "US", "via" => "P17" }, items["Q95"])
      assert_equal({ "cc" => "DE", "via" => "P159" }, items["Q1"])
      assert_equal({ "cc" => "GB", "via" => "P159" }, items["Q2"])
      assert_equal 1, stats["ambiguous_P17"]
    end

    def test_statement_rules
      items, stats = WikidataCountries.parse(json(
        b("Q3", "P17", "FR", rank: "DeprecatedRank"), b("Q4", "P17", "FR", ended: true),
        b("Q5", "P17", "XX"), b("Q6", "P17", "usa"),
        b("Q7", "P17", "CN"), b("Q7", "P17", "HK", rank: "PreferredRank"), # preferred only
        b("Q8", "P17", "NL"), b("Q8", "P17", "BE")                          # ambiguous, no HQ
      ))
      assert_equal({ "Q7" => { "cc" => "HK", "via" => "P17" } }, items)
      assert_equal 1, stats["deprecated"]
      assert_equal 1, stats["ended"]
      assert_equal 2, stats["bad_code"]
      assert_equal 1, stats["ambiguous_P17"]
    end

    # Same strictness as the P3797 names: registry/aggregator-only references
    # are dropped, whether cited by URL or by "stated in" item.
    def test_registry_only_references_are_dropped
      ripe = "http://www.wikidata.org/entity/Q1504968"
      items, stats = WikidataCountries.parse(json(
        b("Q10", "P17", "US", refs: "r1|#{ARIN_BULK}|"),
        b("Q11", "P17", "NL", refs: "r1||#{ripe}"),
        b("Q12", "P17", "NL", refs: "r1||#{ripe} r2|https://www.company.example/imprint|"),
        b("Q13", "P17", "SE", refs: "r1||http://www.wikidata.org/entity/Q27768150") # GRID: fine
      ))
      assert_equal %w[Q12 Q13], items.keys.sort
      assert_equal 2, stats["restricted_refs_only"]
    end

    def test_only_admitted_p3797_links_get_a_country
      names = { 15_169 => { "name" => "Google", "qid" => "Q95" }, 396_982 => { "name" => "Google", "qid" => "Q95" } }
      by_asn = WikidataCountries.for_asns(names, { "Q95" => { "cc" => "US", "via" => "P17" },
                                                   "Q999" => { "cc" => "FR", "via" => "P17" } })
      assert_equal({ "cc" => "US", "qid" => "Q95", "via" => "P17" }, by_asn[15_169])
      assert_equal [15_169, 396_982], by_asn.keys.sort
    end

    def region(qid, region_qid)
      { "item" => { "value" => "http://www.wikidata.org/entity/#{qid}" }, "via" => { "value" => "region" },
        "region" => { "value" => "http://www.wikidata.org/entity/#{region_qid}" } }
    end

    # CD-19b: ISO 3166-1 gives Hong Kong and Macau their own codes; Wikidata's
    # P17 for their companies is the PRC. Shapes as returned 2026-09-19
    # (Q5099786 China Mobile Hong Kong, Q15899929 China Telecom (Macau)).
    def test_hong_kong_and_macau_refine_cn_but_never_rewrite_another_country
      items, stats = WikidataCountries.parse(json(
        b("Q5099786", "P17", "CN"), b("Q5099786", "P159", "CN"), region("Q5099786", "Q8646"),
        b("Q15899929", "P17", "CN"), region("Q15899929", "Q14773"),
        b("Q7575433", "P17", "US"), b("Q7575433", "P159", "CN"), region("Q7575433", "Q8646"), # stale HK HQ
        region("Q77", "Q8646") # located in HK, no P17/P159 country of its own
      ))
      assert_equal({ "cc" => "HK", "via" => "region" }, items["Q5099786"])
      assert_equal({ "cc" => "MO", "via" => "region" }, items["Q15899929"])
      assert_equal({ "cc" => "US", "via" => "P17" }, items["Q7575433"])
      assert_equal({ "cc" => "HK", "via" => "region" }, items["Q77"])
      assert_equal 3, stats["sar"]
      assert_equal 5, stats["statements"], "region rows are not country statements"
    end

    # CD-19a: an item located in an occupied / breakaway territory publishes
    # the recognised state, never the de facto controller's code; any third
    # country makes it ambiguous. Q-numbers of the items are made up; the
    # region QIDs are the real ones (checked 2026-09-19).
    def test_wikidata_can_never_publish_the_occupier_for_a_territory_operator
      items, stats = WikidataCountries.parse(json(
        b("Q901", "P17", "RU"), region("Q901", "Q7835"),                          # Crimea, P17 Russia
        b("Q902", "P159", "RU"), region("Q902", "Q16150196"),                     # "DPR" HQ
        region("Q903", "Q7525"),                                                  # Sevastopol, no country
        b("Q904", "P17", "RU"), region("Q904", "Q23334"),                         # Abkhazia
        b("Q905", "P17", "RU"), region("Q905", "Q907112"),                        # Transnistria
        b("Q906", "P17", "TR"), region("Q906", "Q23681"),                         # Northern Cyprus
        b("Q907", "P17", "UA"), region("Q907", "Q171965"),                        # Luhansk Oblast, already UA
        b("Q908", "P17", "DE"), region("Q908", "Q756294")                         # third country: ambiguous
      ))
      assert_equal %w[UA UA UA GE MD CY UA], %w[Q901 Q902 Q903 Q904 Q905 Q906 Q907].map { |q| items.dig(q, "cc") }
      assert(%w[Q901 Q902 Q903 Q904 Q905 Q906 Q907].all? { |q| items.dig(q, "via") == "territory" })
      refute items.key?("Q908")
      assert_equal 7, stats["territory"]
      assert_equal 1, stats["ambiguous_territory"]
      refute(items.values.any? { |r| %w[RU TR].include?(r["cc"]) })
    end

    def test_the_query_asks_for_every_region_and_every_region_maps_to_a_state
      WikidataCountries::REGIONS.each do |qid, cc|
        assert_includes WikidataCountries::QUERY, "wd:#{qid} "[0..-2]
        assert(WikidataCountries::SAR_CODES.include?(cc) || Countries::TERRITORY_STATES.value?(cc), "#{qid} -> #{cc}")
      end
      assert_equal Countries::TERRITORY_STATES.values.uniq.sort,
                   (WikidataCountries::REGIONS.values.uniq - WikidataCountries::SAR_CODES).sort
    end

    def test_error_pages_raise_instead_of_publishing_nothing
      assert_raises(JSON::ParserError) { WikidataCountries.parse("<html>502 Bad Gateway</html>") }
      assert_raises(ArgumentError) { WikidataCountries.parse("{}") }
    end
  end

  class CountryOverridesTest < Minitest::Test
    def with_countries(body)
      Dir.mktmpdir do |dir|
        File.write(File.join(dir, "asn_country.txt"), body)
        yield Overrides.load(dir)
      end
    end

    def test_parses_code_and_src
      with_countries("# header\nAS15169  US  # src: https://about.google/intl/en/locations/ (2026-09-19)\n") do |o|
        assert_equal({ "cc" => "US", "src" => "https://about.google/intl/en/locations/" }, o.countries[15_169])
        refute o.all_asns.include?(15_169), "countries must not feed gap-fill / flag membership"
      end
    end

    def test_a_country_resting_on_registry_data_fails_the_build
      ["AS1  US  # src: https://rdap.arin.net/registry/autnum/1 (2026-09-19)\n",
       "AS3333  NL  # src: https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest (2026-09-19)\n"].each do |body|
        assert_raises(StageFailure, body) { with_countries(body) { nil } }
      end
    end

    def test_none_publishes_nothing
      with_countries("AS9002  --  # none: Wikidata says RU; src: https://retn.net/about (2026-09-19)\n") do |o|
        assert_equal({ "cc" => nil, "src" => "https://retn.net/about" }, o.countries[9002])
      end
    end

    # CD-19a: a territory-tagged line must carry the recognised state.
    def test_territory_lines_must_carry_the_recognised_state
      with_countries("AS201776  UA  # territory: crimea; src: https://en.wikipedia.org/wiki/Miranda_Media (2026-09-19)\n") do |o|
        assert_equal({ "cc" => "UA", "src" => "https://en.wikipedia.org/wiki/Miranda_Media", "territory" => "crimea" },
                     o.countries[201_776])
      end
      ["AS201776  RU  # territory: crimea; src: https://a.example/ (x)\n",
       "AS57354  RU  # territory: abkhazia; src: https://a.example/ (x)\n",
       "AS1  TR  # territory: northern_cyprus; src: https://a.example/ (x)\n",
       "AS1  --  # territory: transnistria; src: https://a.example/ (x)\n",
       "AS1  UA  # territory: donbas; src: https://a.example/ (x)\n",
       "AS1  UA  # territory: Crimea; src: https://a.example/ (x)\n"].each do |body|
        assert_raises(StageFailure, body) { with_countries(body) { nil } }
      end
    end

    def test_bad_codes_unsourced_and_duplicate_lines_fail
      ["AS1  usa  # src: https://a.example/ (x)\n", "AS1  XX  # src: https://a.example/ (x)\n",
       "AS1  EU  # src: https://a.example/ (x)\n", "AS1  US  # no url here\n",
       "AS1  US  # src: https://a.example/ (x)\nAS1  CA  # src: https://b.example/ (x)\n"].each do |body|
        assert_raises(StageFailure, body) { with_countries(body) { nil } }
      end
    end
  end

  class CountriesMergeTest < Minitest::Test
    def test_overrides_win_over_wikidata
      merged = Countries.merge({ 2914 => { "cc" => "US", "src" => "https://www.gin.ntt.net/" } },
                               { 2914 => { "cc" => "JP", "qid" => "Q6955512", "via" => "P17" },
                                 3320 => { "cc" => "DE", "qid" => "Q9396", "via" => "P17" } })
      assert_equal({ "cc" => "US", "source" => "override" }, merged[2914])
      assert_equal({ "cc" => "DE", "source" => "wikidata:Q9396:P17" }, merged[3320])
      assert_equal({ "total" => 2, "override" => 1, "wikidata" => 1 }, Countries.source_counts(merged))
    end

    def test_none_suppresses_the_wikidata_fallback
      merged = Countries.merge({ 9002 => { "cc" => nil, "src" => "https://retn.net/" } },
                               { 9002 => { "cc" => "RU", "qid" => "Q4047837", "via" => "P17" },
                                 57_304 => { "cc" => "RU", "qid" => "Q4047837", "via" => "P17" } })
      refute merged.key?(9002)
      assert_equal "RU", merged.dig(57_304, "cc")
    end

    # CD-19a end to end: a tagged Crimean operator whose Wikidata item says RU
    # publishes UA, and the belt-and-braces check refuses any other outcome.
    def test_a_territory_operator_never_publishes_the_occupier
      wd = { 201_776 => { "cc" => "RU", "qid" => "Q133119943", "via" => "P17" } }
      tagged = { 201_776 => { "cc" => "UA", "src" => "https://x.example/", "territory" => "crimea" } }
      assert_equal({ "cc" => "UA", "source" => "override" }, Countries.merge(tagged, wd)[201_776])
      assert_raises(StageFailure) do
        Countries.check_territories!(tagged, { 201_776 => { "cc" => "RU", "source" => "wikidata:Q133119943:P17" } })
      end
    end

    # CD-25: the guard binds operators SEATED in a territory (tagged lines),
    # not operators seated elsewhere that run a network there. K-Telecom
    # (Krasnodar, Russia; network in occupied Crimea) is an untagged RU line
    # and publishes RU, even if a Wikidata item placed it in Crimea.
    def test_an_operator_seated_outside_a_territory_keeps_its_seat_country
      line = "AS203451  RU  # src: https://en.wikipedia.org/wiki/K-Telecom " \
             "(\"Krasnodar, Russia\"; network in occupied Crimea) (2026-09-19)\n"
      override = Dir.mktmpdir do |dir|
        File.write(File.join(dir, "asn_country.txt"), line)
        Overrides.load(dir).countries
      end
      assert_equal({ "cc" => "RU", "src" => "https://en.wikipedia.org/wiki/K-Telecom" }, override[203_451])
      wd = { 203_451 => { "cc" => "UA", "qid" => "Q113412240", "via" => "territory" } }
      merged = Countries.merge(override, wd)
      assert_equal({ "cc" => "RU", "source" => "override" }, merged[203_451])
      Countries.check_territories!(override, merged) # no StageFailure
    end
  end

  # The legal guard itself: an RIR country sitting in asn_meta must not appear
  # in the CSV. Rows, header and the other columns are unchanged.
  class CountryColumnIsCc0OnlyTest < Minitest::Test
    def test_csv_country_column_uses_cc0_values_and_blanks_the_rest
      Dir.mktmpdir do |dir|
        old = OpenASNPipeline::DIST_DIR
        silence { OpenASNPipeline.const_set(:DIST_DIR, dir) }
        meta = { 3352 => AsJson::Record.new(3352, "WHOIS DESCR", "ZZ", "isp", "access_provider"),
                 64_500 => AsJson::Record.new(64_500, "WHOIS DESCR", "QQ", "isp", "access_provider") }
        Publish.write_asn_categories_csv({ asn_meta: meta },
                                         { flags_by_asn: Hash.new(0), org_names: {},
                                           base_v4: [[0, 255, 64_500, 0]], # routed, so written (CD-19d)
                                           countries: { 3352 => { "cc" => "ES", "source" => "override" } } })
        rows = CSV.read(File.join(dir, "asn-categories.csv"))
        assert_equal %w[asn org country category network_role openasn_flags], rows[0]
        assert_equal ["3352", nil, "ES"], rows[1][0, 3]
        assert_equal ["64500", nil, nil], rows[2][0, 3]
        body = File.read(File.join(dir, "asn-categories.csv"))
        refute_includes body, "ZZ"
        refute_includes body, "QQ"
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

  # CD-19d: an unrouted ASN is written only if it carries a field (org,
  # country, category/role or flag). The columns never change.
  class CsvRowSetTest < Minitest::Test
    def test_unrouted_rows_without_any_field_are_not_written
      Dir.mktmpdir do |dir|
        old = OpenASNPipeline::DIST_DIR
        silence { OpenASNPipeline.const_set(:DIST_DIR, dir) }
        meta = [64_496, 64_497, 64_498, 64_499, 64_500, 64_501, 64_502].to_h do |a|
          [a, AsJson::Record.new(a, "WHOIS DESCR", "ZZ", nil, nil)]
        end
        flags = Hash.new(0).merge(64_499 => 1, 64_500 => Binary::FLAG_VPN_PROVIDER) # 1 = category isp
        Publish.write_asn_categories_csv(
          { asn_meta: meta },
          { flags_by_asn: flags, org_names: { 64_497 => { "name" => "Named" } },
            countries: { 64_498 => { "cc" => "ES", "source" => "override" } },
            base_v4: [[0, 255, 64_496, 0]], base_v6: [[0, 255, 64_501, 0]] }
        )
        rows = CSV.read(File.join(dir, "asn-categories.csv"))
        assert_equal %w[asn org country category network_role openasn_flags], rows[0]
        # routed v4, org, country, category, flag, routed v6 kept; 64502 (nothing) dropped
        assert_equal %w[64496 64497 64498 64499 64500 64501], rows[1..].map(&:first)
        assert_equal "isp", rows[4][3]
        assert_equal "vpn_provider", rows[5][5]
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

  class CountryGateTest < Minitest::Test
    def setup = DriftGate.reset!
    def teardown = DriftGate.reset!

    def sentinels = Validate::COUNTRY_SENTINELS.transform_values { |cc| { "cc" => cc, "source" => "override" } }

    def test_sentinels_must_carry_their_curated_country
      Env.logger.level = Logger::FATAL
      Validate.check_countries!({ countries: sentinels })
      assert_raises(StageFailure) { Validate.check_countries!({ countries: sentinels.merge(3352 => { "cc" => "PT" }) }) }
      assert_raises(StageFailure) { Validate.check_countries!({ countries: {} }) }
    ensure
      Env.logger.level = Logger::INFO
    end

    def test_country_count_is_drift_gated
      Env.logger.level = Logger::FATAL
      many = sentinels.merge((1..100).to_h { |i| [64_500 + i, { "cc" => "US" }] })
      Validate.check_countries!({ countries: many }, { "countries" => 100 })
      assert_raises(StageFailure) { Validate.check_countries!({ countries: sentinels }, { "countries" => 100 }) }
    ensure
      Env.logger.level = Logger::INFO
    end

    def test_country_stats_reach_the_manifest_shape
      stats = Publish.manifest_stats(PublishManifestStatsTest::ARTIFACTS, PublishManifestStatsTest::CROSSCHECK,
                                     org_stats: Publish.country_stats(
                                       { countries: { 1 => { "cc" => "US", "source" => "override" } } },
                                       { wikidata_country_stats: { "statements" => 3 } }
                                     ))
      assert_equal 1, stats[:countries]
      assert_equal({ "override" => 1, "wikidata" => 0 }, stats[:countries_by_source])
      assert_equal({ "statements" => 3 }, stats[:wikidata_countries])
    end
  end

  class AsnCountryDrafterTest < Minitest::Test
    def dossier(asn, cc, evidence: [], website: nil, qid: nil, city: nil)
      { "asn" => asn, "org" => { "hq_country" => cc, "hq_city" => city, "website" => website },
        "evidence" => evidence, "external_ids" => { "wikidata_qid" => qid } }
    end

    def test_prefers_a_first_party_or_reference_page_that_names_the_country
      rec = dossier(174, "US", website: "https://www.cogentco.com", qid: "Q1",
                               evidence: [{ "claim" => "AS174 registrant, Washington DC, United States", "url" => "https://rdap.arin.net/registry/autnum/174" },
                                          { "claim" => "US multinational ISP, HQ Washington DC", "url" => "https://en.wikipedia.org/wiki/Cogent_Communications" }])
      row, = AsnCountryFromDossiers.draft(rec)
      assert_equal [174, "US", "https://en.wikipedia.org/wiki/Cogent_Communications", "evidence_names_country"], row
    end

    def test_falls_back_to_wikidata_then_website_and_never_cites_a_registry
      row, = AsnCountryFromDossiers.draft(dossier(1, "DE", qid: "Q9396", website: "https://www.telekom.com",
                                                          evidence: [{ "claim" => "Germany", "url" => "https://rdap.db.ripe.net/autnum/1" }]))
      assert_equal "https://www.wikidata.org/wiki/Q9396", row[2]
      row, = AsnCountryFromDossiers.draft(dossier(2, "DE", website: "https://www.telekom.com"))
      assert_equal ["https://www.telekom.com", "operator_website"], row[2, 2]
      assert_equal [nil, "no_admissible_source"], AsnCountryFromDossiers.draft(dossier(3, "DE", website: "https://www.peeringdb.com/net/1"))
    end

    def test_bad_or_missing_codes_are_skipped
      assert_equal [nil, "bad_code"], AsnCountryFromDossiers.draft(dossier(1, "Sweden", website: "https://a.example/"))
      assert_equal [nil, "no_hq_country"], AsnCountryFromDossiers.draft(dossier(1, nil))
    end

    # The registry value only decides which candidate file a line lands in.
    # It is never written into either.
    def test_registry_disagreements_go_to_review_and_the_registry_value_is_never_written
      Dir.mktmpdir do |dir|
        path = File.join(dir, "d.jsonl")
        File.write(path, [dossier(10, "UA", website: "https://a.example/"), dossier(11, "US", website: "https://b.example/")]
                           .map { JSON.generate(_1) }.join("\n"))
        _, ready, review = AsnCountryFromDossiers.run([path], date: "2026-09-19", registry: { 10 => "RU", 11 => "US" })
        assert_equal [11], ready
        assert_equal [10], review
        refute_includes File.read(AsnCountryFromDossiers::REVIEW), "RU"
      end
    end
  end
end
