# frozen_string_literal: true

# PROTOTYPE Wikidata P3797 seed (lib/wikidata_asn.rb). SPARQL JSON shapes as
# returned by query.wikidata.org on 2026-09-19. No network.

require_relative "test_helper"
require_relative "../pipeline/lib/wikidata_asn"

module OpenASNPipeline
  class WikidataAsnTest < Minitest::Test
    def b(qid, asn, label: nil, rank: "NormalRank", ended: false)
      h = { "item" => { "value" => "http://www.wikidata.org/entity/#{qid}" }, "asn" => { "value" => asn },
            "rank" => { "value" => "http://wikiba.se/ontology##{rank}" },
            "itemLabel" => { "value" => label || qid } }
      h["end"] = { "value" => "2019-01-01T00:00:00Z" } if ended
      h
    end

    def json(*bindings) = JSON.generate("results" => { "bindings" => bindings })

    def test_parse_rules
      rows, dropped = WikidataAsn.parse(json(
        b("Q95", "15169", label: "Google"), b("Q95", "AS396982", label: "Google"),
        b("Q1", "100", rank: "DeprecatedRank"), b("Q2", "200", ended: true),
        b("Q3", "300", label: "A"), b("Q4", "300", label: "B"),         # conflict
        b("Q5", "1-5"), b("Q6", "0"), b("Q7", "400")                     # junk, zero, label echo
      ))
      assert_equal({ "qid" => "Q95", "label" => "Google" }, rows[15_169])
      assert_equal "Q95", rows[396_982]["qid"]
      assert_nil rows[400]["label"]                                     # label service echoed the QID
      refute rows.key?(100)
      refute rows.key?(200)
      refute rows.key?(300)
      assert_equal({ "deprecated" => 1, "ended" => 1, "bad_asn" => 2, "conflict" => [300] }, dropped)
    end

    def test_coverage_propagates_within_sibling_clusters_only
      rir = <<~TXT
        arin|US|asn|15169|1|20000330|assigned|g
        arin|US|asn|36040|1|20050101|assigned|g
        arin|US|asn|500|1|20050101|assigned|x
        arin|US|asn|501|1|20050101|assigned|x
        arin|US|asn|502|1|20050101|assigned|x
        apnic|IN|asn|131072|#{RirStats::POOL_THRESHOLD + 1}|20100101|allocated|A918EDB2
      TXT
      rows, _ = RirStats.expand(RirStats.parse_delegations(rir))
      cl = RirStats.clusters(rows)
      wd = { 15_169 => { "qid" => "Q95" }, 500 => { "qid" => "QA" }, 501 => { "qid" => "QB" },
             131_072 => { "qid" => "QNIR" }, 7 => { "qid" => "Q7" } }
      c = WikidataAsn.coverage(wd, rows, cl)
      assert_equal 4, c["direct_in_delegated"]
      assert_equal 1, c["not_in_loaded_rir_files"]           # AS7 not in these files
      assert_equal 1, c["inherited_via_siblings"]            # AS36040 <- Q95; x-cluster disagrees; pool never propagates
      assert_equal 1, c["clusters_with_disagreeing_items"]
      assert_in_delta 1.25, c["multiplier"]
    end

    def test_prototype_is_not_in_the_published_build
      root = File.expand_path("../pipeline", __dir__)
      %w[run.rb compile.rb publish.rb normalize.rb].each do |f|
        # The published org names use lib/wikidata_names.rb (D-SRC-2); the
        # prototype (lib/wikidata_asn.rb) must stay out of the build.
        refute_match(/wikidata_asn|WikidataAsn/, File.read(File.join(root, f)), "#{f} must not use the Wikidata prototype")
      end
      assert_includes WikidataAsn.url, "format=json"
    end
  end
end
