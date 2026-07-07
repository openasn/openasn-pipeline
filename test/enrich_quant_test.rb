# frozen_string_literal: true

# Layer-A quant importer parsers (pipeline/enrich/quant/). Pure-function tests
# on real record shapes captured 2026-07-08 from CAIDA AS Rank and the ARIN
# delegated-extended stats — no network, no LLM. Guards the two things that
# silently corrupt a quant record: field mis-mapping and fabricating a date for
# a legacy "00000000" allocation.

require_relative "test_helper"
require_relative "../pipeline/enrich/quant/build"

module OpenASNPipeline
  module Quant
    class QuantParsersTest < Minitest::Test
      CAIDA_PAGE = <<~JSON
        {"data":{"asns":{"totalCount":121200,"pageInfo":{"hasNextPage":true},"edges":[
          {"node":{"rank":1,"asn":"3356","asnName":"LEVEL3","source":"ARIN","seen":true,
                   "organization":{"orgId":"589f9199b0"},
                   "cone":{"numberAsns":54887,"numberPrefixes":935384,"numberAddresses":2279334944},
                   "country":{"iso":"US"},
                   "asnDegree":{"total":6553,"customer":6478,"peer":74,"provider":1}}},
          {"node":{"rank":2,"asn":"1299","asnName":"TWELVE99","source":"RIPE","seen":true,
                   "organization":{"orgId":"7cf5c4e5ce"},
                   "cone":{"numberAsns":42167,"numberPrefixes":839207,"numberAddresses":1770655445},
                   "country":{"iso":"SE"},
                   "asnDegree":{"total":2596,"customer":2529,"peer":67,"provider":0}}}
        ]}}}
      JSON

      RIR_ARIN = <<~TXT
        arin|*|asn|*|32721|summary
        arin|US|asn|3|1|00000000|assigned|d98c567cda2db06e693f2b574eafe848
        arin|US|asn|4|1|19840222|assigned|8f5d315929a560376b0b58b40a1932fa
        arin|US|asn|3356|1|20000504|assigned|589f9199b0aaaaaaaaaaaaaaaaaaaaaa
      TXT

      def test_caida_page_parses_into_quant_fields
        rows = Caida.parse_page(CAIDA_PAGE)
        assert_equal [1299, 3356], rows.keys.sort
        r = rows[3356]
        assert_equal 1, r["caida_asrank"]
        assert_equal "LEVEL3", r["asn_name"]
        assert_equal "ARIN", r["rir"]
        assert_equal "US", r["country"]
        assert_equal 54_887, r["cone_asns"]
        assert_equal 2_279_334_944, r["cone_addresses"]
        assert_equal 6_478, r["as_degree_customer"]
        assert_equal "589f9199b0", r["org_id"]
      end

      def test_rir_stats_parse_dates_and_skips_summary
        rows = RirStats.parse(RIR_ARIN)
        assert_equal [3, 4, 3356], rows.keys.sort
        # legacy 00000000 -> nil, NEVER a fabricated date
        assert_nil rows[3]["allocated"]
        assert_equal "arin", rows[3]["rir"]
        assert_equal "assigned", rows[3]["status"]
        assert_equal "d98c567cda2db06e693f2b574eafe848", rows[3]["org_hash"]
        # real date -> ISO
        assert_equal "1984-02-22", rows[4]["allocated"]
        assert_equal "2000-05-04", rows[3356]["allocated"]
      end

      def test_record_merges_both_sources_with_provenance
        caida = Caida.parse_page(CAIDA_PAGE)
        rir   = RirStats.parse(RIR_ARIN)
        rec = Build.record(3356, rir[3356], caida[3356], "2026-07-08")

        assert_equal 3356, rec["asn"]
        q = rec["quant"]
        assert_equal 1, q["caida_asrank"]           # from CAIDA
        assert_equal "2000-05-04", q["allocated"]   # from RIR stats
        assert_equal "ARIN", q["rir"]               # normalized uppercase
        assert_equal 54_887, q["cone_asns"]

        srcs = rec["sources"].map { |s| s["source"] }
        assert_includes srcs, "CAIDA AS Rank"
        assert_includes srcs, "RIR delegated-extended stats"
        rec["sources"].each { |s| assert s["url"] && s["as_of"], "every source has url + as_of" }
      end

      def test_record_survives_a_missing_source
        # ASN present in RIR only (allocated but unrouted -> no CAIDA row)
        rir = RirStats.parse(RIR_ARIN)
        rec = Build.record(4, rir[4], nil, "2026-07-08")
        assert_equal "1984-02-22", rec["quant"]["allocated"]
        assert_nil rec["quant"]["caida_asrank"]
        assert_equal ["RIR delegated-extended stats"], rec["sources"].map { |s| s["source"] }
      end
    end
  end
end
