# frozen_string_literal: true

# Layer-A quant importer parsers (pipeline/enrich/quant/). Pure-function tests on
# real record shapes captured 2026-07-08 from each source — no network, no LLM.
# Guards the things that silently corrupt a quant record: field mis-mapping,
# fabricating a date for a legacy "00000000" allocation, and losing precision on
# the v6 address bignum.

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
        arin|US|asn|3356|1|20000310|assigned|589f9199b0aaaaaaaaaaaaaaaaaaaaaa
        apnic|JP|asn|2497|3|20020405|allocated|A91A7381
        ripencc|ZZ|asn|9999|1|20100101|available
      TXT

      # One row per (AS, ECONOMY) — AS9999 spans two economies to guard the last-wins bug.
      APNIC = <<~JSON
        {"Date":"04/07/2026","Window":"60 Days","Data":[
          {"rank":1,"AS":55836,"CC":"IN","Users":297688551,"Percent of Internet":7.1336},
          {"rank":9,"AS":7922,"CC":"US","Users":43791898,"Percent of Internet":1.0494},
          {"rank":50,"AS":9999,"CC":"US","Users":1000000,"Percent of Internet":0.5000},
          {"rank":900,"AS":9999,"CC":"GB","Users":50000,"Percent of Internet":0.0200}
        ]}
      JSON

      RPKI_CSV = <<~CSV
        ASN,IP Prefix,Max Length,Trust Anchor,Expires
        AS13335,1.0.0.0/24,24,apnic,1783952256
        AS13335,1.1.1.0/24,24,apnic,1783952256
        AS3356,4.0.0.0/9,24,arin,1783952256
      CSV

      # CAIDA prefix2as: "prefix<TAB>len<TAB>AS". Real tabs (heredocs don't interpret \t),
      # so build the fixture explicitly. AS may be MOAS ("AS1,AS2").
      PFX2AS = [
        "1.1.1.0\t24\t13335",
        "1.0.0.0\t24\t13335",
        "2606:4700::\t32\t13335",
        "10.0.0.0\t8\t0",             # ASN0 -> dropped
        "8.8.8.0\t24\t15169,396982",  # MOAS -> counts for BOTH origins
      ].join("\n")

      def test_caida_page_parses_into_quant_fields
        r = Caida.parse_page(CAIDA_PAGE)[3356]
        assert_equal 1, r["caida_asrank"]
        assert_equal "LEVEL3", r["asn_name"]
        assert_equal "ARIN", r["rir"]
        assert_equal 54_887, r["cone_asns"]
        assert_equal 6_478, r["as_degree_customer"]
        assert_equal "589f9199b0", r["org_id"]
      end

      def test_rir_stats_expands_blocks_strips_status_nils_sentinels
        rows = RirStats.parse(RIR_ARIN)
        assert_nil rows[3]["allocated"]                       # 00000000 -> nil, never fabricated
        assert_equal "assigned", rows[3]["status"]
        assert_equal "d98c567cda2db06e693f2b574eafe848", rows[3]["org_hash"]
        assert_equal "1984-02-22", rows[4]["allocated"]
        # BLOCK EXPANSION: apnic|JP|asn|2497|3 -> AS2497,2498,2499 (NOT 2500), sharing org_hash
        assert_equal "2002-04-05", rows[2497]["allocated"]
        assert_equal "2002-04-05", rows[2499]["allocated"]
        assert_equal "A91A7381", rows[2499]["org_hash"]       # sibling shares the org hash
        refute rows.key?(2500)                                # block is [2497, 2500)
        # 7-field line: status stripped of the trailing newline; ZZ country -> nil;
        # absent/empty opaque-id -> org_hash nil (not "")
        assert_equal "available", rows[9999]["status"]
        assert_nil rows[9999]["country"]
        assert_nil rows[9999]["org_hash"]
      end

      def test_apnic_aggregates_multi_economy_rows_and_reranks
        rows = Apnic.parse(APNIC)
        # AS9999 spans two economy rows -> SUMMED, not last-wins (the CRITICAL bug the audit caught)
        assert_equal 1_050_000, rows[9999]["eyeball_users"]
        assert_in_delta 0.52, rows[9999]["eyeball_pct_internet"], 0.0001
        # eyeball_rank recomputed by TOTAL users: Jio(297M)=1, Comcast(43M)=2, AS9999(1.05M)=3
        assert_equal 1, rows[55836]["eyeball_rank"]
        assert_equal 2, rows[7922]["eyeball_rank"]
        assert_equal 3, rows[9999]["eyeball_rank"]
        assert_equal 43_791_898, rows[7922]["eyeball_users"]
      end

      def test_rpki_counts_roas_per_asn_and_skips_header
        rows = Rpki.parse(RPKI_CSV)
        assert_equal 2, rows[13335]["rpki_roas"]
        assert_equal 1, rows[3356]["rpki_roas"]
        refute rows.key?("ASN") # header never becomes an ASN key
      end

      def test_prefixes_counts_v6_bignum_and_moas
        rows = Prefixes.tally(PFX2AS)
        r = rows[13335]
        assert_equal 2, r["prefixes_v4"]
        assert_equal 1, r["prefixes_v6"]
        assert_equal 512, r["ipv4_addresses"]               # two /24
        assert_equal (2**96).to_s, r["ipv6_addresses"]      # one /32, kept exact as a string
        refute rows.key?(0)                                 # ASN0 dropped
        assert_equal 1, rows[15169]["prefixes_v4"]          # MOAS attributed to each origin
        assert_equal 1, rows[396982]["prefixes_v4"]
      end

      def test_record_merges_all_sources_with_provenance
        rows = {
          rir:      RirStats.parse(RIR_ARIN)[3356],
          caida:    Caida.parse_page(CAIDA_PAGE)[3356],
          apnic:    nil,
          rpki:     Rpki.parse(RPKI_CSV)[3356],
          prefixes: nil,
        }
        rec = Build.record(3356, rows, "2026-07-08")
        q = rec["quant"]
        assert_equal 1, q["caida_asrank"]                   # CAIDA
        assert_equal "2000-03-10", q["allocated"]           # RIR stats
        assert_equal "ARIN", q["rir"]                       # normalized uppercase
        assert_equal 1, q["rpki_roas"]                      # RPKI
        srcs = rec["sources"].map { |s| s["source"] }
        assert_includes srcs, "CAIDA AS Rank"
        assert_includes srcs, "RIR delegated-extended stats"
        assert_includes srcs, "RPKI VRPs (rpki-client)"
        refute_includes srcs, "APNIC AS-Pop (eyeball estimates)" # nil source -> no provenance line
        rec["sources"].each { |s| assert s["url"] && s["as_of"], "every source has url + as_of" }
      end

      def test_record_survives_a_missing_source
        rows = { rir: RirStats.parse(RIR_ARIN)[4], caida: nil, apnic: nil, rpki: nil, prefixes: nil }
        rec = Build.record(4, rows, "2026-07-08")
        assert_equal "1984-02-22", rec["quant"]["allocated"]
        assert_nil rec["quant"]["caida_asrank"]
        assert_equal ["RIR delegated-extended stats"], rec["sources"].map { |s| s["source"] }
      end

      # --- RoV / RFC 6811 -------------------------------------------------------
      ROV_VRPS = <<~CSV
        ASN,IP Prefix,Max Length,Trust Anchor,Expires
        AS13335,1.0.0.0/24,24,apnic,1
        AS3356,4.0.0.0/9,24,arin,1
      CSV

      def rov_state(cidr, origin)
        idx, l4, l6 = Rov.build_index(StringIO.new(ROV_VRPS))
        v6, net, len = Rov.parse_cidr(cidr)
        Rov.classify(v6, net, len, origin, idx, v6 ? l6 : l4)
      end

      def test_rov_valid_exact_match
        assert_equal :valid, rov_state("1.0.0.0/24", 13335)
      end

      def test_rov_invalid_wrong_origin
        assert_equal :invalid, rov_state("1.0.0.0/24", 64500) # covered by AS13335's ROA, wrong origin
      end

      def test_rov_invalid_more_specific_than_maxlength
        assert_equal :invalid, rov_state("1.0.0.128/25", 13335) # /25 under a /24-max ROA
      end

      def test_rov_valid_under_less_specific_roa
        assert_equal :valid, rov_state("4.1.0.0/16", 3356) # covered by 4.0.0.0/9 max24; 16<=24, AS matches
      end

      def test_rov_notfound_no_covering_vrp
        assert_equal :notfound, rov_state("8.8.8.0/24", 15169)
      end

      def test_rov_status_derivation
        assert_equal "has_invalids", Rov.rov_status({ "rov_valid" => 3, "rov_invalid" => 1, "rov_notfound" => 0 })
        assert_equal "all_valid",    Rov.rov_status({ "rov_valid" => 5, "rov_invalid" => 0, "rov_notfound" => 0 })
        assert_equal "partial",      Rov.rov_status({ "rov_valid" => 2, "rov_invalid" => 0, "rov_notfound" => 4 })
        assert_equal "unknown",      Rov.rov_status({ "rov_valid" => 0, "rov_invalid" => 0, "rov_notfound" => 7 })
      end
    end
  end
end
