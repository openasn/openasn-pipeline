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
      TXT

      APNIC = <<~JSON
        {"Date":"04/07/2026","Window":"60 Days","Data":[
          {"rank":9,"AS":7922,"Description":"COMCAST","CC":"US","Users":43791898,"Percent of Internet":1.0494,"Samples":27316655},
          {"rank":1,"AS":55836,"Description":"RELIANCEJIO-IN","CC":"IN","Users":297688551,"Percent of Internet":7.1336,"Samples":99449128}
        ]}
      JSON

      RPKI_CSV = <<~CSV
        ASN,IP Prefix,Max Length,Trust Anchor,Expires
        AS13335,1.0.0.0/24,24,apnic,1783952256
        AS13335,1.1.1.0/24,24,apnic,1783952256
        AS3356,4.0.0.0/9,24,arin,1783952256
      CSV

      # /24 = 256 v4 addrs; /48 = 2^80 v6 addrs (the bignum-as-string case)
      BGPTABLE = <<~JSONL
        {"CIDR":"1.1.1.0/24","ASN":13335,"Hits":3359}
        {"CIDR":"1.0.0.0/24","ASN":13335,"Hits":100}
        {"CIDR":"2606:4700::/32","ASN":13335,"Hits":900}
        {"CIDR":"0.0.0.0/0","ASN":0,"Hits":1}
      JSONL

      def test_caida_page_parses_into_quant_fields
        r = Caida.parse_page(CAIDA_PAGE)[3356]
        assert_equal 1, r["caida_asrank"]
        assert_equal "LEVEL3", r["asn_name"]
        assert_equal "ARIN", r["rir"]
        assert_equal 54_887, r["cone_asns"]
        assert_equal 6_478, r["as_degree_customer"]
        assert_equal "589f9199b0", r["org_id"]
      end

      def test_rir_stats_parse_dates_and_skips_summary
        rows = RirStats.parse(RIR_ARIN)
        assert_equal [3, 4, 3356], rows.keys.sort
        assert_nil rows[3]["allocated"]                     # 00000000 -> nil, NEVER fabricated
        assert_equal "assigned", rows[3]["status"]
        assert_equal "d98c567cda2db06e693f2b574eafe848", rows[3]["org_hash"]
        assert_equal "1984-02-22", rows[4]["allocated"]
      end

      def test_apnic_eyeball_parse
        rows = Apnic.parse(APNIC)
        assert_equal 43_791_898, rows[7922]["eyeball_users"]
        assert_equal 9, rows[7922]["eyeball_rank"]
        assert_in_delta 7.1336, rows[55836]["eyeball_pct_internet"], 0.0001
      end

      def test_rpki_counts_roas_per_asn_and_skips_header
        rows = Rpki.parse(RPKI_CSV)
        assert_equal 2, rows[13335]["rpki_roas"]
        assert_equal 1, rows[3356]["rpki_roas"]
        refute rows.key?("ASN") # header never becomes an ASN key
      end

      def test_prefixes_counts_and_v6_bignum_as_string
        rows = Prefixes.parse(BGPTABLE)
        r = rows[13335]
        assert_equal 2, r["prefixes_v4"]
        assert_equal 1, r["prefixes_v6"]
        assert_equal 512, r["ipv4_addresses"]               # two /24 = 512
        assert_equal (2**96).to_s, r["ipv6_addresses"]      # one /32 = 2^96, kept exact as a string
        refute rows.key?(0)                                 # ASN 0 (bogon) skipped
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

      def test_rov_compute_aggregates_and_derives_status
        table = <<~JSONL
          {"CIDR":"1.0.0.0/24","ASN":13335,"Hits":1}
          {"CIDR":"1.0.0.128/25","ASN":13335,"Hits":1}
          {"CIDR":"8.8.8.0/24","ASN":15169,"Hits":1}
        JSONL
        idx, l4, l6 = Rov.build_index(StringIO.new(ROV_VRPS))
        out = Rov.compute(StringIO.new(table), idx, l4, l6)
        assert_equal 1, out[13335]["rov_valid"]
        assert_equal 1, out[13335]["rov_invalid"]
        assert_equal "has_invalids", out[13335]["rpki_rov_status"]
        assert_equal "unknown", out[15169]["rpki_rov_status"] # only a not-found route
      end
    end
  end
end
