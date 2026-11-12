# frozen_string_literal: true

require_relative "test_helper"
require "tmpdir"
require_relative "../pipeline/lib/x4b_first_party"
require_relative "../pipeline/lib/sources"
require_relative "../pipeline/normalize"

module OpenASNPipeline
  # The X4B overlays are OpenASN's own expansion of X4B's hand-curated inputs
  # (ASN.txt against our backbone, plus ips/Manual.txt). X4B's generated
  # output/ is never read: it merges third-party feeds (D-SRC-3) and, since
  # X4BNet/lists_vpn ea035c77 / fdf1db6a (2026-10-29), is cut from the CC BY-SA
  # IPLocate database and carries keyword-matched networks (D-SRC-4). The
  # addresses are the real ones from the 2026-09-19 audit.
  class X4BFirstPartyTest < Minitest::Test
    def r(cidr) = IPMath.cidr_to_range(cidr).first(2)
    def ip(str) = IPMath.v4_to_int(str)
    def covers?(ranges, addr) = !IPMath.find_range(ranges, ip(addr)).nil?

    # Backbone: Cloudflare (Apple relay egress lives here), M247, the Tor
    # ASN X4B lists, ProtonVPN's own ASN, and a parent /16 of a listed ASN
    # with a more specific /24 announced by an unlisted ASN.
    BASE = [
      ["104.28.0.0/16",    13_335],
      ["146.70.107.0/24",  9009],
      ["149.88.16.0/22",   208_172],
      ["185.220.101.0/24", 60_729],
      ["198.18.0.0/24",    64_500],
      ["198.18.1.0/24",    64_501], # child announced by an unlisted ASN
      ["198.18.2.0/23",    64_500]
    ].freeze

    def base_rows
      BASE.map { |cidr, asn| r(cidr) + [asn] }.sort_by(&:first)
    end

    def expand(asns: Set[9009, 208_172, 60_729, 64_500], manual: [r("194.5.52.0/23")])
      X4BFirstParty.expand(base_rows: base_rows, asns: asns, manual: manual)
    end

    def test_first_party_asn_space_and_manual_netblocks_are_the_overlay
      kept = expand.ranges
      assert covers?(kept, "146.70.107.100"), "AS9009 is in X4B's own ASN list"
      assert covers?(kept, "185.220.101.5"), "AS60729 is in X4B's own ASN list"
      assert covers?(kept, "149.88.16.10"), "a listed ASN covers its whole backbone space"
      assert covers?(kept, "149.88.19.255")
      assert covers?(kept, "194.5.52.1"), "Manual.txt netblock"
      assert covers?(kept, "194.5.53.255"), "Manual.txt /23 upper edge"
    end

    def test_space_of_unlisted_asns_never_enters
      kept = expand.ranges
      # Apple Private Relay egress inside Cloudflare (a feed in X4B's output,
      # Tier B for us) and anything a keyword match would add: neither is an
      # input, so neither can appear.
      refute covers?(kept, "104.28.28.1")
      refute covers?(kept, "198.51.100.7")
    end

    def test_a_child_prefix_announced_by_an_unlisted_asn_follows_the_backbone
      # X4B's IPLocate build includes children of a listed parent; the
      # backbone attributes this /24 to AS64501, so it stays out (recall cost,
      # never a precision cost).
      kept = expand.ranges
      assert covers?(kept, "198.18.0.255")
      refute covers?(kept, "198.18.1.1")
      assert covers?(kept, "198.18.2.0")
    end

    def test_result_counts
      res = expand
      assert_equal 4, res.asns
      assert_equal 5, res.asn_ranges
      assert_equal 1, res.manual_ranges
      assert_equal IPMath.address_count(res.ranges), res.addresses
    end

    def test_an_empty_asn_list_keeps_only_manual_space
      assert_equal [r("194.5.52.0/23")], expand(asns: Set.new).ranges
    end

    def test_exclusion_lines_are_not_includes
      Dir.mktmpdir do |dir|
        path = File.join(dir, "ASN.txt")
        File.write(path, "# header\nAS9009 # M247\n-AS13335 # exclusion, X4B builder syntax\n  AS64496 indented\nAS208172\n")
        assert_equal Set[9009, 208_172], Normalize.parse_x4b_asn_file(path)
      end
    end

    # The legal guard (D-SRC-4). Every X4B URL the pipeline knows must be one
    # of the four curated files; output/, Keywords.txt and the third-party
    # feeds under input/*/ips/ must never come back.
    CURATED = %w[input/vpn/ASN.txt input/datacenter/ASN.txt
                 input/vpn/ips/Manual.txt input/datacenter/ips/Manual.txt].freeze

    def test_only_x4b_curated_inputs_are_fetched
      x4b = Sources.constants.filter_map do |c|
        v = Sources.const_get(c)
        v if v.is_a?(String) && v.include?("X4BNet/lists_vpn/") && v.start_with?("https://raw.")
      end
      paths = x4b.map { |u| u.sub(%r{\Ahttps://raw\.githubusercontent\.com/X4BNet/lists_vpn/[^/]+/}, "") }
      assert_equal CURATED.sort, paths.sort
      refute Sources.const_defined?(:X4B_DC_FEEDS), "third-party feed files are no longer read at all"
      fetch_src = File.read(File.expand_path("../pipeline/fetch.rb", __dir__))
      refute_match(%r{output/|Keywords}, fetch_src)
    end

    def test_subtract_ranges
      assert_equal [[1, 2], [6, 9], [21, 30]], IPMath.subtract_ranges([[1, 9], [20, 30]], [[3, 5], [15, 20]])
      assert_equal [[1, 9]], IPMath.subtract_ranges([[1, 9]], [])
      assert_empty IPMath.subtract_ranges([[3, 4]], [[1, 9]])
    end

    def test_intersect_ranges
      a = [[1, 5], [10, 20], [30, 40]]
      b = [[3, 12], [15, 15], [18, 35]]
      assert_equal [[3, 5], [10, 12], [15, 15], [18, 20], [30, 35]], IPMath.intersect_ranges(a, b)
      assert_empty IPMath.intersect_ranges([], b)
      assert_equal 20, IPMath.address_count([[1, 10], [21, 30]])
    end
  end

  # End to end through Normalize.run and the reference classifier.
  class X4BNormalizeIntegrationTest < Minitest::Test
    def setup
      @dir = Dir.mktmpdir("x4b-fp")
    end

    def teardown
      FileUtils.rm_rf(@dir)
    end

    def write(name, body)
      File.join(@dir, name).tap { |p| File.write(p, body) }
    end

    def v4(str) = IPMath.v4_to_int(str)

    # as.json's parser has a size floor (100k+ ASNs); the overlays under test
    # never read it, so swap it out for the duration of one run.
    def without_as_metadata
      sc = Normalize.singleton_class
      sc.alias_method(:__x4b_test_orig_pam, :parse_as_metadata)
      sc.define_method(:parse_as_metadata) { |_path| {} }
      yield
    ensure
      sc.alias_method(:parse_as_metadata, :__x4b_test_orig_pam)
      sc.remove_method(:__x4b_test_orig_pam)
    end

    # No :x4b_vpn / :x4b_dc output files at all: Normalize must not need them.
    def paths
      {
        backbone_v4: write("v4.csv", [
          "#{v4('35.208.0.0')},#{v4('35.209.255.255')},43515,\"X\"",
          "#{v4('104.28.0.0')},#{v4('104.28.255.255')},13335,\"CLOUDFLARENET\"",
          "#{v4('146.70.107.0')},#{v4('146.70.107.255')},9009,\"M247\"",
          "#{v4('203.0.113.0')},#{v4('203.0.113.255')},64497,\"X\""
        ].join("\n") + "\n"),
        backbone_v6: write("v6.csv", "#{IPAddr.new('2001:db8::').to_i},#{IPAddr.new('2001:db8::ffff').to_i},64496,\"X\"\n"),
        as_json: write("as.json", "[]"), # see without_as_metadata
        x4b_vpn_asn: write("vpn-asn.txt", "AS9009 # M247, GB (NordVPN)\n"),
        x4b_dc_asn: write("dc-asn.txt", "AS64497 # example\n-AS43515 # exclusion line, ignored\n"),
        x4b_vpn_manual: write("vpn-manual.txt", "# Manually added netblocks\n# Comment description manditory\n" \
                                                "194.5.52.0/23 # VPN Consumer Network Services (https://github.com/X4BNet/lists_vpn/issues/171)\n"),
        x4b_dc_manual: write("dc-manual.txt", "# Manually added netblocks\n# Comment description manditory"),
        bad_asn: write("bad.csv", "ASN,Entity\n"),
        wikidata: write("wikidata.json", %q({"results":{"bindings":[]}})),
        wikidata_countries: write("wikidata-countries.json", %q({"results":{"bindings":[]}}))
      }
    end

    def test_overlays_are_the_curated_inputs_expanded_against_our_backbone
      n = without_as_metadata { Normalize.run(paths) }
      assert_equal [[v4("146.70.107.0"), v4("146.70.107.255")], [v4("194.5.52.0"), v4("194.5.53.255")]], n[:vpn_v4]
      # dc = dc ASNs ∪ vpn ASNs (X4B's dc list inherits vpn includes) + dc Manual.txt.
      assert_equal [[v4("146.70.107.0"), v4("146.70.107.255")], [v4("203.0.113.0"), v4("203.0.113.255")]], n[:dc_v4]

      hosting = AsJson::CATEGORY_CODES["hosting"]
      path = File.join(@dir, "t.bin")
      Binary.write(path, family: :ipv4, build_ts: 1,
                   base_rows: n[:base_v4].map { |(s, e, asn)| [s, e, asn, hosting] },
                   vpn_rows: n[:vpn_v4], dc_rows: n[:dc_v4])
      art = Binary::Artifact.new(path)

      relay = Classifier.classify(art, v4("104.28.28.1"))
      refute_equal :vpn, relay.verdict, "Apple Private Relay egress must not be :vpn in the core"
      assert_equal %i[hosting asn_category], [relay.verdict, relay.rule]

      m247 = Classifier.classify(art, v4("146.70.107.100"))
      assert_equal %i[vpn x4b_vpn], [m247.verdict, m247.rule]

      manual = Classifier.classify(art, v4("194.5.52.10"))
      assert_equal %i[vpn x4b_vpn], [manual.verdict, manual.rule]

      dc = Classifier.classify(art, v4("203.0.113.9"))
      assert_equal %i[hosting x4b_dc], [dc.verdict, dc.rule]

      # Not in any curated input: classified by its own ASN, never by x4b_dc.
      gcp = Classifier.classify(art, v4("35.208.0.1"))
      assert_equal %i[hosting asn_category], [gcp.verdict, gcp.rule]
    end
  end
end
