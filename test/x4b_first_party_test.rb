# frozen_string_literal: true

require_relative "test_helper"
require "tmpdir"
require_relative "../pipeline/lib/x4b_first_party"
require_relative "../pipeline/normalize"

module OpenASNPipeline
  # X4B's published output/vpn/ipv4.txt merges Apple iCloud Private Relay
  # egress, Mullvad, PIA and Proton feeds (Tier B for OpenASN). These tests
  # pin the first-party restriction that keeps them out of the core
  # (lib/x4b_first_party.rb; data-repo DECISIONS.md D-SRC-3). The addresses
  # are the real ones from the 2026-09-19 audit.
  class X4BFirstPartyTest < Minitest::Test
    def r(cidr) = IPMath.cidr_to_range(cidr).first(2)
    def ip(str) = IPMath.v4_to_int(str)
    def covers?(ranges, addr) = !IPMath.find_range(ranges, ip(addr)).nil?

    # Backbone: Cloudflare (Apple relay egress lives here), M247, the Tor
    # ASN X4B lists, and ProtonVPN's own ASN.
    BASE = [
      ["104.28.0.0/16",    13_335],
      ["146.70.107.0/24",  9009],
      ["149.88.16.0/22",   208_172],
      ["185.220.101.0/24", 60_729]
    ].freeze

    def base_rows
      BASE.map { |cidr, asn| r(cidr) + [asn] }.sort_by(&:first)
    end

    # What X4B publishes: its ASN expansion + Manual.txt + the feed files.
    def published
      IPMath.merge_ranges([
        r("104.28.28.0/26"), r("104.28.28.64/29"), r("104.28.28.72/30"), r("104.28.28.76/32"), # apple.txt
        r("146.70.107.0/24"),                                                                 # AS9009 expansion
        r("149.88.16.10/32"),                                                                 # protonvpn.txt, inside AS208172
        r("185.220.101.0/24"),                                                                # AS60729 expansion
        r("194.5.52.0/23"),                                                                   # Manual.txt
        r("198.51.100.7/32")                                                                  # pia.txt, unrouted here
      ])
    end

    def restrict
      X4BFirstParty.restrict(published, base_rows: base_rows,
                                        asns: Set[9009, 208_172, 60_729],
                                        manual: [r("194.5.52.0/23")])
    end

    def test_apple_private_relay_egress_is_never_kept
      kept = restrict.ranges
      %w[104.28.28.0 104.28.28.1 104.28.28.63 104.28.28.64 104.28.28.76].each do |addr|
        refute covers?(kept, addr), "#{addr} is Apple Private Relay egress (Tier B relay) and must not survive"
      end
    end

    def test_first_party_asn_space_and_manual_netblocks_are_kept
      kept = restrict.ranges
      assert covers?(kept, "146.70.107.100"), "AS9009 is in X4B's own ASN list"
      assert covers?(kept, "185.220.101.5"), "AS60729 is in X4B's own ASN list"
      assert covers?(kept, "194.5.52.1"), "Manual.txt netblock"
      assert covers?(kept, "194.5.53.255"), "Manual.txt /23 upper edge"
    end

    def test_a_feed_entry_inside_a_listed_asn_stays_because_the_asn_justifies_it
      assert covers?(restrict.ranges, "149.88.16.10")
    end

    def test_a_feed_entry_outside_every_listed_asn_is_dropped
      refute covers?(restrict.ranges, "198.51.100.7")
    end

    def test_the_restriction_never_adds_space_x4b_did_not_publish
      kept = restrict.ranges
      # AS208172's backbone /22 is listed, but X4B only published one /32 of it.
      refute covers?(kept, "149.88.16.11")
      assert_empty IPMath.intersect_ranges(kept, [[0, published.first[0] - 1]])
      kept.each do |(s, e)|
        assert_equal e - s + 1, IPMath.address_count(IPMath.intersect_ranges([[s, e]], published)),
                     "#{IPMath.int_to_v4(s)}-#{IPMath.int_to_v4(e)} is not inside the published list"
      end
    end

    def test_result_accounts_for_every_dropped_address
      res = restrict
      assert_equal IPMath.address_count(published), res.published_addresses
      # apple 64+8+4+1 = 77, pia 1
      assert_equal 78, res.dropped_addresses
      assert_equal res.published_addresses - 78, res.kept_addresses
    end

    def test_an_empty_asn_list_keeps_only_manual_space
      res = X4BFirstParty.restrict(published, base_rows: base_rows, asns: Set.new, manual: [r("194.5.52.0/23")])
      assert_equal [r("194.5.52.0/23")], res.ranges
    end

    # --- datacenter: blacklist of the named feed file ------------------------

    def dc_published
      IPMath.merge_ranges([
        r("35.208.0.0/15"),     # X4B expansion of AS15169 via iptoasn; our backbone disagrees on the origin
        r("146.70.107.0/24"),   # AS9009 expansion
        r("149.88.16.10/32"),   # dc protonvpn.txt, inside listed AS208172
        r("203.0.113.9/32")     # dc protonvpn.txt, outside every listed ASN
      ])
    end

    def strip
      X4BFirstParty.strip_feeds(dc_published, feeds: [r("149.88.16.10/32"), r("203.0.113.9/32")],
                                              base_rows: base_rows, asns: Set[9009, 208_172], manual: [])
    end

    def test_strip_feeds_removes_only_unjustified_feed_space
      kept = strip.ranges
      refute covers?(kept, "203.0.113.9"), "third-party feed entry outside every listed ASN"
      assert covers?(kept, "149.88.16.10"), "feed entry inside a listed ASN stays"
      assert covers?(kept, "146.70.107.1")
      assert_equal 1, strip.dropped_addresses
    end

    def test_strip_feeds_keeps_published_space_our_backbone_does_not_explain
      # The reason dc is not a whitelist: X4B's ASN expansion and our
      # backbone disagree on real cloud space, and that is not feed data.
      assert covers?(strip.ranges, "35.208.0.1")
      assert covers?(strip.ranges, "35.209.255.255")
    end

    def test_strip_feeds_with_no_feeds_is_the_identity
      res = X4BFirstParty.strip_feeds(dc_published, feeds: [], base_rows: base_rows, asns: Set.new, manual: [])
      assert_equal dc_published, res.ranges
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

  # End to end through Normalize.run and the reference classifier: the
  # published X4B file contains Apple relay space; the compiled artifact must
  # not answer :vpn for it.
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

    def paths
      {
        backbone_v4: write("v4.csv", [
          "#{v4('104.28.0.0')},#{v4('104.28.255.255')},13335,\"CLOUDFLARENET\"",
          "#{v4('146.70.107.0')},#{v4('146.70.107.255')},9009,\"M247\""
        ].join("\n") + "\n"),
        backbone_v6: write("v6.csv", "#{IPAddr.new('2001:db8::').to_i},#{IPAddr.new('2001:db8::ffff').to_i},64496,\"X\"\n"),
        as_json: write("as.json", "[]"), # see without_as_metadata
        x4b_vpn: write("vpn.txt", "104.28.28.0/26\n104.28.28.64/29\n146.70.107.0/24\n194.5.52.0/23\n"),
        x4b_dc: write("dc.txt", "35.208.0.0/15\n146.70.107.0/24\n203.0.113.9/32\n"),
        x4b_vpn_asn: write("vpn-asn.txt", "AS9009 # M247, GB (NordVPN)\n"),
        x4b_dc_asn: write("dc-asn.txt", "AS64496 # example\n"),
        x4b_vpn_manual: write("vpn-manual.txt", "# Manually added netblocks\n# Comment description manditory\n" \
                                                "194.5.52.0/23 # VPN Consumer Network Services (https://github.com/X4BNet/lists_vpn/issues/171)\n"),
        x4b_dc_manual: write("dc-manual.txt", "# Manually added netblocks\n# Comment description manditory"),
        x4b_dc_feeds: [write("dc-protonvpn.txt", "203.0.113.9\n")],
        bad_asn: write("bad.csv", "ASN,Entity\n"),
        wikidata: write("wikidata.json", %q({"results":{"bindings":[]}}))
      }
    end

    def test_apple_relay_sample_never_gets_verdict_vpn_from_x4b
      n = without_as_metadata { Normalize.run(paths) }
      assert_equal [[v4("146.70.107.0"), v4("146.70.107.255")], [v4("194.5.52.0"), v4("194.5.53.255")]], n[:vpn_v4]
      # dc loses only the feed entry; unexplained-but-not-feed space stays.
      assert_equal [[v4("35.208.0.0"), v4("35.209.255.255")], [v4("146.70.107.0"), v4("146.70.107.255")]], n[:dc_v4]

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
    end
  end
end
