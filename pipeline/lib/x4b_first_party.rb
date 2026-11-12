# frozen_string_literal: true

# X4BNet's vpn/datacenter overlays, rebuilt by OpenASN from X4B's own
# hand-curated inputs. X4B's generated output/ lists are NOT read.
#
# HISTORY (data-repo DECISIONS.md D-SRC-3, then D-SRC-4).
#
# D-SRC-3 (2026-09-19): X4B's build concatenates EVERY file in
# input/<list>/ips/ into output/<list>/ipv4.txt, and X4B's own scheduled
# workflows fill input/vpn/ips/ with feeds X4B does not own (Apple iCloud
# Private Relay egress, Mullvad, PIA, Proton). Those are Tier B for OpenASN,
# so the published output was treated as an upper bound and cut back to what
# X4B's first-party inputs justify.
#
# D-SRC-4 (2026-11-12): on 2026-10-29 X4BNet/lists_vpn ea035c77 ("move to
# IPLocate IP to ASN database (#285)") switched the ASN -> range expansion
# behind output/ to the IPLocate ip-to-asn database, which is CC BY-SA 4.0,
# and fdf1db6a ("keyword matching prototype (#286)") began adding networks
# whose IPLocate name/org/domain contains a keyword ("VPN", "Host",
# "Huawei"). X4B's README now says its generated lists are MIT while
# "upstream sources retain their own licenses". Whether a range list cut
# out of a CC BY-SA database is Adapted Material is exactly the kind of
# doubt README "Legal design" rule 3 resolves by exclusion: ShareAlike
# never enters the composite. So the generated output is not used at all.
#
# What OpenASN takes from X4B now - first-party curation only, MIT under
# X4B's README ("curated source files"):
#   * input/<list>/ASN.txt, X4B's hand-curated ASN list. Only the AS numbers
#     are read (`AS123 # comment`); `-AS123` exclusion lines are not includes
#     and are ignored. The numbers are expanded against OpenASN's OWN
#     backbone (RouteViews via tools/rib2origin; sapics on the legacy path),
#     never against any X4B, IPLocate or iptoasn table.
#   * input/<list>/ips/Manual.txt, X4B's hand-curated netblocks.
#
# Never read: output/*, input/*/Keywords.txt, and every third-party feed
# file in input/*/ips/. Keyword-selected networks therefore cannot reach the
# core: they exist only in X4B's generated output. A keyword entry inside an
# ASN that X4B lists by hand is covered by the ASN entry itself, the same as
# before.
#
# Known costs (measured in D-SRC-4): X4B's expansion "includes child ranges"
# of a listed parent prefix even when a more specific child is announced by
# an unlisted ASN; ours follows the backbone's origin per prefix, so such
# children drop out of the overlay (they still classify by their own ASN).
# Where X4B's expansion database and our backbone disagree on the origin
# ASN, the backbone wins. Both only ever cost recall, never precision -
# the direction this project prefers.

require "set"
require_relative "env"
require_relative "ipmath"

module OpenASNPipeline
  module X4BFirstParty
    Result = Struct.new(:ranges, :asns, :asn_ranges, :manual_ranges, :addresses, keyword_init: true)

    module_function

    # base_rows: backbone [[s, e, asn], ...] (sorted, disjoint)
    # asns:      Set[Integer] - X4B's first-party ASN list(s) for this layer
    # manual:    merged [[s, e], ...] from X4B input/<list>/ips/Manual.txt
    def expand(base_rows:, asns:, manual:)
      asn_space = base_rows.filter_map { |r| [r[0], r[1]] if asns.include?(r[2]) }
      ranges = IPMath.merge_ranges(asn_space + manual)
      Result.new(ranges: ranges, asns: asns.size, asn_ranges: asn_space.length,
                 manual_ranges: manual.length, addresses: IPMath.address_count(ranges))
    end

    def log(label, res)
      Env.log(format("%s: %d first-party ASNs -> %d backbone ranges, + %d Manual.txt ranges = %d merged ranges " \
                     "(%d addresses; X4B generated output not used, D-SRC-4)",
                     label, res.asns, res.asn_ranges, res.manual_ranges, res.ranges.length, res.addresses))
    end
  end
end
