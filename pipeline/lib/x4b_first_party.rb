# frozen_string_literal: true

# X4BNet's published overlays, minus the third-party feeds X4B merges in.
#
# WHY THIS EXISTS (data-repo DECISIONS.md D-SRC-3; audit P4-L, verified P4-X
# 2026-09-19 against X4BNet/lists_vpn 07f9013b). X4B's MIT grant covers "the
# list itself", but its build (.github/workflows/build-list.yml) concatenates
# EVERY file in input/<list>/ips/ into output/<list>/ipv4.txt, and X4B's own
# scheduled workflows fill input/vpn/ips/ with feeds X4B does not own:
#
#   input/vpn/ips/apple.txt       <- mask-api.icloud.com/egress-ip-ranges.csv
#                                    (Apple iCloud Private Relay egress)
#   input/vpn/ips/mullvadvpn.txt  <- api.mullvad.net/www/relays/all
#   input/vpn/ips/pia.txt         <- github.com/Lars-/PIA-servers (no licence)
#   input/vpn/ips/protonvpn.txt   <- api.protonmail.ch/vpn/logicals
#   input/datacenter/ips/protonvpn.txt   (a 2023 snapshot of the same API)
#
# OpenASN classes every one of those as Tier B - fetched by clients from the
# original authority, never republished (README "Legal design" rules 1-2).
# Apple's list also shipped as core_verdict=vpn, breaking the "relay is never
# folded into vpn" rule. X4B's licence cannot sanitize data it does not own.
#
# "Justified" space is what X4B's FIRST-PARTY inputs account for:
#   * input/<list>/ASN.txt, X4B's hand-curated ASN list, expanded against
#     OpenASN's own backbone (sapics origin-asn, already Tier A), and
#   * input/<list>/ips/Manual.txt, X4B's hand-curated netblocks.
# A feed entry inside justified space stays (e.g. Proton servers inside
# AS208172, which X4B lists itself): the first-party entry covers it.
#
# Two layers, two methods - chosen by measurement, not symmetry:
#
# vpn -> restrict (WHITELIST): kept = published ∩ justified.
#   This is where X4B's feed bots write, so it must hold against a feed X4B
#   adds tomorrow and against a feed file updated between X4B's builds;
#   a whitelist needs neither the feed files nor a list of them. Cost of
#   the whitelist beyond the feeds is tiny: 1,024 addresses (four /24s)
#   where X4B's expansion DB (iptoasn.com) and our backbone disagree on
#   the origin ASN.
#
# datacenter -> strip_feeds (BLACKLIST): kept = published − (feeds − justified).
#   A whitelist here was built and measured, and rejected: the DC ASN
#   expansion disagrees with our backbone on ~222k addresses (e.g. GCP's
#   35.208.0.0/15: iptoasn AS15169, sapics AS43515), which would have
#   flipped real cloud space from hosting to business. No X4B workflow
#   writes to input/datacenter/ips/ (its only non-manual file is one frozen
#   2023 commit), so naming that file is precise and stable.
#   IF X4B EVER ADDS A FILE THERE, it must be added to Sources::X4B_DC_FEEDS.
#   (The pipeline never calls api.github.com - see lib/http.rb - so the
#   directory cannot be enumerated at build time.)
#
# Both methods only ever REMOVE space X4B published; neither can add any.

require "set"
require_relative "env"
require_relative "ipmath"

module OpenASNPipeline
  module X4BFirstParty
    Result = Struct.new(:ranges, :method, :published_ranges, :published_addresses,
                        :kept_addresses, keyword_init: true) do
      def dropped_addresses = published_addresses - kept_addresses
    end

    module_function

    # published:  merged [[s, e], ...] from X4B output/<list>/ipv4.txt
    # base_rows:  backbone [[s, e, asn], ...] (sorted, disjoint)
    # asns:       Set[Integer] - X4B's first-party ASN list(s) for this layer
    # manual:     merged [[s, e], ...] from X4B input/<list>/ips/Manual.txt
    def justified(base_rows:, asns:, manual:)
      asn_space = base_rows.filter_map { |r| [r[0], r[1]] if asns.include?(r[2]) }
      IPMath.merge_ranges(asn_space + manual)
    end

    # Whitelist: keep only published space the first-party inputs justify.
    def restrict(published, base_rows:, asns:, manual:)
      kept = IPMath.merge_ranges(IPMath.intersect_ranges(published, justified(base_rows: base_rows, asns: asns,
                                                                              manual: manual)))
      result(published, kept, :restrict)
    end

    # Blacklist: remove published space that a named third-party feed put
    # there, unless the first-party inputs justify it anyway.
    # feeds: merged [[s, e], ...] - union of the third-party files.
    def strip_feeds(published, feeds:, base_rows:, asns:, manual:)
      strip = IPMath.subtract_ranges(feeds, justified(base_rows: base_rows, asns: asns, manual: manual))
      kept = IPMath.merge_ranges(IPMath.subtract_ranges(published, strip))
      result(published, kept, :strip_feeds)
    end

    def result(published, kept, method)
      Result.new(ranges: kept, method: method,
                 published_ranges: published.length,
                 published_addresses: IPMath.address_count(published),
                 kept_addresses: IPMath.address_count(kept))
    end

    def log(label, res)
      pct = res.published_addresses.zero? ? 0.0 : 100.0 * res.dropped_addresses / res.published_addresses
      how = res.method == :restrict ? "not justified by X4B's ASN list or Manual.txt" : "third-party feed space"
      Env.log(format("%s: %s kept %d of %d published addresses (removed %d = %.2f%%, %s); %d -> %d ranges",
                     label, res.method, res.kept_addresses, res.published_addresses, res.dropped_addresses, pct,
                     how, res.published_ranges, res.ranges.length))
    end
  end
end
