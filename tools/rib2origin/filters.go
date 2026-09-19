package main

import "net/netip"

// Filtering rules. Every rule returns a short reason string that is counted
// in the stats report, so the effect of each rule on a real day is visible.
//
// Prefix rules (whole RIB record dropped):
//   - IPv4 outside /8../24 and IPv6 outside /16../48: a default route or a
//     covering super-block is not an origin fact, and anything more specific
//     than /24 (v4) or /48 (v6) is filtered by most of the Internet, so it
//     is not a route the world actually uses (the de-facto global filtering
//     boundary). Bounds are flags, so the report can show their effect.
//   - Martians / special-purpose space (IANA special-purpose registries,
//     RFC 6890 and successors) and, for IPv6, anything outside 2000::/3.
//
// Origin rules (single route dropped): AS 0 (RFC 7607), AS_TRANS 23456
// (RFC 6793), documentation (RFC 5398), private use (RFC 6996), and the
// reserved 65535 / 4294967295 (RFC 7300) and 65552-131071 (IANA reserved).

var v4Martians = mustPrefixes(
	"0.0.0.0/8",       // "this network"
	"10.0.0.0/8",      // RFC 1918
	"100.64.0.0/10",   // RFC 6598 shared/CGNAT
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link local
	"172.16.0.0/12",   // RFC 1918
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"192.88.99.0/24",  // deprecated 6to4 relay anycast (RFC 7526)
	"192.168.0.0/16",  // RFC 1918
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved + broadcast
)

var v6Global = netip.MustParsePrefix("2000::/3")

var v6Martians = mustPrefixes(
	"2001::/32",     // Teredo
	"2001:2::/48",   // benchmarking
	"2001:10::/28",  // ORCHID (deprecated)
	"2001:20::/28",  // ORCHIDv2
	"2001:db8::/32", // documentation
	"2002::/16",     // 6to4
	"3fff::/20",     // documentation (RFC 9637)
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// insideAny: p lies entirely within a special-purpose block. A legitimately
// routed aggregate that merely COVERS a martian (rare) is kept; its martian
// part is unrouted in practice and harmless.
func insideAny(p netip.Prefix, set []netip.Prefix) bool {
	for _, m := range set {
		if m.Bits() <= p.Bits() && m.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

func prefixRejectReason(p netip.Prefix, cfg *Config) string {
	if p.Addr().Is4() {
		switch {
		case p.Bits() == 0:
			return "default_route"
		case p.Bits() < cfg.V4MinLen:
			return "v4_too_short"
		case p.Bits() > cfg.V4MaxLen:
			return "v4_too_specific"
		case insideAny(p, v4Martians):
			return "v4_martian"
		}
		return ""
	}
	switch {
	case p.Bits() == 0:
		return "default_route"
	case !v6Global.Contains(p.Addr()) || p.Bits() < 3:
		return "v6_not_global_unicast"
	case p.Bits() < cfg.V6MinLen:
		return "v6_too_short"
	case p.Bits() > cfg.V6MaxLen:
		return "v6_too_specific"
	case insideAny(p, v6Martians):
		return "v6_martian"
	}
	return ""
}

func originRejectReason(asn uint32) string {
	switch {
	case asn == 0:
		return "origin_as0"
	case asn == 23456:
		return "origin_as_trans"
	case asn >= 64496 && asn <= 64511, asn >= 65536 && asn <= 65551:
		return "origin_documentation_asn"
	case asn >= 64512 && asn <= 65534, asn >= 4200000000 && asn <= 4294967294:
		return "origin_private_asn"
	case asn == 65535, asn == 4294967295, asn >= 65552 && asn <= 131071:
		return "origin_reserved_asn"
	}
	return ""
}
