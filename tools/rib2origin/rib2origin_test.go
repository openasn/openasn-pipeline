package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/netip"
	"testing"
)

// --- synthetic MRT builders ---------------------------------------------------

func mrtRecord(sub uint16, body []byte) []byte {
	h := make([]byte, 12)
	binary.BigEndian.PutUint32(h[0:], 1758225600)
	binary.BigEndian.PutUint16(h[4:], mrtTableDumpV2)
	binary.BigEndian.PutUint16(h[6:], sub)
	binary.BigEndian.PutUint32(h[8:], uint32(len(body)))
	return append(h, body...)
}

func peerIndex(ases ...uint32) []byte {
	var b bytes.Buffer
	b.Write([]byte{10, 0, 0, 1}) // collector id
	b.Write([]byte{0, 0})        // view name len
	binary.Write(&b, binary.BigEndian, uint16(len(ases)))
	for i, as := range ases {
		b.WriteByte(peerTypeAS4)               // v4 peer, AS4
		b.Write([]byte{1, 1, 1, byte(i)})      // bgp id
		b.Write([]byte{192, 0, 2, byte(i)})    // peer ip
		binary.Write(&b, binary.BigEndian, as) // peer as
	}
	return b.Bytes()
}

type seg struct {
	typ  byte
	asns []uint32
}

func asPathAttr(segs ...seg) []byte {
	var p bytes.Buffer
	for _, s := range segs {
		p.WriteByte(s.typ)
		p.WriteByte(byte(len(s.asns)))
		for _, a := range s.asns {
			binary.Write(&p, binary.BigEndian, a)
		}
	}
	attr := []byte{0x40, attrASPath, byte(p.Len())}
	return append(attr, p.Bytes()...)
}

func ribV4(pfx string, entries map[uint16][]byte) []byte {
	p := netip.MustParsePrefix(pfx)
	var b bytes.Buffer
	b.Write([]byte{0, 0, 0, 1}) // seq
	b.WriteByte(byte(p.Bits()))
	a := p.Addr().As4()
	b.Write(a[:(p.Bits()+7)/8])
	binary.Write(&b, binary.BigEndian, uint16(len(entries)))
	for i := uint16(0); i < 16; i++ { // deterministic order
		attrs, ok := entries[i]
		if !ok {
			continue
		}
		binary.Write(&b, binary.BigEndian, i)
		b.Write([]byte{0, 0, 0, 0}) // originated time
		binary.Write(&b, binary.BigEndian, uint16(len(attrs)))
		b.Write(attrs)
	}
	return b.Bytes()
}

func seq(asns ...uint32) seg { return seg{segASSequence, asns} }
func set(asns ...uint32) seg { return seg{segASSet, asns} }

// --- tests ----------------------------------------------------------------------

func TestOriginFromASPath(t *testing.T) {
	cases := []struct {
		name     string
		segs     []seg
		origin   uint32
		upstream uint32
	}{
		{"plain", []seg{seq(3356, 174, 13335)}, 13335, 174},
		{"prepending skipped for upstream", []seg{seq(3356, 64500, 64500, 64500)}, 64500, 3356},
		{"single-member set is the origin", []seg{seq(3356, 174), set(13335)}, 13335, 174},
		{"multi-member set has no origin", []seg{seq(3356, 174), set(13335, 15169)}, originASSet, 174},
		{"confed segments ignored", []seg{{segConfedSequence, []uint32{65001}}, seq(3356, 2914)}, 2914, 3356},
	}
	for _, c := range cases {
		o, u, empty := originFromAttrs(asPathAttr(c.segs...))
		if empty || o != c.origin || u != c.upstream {
			t.Errorf("%s: got origin=%d upstream=%d empty=%v, want %d/%d", c.name, o, u, empty, c.origin, c.upstream)
		}
	}
	if _, _, empty := originFromAttrs(asPathAttr()); !empty {
		t.Error("empty AS_PATH must report empty")
	}
}

func TestReaderAndMajorityVote(t *testing.T) {
	var stream []byte
	stream = append(stream, mrtRecord(subPeerIndexTable, peerIndex(3356, 174, 2914, 6939))...)
	stream = append(stream, mrtRecord(subRIBIPv4Unicast, ribV4("5.5.0.0/22", map[uint16][]byte{
		0: asPathAttr(seq(3356, 64501)), // private-ish? no: 64501 is documentation -> dropped
	}))...)
	stream = append(stream, mrtRecord(subRIBIPv4Unicast, ribV4("8.8.8.0/24", map[uint16][]byte{
		0: asPathAttr(seq(3356, 15169)),
		1: asPathAttr(seq(174, 15169)),
		2: asPathAttr(seq(2914, 15169)),
		3: asPathAttr(seq(6939, 12345)), // hijack seen by one peer
	}))...)
	stream = append(stream, mrtRecord(subRIBIPv4Unicast, ribV4("1.1.1.0/24", map[uint16][]byte{
		0: asPathAttr(seq(3356, 13335)), // seen by one peer only -> below floor
	}))...)
	stream = append(stream, mrtRecord(subRIBIPv4Unicast, ribV4("10.0.0.0/8", map[uint16][]byte{
		0: asPathAttr(seq(3356, 65000)),
	}))...)

	cfg := Config{MinPeers: 2, V4MinLen: 8, V4MaxLen: 24, V6MinLen: 16, V6MaxLen: 48, CollectLinks: true}
	agg := NewAggregator()
	mr := NewReader(bytes.NewReader(stream))
	l := newLocalStats()
	var rec RIBRecord
	for {
		err := mr.Next(&rec)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		agg.Add(&rec, mr.Peers, agg.PeerIDs(mr.Peers), l, &cfg)
	}
	agg.merge(l)
	v4, _, dropped, st := agg.Resolve(&cfg)
	if len(v4) != 1 || v4[0].Prefix.String() != "8.8.8.0/24" || v4[0].Origin != 15169 || v4[0].OriginVis != 3 || v4[0].TotalVis != 4 {
		t.Fatalf("unexpected kept set: %+v", v4)
	}
	if v4[0].MOAS {
		t.Error("a single-peer hijack must not count as MOAS at min-peers 2")
	}
	if st.DroppedLowVis != 1 || len(dropped) != 2 { // 1.1.1.0/24 low-vis; 5.5.0.0/22 has no valid origin left
		t.Errorf("dropped: stats=%+v list=%d", st, len(dropped))
	}
	if agg.Stats.DroppedPrefix["v4_martian"] != 1 {
		t.Errorf("10/8 must be dropped as martian: %+v", agg.Stats.DroppedPrefix)
	}
	if agg.Stats.DroppedEntry["origin_documentation_asn"] != 1 {
		t.Errorf("AS64501 must be dropped as documentation ASN: %+v", agg.Stats.DroppedEntry)
	}
	if _, ok := l.links[uint64(174)<<32|15169]; !ok {
		t.Error("upstream->origin link 174->15169 not recorded")
	}
}

func TestFlattenLongestPrefixWins(t *testing.T) {
	mk := func(p string, asn uint32) Resolved {
		return Resolved{Prefix: netip.MustParsePrefix(p), Origin: asn}
	}
	rs := []Resolved{
		mk("10.0.0.0/16", 1),
		mk("10.0.1.0/24", 2),
		mk("10.0.1.128/25", 3),
		mk("10.0.2.0/24", 1), // same origin as cover: merges back
		mk("10.1.0.0/24", 4), // disjoint
	}
	sortResolved(rs)
	got := Flatten(rs)
	ip := func(s string) u128 {
		a := netip.MustParseAddr(s).As4()
		return u128{0, uint64(binary.BigEndian.Uint32(a[:]))}
	}
	want := []Range{
		{ip("10.0.0.0"), ip("10.0.0.255"), 1},
		{ip("10.0.1.0"), ip("10.0.1.127"), 2},
		{ip("10.0.1.128"), ip("10.0.1.255"), 3},
		{ip("10.0.2.0"), ip("10.0.255.255"), 1},
		{ip("10.1.0.0"), ip("10.1.0.255"), 4},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d ranges %+v", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("range %d: got %+v want %+v", i, got[i], want[i])
		}
	}
}

func TestFlattenIPv6(t *testing.T) {
	rs := []Resolved{
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), Origin: 1},
		{Prefix: netip.MustParsePrefix("2001:db8:1::/48"), Origin: 2},
	}
	got := Flatten(rs)
	if len(got) != 3 || got[1].ASN != 2 || got[2].ASN != 1 {
		t.Fatalf("unexpected v6 flatten: %+v", got)
	}
	if got[2].End != (u128{0x20010db8ffffffff, ^uint64(0)}) {
		t.Errorf("v6 /32 end wrong: %x %x", got[2].End.hi, got[2].End.lo)
	}
}

func TestFilters(t *testing.T) {
	cfg := Config{V4MinLen: 8, V4MaxLen: 24, V6MinLen: 16, V6MaxLen: 48}
	for p, want := range map[string]string{
		"0.0.0.0/0":       "default_route",
		"1.2.3.0/25":      "v4_too_specific",
		"100.64.0.0/10":   "v4_martian",
		"8.8.8.0/24":      "",
		"2001:db8::/32":   "v6_martian",
		"2a00:1450::/32":  "",
		"fc00::/7":        "v6_not_global_unicast",
		"2a00:1450::/64":  "v6_too_specific",
		"192.88.99.0/24":  "v4_martian",
		"44.0.0.0/7":      "v4_too_short",
		"2400:cb00::/32":  "",
		"2002:c000::/24":  "v6_martian",
		"3fff:abc::/32":   "v6_martian",
		"2620:fe::fe/128": "v6_too_specific",
		"198.51.0.0/16":   "", // covers TEST-NET-2 but is not inside it
	} {
		if got := prefixRejectReason(netip.MustParsePrefix(p), &cfg); got != want {
			t.Errorf("%s: got %q want %q", p, got, want)
		}
	}
	for asn, bad := range map[uint32]bool{0: true, 23456: true, 64512: true, 65535: true, 4200000000: true, 13335: false, 131072: false, 401308: false} {
		if (originRejectReason(asn) != "") != bad {
			t.Errorf("AS%d: reject=%v", asn, !bad)
		}
	}
}
