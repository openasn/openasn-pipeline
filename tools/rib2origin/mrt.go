package main

// A minimal, allocation-light reader for MRT TABLE_DUMP_V2 RIB dumps
// (RFC 6396, plus the RFC 8050 ADD-PATH subtypes). It extracts exactly what
// the backbone needs and nothing else: for every RIB record, the prefix and,
// per RIB entry, the peer's AS and the path's origin.
//
// Written in-repo (MIT, stdlib only) instead of importing a BGP library: the
// subset needed is ~200 lines, and a dependency-free reader keeps the
// provenance of the backbone code as simple as the provenance of its data.

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

const (
	mrtTableDumpV2 = 13

	subPeerIndexTable          = 1
	subRIBIPv4Unicast          = 2
	subRIBIPv6Unicast          = 4
	subRIBIPv4UnicastAP        = 8  // RFC 8050
	subRIBIPv6UnicastAP        = 10 // RFC 8050
	attrASPath                 = 2
	attrFlagExtendedLen        = 0x10
	segASSet                   = 1
	segASSequence              = 2
	segConfedSequence          = 3
	segConfedSet               = 4
	peerTypeIPv6               = 0x01
	peerTypeAS4                = 0x02
	originNone                 = 0          // path yielded no usable origin
	originASSet         uint32 = 0xFFFFFFFF // sentinel: path ends in a multi-member AS_SET
)

// Entry is one route for a prefix, as seen by one peer.
type Entry struct {
	PeerIndex uint16
	Origin    uint32 // originNone / originASSet sentinels, else the origin ASN
	Upstream  uint32 // nearest distinct ASN before the origin (0 if none)
}

// RIBRecord is one prefix with all of its per-peer entries.
type RIBRecord struct {
	Prefix  netip.Prefix
	Entries []Entry
}

// Peer from the PEER_INDEX_TABLE.
type Peer struct {
	AS   uint32
	Addr netip.Addr
}

// Reader streams RIB records out of one MRT file.
type Reader struct {
	r     *bufio.Reader
	hdr   [12]byte
	buf   []byte
	Peers []Peer
	// PeerGen counts PEER_INDEX_TABLEs read, so callers re-map peer ids
	// whenever a new table arrives, even one of the same size (RB-3).
	PeerGen int

	// Counters for the stats report (skipped subtypes are not errors: RIBs
	// may carry multicast or RIB_GENERIC records the backbone ignores).
	SkippedRecords map[string]int
	EmptyPath      int
}

func NewReader(r io.Reader) *Reader {
	return &Reader{r: bufio.NewReaderSize(r, 1<<20), SkippedRecords: map[string]int{}}
}

// Next fills rec with the next unicast RIB record. It returns io.EOF at the
// clean end of the stream. rec.Entries is reused between calls.
func (m *Reader) Next(rec *RIBRecord) error {
	for {
		if _, err := io.ReadFull(m.r, m.hdr[:]); err != nil {
			if err == io.EOF {
				return io.EOF
			}
			return fmt.Errorf("mrt header: %w", err)
		}
		typ := binary.BigEndian.Uint16(m.hdr[4:6])
		sub := binary.BigEndian.Uint16(m.hdr[6:8])
		length := binary.BigEndian.Uint32(m.hdr[8:12])
		if length > 64<<20 {
			return fmt.Errorf("mrt record length %d is implausible (corrupt stream?)", length)
		}
		if cap(m.buf) < int(length) {
			m.buf = make([]byte, length)
		}
		body := m.buf[:length]
		if _, err := io.ReadFull(m.r, body); err != nil {
			return fmt.Errorf("mrt body (type %d/%d, %d bytes): %w", typ, sub, length, err)
		}
		if typ != mrtTableDumpV2 {
			m.SkippedRecords[fmt.Sprintf("type%d", typ)]++
			continue
		}
		switch sub {
		case subPeerIndexTable:
			if err := m.parsePeerIndex(body); err != nil {
				return err
			}
		case subRIBIPv4Unicast, subRIBIPv6Unicast, subRIBIPv4UnicastAP, subRIBIPv6UnicastAP:
			if m.Peers == nil {
				return errors.New("RIB record before PEER_INDEX_TABLE")
			}
			v6 := sub == subRIBIPv6Unicast || sub == subRIBIPv6UnicastAP
			addPath := sub == subRIBIPv4UnicastAP || sub == subRIBIPv6UnicastAP
			if err := m.parseRIB(body, v6, addPath, rec); err != nil {
				return fmt.Errorf("rib subtype %d: %w", sub, err)
			}
			return nil
		default:
			m.SkippedRecords[fmt.Sprintf("tdv2-sub%d", sub)]++
		}
	}
}

func (m *Reader) parsePeerIndex(b []byte) error {
	if len(b) < 8 {
		return errors.New("peer index table truncated")
	}
	off := 4 // collector BGP ID
	nameLen := int(binary.BigEndian.Uint16(b[off:]))
	off += 2 + nameLen
	if off+2 > len(b) {
		return errors.New("peer index table truncated (view name)")
	}
	count := int(binary.BigEndian.Uint16(b[off:]))
	off += 2
	peers := make([]Peer, 0, count)
	for i := 0; i < count; i++ {
		if off+5 > len(b) {
			return errors.New("peer index table truncated (peer)")
		}
		pt := b[off]
		off += 1 + 4 // type + BGP ID
		var addr netip.Addr
		if pt&peerTypeIPv6 != 0 {
			if off+16 > len(b) {
				return errors.New("peer index table truncated (v6 addr)")
			}
			addr = netip.AddrFrom16([16]byte(b[off : off+16]))
			off += 16
		} else {
			if off+4 > len(b) {
				return errors.New("peer index table truncated (v4 addr)")
			}
			addr = netip.AddrFrom4([4]byte(b[off : off+4]))
			off += 4
		}
		var as uint32
		if pt&peerTypeAS4 != 0 {
			if off+4 > len(b) {
				return errors.New("peer index table truncated (as4)")
			}
			as = binary.BigEndian.Uint32(b[off:])
			off += 4
		} else {
			if off+2 > len(b) {
				return errors.New("peer index table truncated (as2)")
			}
			as = uint32(binary.BigEndian.Uint16(b[off:]))
			off += 2
		}
		peers = append(peers, Peer{AS: as, Addr: addr})
	}
	m.Peers = peers
	m.PeerGen++
	return nil
}

func (m *Reader) parseRIB(b []byte, v6, addPath bool, rec *RIBRecord) error {
	if len(b) < 5 {
		return errors.New("truncated")
	}
	off := 4 // sequence number
	plen := int(b[off])
	off++
	maxLen := 32
	if v6 {
		maxLen = 128
	}
	if plen > maxLen {
		return fmt.Errorf("prefix length %d > %d", plen, maxLen)
	}
	nb := (plen + 7) / 8
	if off+nb+2 > len(b) {
		return errors.New("truncated prefix")
	}
	var pfx netip.Prefix
	if v6 {
		var a [16]byte
		copy(a[:], b[off:off+nb])
		pfx = netip.PrefixFrom(netip.AddrFrom16(a), plen)
	} else {
		var a [4]byte
		copy(a[:], b[off:off+nb])
		pfx = netip.PrefixFrom(netip.AddrFrom4(a), plen)
	}
	rec.Prefix = pfx.Masked()
	off += nb
	count := int(binary.BigEndian.Uint16(b[off:]))
	off += 2
	rec.Entries = rec.Entries[:0]
	for i := 0; i < count; i++ {
		need := 2 + 4 + 2
		if addPath {
			need += 4
		}
		if off+need > len(b) {
			return errors.New("truncated rib entry")
		}
		peer := binary.BigEndian.Uint16(b[off:])
		off += 2 + 4 // peer index + originated time
		if addPath {
			off += 4
		}
		alen := int(binary.BigEndian.Uint16(b[off:]))
		off += 2
		if off+alen > len(b) {
			return errors.New("truncated attributes")
		}
		origin, upstream, empty := originFromAttrs(b[off : off+alen])
		off += alen
		if int(peer) >= len(m.Peers) {
			return fmt.Errorf("peer index %d out of range (%d peers)", peer, len(m.Peers))
		}
		if empty {
			// A peer's own route carries an empty AS_PATH on some iBGP/multihop
			// sessions: the origin is the peer itself.
			m.EmptyPath++
			origin = m.Peers[peer].AS
		}
		rec.Entries = append(rec.Entries, Entry{PeerIndex: peer, Origin: origin, Upstream: upstream})
	}
	return nil
}

// originFromAttrs walks the path attributes and returns the origin AS of the
// AS_PATH. TABLE_DUMP_V2 always encodes AS_PATH with 4-byte ASNs (RFC 6396
// section 4.3.4), so AS4_PATH reconciliation is unnecessary.
//
// Rules: confederation segments are ignored (they are local to the peer's
// confederation). If the last remaining segment is an AS_SEQUENCE, its last
// ASN is the origin. If it is an AS_SET with one member, that member is the
// origin; a multi-member AS_SET (aggregation) yields originASSet, which the
// aggregator excludes - there is no single origin to publish.
func originFromAttrs(a []byte) (origin, upstream uint32, emptyPath bool) {
	off := 0
	for off+3 <= len(a) {
		flags := a[off]
		typ := a[off+1]
		var l int
		if flags&attrFlagExtendedLen != 0 {
			if off+4 > len(a) {
				return originNone, 0, false
			}
			l = int(binary.BigEndian.Uint16(a[off+2:]))
			off += 4
		} else {
			l = int(a[off+2])
			off += 3
		}
		if off+l > len(a) {
			return originNone, 0, false
		}
		if typ == attrASPath {
			return originFromASPath(a[off : off+l])
		}
		off += l
	}
	return originNone, 0, false
}

func originFromASPath(p []byte) (origin, upstream uint32, empty bool) {
	var last, prev uint32 // prev = nearest ASN before last that differs from it (prepending skipped)
	seen := false
	off := 0
	for off+2 <= len(p) {
		st := p[off]
		n := int(p[off+1])
		off += 2
		if off+4*n > len(p) {
			return originNone, 0, false
		}
		switch st {
		case segASSequence:
			for i := 0; i < n; i++ {
				a := binary.BigEndian.Uint32(p[off+4*i:])
				if seen && a != last {
					prev = last
				}
				last, seen = a, true
			}
		case segASSet:
			if n == 0 {
				break
			}
			first := binary.BigEndian.Uint32(p[off:])
			multi := false
			for i := 1; i < n; i++ {
				if binary.BigEndian.Uint32(p[off+4*i:]) != first {
					multi = true
				}
			}
			if multi {
				// Only fatal if nothing follows it; checked after the loop.
				if seen {
					prev = last
				}
				last, seen = originASSet, true
				break
			}
			if seen && first != last {
				prev = last
			}
			last, seen = first, true
		}
		// Confederation segments (3, 4) are local to the peer: ignored.
		off += 4 * n
	}
	if !seen {
		return originNone, 0, true
	}
	if last == originASSet {
		return originASSet, prev, false
	}
	return last, prev, false
}
