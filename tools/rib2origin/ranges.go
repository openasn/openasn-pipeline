package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net/netip"
	"sort"
)

// u128 is an address as an unsigned 128-bit integer (IPv4 uses lo only).
type u128 struct{ hi, lo uint64 }

func (a u128) less(b u128) bool { return a.hi < b.hi || (a.hi == b.hi && a.lo < b.lo) }
func (a u128) inc() u128 {
	lo := a.lo + 1
	hi := a.hi
	if lo == 0 {
		hi++
	}
	return u128{hi, lo}
}
func (a u128) dec() u128 {
	lo := a.lo - 1
	hi := a.hi
	if a.lo == 0 {
		hi--
	}
	return u128{hi, lo}
}

func (a u128) String() string {
	if a.hi == 0 {
		return fmt.Sprint(a.lo)
	}
	b := new(big.Int).SetUint64(a.hi)
	b.Lsh(b, 64)
	b.Or(b, new(big.Int).SetUint64(a.lo))
	return b.String()
}

// Size returns end-start+1 as float64 (exact enough for coverage ratios).
func span(s, e u128) float64 {
	const two64 = 18446744073709551616.0
	hi := float64(e.hi) - float64(s.hi)
	lo := float64(e.lo) - float64(s.lo)
	return hi*two64 + lo + 1
}

func prefixBounds(p netip.Prefix) (u128, u128) {
	if p.Addr().Is4() {
		a := p.Addr().As4()
		s := uint64(binary.BigEndian.Uint32(a[:]))
		host := uint64(1)<<(32-p.Bits()) - 1
		return u128{0, s}, u128{0, s | host}
	}
	a := p.Addr().As16()
	s := u128{binary.BigEndian.Uint64(a[:8]), binary.BigEndian.Uint64(a[8:])}
	e := s
	hb := 128 - p.Bits()
	switch {
	case hb >= 64:
		e.lo = ^uint64(0)
		if hb > 64 {
			e.hi |= uint64(1)<<(hb-64) - 1
		}
		if hb == 128 {
			e.hi = ^uint64(0)
		}
	case hb > 0:
		e.lo |= uint64(1)<<hb - 1
	}
	return s, e
}

// Range is an inclusive [Start, End] address range with its origin.
type Range struct {
	Start, End u128
	ASN        uint32
}

// Flatten turns a set of (possibly nested) prefixes into non-overlapping
// ranges with longest-prefix-match semantics - exactly what a router does:
// a more-specific prefix wins over the block that covers it. Adjacent
// ranges with the same origin are merged, like sapics' output.
func Flatten(rs []Resolved) []Range {
	type pr struct {
		s, e u128
		bits int
		asn  uint32
	}
	ps := make([]pr, len(rs))
	for i, r := range rs {
		s, e := prefixBounds(r.Prefix)
		ps[i] = pr{s, e, r.Prefix.Bits(), r.Origin}
	}
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].s != ps[j].s {
			return ps[i].s.less(ps[j].s)
		}
		return ps[i].bits < ps[j].bits
	})
	var out []Range
	emit := func(s, e u128, asn uint32) {
		if e.less(s) {
			return
		}
		if n := len(out); n > 0 && out[n-1].ASN == asn && out[n-1].End.inc() == s {
			out[n-1].End = e
			return
		}
		out = append(out, Range{s, e, asn})
	}
	var stack []pr
	var pos u128 // next address not yet emitted
	posValid := false
	for _, p := range ps {
		// Close every open prefix that ends before p starts.
		for len(stack) > 0 && stack[len(stack)-1].e.less(p.s) {
			top := stack[len(stack)-1]
			if posValid && !top.e.less(pos) {
				emit(pos, top.e, top.asn)
			}
			pos, posValid = top.e.inc(), true
			if top.e == (u128{^uint64(0), ^uint64(0)}) {
				posValid = false
			}
			stack = stack[:len(stack)-1]
		}
		// The covering prefix (if any) owns the gap up to p.
		if len(stack) > 0 && posValid && pos.less(p.s) {
			emit(pos, p.s.dec(), stack[len(stack)-1].asn)
		}
		pos, posValid = p.s, true
		stack = append(stack, p)
	}
	for len(stack) > 0 {
		top := stack[len(stack)-1]
		if posValid && !top.e.less(pos) {
			emit(pos, top.e, top.asn)
		}
		pos, posValid = top.e.inc(), true
		stack = stack[:len(stack)-1]
	}
	return out
}

// WriteCSV writes the sapics "-num" shape the pipeline already parses
// (pipeline/normalize.rb parse_origin_asn): start_int,end_int,asn,name.
// The name column is left empty on purpose: names are not BGP facts, and
// org names come from elsewhere.
func WriteCSV(w io.Writer, rs []Range) error {
	bw := bufio.NewWriterSize(w, 1<<20)
	for _, r := range rs {
		if _, err := fmt.Fprintf(bw, "%s,%s,%d,\n", r.Start, r.End, r.ASN); err != nil {
			return err
		}
	}
	return bw.Flush()
}
