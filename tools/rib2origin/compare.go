package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
)

// compare measures how well two range tables agree, address-weighted, and
// classifies every disagreement. Written for "is the RouteViews backbone
// equivalent to sapics?", usable for any two tables in the -num CSV shape.

type segClass string

const (
	clsSame           segClass = "same_origin"
	clsOnlyA          segClass = "only_in_a"
	clsOnlyB          segClass = "only_in_b"
	clsDiffMOAS       segClass = "differ_a_is_minority_origin_in_b" // B saw A's ASN originate this prefix too, but it lost the vote
	clsDiffLowVis     segClass = "differ_a_seen_below_floor_in_b"
	clsDiffAdjacent   segClass = "differ_adjacent_in_paths" // A and B's ASNs are neighbours in observed AS paths (provider/customer)
	clsDiffUnrelated  segClass = "differ_unrelated"
	clsDiffBFromCover segClass = "differ_b_from_covering_prefix" // B has no prefix of its own here; the answer comes from a less-specific
)

type bucket struct {
	Segments  int     `json:"segments"`
	Addresses float64 `json:"addresses"`
}

type example struct {
	Start, End string
	Size       float64
	A, B       uint32
	BPrefix    string
	BCands     string
	Class      string `json:",omitempty"`
}

type familyReport struct {
	Family      string               `json:"family"`
	Unit        string               `json:"unit"`
	ARanges     int                  `json:"a_ranges"`
	BRanges     int                  `json:"b_ranges"`
	ACovered    float64              `json:"a_covered"`
	BCovered    float64              `json:"b_covered"`
	BothCovered float64              `json:"both_covered"`
	Agreement   float64              `json:"origin_agreement_where_both_cover"`
	BCoversOfA  float64              `json:"share_of_a_covered_by_b"`
	ACoversOfB  float64              `json:"share_of_b_covered_by_a"`
	Buckets     map[segClass]*bucket `json:"buckets"`
	TopDiffer   []example            `json:"largest_disagreements"`
	TopOnlyA    []example            `json:"largest_only_in_a"`
	TopOnlyB    []example            `json:"largest_only_in_b"`
	DiffByBLen  map[string]float64   `json:"differ_addresses_by_b_prefix_len"`
	OnlyAByLen  map[string]int       `json:"only_in_a_segments_by_size_bucket"`
	OnlyASplit  map[string]*bucket   `json:"only_in_a_split"`
}

func runCompare(args []string) error {
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	a4 := fs.String("a4", "", "table A, IPv4 (e.g. sapics origin-asn-ipv4-num.csv)")
	a6 := fs.String("a6", "", "table A, IPv6")
	bdir := fs.String("b", "", "rib2origin build output directory (table B)")
	out := fs.String("out", "", "JSON report path")
	top := fs.Int("top", 40, "examples per list")
	dump := fs.String("dump", "", "if set, write every only_in_a / differ segment to DUMP-<family>.tsv")
	fs.Parse(args)
	if *bdir == "" || *out == "" {
		return fmt.Errorf("compare needs -b and -out")
	}
	links, err := readLinks(*bdir + "/links.bin")
	if err != nil {
		return err
	}
	pfx, err := readPrefixIndex(*bdir+"/prefixes-ipv4.tsv", *bdir+"/prefixes-ipv6.tsv", *bdir+"/prefixes-dropped.tsv")
	if err != nil {
		return err
	}
	var reps []familyReport
	for _, fam := range []struct{ name, a, b string }{
		{"ipv4", *a4, *bdir + "/origin-asn-ipv4-num.csv"},
		{"ipv6", *a6, *bdir + "/origin-asn-ipv6-num.csv"},
	} {
		if fam.a == "" {
			continue
		}
		ra, err := readRanges(fam.a)
		if err != nil {
			return err
		}
		rb, err := readRanges(fam.b)
		if err != nil {
			return err
		}
		rep, all := compareFamily(fam.name, ra, rb, links, pfx, *top)
		reps = append(reps, rep)
		if *dump != "" {
			if err := writeFile(*dump+"-"+fam.name+".tsv", func(w io.Writer) error {
				bw := bufio.NewWriter(w)
				for _, e := range all {
					fmt.Fprintf(bw, "%s\t%s\t%s\t%g\t%d\t%d\t%s\t%s\n", e.Class, e.Start, e.End, e.Size, e.A, e.B, e.BPrefix, e.BCands)
				}
				return bw.Flush()
			}); err != nil {
				return err
			}
		}
	}
	return writeFile(*out, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(reps)
	})
}

func compareFamily(name string, A, B []Range, links map[uint64]struct{}, pfx *prefixIndex, top int) (familyReport, []example) {
	unit := 1.0
	unitName := "addresses"
	if name == "ipv6" {
		unit = float64(1 << 80)
		unitName = "/48 equivalents"
	}
	rep := familyReport{Family: name, Unit: unitName, ARanges: len(A), BRanges: len(B),
		Buckets: map[segClass]*bucket{}, DiffByBLen: map[string]float64{}, OnlyAByLen: map[string]int{}}
	var differ, onlyA, onlyB []example
	var oaIdx []int
	aTouched := make([]bool, len(A))
	type oaSeg struct {
		i  int
		sz float64
	}
	var oaSegs []oaSeg
	bOrigins := map[uint32]bool{}
	for _, r := range B {
		bOrigins[r.ASN] = true
	}
	add := func(c segClass, s, e u128) float64 {
		sz := span(s, e) / unit
		b := rep.Buckets[c]
		if b == nil {
			b = &bucket{}
			rep.Buckets[c] = b
		}
		b.Segments++
		b.Addresses += sz
		return sz
	}
	for _, r := range A {
		rep.ACovered += span(r.Start, r.End) / unit
	}
	for _, r := range B {
		rep.BCovered += span(r.Start, r.End) / unit
	}
	i, j := 0, 0
	var x u128
	if len(A) > 0 && (len(B) == 0 || A[0].Start.less(B[0].Start)) {
		x = A[0].Start
	} else if len(B) > 0 {
		x = B[0].Start
	}
	maxU := u128{^uint64(0), ^uint64(0)}
	for i < len(A) || j < len(B) {
		for i < len(A) && A[i].End.less(x) {
			i++
		}
		for j < len(B) && B[j].End.less(x) {
			j++
		}
		if i >= len(A) && j >= len(B) {
			break
		}
		inA := i < len(A) && !x.less(A[i].Start)
		inB := j < len(B) && !x.less(B[j].Start)
		if !inA && !inB {
			switch {
			case i >= len(A):
				x = B[j].Start
			case j >= len(B):
				x = A[i].Start
			case A[i].Start.less(B[j].Start):
				x = A[i].Start
			default:
				x = B[j].Start
			}
			continue
		}
		end := maxU
		clip := func(v u128) {
			if v.less(end) {
				end = v
			}
		}
		if inA {
			clip(A[i].End)
		} else if i < len(A) {
			clip(A[i].Start.dec())
		}
		if inB {
			clip(B[j].End)
		} else if j < len(B) {
			clip(B[j].Start.dec())
		}
		switch {
		case inA && inB && A[i].ASN == B[j].ASN:
			aTouched[i] = true
			rep.BothCovered += add(clsSame, x, end)
		case inA && inB:
			aTouched[i] = true
			cls, bp, cands := classify(A[i].ASN, B[j].ASN, x, links, pfx)
			sz := add(cls, x, end)
			rep.BothCovered += sz
			rep.DiffByBLen[bp.lenKey()] += sz
			differ = append(differ, example{x.addrString(name), end.addrString(name), sz, A[i].ASN, B[j].ASN, bp.String(), cands, string(cls)})
		case inA:
			sz := add(clsOnlyA, x, end)
			oaSegs = append(oaSegs, oaSeg{i, sz})
			rep.OnlyAByLen[sizeBucket(name, x, end)]++
			bp, cands := pfx.droppedAt(x, name)
			onlyA = append(onlyA, example{x.addrString(name), end.addrString(name), sz, A[i].ASN, 0, bp, cands, ""})
			oaIdx = append(oaIdx, i)
		default:
			sz := add(clsOnlyB, x, end)
			bp, cands := pfx.lookup(x, name)
			onlyB = append(onlyB, example{x.addrString(name), end.addrString(name), sz, 0, B[j].ASN, bp.String(), cands, string(clsOnlyB)})
		}
		if end == maxU {
			break
		}
		x = end.inc()
	}
	rep.OnlyASplit = map[string]*bucket{}
	for _, sg := range oaSegs {
		k := "a_range_partly_routed_in_b"
		if !aTouched[sg.i] {
			if bOrigins[A[sg.i].ASN] {
				k = "a_range_unseen_in_b_asn_originates_elsewhere_in_b"
			} else {
				k = "a_range_unseen_in_b_asn_absent_from_b"
			}
		}
		b := rep.OnlyASplit[k]
		if b == nil {
			b = &bucket{}
			rep.OnlyASplit[k] = b
		}
		b.Segments++
		b.Addresses += sg.sz
	}
	if rep.BothCovered > 0 {
		rep.Agreement = rep.Buckets[clsSame].Addresses / rep.BothCovered
	}
	if rep.ACovered > 0 {
		rep.BCoversOfA = rep.BothCovered / rep.ACovered
	}
	if rep.BCovered > 0 {
		rep.ACoversOfB = rep.BothCovered / rep.BCovered
	}
	for k := range onlyA {
		onlyA[k].Class = "only_in_a/a_range_partly_routed_in_b"
		if !aTouched[oaIdx[k]] {
			if bOrigins[A[oaIdx[k]].ASN] {
				onlyA[k].Class = "only_in_a/a_range_unseen_in_b_asn_originates_elsewhere_in_b"
			} else {
				onlyA[k].Class = "only_in_a/a_range_unseen_in_b_asn_absent_from_b"
			}
		}
	}
	all := append(append(append([]example{}, differ...), onlyA...), onlyB...)
	rep.TopDiffer = topN(differ, top)
	rep.TopOnlyA = topN(onlyA, top)
	rep.TopOnlyB = topN(onlyB, top)
	return rep, all
}

func topN(xs []example, n int) []example {
	sort.Slice(xs, func(i, j int) bool { return xs[i].Size > xs[j].Size })
	if len(xs) > n {
		xs = xs[:n]
	}
	return xs
}

func sizeBucket(fam string, s, e u128) string {
	sz := span(s, e)
	bitsLen := 0
	for v := sz; v > 1; v /= 2 {
		bitsLen++
	}
	if fam == "ipv4" {
		return fmt.Sprintf("~/%d", 32-bitsLen)
	}
	return fmt.Sprintf("~/%d", 128-bitsLen)
}

func classify(a, b uint32, x u128, links map[uint64]struct{}, pfx *prefixIndex) (segClass, pfxInfo, string) {
	fam := "ipv4"
	if x.hi != 0 {
		fam = "ipv6"
	}
	bp, cands := pfx.lookupInfo(x, fam)
	for _, c := range bp.cands {
		if c.ASN == a {
			if bp.dropped {
				return clsDiffLowVis, bp, cands
			}
			return clsDiffMOAS, bp, cands
		}
	}
	// A's ASN may have been a (sub-floor) origin for a more-specific prefix
	// that B dropped; check the dropped set at this address.
	if d, ok := pfx.droppedInfo(x, fam); ok {
		for _, c := range d.cands {
			if c.ASN == a {
				return clsDiffLowVis, bp, cands
			}
		}
	}
	if _, ok := links[uint64(a)<<32|uint64(b)]; ok {
		return clsDiffAdjacent, bp, cands
	}
	if _, ok := links[uint64(b)<<32|uint64(a)]; ok {
		return clsDiffAdjacent, bp, cands
	}
	return clsDiffUnrelated, bp, cands
}

// --- prefix index (B's per-prefix decisions, kept and dropped) -------------

type pfxInfo struct {
	p       netip.Prefix
	cands   []OriginVis
	dropped bool
}

func (p pfxInfo) String() string {
	if !p.p.IsValid() {
		return ""
	}
	return p.p.String()
}

func (p pfxInfo) lenKey() string {
	if !p.p.IsValid() {
		return "none"
	}
	return "/" + strconv.Itoa(p.p.Bits())
}

type prefixIndex struct {
	kept    map[netip.Prefix]pfxInfo
	dropped map[netip.Prefix]pfxInfo
}

func readPrefixIndex(paths ...string) (*prefixIndex, error) {
	idx := &prefixIndex{kept: map[netip.Prefix]pfxInfo{}, dropped: map[netip.Prefix]pfxInfo{}}
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "#") {
				continue
			}
			f := strings.Split(line, "\t")
			if len(f) < 7 {
				continue
			}
			p, err := netip.ParsePrefix(f[0])
			if err != nil {
				continue
			}
			var cands []OriginVis
			for _, c := range strings.Split(f[5], ",") {
				if c == "" {
					continue
				}
				k, v, _ := strings.Cut(c, ":")
				asn, _ := strconv.ParseUint(k, 10, 32)
				vis, _ := strconv.Atoi(v)
				cands = append(cands, OriginVis{uint32(asn), vis})
			}
			info := pfxInfo{p: p, cands: cands, dropped: f[6] != ""}
			if info.dropped {
				idx.dropped[p] = info
			} else {
				idx.kept[p] = info
			}
		}
		f.Close()
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	return idx, nil
}

func (x u128) addr(fam string) netip.Addr {
	if fam == "ipv4" {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(x.lo))
		return netip.AddrFrom4(b)
	}
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], x.hi)
	binary.BigEndian.PutUint64(b[8:], x.lo)
	return netip.AddrFrom16(b)
}

func (x u128) addrString(fam string) string { return x.addr(fam).String() }

func lpm(m map[netip.Prefix]pfxInfo, a netip.Addr) (pfxInfo, bool) {
	for l := a.BitLen(); l >= 0; l-- {
		p, _ := a.Prefix(l)
		if info, ok := m[p]; ok {
			return info, true
		}
	}
	return pfxInfo{}, false
}

func candString(c []OriginVis) string {
	var sb strings.Builder
	for i, o := range c {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, "%d:%d", o.ASN, o.Vis)
	}
	return sb.String()
}

func (idx *prefixIndex) lookupInfo(x u128, fam string) (pfxInfo, string) {
	info, _ := lpm(idx.kept, x.addr(fam))
	return info, candString(info.cands)
}

func (idx *prefixIndex) lookup(x u128, fam string) (pfxInfo, string) { return idx.lookupInfo(x, fam) }

func (idx *prefixIndex) droppedInfo(x u128, fam string) (pfxInfo, bool) {
	return lpm(idx.dropped, x.addr(fam))
}

func (idx *prefixIndex) droppedAt(x u128, fam string) (string, string) {
	if d, ok := lpm(idx.dropped, x.addr(fam)); ok {
		return d.p.String() + " (dropped)", candString(d.cands)
	}
	return "", ""
}

// --- readers ------------------------------------------------------------------

func readRanges(path string) ([]Range, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Range
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), ",", 4)
		if len(parts) < 3 {
			continue
		}
		s, ok1 := parseU128(parts[0])
		e, ok2 := parseU128(parts[1])
		asn, err := strconv.ParseUint(parts[2], 10, 32)
		if !ok1 || !ok2 || err != nil {
			continue
		}
		out = append(out, Range{s, e, uint32(asn)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start.less(out[j].Start) })
	// Clip overlaps the same way pipeline/normalize.rb does, so the comparison
	// sees what the pipeline would see.
	clean := out[:0]
	var prevEnd u128
	have := false
	for _, r := range out {
		if have && !prevEnd.less(r.Start) {
			if !prevEnd.less(r.End) {
				continue
			}
			r.Start = prevEnd.inc()
		}
		clean = append(clean, r)
		prevEnd, have = r.End, true
	}
	return clean, sc.Err()
}

func parseU128(s string) (u128, bool) {
	if len(s) < 20 {
		v, err := strconv.ParseUint(s, 10, 64)
		return u128{0, v}, err == nil
	}
	b, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return u128{}, false
	}
	lo := new(big.Int).And(b, new(big.Int).SetUint64(^uint64(0))).Uint64()
	hi := new(big.Int).Rsh(b, 64).Uint64()
	return u128{hi, lo}, true
}

func readLinks(path string) (map[uint64]struct{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := make(map[uint64]struct{}, len(data)/8)
	for i := 0; i+8 <= len(data); i += 8 {
		m[binary.BigEndian.Uint64(data[i:])] = struct{}{}
	}
	return m, nil
}
