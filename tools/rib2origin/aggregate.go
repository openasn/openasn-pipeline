package main

import (
	"hash/maphash"
	"math/bits"
	"net/netip"
	"sort"
	"sync"
)

// Aggregator collects, per prefix, which origin ASNs were seen by which
// distinct peer ASes across every collector. Visibility is counted in
// distinct PEER ASes, not sessions: an operator with four sessions into
// three collectors is one witness, not twelve.
type Aggregator struct {
	shards [256]shard
	seed   maphash.Seed

	peerMu  sync.Mutex
	peerIDs map[uint32]int // peer ASN -> bit index

	statsMu sync.Mutex
	Stats   IngestStats
}

type shard struct {
	mu sync.Mutex
	m  map[netip.Prefix]*prefixAgg
}

type prefixAgg struct {
	origins []originAgg
}

type originAgg struct {
	asn   uint32 // originASSet for multi-member AS_SET paths
	peers bitset
}

type bitset []uint64

func (b *bitset) set(i int) {
	w := i >> 6
	for len(*b) <= w {
		*b = append(*b, 0)
	}
	(*b)[w] |= 1 << uint(i&63)
}

func (b bitset) count() int {
	n := 0
	for _, w := range b {
		n += bits.OnesCount64(w)
	}
	return n
}

func (b *bitset) or(o bitset) {
	for len(*b) < len(o) {
		*b = append(*b, 0)
	}
	for i, w := range o {
		(*b)[i] |= w
	}
}

// IngestStats counts what was dropped at ingestion, and why. Every rule in
// filters.go has a counter here so the report shows its effect.
type IngestStats struct {
	Records          int64            `json:"rib_records"`
	Entries          int64            `json:"rib_entries"`
	DroppedPrefix    map[string]int64 `json:"dropped_prefix_records"`
	DroppedEntry     map[string]int64 `json:"dropped_entries"`
	ASSetEntries     int64            `json:"as_set_entries"`
	EmptyPathEntries int64            `json:"empty_path_entries"`
}

func NewAggregator() *Aggregator {
	a := &Aggregator{seed: maphash.MakeSeed(), peerIDs: map[uint32]int{}}
	for i := range a.shards {
		a.shards[i].m = make(map[netip.Prefix]*prefixAgg, 8192)
	}
	a.Stats.DroppedPrefix = map[string]int64{}
	a.Stats.DroppedEntry = map[string]int64{}
	return a
}

// PeerIDs maps a collector's peer-index table onto global peer-AS bit ids.
func (a *Aggregator) PeerIDs(peers []Peer) []int {
	a.peerMu.Lock()
	defer a.peerMu.Unlock()
	ids := make([]int, len(peers))
	for i, p := range peers {
		id, ok := a.peerIDs[p.AS]
		if !ok {
			id = len(a.peerIDs)
			a.peerIDs[p.AS] = id
		}
		ids[i] = id
	}
	return ids
}

func (a *Aggregator) NumPeerASes() int {
	a.peerMu.Lock()
	defer a.peerMu.Unlock()
	return len(a.peerIDs)
}

// localStats is per-worker, merged once at the end (no lock per record).
type localStats struct {
	records, entries, asset, empty int64
	droppedPrefix, droppedEntry    map[string]int64
	links                          map[uint64]struct{}
}

func newLocalStats() *localStats {
	return &localStats{droppedPrefix: map[string]int64{}, droppedEntry: map[string]int64{}, links: map[uint64]struct{}{}}
}

func (a *Aggregator) merge(l *localStats) {
	a.statsMu.Lock()
	defer a.statsMu.Unlock()
	a.Stats.Records += l.records
	a.Stats.Entries += l.entries
	a.Stats.ASSetEntries += l.asset
	a.Stats.EmptyPathEntries += l.empty
	for k, v := range l.droppedPrefix {
		a.Stats.DroppedPrefix[k] += v
	}
	for k, v := range l.droppedEntry {
		a.Stats.DroppedEntry[k] += v
	}
}

// Add ingests one RIB record. peerIDs is the collector's translation table.
func (a *Aggregator) Add(rec *RIBRecord, peers []Peer, peerIDs []int, l *localStats, cfg *Config) {
	l.records++
	l.entries += int64(len(rec.Entries))
	if reason := prefixRejectReason(rec.Prefix, cfg); reason != "" {
		l.droppedPrefix[reason]++
		return
	}
	sh := &a.shards[maphash.Comparable(a.seed, rec.Prefix)&255]
	sh.mu.Lock()
	pa := sh.m[rec.Prefix]
	if pa == nil {
		pa = &prefixAgg{}
		sh.m[rec.Prefix] = pa
	}
	for _, e := range rec.Entries {
		origin := e.Origin
		switch {
		case origin == originNone:
			l.droppedEntry["no_as_path"]++
			continue
		case origin == originASSet:
			l.asset++
		default:
			if reason := originRejectReason(origin); reason != "" {
				l.droppedEntry[reason]++
				continue
			}
		}
		if cfg.CollectLinks && e.Upstream != 0 && origin != originASSet {
			l.links[uint64(e.Upstream)<<32|uint64(origin)] = struct{}{}
		}
		pid := peerIDs[e.PeerIndex]
		found := false
		for i := range pa.origins {
			if pa.origins[i].asn == origin {
				pa.origins[i].peers.set(pid)
				found = true
				break
			}
		}
		if !found {
			oa := originAgg{asn: origin}
			oa.peers.set(pid)
			pa.origins = append(pa.origins, oa)
		}
	}
	sh.mu.Unlock()
}

// Resolved is the per-prefix decision.
type Resolved struct {
	Prefix     netip.Prefix
	Origin     uint32
	OriginVis  int // distinct peer ASes that saw the winning origin
	TotalVis   int // distinct peer ASes that saw the prefix at all
	Candidates []OriginVis
	MOAS       bool   // more than one origin clears the visibility floor
	Tie        bool   // winner tied on visibility; broken by lowest ASN
	Reason     string // set only on dropped prefixes
}

type OriginVis struct {
	ASN uint32
	Vis int
}

// ResolveStats counts the fate of every prefix that survived ingestion.
type ResolveStats struct {
	Prefixes       int `json:"prefixes_seen"`
	Kept           int `json:"prefixes_kept"`
	DroppedLowVis  int `json:"dropped_below_min_peers"`
	DroppedASSet   int `json:"dropped_as_set_only"`
	DroppedNoOrig  int `json:"dropped_no_usable_origin"`
	MOAS           int `json:"moas_prefixes_kept"`
	Ties           int `json:"visibility_ties_broken_by_lowest_asn"`
	MinorityShare  int `json:"kept_where_winner_below_half_of_prefix_peers"`
	PeerASes       int `json:"distinct_peer_ases"`
	FullFeedFloors int `json:"min_peers"`
}

// Resolve applies the origin-selection rule to every prefix:
//
//  1. An origin counts only if >= MinPeers distinct peer ASes saw it.
//  2. The winner is the origin seen by the most distinct peer ASes
//     (majority vote across all collectors); ties go to the lowest ASN so
//     the output is deterministic.
//  3. A prefix whose only paths end in a multi-member AS_SET is dropped:
//     aggregation erased its origin, and guessing one would publish a
//     fact nobody observed.
func (a *Aggregator) Resolve(cfg *Config) ([]Resolved, []Resolved, []Resolved, ResolveStats) {
	var v4, v6, dropped []Resolved
	st := ResolveStats{PeerASes: a.NumPeerASes(), FullFeedFloors: cfg.MinPeers}
	for i := range a.shards {
		for pfx, pa := range a.shards[i].m {
			st.Prefixes++
			var union bitset
			cands := make([]OriginVis, 0, len(pa.origins))
			for _, o := range pa.origins {
				union.or(o.peers)
				if o.asn == originASSet {
					continue
				}
				cands = append(cands, OriginVis{ASN: o.asn, Vis: o.peers.count()})
			}
			if len(cands) == 0 {
				// Two different causes (RB-2): paths ending in a multi-member
				// AS_SET, or every path rejected at ingestion (bogon origin,
				// no AS_PATH), which leaves no origins at all. The first
				// version reported both as as_set_only (520 of 566 on
				// 2026-09-18 were really bogon-origin-only).
				if len(pa.origins) == 0 {
					st.DroppedNoOrig++
					dropped = append(dropped, Resolved{Prefix: pfx, Reason: "no_usable_origin"})
					continue
				}
				st.DroppedASSet++
				dropped = append(dropped, Resolved{Prefix: pfx, TotalVis: union.count(), Reason: "as_set_only"})
				continue
			}
			sort.Slice(cands, func(i, j int) bool {
				if cands[i].Vis != cands[j].Vis {
					return cands[i].Vis > cands[j].Vis
				}
				return cands[i].ASN < cands[j].ASN
			})
			if cands[0].Vis < cfg.MinPeers {
				st.DroppedLowVis++
				dropped = append(dropped, Resolved{Prefix: pfx, Origin: cands[0].ASN, OriginVis: cands[0].Vis, TotalVis: union.count(), Candidates: cands, Reason: "below_min_peers"})
				continue
			}
			r := Resolved{Prefix: pfx, Origin: cands[0].ASN, OriginVis: cands[0].Vis, TotalVis: union.count(), Candidates: cands}
			above := 0
			for _, c := range cands {
				if c.Vis >= cfg.MinPeers {
					above++
				}
			}
			r.MOAS = above > 1
			r.Tie = len(cands) > 1 && cands[1].Vis == cands[0].Vis
			if r.MOAS {
				st.MOAS++
			}
			if r.Tie {
				st.Ties++
			}
			if 2*r.OriginVis < r.TotalVis {
				st.MinorityShare++
			}
			st.Kept++
			if pfx.Addr().Is4() {
				v4 = append(v4, r)
			} else {
				v6 = append(v6, r)
			}
		}
	}
	return v4, v6, dropped, st
}
