package main

import (
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Config holds every tunable rule. Defaults are the proposed production
// values; the report records the values actually used.
type Config struct {
	MinPeers     int  `json:"min_peers"`
	V4MinLen     int  `json:"v4_min_len"`
	V4MaxLen     int  `json:"v4_max_len"`
	V6MinLen     int  `json:"v6_min_len"`
	V6MaxLen     int  `json:"v6_max_len"`
	CollectLinks bool `json:"collect_links"`
}

type fileStats struct {
	File      string         `json:"file"`
	Bytes     int64          `json:"compressed_bytes"`
	Peers     int            `json:"peers"`
	PeerASes  int            `json:"peer_ases"`
	Records   int64          `json:"rib_records"`
	Entries   int64          `json:"rib_entries"`
	Seconds   float64        `json:"seconds"`
	Skipped   map[string]int `json:"skipped_records,omitempty"`
	EmptyPath int            `json:"empty_path_entries"`
}

type buildReport struct {
	GeneratedAt string       `json:"generated_at"`
	Config      Config       `json:"config"`
	Files       []fileStats  `json:"files"`
	Ingest      IngestStats  `json:"ingest"`
	Resolve     ResolveStats `json:"resolve"`
	V4Ranges    int          `json:"v4_ranges"`
	V6Ranges    int          `json:"v6_ranges"`
	V4Addresses float64      `json:"v4_addresses"`
	V6Slash48s  float64      `json:"v6_slash48_equivalents"`
	Links       int          `json:"distinct_upstream_origin_links"`
	Decompress  string       `json:"decompressor"`
	Seconds     float64      `json:"seconds_total"`
	PeakHeapMB  uint64       `json:"heap_sys_mb"`
}

func runBuild(args []string) error {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	out := fs.String("out", "", "output directory (required)")
	cfg := Config{}
	fs.IntVar(&cfg.MinPeers, "min-peers", 2, "an origin must be seen by at least this many distinct peer ASes")
	fs.IntVar(&cfg.V4MinLen, "v4-min-len", 8, "shortest IPv4 prefix kept")
	fs.IntVar(&cfg.V4MaxLen, "v4-max-len", 24, "longest IPv4 prefix kept")
	fs.IntVar(&cfg.V6MinLen, "v6-min-len", 16, "shortest IPv6 prefix kept")
	fs.IntVar(&cfg.V6MaxLen, "v6-max-len", 48, "longest IPv6 prefix kept")
	fs.BoolVar(&cfg.CollectLinks, "links", true, "record upstream->origin adjacencies (for compare)")
	decomp := fs.String("bzip2", "auto", "bz2 decompressor: auto (external lbzip2/bzip2 if on PATH), go (stdlib), or a command")
	fs.Parse(args)
	if *out == "" || fs.NArg() == 0 {
		return fmt.Errorf("build needs -out and at least one RIB file")
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	started := time.Now()
	agg := NewAggregator()
	links := map[uint64]struct{}{}
	var linksMu sync.Mutex
	files := make([]fileStats, fs.NArg())
	errs := make([]error, fs.NArg())
	decName := resolveDecompressor(*decomp)

	var wg sync.WaitGroup
	sem := make(chan struct{}, runtime.NumCPU())
	for i, path := range fs.Args() {
		wg.Add(1)
		go func(i int, path string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			t0 := time.Now()
			st, l, err := ingestFile(path, decName, agg, &cfg)
			st.Seconds = time.Since(t0).Seconds()
			files[i] = st
			errs[i] = err
			if l != nil {
				agg.merge(l)
				linksMu.Lock()
				for k := range l.links {
					links[k] = struct{}{}
				}
				linksMu.Unlock()
			}
			fmt.Fprintf(os.Stderr, "  %s: %d records, %d entries, %d peers, %.0fs\n", filepath.Base(path), st.Records, st.Entries, st.Peers, st.Seconds)
		}(i, path)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			return fmt.Errorf("%s: %w", fs.Arg(i), err)
		}
	}

	v4, v6, dropped, rst := agg.Resolve(&cfg)
	sortResolved(v4)
	sortResolved(v6)
	sortResolved(dropped)
	r4 := Flatten(v4)
	r6 := Flatten(v6)

	if err := writeFile(filepath.Join(*out, "origin-asn-ipv4-num.csv"), func(w io.Writer) error { return WriteCSV(w, r4) }); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(*out, "origin-asn-ipv6-num.csv"), func(w io.Writer) error { return WriteCSV(w, r6) }); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(*out, "prefixes-ipv4.tsv"), func(w io.Writer) error { return writePrefixes(w, v4) }); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(*out, "prefixes-ipv6.tsv"), func(w io.Writer) error { return writePrefixes(w, v6) }); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(*out, "prefixes-dropped.tsv"), func(w io.Writer) error { return writePrefixes(w, dropped) }); err != nil {
		return err
	}
	if cfg.CollectLinks {
		if err := writeFile(filepath.Join(*out, "links.bin"), func(w io.Writer) error { return writeLinks(w, links) }); err != nil {
			return err
		}
	}

	rep := buildReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339), Config: cfg, Files: files,
		Ingest: agg.Stats, Resolve: rst, V4Ranges: len(r4), V6Ranges: len(r6),
		Links: len(links), Decompress: decName,
	}
	for _, r := range r4 {
		rep.V4Addresses += span(r.Start, r.End)
	}
	for _, r := range r6 {
		rep.V6Slash48s += span(r.Start, r.End) / (1 << 80)
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	rep.PeakHeapMB = ms.HeapSys >> 20
	rep.Seconds = time.Since(started).Seconds()
	return writeFile(filepath.Join(*out, "stats.json"), func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	})
}

func resolveDecompressor(choice string) string {
	switch choice {
	case "go":
		return "go"
	case "auto":
		for _, c := range []string{"lbzip2", "pbzip2", "bzip2"} {
			if p, err := exec.LookPath(c); err == nil {
				return p
			}
		}
		return "go"
	default:
		return choice
	}
}

func openRIB(path, dec string) (io.Reader, func() error, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	switch {
	case strings.HasSuffix(path, ".bz2") && dec != "go":
		f.Close()
		cmd := exec.Command(dec, "-dc", path)
		cmd.Stderr = os.Stderr
		pipe, err := cmd.StdoutPipe()
		if err != nil {
			return nil, nil, err
		}
		if err := cmd.Start(); err != nil {
			return nil, nil, err
		}
		return pipe, cmd.Wait, nil
	case strings.HasSuffix(path, ".bz2"):
		return bzip2.NewReader(bufio.NewReaderSize(f, 1<<20)), f.Close, nil
	case strings.HasSuffix(path, ".gz"):
		zr, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, nil, err
		}
		return zr, f.Close, nil
	default:
		return f, f.Close, nil
	}
}

func ingestFile(path, dec string, agg *Aggregator, cfg *Config) (fileStats, *localStats, error) {
	st := fileStats{File: filepath.Base(path)}
	if fi, err := os.Stat(path); err == nil {
		st.Bytes = fi.Size()
	}
	r, closeFn, err := openRIB(path, dec)
	if err != nil {
		return st, nil, err
	}
	mr := NewReader(r)
	l := newLocalStats()
	var rec RIBRecord
	var peerIDs []int
	peerGen := 0
	for {
		err := mr.Next(&rec)
		if err == io.EOF {
			break
		}
		if err != nil {
			closeFn()
			return st, l, err
		}
		if mr.PeerGen != peerGen {
			peerGen = mr.PeerGen
			peerIDs = agg.PeerIDs(mr.Peers)
		}
		agg.Add(&rec, mr.Peers, peerIDs, l, cfg)
	}
	if err := closeFn(); err != nil {
		return st, l, fmt.Errorf("decompressor: %w", err)
	}
	st.Peers = len(mr.Peers)
	pas := map[uint32]bool{}
	for _, p := range mr.Peers {
		pas[p.AS] = true
	}
	st.PeerASes = len(pas)
	st.Records = l.records
	st.Entries = l.entries
	st.Skipped = mr.SkippedRecords
	st.EmptyPath = mr.EmptyPath
	l.empty = int64(mr.EmptyPath)
	return st, l, nil
}

func sortResolved(rs []Resolved) {
	sort.Slice(rs, func(i, j int) bool {
		a, b := rs[i].Prefix, rs[j].Prefix
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		return a.Bits() < b.Bits()
	})
}

// prefixes TSV: prefix, origin, origin_vis, total_vis, moas, candidates(asn:vis,...)
func writePrefixes(w io.Writer, rs []Resolved) error {
	bw := bufio.NewWriterSize(w, 1<<20)
	fmt.Fprintln(bw, "#prefix\torigin\torigin_peer_ases\tprefix_peer_ases\tmoas\tcandidates\treason")
	for _, r := range rs {
		var sb strings.Builder
		for i, c := range r.Candidates {
			if i > 0 {
				sb.WriteByte(',')
			}
			fmt.Fprintf(&sb, "%d:%d", c.ASN, c.Vis)
		}
		m := 0
		if r.MOAS {
			m = 1
		}
		fmt.Fprintf(bw, "%s\t%d\t%d\t%d\t%d\t%s\t%s\n", r.Prefix, r.Origin, r.OriginVis, r.TotalVis, m, sb.String(), r.Reason)
	}
	return bw.Flush()
}

func writeLinks(w io.Writer, links map[uint64]struct{}) error {
	bw := bufio.NewWriter(w)
	var b [8]byte
	for k := range links {
		binary.BigEndian.PutUint64(b[:], k)
		if _, err := bw.Write(b[:]); err != nil {
			return err
		}
	}
	return bw.Flush()
}

func writeFile(path string, fn func(io.Writer) error) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if err := fn(f); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
