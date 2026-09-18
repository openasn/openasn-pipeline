package main

import (
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/netip"
	"os"
	"time"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

// Independent validation (PRD §12.5).
//
// "Independent" is the load-bearing word: every check below goes through
// oschwald/maxminddb-golang, a different codebase from maxmind/mmdbwriter,
// so a shared misunderstanding of the format cannot validate itself. The
// reader's own structural Verify() runs first, then the standard metadata,
// then the data: every interval's start and end, a selected interior, the
// addresses either side of every gap, and finally a full walk of the tree to
// reconstruct coverage.
//
// The walk is what catches the failure modes a lookup cannot see. A lookup at
// an address inside an interval still succeeds if the writer widened that
// interval to an enclosing CIDR or aliased it into another part of the tree;
// only enumerating what the tree actually claims shows the extra space. So
// the prefixes are required to tile each record exactly: first prefix starts
// where the record starts, each next one starts where the last ended, the
// last ends where the record ends, and nothing is left over on either side.

// mismatchReportLimit bounds the stderr noise. A systematic bug produces
// hundreds of thousands of differences and the first few already show the
// pattern; the count is always reported in full.
const mismatchReportLimit = 20

type verifyStats struct {
	endpointComparisons int64
	interiorProbes      int64
	gapProbes           int64
	prefixComparisons   int64
	networks            int64
	mismatches          int64

	coveredIPv4 *big.Int
	coveredIPv6 *big.Int
}

func (s *verifyStats) fail(format string, args ...any) {
	s.mismatches++
	if s.mismatches <= mismatchReportLimit {
		fmt.Fprintf(os.Stderr, "%s: verify: mismatch: %s\n", programName, fmt.Sprintf(format, args...))
	}
	if s.mismatches == mismatchReportLimit+1 {
		fmt.Fprintf(os.Stderr, "%s: verify: further mismatches suppressed; the total is reported at the end\n",
			programName)
	}
}

func verifyCommand(databasePath, recordsPath, metadataPath string) error {
	started := time.Now()

	meta, err := loadMetadata(metadataPath)
	if err != nil {
		return fmt.Errorf("verify: metadata: %w", err)
	}

	reader, err := maxminddb.Open(databasePath)
	if err != nil {
		return fmt.Errorf("verify: opening the database: %w", err)
	}
	defer reader.Close()

	if err := reader.Verify(); err != nil {
		return fmt.Errorf("verify: the reader's structural verification failed: %w", err)
	}
	if err := checkStandardMetadata(&reader.Metadata, meta); err != nil {
		return fmt.Errorf("verify: metadata: %w", err)
	}

	stats := &verifyStats{coveredIPv4: new(big.Int), coveredIPv6: new(big.Int)}

	spoolRecords, err := probeRecords(reader, recordsPath, stats)
	if err != nil {
		return fmt.Errorf("verify: probing records: %w", err)
	}
	if spoolRecords != meta.RecordsTotal.value {
		return fmt.Errorf("verify: the spool holds %d records but the metadata says %d",
			spoolRecords, meta.RecordsTotal.value)
	}

	if err := reconstructCoverage(reader, recordsPath, stats); err != nil {
		return fmt.Errorf("verify: reconstructing coverage: %w", err)
	}

	summary := map[string]any{
		"mode":                 "verify",
		"database":             databasePath,
		"records_total":        spoolRecords,
		"endpoint_comparisons": stats.endpointComparisons,
		"interior_probes":      stats.interiorProbes,
		"gap_probes":           stats.gapProbes,
		"prefix_comparisons":   stats.prefixComparisons,
		"networks":             stats.networks,
		"covered_ipv4":         stats.coveredIPv4.String(),
		"covered_ipv6":         stats.coveredIPv6.String(),
		"mismatches":           stats.mismatches,
		"node_count":           reader.Metadata.NodeCount,
		"record_size":          reader.Metadata.RecordSize,
		"ip_version":           reader.Metadata.IPVersion,
		"database_type":        reader.Metadata.DatabaseType,
		"build_epoch":          reader.Metadata.BuildEpoch,
		"description_bytes":    len(reader.Metadata.Description["en"]),
		"seconds":              round3(time.Since(started).Seconds()),
	}
	if err := printJSON(summary); err != nil {
		return err
	}
	if stats.mismatches > 0 {
		return fmt.Errorf("verify: %d mismatch(es) between the database and the spool", stats.mismatches)
	}
	return nil
}

// probeRecords walks the spool and queries the database at the addresses that
// matter: both ends of every interval, one interior, and both sides of every
// gap.
func probeRecords(reader *maxminddb.Reader, path string, stats *verifyStats) (int64, error) {
	spool, err := openSpool(path)
	if err != nil {
		return 0, err
	}
	defer spool.Close()

	var count int64
	var previous *record
	for {
		rec, err := spool.next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, err
		}
		count++

		stats.endpointComparisons++
		probeHit(reader, rec.start, rec, stats)
		if rec.end != rec.start {
			stats.endpointComparisons++
			probeHit(reader, rec.end, rec, stats)
		}

		if interior, ok := interiorAddress(rec); ok {
			stats.interiorProbes++
			probeHit(reader, interior, rec, stats)
		}

		// A gap probe only means something between neighbours in the same
		// family, so the family change resets the chain rather than
		// inventing a gap between the last IPv4 and the first IPv6 record.
		if previous != nil && previous.version == rec.version {
			probeGap(reader, previous.end, rec.start, stats)
		} else {
			probeBelow(reader, rec.start, stats)
		}
		previous = rec
	}

	if previous != nil {
		probeAbove(reader, previous.end, stats)
	}
	return count, nil
}

// interiorAddress is the midpoint of an interval with at least three
// addresses. One interior per record is enough alongside the full tree walk,
// which compares the payload of every prefix.
func interiorAddress(rec *record) (netip.Addr, bool) {
	size := addressCount(rec.start, rec.end)
	if size.Cmp(big.NewInt(3)) < 0 {
		return netip.Addr{}, false
	}
	middle := new(big.Int).Add(addrToBig(rec.start), addrToBig(rec.end))
	middle.Rsh(middle, 1)
	addr, err := bigToAddr(middle, rec.version)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}

func probeHit(reader *maxminddb.Reader, addr netip.Addr, rec *record, stats *verifyStats) {
	result := reader.Lookup(addr)
	if err := result.Err(); err != nil {
		stats.fail("%s: lookup failed: %v", addr, err)
		return
	}
	if !result.Found() {
		stats.fail("%s: no record, but the spool covers it in %s-%s", addr, rec.start, rec.end)
		return
	}
	var decoded leaf
	if err := result.Decode(&decoded); err != nil {
		stats.fail("%s: decode failed: %v", addr, err)
		return
	}
	for _, diff := range rec.payload.diff(&decoded.value) {
		stats.fail("%s (in %s-%s): %s", addr, rec.start, rec.end, diff)
	}
}

func probeMiss(reader *maxminddb.Reader, addr netip.Addr, stats *verifyStats) {
	stats.gapProbes++
	result := reader.Lookup(addr)
	if err := result.Err(); err != nil {
		stats.fail("%s: lookup failed in a gap: %v", addr, err)
		return
	}
	if result.Found() {
		stats.fail("%s: the database has a record here, but the spool leaves it uncovered", addr)
	}
}

// probeGap checks the addresses either side of the hole between two
// neighbouring records. Adjacent records have no hole and no probe.
func probeGap(reader *maxminddb.Reader, previousEnd, nextStart netip.Addr, stats *verifyStats) {
	first := previousEnd.Next()
	if !first.IsValid() || !first.Less(nextStart) {
		return
	}
	probeMiss(reader, first, stats)
	last := nextStart.Prev()
	if last.IsValid() && first != last {
		probeMiss(reader, last, stats)
	}
}

// probeBelow / probeAbove check the address just outside the first and last
// record of a family. IPv4's own 0.0.0.0 and 255.255.255.255 have no
// neighbour, so there is nothing to probe there.
func probeBelow(reader *maxminddb.Reader, start netip.Addr, stats *verifyStats) {
	below := start.Prev()
	if !below.IsValid() {
		return
	}
	probeMiss(reader, below, stats)
}

func probeAbove(reader *maxminddb.Reader, end netip.Addr, stats *verifyStats) {
	above := end.Next()
	if !above.IsValid() {
		return
	}
	probeMiss(reader, above, stats)
}

// reconstructCoverage walks every network the tree claims and requires the
// prefixes to tile the spool's intervals exactly, in order.
//
// The walk excludes the IPv4 alias subtrees by default, which is what we
// want: with DisableIPv4Aliasing there are none, and the reader reports the
// representational IPv4 subtree at ::/96 as ordinary IPv4 prefixes. That is
// the documented representation, so IPv4 prefixes are matched against the
// IPv4 records and native IPv6 is reasoned about without them.
func reconstructCoverage(reader *maxminddb.Reader, path string, stats *verifyStats) error {
	spool, err := openSpool(path)
	if err != nil {
		return err
	}
	defer spool.Close()

	var current *record
	var cursor *big.Int
	advance := func() error {
		rec, err := spool.next()
		if errors.Is(err, io.EOF) {
			current = nil
			return nil
		}
		if err != nil {
			return err
		}
		current = rec
		cursor = addrToBig(rec.start)
		return nil
	}
	if err := advance(); err != nil {
		return err
	}

	for result := range reader.Networks() {
		if err := result.Err(); err != nil {
			return fmt.Errorf("walking the tree: %w", err)
		}
		stats.networks++

		prefix := result.Prefix()
		version := 6
		if prefix.Addr().Is4() {
			version = 4
		}
		start, end, err := prefixBounds(prefix, version)
		if err != nil {
			return err
		}

		if current == nil {
			stats.fail("the tree claims %s but the spool has no records left to cover it", prefix)
			return nil
		}
		if current.version != version {
			stats.fail("the tree claims IPv%d network %s where the spool expects an IPv%d record (%s-%s)",
				version, prefix, current.version, current.start, current.end)
			return nil
		}
		if start.Cmp(cursor) != 0 {
			expected, _ := bigToAddr(cursor, version)
			stats.fail("the tree claims %s, but the next uncovered address of %s-%s is %s: "+
				"the network either covers space the spool does not, or leaves a hole inside a record",
				prefix, current.start, current.end, expected)
			return nil
		}
		if end.Cmp(addrToBig(current.end)) > 0 {
			stats.fail("the tree claims %s, which reaches past the end of record %s-%s: a widened network",
				prefix, current.start, current.end)
			return nil
		}

		stats.prefixComparisons++
		var decoded leaf
		if err := result.Decode(&decoded); err != nil {
			stats.fail("%s: decode failed: %v", prefix, err)
		} else {
			for _, diff := range current.payload.diff(&decoded.value) {
				stats.fail("%s (in %s-%s): %s", prefix, current.start, current.end, diff)
			}
		}

		size := new(big.Int).Sub(end, start)
		size.Add(size, big.NewInt(1))
		if version == 4 {
			stats.coveredIPv4.Add(stats.coveredIPv4, size)
		} else {
			stats.coveredIPv6.Add(stats.coveredIPv6, size)
		}

		cursor = new(big.Int).Add(end, big.NewInt(1))
		if cursor.Cmp(addrToBig(current.end)) > 0 {
			if err := advance(); err != nil {
				return err
			}
		}
	}

	if current != nil {
		stats.fail("the spool record %s-%s is not covered by the tree from %s onwards",
			current.start, current.end, current.start)
	}
	return nil
}

func prefixBounds(prefix netip.Prefix, version int) (start, end *big.Int, err error) {
	bits := 32
	if version == 6 {
		bits = 128
	}
	if prefix.Bits() < 0 || prefix.Bits() > bits {
		return nil, nil, fmt.Errorf("network %s has %d bits, impossible for IPv%d", prefix, prefix.Bits(), version)
	}
	masked := prefix.Masked()
	if masked.Addr() != prefix.Addr() {
		return nil, nil, fmt.Errorf("network %s is not in canonical masked form", prefix)
	}
	start = addrToBig(prefix.Addr())
	size := new(big.Int).Lsh(big.NewInt(1), uint(bits-prefix.Bits()))
	end = new(big.Int).Add(start, size)
	end.Sub(end, big.NewInt(1))
	return start, end, nil
}
