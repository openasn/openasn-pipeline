package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

// The MMDB writer (PRD §12.1).
//
// The options below are contract, not tuning. DatabaseType is what a reader
// validates before trusting a single field; IPVersion 6 with
// DisableIPv4Aliasing keeps IPv4 in one place instead of four; BuildEpoch
// comes from the OASN build, never from the clock, or the same inputs would
// produce different bytes every night; IncludeReservedNetworks is true so the
// writer's own idea of reserved space cannot quietly drop input rows.
const (
	databaseType = "OpenASN-Core-v1"
	ipVersion    = 6
	recordSize   = 28
)

// The two prefixes of PRD §12.4. Built from bytes rather than parsed from
// text because netip parses "::ffff:0:0" into an IPv4-in-IPv6 address, and
// the whole point here is to reason about native IPv6 without letting any
// layer helpfully turn it into IPv4.
var (
	lowPrefixStart    = netip.AddrFrom16([16]byte{})
	lowPrefixEnd      = netip.AddrFrom16([16]byte{12: 0xff, 13: 0xff, 14: 0xff, 15: 0xff})
	mappedPrefixStart = netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff})
	mappedPrefixEnd   = netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 12: 0xff, 13: 0xff, 14: 0xff, 15: 0xff})
)

type scanResult struct {
	ipv4Records   int64
	ipv6Records   int64
	lowOverlaps   int64
	mappedOverlap int64
	coveredIPv4   *big.Int
	coveredIPv6   *big.Int
}

func buildCommand(recordsPath, metadataPath, outputPath string) error {
	started := time.Now()

	if err := refuseToClobberInput(outputPath, recordsPath, metadataPath); err != nil {
		return err
	}

	meta, err := loadMetadata(metadataPath)
	if err != nil {
		return fmt.Errorf("build: metadata: %w", err)
	}
	if err := meta.checkDescriptionFits(); err != nil {
		return fmt.Errorf("build: metadata: %w", err)
	}

	// Gate first, insert second. PRD §12.4 says "before MMDB generation", and
	// counting the whole spool rather than stopping at the first hit is what
	// makes the failure actionable: a representation change has to be argued
	// from how much data it touches.
	scan, err := scanSpool(recordsPath)
	if err != nil {
		return fmt.Errorf("build: scanning spool: %w", err)
	}
	fmt.Fprintf(os.Stderr,
		"%s: gate: native IPv6 rows overlapping ::/96 = %d, overlapping ::ffff:0:0/96 = %d\n",
		programName, scan.lowOverlaps, scan.mappedOverlap)

	if scan.lowOverlaps > 0 || scan.mappedOverlap > 0 {
		return fmt.Errorf(
			"build: address representation: %d native IPv6 record(s) overlap ::/96 and %d overlap "+
				"::ffff:0:0/96. A combined MMDB stores IPv4 in ::/96 and normalizes the mapped "+
				"prefix, so either would collide with IPv4 data or with another IPv6 record. "+
				"This needs a reviewed representation change, not a dropped record",
			scan.lowOverlaps, scan.mappedOverlap)
	}

	if scan.ipv4Records != meta.RecordsIPv4.value || scan.ipv6Records != meta.RecordsIPv6.value {
		return fmt.Errorf(
			"build: the spool holds %d IPv4 and %d IPv6 records but the metadata says %d and %d; "+
				"the description would state counts that are not in the file",
			scan.ipv4Records, scan.ipv6Records, meta.RecordsIPv4.value, meta.RecordsIPv6.value)
	}

	tree, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            databaseType,
		IPVersion:               ipVersion,
		RecordSize:              recordSize,
		BuildEpoch:              meta.BuildUnixTS.value,
		IncludeReservedNetworks: true,
		DisableIPv4Aliasing:     true,
		Description:             map[string]string{"en": meta.description()},
	})
	if err != nil {
		return fmt.Errorf("build: creating tree: %w", err)
	}

	if err := insertSpool(tree, recordsPath); err != nil {
		return fmt.Errorf("build: %w", err)
	}

	candidate := outputPath + ".candidate"
	written, sum, err := writeCandidate(tree, candidate)
	if err != nil {
		// The partial candidate is left where it is. Removing it would erase
		// the only evidence of what went wrong, and it can never be mistaken
		// for the export: the export only ever appears under its final name.
		return fmt.Errorf("build: writing %s: %w", candidate, err)
	}

	summary, err := inspectDatabase(candidate, meta)
	if err != nil {
		return fmt.Errorf("build: the candidate does not read back: %w", err)
	}

	if err := os.Rename(candidate, outputPath); err != nil {
		return fmt.Errorf("build: promoting the candidate: %w", err)
	}

	return printJSON(map[string]any{
		"mode":                  "build",
		"output":                outputPath,
		"bytes":                 written,
		"sha256":                sum,
		"records_ipv4":          scan.ipv4Records,
		"records_ipv6":          scan.ipv6Records,
		"records_total":         scan.ipv4Records + scan.ipv6Records,
		"covered_ipv4":          scan.coveredIPv4.String(),
		"covered_ipv6":          scan.coveredIPv6.String(),
		"overlap_low_prefix":    scan.lowOverlaps,
		"overlap_mapped_prefix": scan.mappedOverlap,
		"database_type":         summary.DatabaseType,
		"build_epoch":           summary.BuildEpoch,
		"ip_version":            summary.IPVersion,
		"record_size":           summary.RecordSize,
		"node_count":            summary.NodeCount,
		"seconds":               round3(time.Since(started).Seconds()),
	})
}

// refuseToClobberInput keeps a mistyped --output from eating the spool. PRD
// §14: refuse to overwrite a source artifact, and never delete an input to
// repair a failed export.
func refuseToClobberInput(output string, inputs ...string) error {
	absOutput, err := filepath.Abs(output)
	if err != nil {
		return fmt.Errorf("build: resolving --output: %w", err)
	}
	for _, input := range inputs {
		absInput, err := filepath.Abs(input)
		if err != nil {
			return fmt.Errorf("build: resolving input path: %w", err)
		}
		if absInput == absOutput {
			return fmt.Errorf("build: --output %s is one of this build's inputs", output)
		}
	}
	return nil
}

func scanSpool(path string) (*scanResult, error) {
	spool, err := openSpool(path)
	if err != nil {
		return nil, err
	}
	defer spool.Close()

	result := &scanResult{coveredIPv4: new(big.Int), coveredIPv6: new(big.Int)}
	for {
		rec, err := spool.next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}

		if rec.version == 4 {
			result.ipv4Records++
			result.coveredIPv4.Add(result.coveredIPv4, addressCount(rec.start, rec.end))
			continue
		}

		result.ipv6Records++
		result.coveredIPv6.Add(result.coveredIPv6, addressCount(rec.start, rec.end))
		if overlaps(rec.start, rec.end, lowPrefixStart, lowPrefixEnd) {
			result.lowOverlaps++
		}
		if overlaps(rec.start, rec.end, mappedPrefixStart, mappedPrefixEnd) {
			result.mappedOverlap++
		}
	}
	return result, nil
}

func overlaps(startA, endA, startB, endB netip.Addr) bool {
	return !endA.Less(startB) && !endB.Less(startA)
}

func insertSpool(tree *mmdbwriter.Tree, path string) error {
	spool, err := openSpool(path)
	if err != nil {
		return err
	}
	defer spool.Close()

	// One mmdbtype.Map per distinct payload. mmdbwriter deduplicates the data
	// section itself by hashing what it is handed; this cache is about the
	// build's resident set, not about the file size.
	cache := map[string]mmdbtype.Map{}
	for {
		rec, err := spool.next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

		if rec.version == 6 &&
			(overlaps(rec.start, rec.end, lowPrefixStart, lowPrefixEnd) ||
				overlaps(rec.start, rec.end, mappedPrefixStart, mappedPrefixEnd)) {
			// Unreachable after the gate; kept because the cost of being
			// wrong here is a record silently landing on top of IPv4 data.
			return fmt.Errorf("record %s-%s reached insertion inside a gated prefix", rec.start, rec.end)
		}

		key := rec.payload.cacheKey()
		value, ok := cache[key]
		if !ok {
			value = rec.payload.mmdbValue()
			cache[key] = value
		}

		// InsertRange decomposes [start, end] into the exact minimal set of
		// prefixes covering it and nothing else. The interval is never
		// widened to an enclosing CIDR to make it fit.
		if err := tree.InsertRange(net.IP(rec.start.AsSlice()), net.IP(rec.end.AsSlice()), value); err != nil {
			return fmt.Errorf("inserting %s-%s: %w", rec.start, rec.end, err)
		}
	}
}

func writeCandidate(tree *mmdbwriter.Tree, path string) (int64, string, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, "", err
	}
	defer file.Close()

	digest := sha256.New()
	written, err := tree.WriteTo(io.MultiWriter(file, digest))
	if err != nil {
		return written, "", err
	}
	if err := file.Sync(); err != nil {
		return written, "", fmt.Errorf("syncing: %w", err)
	}
	if err := file.Close(); err != nil {
		return written, "", fmt.Errorf("closing: %w", err)
	}
	return written, hex.EncodeToString(digest.Sum(nil)), nil
}

// inspectDatabase reads the finished bytes back with the independent reader
// before the candidate is promoted. It is a cheap structural check - full
// payload verification is `verify` mode - plus the one thing that can only be
// checked on the finished file: MMDB readers hunt for the metadata start
// marker in the last 128 KiB, so a metadata section that overruns that
// produces an unreadable database rather than a large one.
func inspectDatabase(path string, meta *exportMetadata) (*maxminddb.Metadata, error) {
	reader, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	if err := checkStandardMetadata(&reader.Metadata, meta); err != nil {
		return nil, err
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	marker, err := metadataMarkerOffset(path)
	if err != nil {
		return nil, err
	}
	if tail := info.Size() - marker; tail > metadataSectionLimit {
		return nil, fmt.Errorf("the metadata section is %d bytes from the end of the file, over the "+
			"%d-byte window a reader searches", tail, metadataSectionLimit)
	}

	metadata := reader.Metadata
	return &metadata, nil
}

func checkStandardMetadata(got *maxminddb.Metadata, want *exportMetadata) error {
	if got.DatabaseType != databaseType {
		return fmt.Errorf("database_type is %q, wanted %q", got.DatabaseType, databaseType)
	}
	if got.IPVersion != ipVersion {
		return fmt.Errorf("ip_version is %d, wanted %d", got.IPVersion, ipVersion)
	}
	if got.RecordSize != recordSize {
		return fmt.Errorf("record_size is %d, wanted %d", got.RecordSize, recordSize)
	}
	if int64(got.BuildEpoch) != want.BuildUnixTS.value {
		return fmt.Errorf("build_epoch is %d, wanted the OASN build epoch %d",
			got.BuildEpoch, want.BuildUnixTS.value)
	}
	if got.BinaryFormatMajorVersion != 2 || got.BinaryFormatMinorVersion != 0 {
		return fmt.Errorf("binary format is %d.%d, wanted 2.0",
			got.BinaryFormatMajorVersion, got.BinaryFormatMinorVersion)
	}
	if description := got.Description["en"]; description != want.description() {
		return fmt.Errorf("description.en is not the deterministic text of the contract")
	}
	if len(got.Description) != 1 {
		return fmt.Errorf("description carries %d languages, wanted only en", len(got.Description))
	}
	return nil
}

var metadataStartMarker = []byte("\xAB\xCD\xEFMaxMind.com")

func metadataMarkerOffset(path string) (int64, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	for i := len(raw) - len(metadataStartMarker); i >= 0; i-- {
		if string(raw[i:i+len(metadataStartMarker)]) == string(metadataStartMarker) {
			return int64(i), nil
		}
	}
	return 0, errors.New("no metadata start marker in the file")
}

func printJSON(summary map[string]any) error {
	encoded, err := json.Marshal(summary)
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
}

func round3(value float64) float64 {
	return float64(int64(value*1000+0.5)) / 1000
}
