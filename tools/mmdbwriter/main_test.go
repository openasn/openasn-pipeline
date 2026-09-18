package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Go-side unit tests for the pieces the Ruby suite reaches only through the
// CLI: the spool parser's rejections, the §12.4 gates, and a build/verify
// round trip small enough to read. The acceptance cases M01-M07 live in
// test/export_mmdb_test.rb, where the expectations are hand-authored against
// the same contract the Ruby writers use.

func writeSpool(t *testing.T, dir string, lines ...string) string {
	t.Helper()
	path := filepath.Join(dir, "records.jsonl")
	body := ""
	for _, line := range lines {
		body += line + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeMetadata(t *testing.T, dir string, ipv4, ipv6 int) string {
	t.Helper()
	meta := map[string]any{
		"schema_version": 1, "schema_revision": 0,
		"classification_profile": "core-v1", "lookup_policy_version": 1,
		"scope": "tier_a", "build_id": "2026-09-18T18:43:40Z",
		"build_unix_ts": 1789757020,
		"records_ipv4":  ipv4, "records_ipv6": ipv6, "records_total": ipv4 + ipv6,
		"attribution": "Synthetic attribution text.\n",
	}
	path := filepath.Join(dir, "metadata.json")
	encoded, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// row builds one canonical spool line. Every field is spelled out so a test
// that wants a missing key removes it explicitly rather than relying on a
// default that would hide the very bug the parser exists to catch.
func row(version int, start, end string, overrides map[string]any) string {
	fields := map[string]any{
		"ip_version": version, "start_hex": start, "end_hex": end,
		"asn": nil, "as_org": nil, "category": nil, "network_role": nil,
		"bad_asn": false, "vpn_provider": false, "mobile_carrier": false,
		"enterprise_gw": false, "cdn": false, "hosting_extra": false,
		"vpn_range": false, "datacenter_range": false,
		"core_verdict": "unknown", "core_sources": []string{"unrouted"},
	}
	for key, value := range overrides {
		if value == nil {
			delete(fields, key)
			continue
		}
		fields[key] = value
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func parseOne(t *testing.T, line string) (*record, error) {
	t.Helper()
	dir := t.TempDir()
	spool, err := openSpool(writeSpool(t, dir, line))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	return spool.next()
}

func TestSpoolRejectsAnEndpointThatIsNotCanonicalHex(t *testing.T) {
	cases := map[string]string{
		"uppercase":  row(4, "0A000000", "0a0000ff", nil),
		"too short":  row(4, "a000000", "0a0000ff", nil),
		"too long":   row(4, "0a0000000", "0a0000ff", nil),
		"v6 width":   row(6, "20010db8", "20010db8000000000000000000000001", nil),
		"non hex":    row(4, "0a00000g", "0a0000ff", nil),
		"end below":  row(4, "0a0000ff", "0a000000", nil),
		"0x prefix":  row(4, "0x0a0000", "0a0000ff", nil),
		"whitespace": row(4, "0a00000 ", "0a0000ff", nil),
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseOne(t, line); err == nil {
				t.Fatalf("expected a rejection for %s", name)
			}
		})
	}
}

func TestSpoolRejectsAMissingBooleanRatherThanDefaultingItToFalse(t *testing.T) {
	line := row(4, "0a000000", "0a0000ff", map[string]any{"cdn": nil})
	_, err := parseOne(t, line)
	if err == nil || !strings.Contains(err.Error(), "cdn") {
		t.Fatalf("expected a complaint about the missing cdn boolean, got %v", err)
	}
}

func TestSpoolRejectsAnUnknownField(t *testing.T) {
	line := row(4, "0a000000", "0a0000ff", map[string]any{"tier_b_relay": true})
	_, err := parseOne(t, line)
	if err == nil || !strings.Contains(err.Error(), "tier_b_relay") {
		t.Fatalf("expected a complaint about the unknown field, got %v", err)
	}
}

func TestSpoolRejectsEvidenceOnARecordWithNoASN(t *testing.T) {
	line := row(4, "0a000000", "0a0000ff", map[string]any{"category": "hosting"})
	if _, err := parseOne(t, line); err == nil {
		t.Fatal("expected a null-asn record carrying a category to be rejected")
	}
	line = row(4, "0a000000", "0a0000ff", map[string]any{"bad_asn": true})
	if _, err := parseOne(t, line); err == nil {
		t.Fatal("expected a null-asn record carrying an ASN-level signal to be rejected")
	}
}

func TestSpoolRejectsATokenOutsideTheProfileVocabulary(t *testing.T) {
	line := row(4, "0a000000", "0a0000ff", map[string]any{"core_verdict": "tor_exit"})
	if _, err := parseOne(t, line); err == nil {
		t.Fatal("expected a verdict outside core-v1 to be rejected")
	}
	line = row(4, "0a000000", "0a0000ff", map[string]any{"core_sources": []string{"relay"}})
	if _, err := parseOne(t, line); err == nil {
		t.Fatal("expected a source outside core-v1 to be rejected")
	}
}

func TestSpoolRejectsOutOfOrderOrOverlappingRecords(t *testing.T) {
	dir := t.TempDir()
	path := writeSpool(t, dir,
		row(4, "0a000000", "0a0000ff", nil),
		row(4, "0a000080", "0a0001ff", nil),
	)
	spool, err := openSpool(path)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	if _, err := spool.next(); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.next(); err == nil {
		t.Fatal("expected the overlapping second record to be rejected")
	}
}

func TestGateRejectsNativeIPv6InTheCollisionPrefixes(t *testing.T) {
	cases := map[string]string{
		"low prefix":    row(6, "00000000000000000000000000000001", "000000000000000000000000000000ff", nil),
		"mapped prefix": row(6, "00000000000000000000ffff08080800", "00000000000000000000ffff080808ff", nil),
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			records := writeSpool(t, dir, line)
			metadata := writeMetadata(t, dir, 0, 1)
			err := buildCommand(records, metadata, filepath.Join(dir, "out.mmdb"))
			if err == nil {
				t.Fatal("expected the build to fail")
			}
			if !strings.Contains(err.Error(), "address representation") {
				t.Fatalf("expected an address-representation failure, got %v", err)
			}
			if _, statErr := os.Stat(filepath.Join(dir, "out.mmdb")); !os.IsNotExist(statErr) {
				t.Fatal("a rejected build must not leave an output file behind")
			}
		})
	}
}

func TestBuildRefusesToWriteOverItsOwnInput(t *testing.T) {
	dir := t.TempDir()
	records := writeSpool(t, dir, row(4, "0a000000", "0a0000ff", nil))
	metadata := writeMetadata(t, dir, 1, 0)
	if err := buildCommand(records, metadata, records); err == nil {
		t.Fatal("expected the build to refuse to overwrite the spool")
	}
}

func TestBuildAndVerifyRoundTripTheWholeRecord(t *testing.T) {
	dir := t.TempDir()
	maxASN := uint32(4294967295)
	records := writeSpool(t, dir,
		row(4, "01000005", "0100000a", map[string]any{
			"asn": maxASN, "as_org": "Edge Org", "category": "isp",
			"network_role": "access_provider", "core_verdict": "residential_isp",
			"core_sources": []string{"asn_category"},
		}),
		row(4, "0100000b", "0100000f", map[string]any{
			"datacenter_range": true, "core_verdict": "hosting",
			"core_sources": []string{"x4b_dc"},
		}),
		row(6, "2a001450000000000000000000000000", "2a001450ffffffffffffffffffffffff", map[string]any{
			"asn": 15169, "as_org": "Google LLC", "category": "hosting",
			"network_role": "midsize_transit", "bad_asn": true,
			"core_verdict": "hosting", "core_sources": []string{"asn_bad_asn", "asn_category"},
		}),
	)
	metadata := writeMetadata(t, dir, 2, 1)
	output := filepath.Join(dir, "out.mmdb")

	if err := buildCommand(records, metadata, output); err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := verifyCommand(output, records, metadata); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestBuildIsDeterministicForTheSameInputs(t *testing.T) {
	dir := t.TempDir()
	records := writeSpool(t, dir,
		row(4, "01000005", "0100000a", map[string]any{
			"asn": 100, "as_org": "Access A", "category": "isp",
			"network_role": "access_provider", "core_verdict": "residential_isp",
			"core_sources": []string{"asn_category"},
		}),
		row(6, "2a001450000000000000000000000000", "2a001450ffffffffffffffffffffffff", map[string]any{
			"asn": 15169, "core_verdict": "unknown", "core_sources": []string{"asn_no_category"},
		}),
	)
	metadata := writeMetadata(t, dir, 1, 1)

	sums := []string{}
	for i := 0; i < 2; i++ {
		output := filepath.Join(dir, fmt.Sprintf("out-%d.mmdb", i))
		if err := buildCommand(records, metadata, output); err != nil {
			t.Fatalf("build %d: %v", i, err)
		}
		raw, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		sums = append(sums, fmt.Sprintf("%x", len(raw))+":"+hashOf(raw))
	}
	if sums[0] != sums[1] {
		t.Fatalf("two builds of the same inputs differ: %s vs %s", sums[0], sums[1])
	}
}

func TestMetadataMustMatchTheSpoolCounts(t *testing.T) {
	dir := t.TempDir()
	records := writeSpool(t, dir, row(4, "0a000000", "0a0000ff", nil))
	metadata := writeMetadata(t, dir, 2, 0)
	err := buildCommand(records, metadata, filepath.Join(dir, "out.mmdb"))
	if err == nil || !strings.Contains(err.Error(), "the spool holds") {
		t.Fatalf("expected a count mismatch failure, got %v", err)
	}
}

func TestMetadataRejectsAnUnsupportedProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metadata.json")
	raw, err := os.ReadFile(writeMetadata(t, dir, 1, 0))
	if err != nil {
		t.Fatal(err)
	}
	var meta map[string]any
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	meta["classification_profile"] = "core-v2"
	encoded, _ := json.Marshal(meta)
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMetadata(path); err == nil {
		t.Fatal("expected core-v2 metadata to be rejected by a core-v1 writer")
	}
}

func TestMetadataAcceptsIntegersAsNumbersOrDecimalStrings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metadata.json")
	body := `{"schema_version":"1","schema_revision":0,"classification_profile":"core-v1",` +
		`"lookup_policy_version":"1","scope":"tier_a","build_id":"2026-09-18T18:43:40Z",` +
		`"build_unix_ts":"1789757020","records_ipv4":"2","records_ipv6":1,"records_total":"3",` +
		`"attribution":"text"}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	meta, err := loadMetadata(path)
	if err != nil {
		t.Fatal(err)
	}
	if meta.BuildUnixTS.value != 1789757020 || meta.RecordsTotal.value != 3 {
		t.Fatalf("unexpected metadata: %+v", meta)
	}
}

func TestMetadataRejectsANonIntegerCount(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metadata.json")
	body := `{"schema_version":1,"schema_revision":0,"classification_profile":"core-v1",` +
		`"lookup_policy_version":1,"scope":"tier_a","build_id":"b","build_unix_ts":1789757020,` +
		`"records_ipv4":446741.0,"records_ipv6":1,"records_total":446742,"attribution":"text"}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMetadata(path); err == nil {
		t.Fatal("expected a float record count to be rejected")
	}
}

func TestDescriptionIsTheDeterministicContractText(t *testing.T) {
	dir := t.TempDir()
	meta, err := loadMetadata(writeMetadata(t, dir, 446741, 125616))
	if err != nil {
		t.Fatal(err)
	}
	want := "OpenASN core; schema_version=1; schema_revision=0; classification_profile=core-v1; " +
		"lookup_policy_version=1; scope=tier_a; build_id=2026-09-18T18:43:40Z; " +
		"records_ipv4=446741; records_ipv6=125616\nSynthetic attribution text.\n"
	if got := meta.description(); got != want {
		t.Fatalf("description:\n%q\nwanted:\n%q", got, want)
	}
}

func hashOf(raw []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}
