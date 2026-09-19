package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// The subset of the export metadata (PRD §10.2) that MMDB needs: the identity
// triple that has to match the frozen contract, the build identity that goes
// into BuildEpoch and the description, the row counts the description states,
// and the attribution text the description ends with.
//
// Everything else in metadata.json is read by other writers and ignored here,
// so unknown keys are fine. The keys below are not: a missing one is a build
// failure, because an MMDB whose description claims counts nobody checked is
// worse than no MMDB.
//
// PRD §10.2 defines the SQLite `meta` encoding, where every value is TEXT.
// Whether metadata.json carries these scalars as JSON numbers or as those same
// decimal strings is the metadata writer's choice, so `number` below accepts
// either and rejects anything that is not an exact non-negative integer.
type exportMetadata struct {
	SchemaVersion         number `json:"schema_version"`
	SchemaRevision        number `json:"schema_revision"`
	ClassificationProfile string `json:"classification_profile"`
	LookupPolicyVersion   number `json:"lookup_policy_version"`
	Scope                 string `json:"scope"`
	BuildID               string `json:"build_id"`
	BuildUnixTS           number `json:"build_unix_ts"`
	RecordsIPv4           number `json:"records_ipv4"`
	RecordsIPv6           number `json:"records_ipv6"`
	RecordsTotal          number `json:"records_total"`
	Attribution           string `json:"attribution"`
}

// number is a non-negative integer that may arrive as a JSON number or as a
// decimal string. It refuses floats outright: a metadata count that arrives as
// 4.46741e+05 has already lost the exactness the manifest exists to provide.
type number struct {
	value int64
	set   bool
}

func (n *number) UnmarshalJSON(data []byte) error {
	text := string(data)
	if strings.HasPrefix(text, `"`) {
		var unquoted string
		if err := json.Unmarshal(data, &unquoted); err != nil {
			return err
		}
		text = unquoted
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return fmt.Errorf("%s is not a base-10 integer", text)
	}
	if value < 0 {
		return fmt.Errorf("%d is negative", value)
	}
	n.value = value
	n.set = true
	return nil
}

func loadMetadata(path string) (*exportMetadata, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading metadata: %w", err)
	}
	var meta exportMetadata
	if err := json.Unmarshal(raw, &meta); err != nil {
		return nil, fmt.Errorf("parsing metadata: %w", err)
	}

	for name, field := range map[string]number{
		"schema_version": meta.SchemaVersion, "schema_revision": meta.SchemaRevision,
		"lookup_policy_version": meta.LookupPolicyVersion, "build_unix_ts": meta.BuildUnixTS,
		"records_ipv4": meta.RecordsIPv4, "records_ipv6": meta.RecordsIPv6,
		"records_total": meta.RecordsTotal,
	} {
		if !field.set {
			return nil, fmt.Errorf("metadata is missing %s", name)
		}
	}
	for name, field := range map[string]string{
		"classification_profile": meta.ClassificationProfile, "scope": meta.Scope,
		"build_id": meta.BuildID, "attribution": meta.Attribution,
	} {
		if field == "" {
			return nil, fmt.Errorf("metadata is missing %s", name)
		}
	}

	// Schema 1 revision 0 / core-v1 / policy 1 / tier_a is the only thing this
	// writer knows how to serialize. A successor profile ships as its own
	// asset name (D-FMT-1); it does not arrive through this code path.
	if meta.SchemaVersion.value != 1 || meta.SchemaRevision.value != 0 {
		return nil, fmt.Errorf("metadata declares schema %d revision %d, this writer produces 1/0",
			meta.SchemaVersion.value, meta.SchemaRevision.value)
	}
	if meta.ClassificationProfile != "core-v1" {
		return nil, fmt.Errorf("metadata declares classification_profile %q, this writer produces core-v1",
			meta.ClassificationProfile)
	}
	if meta.LookupPolicyVersion.value != 1 {
		return nil, fmt.Errorf("metadata declares lookup_policy_version %d, this writer produces 1",
			meta.LookupPolicyVersion.value)
	}
	if meta.Scope != "tier_a" {
		return nil, fmt.Errorf("metadata declares scope %q, this writer produces tier_a", meta.Scope)
	}
	if meta.BuildUnixTS.value <= 0 {
		return nil, fmt.Errorf("metadata build_unix_ts %d is not a plausible build epoch", meta.BuildUnixTS.value)
	}
	if meta.RecordsIPv4.value+meta.RecordsIPv6.value != meta.RecordsTotal.value {
		return nil, fmt.Errorf("metadata records_total %d != records_ipv4 %d + records_ipv6 %d",
			meta.RecordsTotal.value, meta.RecordsIPv4.value, meta.RecordsIPv6.value)
	}

	return &meta, nil
}

// description is the deterministic text of PRD §12.3 / EXPORT_FORMATS.md §6.3.
// The `\n` in the spec is one real newline, and the attribution follows it
// verbatim. It is for humans: helpers validate database_type and build_epoch
// against their installed manifest, never by parsing this prose.
func (m *exportMetadata) description() string {
	return fmt.Sprintf(
		"OpenASN core; schema_version=%d; schema_revision=%d; classification_profile=%s; "+
			"lookup_policy_version=%d; scope=%s; build_id=%s; records_ipv4=%d; records_ipv6=%d\n%s",
		m.SchemaVersion.value, m.SchemaRevision.value, m.ClassificationProfile,
		m.LookupPolicyVersion.value, m.Scope, m.BuildID,
		m.RecordsIPv4.value, m.RecordsIPv6.value, m.Attribution,
	)
}

// MMDB readers look for the metadata start marker in the last 128 KiB of the
// file, so an oversized description does not produce a large database, it
// produces an unreadable one. Checked before the tree is built as well as
// against the finished bytes.
const metadataSectionLimit = 128 * 1024

// metadataHeadroom is the slack left for the rest of the metadata map (type,
// versions, epoch, node count, record size, language list and their control
// bytes), which is a few hundred bytes in practice.
const metadataHeadroom = 4096

func (m *exportMetadata) checkDescriptionFits() error {
	size := len(m.description())
	if size+metadataHeadroom > metadataSectionLimit {
		return fmt.Errorf("description is %d bytes; the MMDB metadata section must stay under %d bytes "+
			"including the standard keys, so the attribution text cannot fit", size, metadataSectionLimit)
	}
	return nil
}
