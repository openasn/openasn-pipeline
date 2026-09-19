package main

import (
	"fmt"
	"strings"

	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/oschwald/maxminddb-golang/v2/mmdbdata"
)

// The MMDB leaf value (PRD §12.2, EXPORT_FORMATS.md §6.2).
//
// Two rules do all the work here. MMDB has no null type, so a nullable field
// whose value is null is OMITTED - and a boolean is never omitted, not even
// when false, because "absent" would then have to mean both "false" and "this
// build forgot to write it". And nothing identifies the row: no ip_version,
// no start/end, no row id, no timestamp. Bounds are implicit in the search
// tree, and a per-row identity would defeat the deduplication that keeps 572k
// records inside 16 MB - measured on the 2026-09-18 snapshot, 96,525 distinct
// payloads stand behind those records.

func (p *payload) mmdbValue() mmdbtype.Map {
	value := mmdbtype.Map{}
	if p.asn != nil {
		value["asn"] = mmdbtype.Uint32(*p.asn)
	}
	if p.asOrg != nil {
		value["as_org"] = mmdbtype.String(*p.asOrg)
	}
	if p.category != nil {
		value["category"] = mmdbtype.String(*p.category)
	}
	if p.role != nil {
		value["network_role"] = mmdbtype.String(*p.role)
	}
	for i, name := range signalNames {
		value[mmdbtype.String(name)] = mmdbtype.Bool(p.signals[i])
	}
	value["core_verdict"] = mmdbtype.String(p.verdict)
	sources := make(mmdbtype.Slice, len(p.sources))
	for i, source := range p.sources {
		sources[i] = mmdbtype.String(source)
	}
	value["core_sources"] = sources
	return value
}

// cacheKey identifies a payload for the writer's own value cache. Identical
// evidence over thousands of intervals should allocate one mmdbtype.Map, not
// thousands. This is not the deduplication that shrinks the file - mmdbwriter
// does that itself, by hashing what it is handed - it is what keeps the
// build's resident set flat.
func (p *payload) cacheKey() string {
	var b strings.Builder
	if p.asn != nil {
		fmt.Fprintf(&b, "%d", *p.asn)
	}
	// Record and unit separators: the org name is arbitrary UTF-8, but it
	// cannot contain a C0 control character without failing the input
	// adapter, so no name can forge a field boundary here.
	b.WriteByte(0x1e)
	if p.asOrg != nil {
		b.WriteString(*p.asOrg)
	}
	b.WriteByte(0x1e)
	if p.category != nil {
		b.WriteString(*p.category)
	}
	b.WriteByte(0x1e)
	if p.role != nil {
		b.WriteString(*p.role)
	}
	b.WriteByte(0x1e)
	for _, on := range p.signals {
		if on {
			b.WriteByte('1')
		} else {
			b.WriteByte('0')
		}
	}
	b.WriteByte(0x1e)
	b.WriteString(p.verdict)
	b.WriteByte(0x1e)
	b.WriteString(strings.Join(p.sources, "\x1f"))
	return b.String()
}

// leaf decodes a stored record back into a payload.
//
// It reads the data section through mmdbdata's typed decoder rather than
// through a reflection decode into a struct or a map, and that is the whole
// point of this type. A reflection decode into `any` widens a stored uint32
// to uint64, so it cannot tell a uint32 from a uint64 field, and a decode
// into a struct silently ignores a key the struct does not declare. Here the
// stored KIND is checked - ReadUint32 fails on anything that is not an MMDB
// uint32 - an unexpected key is an error, and a missing one is too.
type leaf struct {
	value payload
	seen  map[string]bool
}

var requiredLeafKeys = func() []string {
	keys := append([]string{}, signalNames[:]...)
	return append(keys, "core_verdict", "core_sources")
}()

func (l *leaf) UnmarshalMaxMindDB(d *mmdbdata.Decoder) error {
	l.value = payload{}
	l.seen = make(map[string]bool, spoolFieldCount)

	entries, _, err := d.ReadMap()
	if err != nil {
		return fmt.Errorf("record is not a map: %w", err)
	}

	for rawKey, err := range entries {
		if err != nil {
			return err
		}
		key := string(rawKey)
		if l.seen[key] {
			return fmt.Errorf("key %q appears twice in one record", key)
		}
		l.seen[key] = true

		if index, ok := signalIndex[key]; ok {
			value, err := d.ReadBool()
			if err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
			l.value.signals[index] = value
			continue
		}

		switch key {
		case "asn":
			value, err := d.ReadUint32()
			if err != nil {
				return fmt.Errorf("asn: %w", err)
			}
			l.value.asn = &value
		case "as_org":
			value, err := d.ReadString()
			if err != nil {
				return fmt.Errorf("as_org: %w", err)
			}
			l.value.asOrg = &value
		case "category":
			value, err := d.ReadString()
			if err != nil {
				return fmt.Errorf("category: %w", err)
			}
			l.value.category = &value
		case "network_role":
			value, err := d.ReadString()
			if err != nil {
				return fmt.Errorf("network_role: %w", err)
			}
			l.value.role = &value
		case "core_verdict":
			value, err := d.ReadString()
			if err != nil {
				return fmt.Errorf("core_verdict: %w", err)
			}
			l.value.verdict = value
		case "core_sources":
			values, size, err := d.ReadSlice()
			if err != nil {
				return fmt.Errorf("core_sources: %w", err)
			}
			sources := make([]string, 0, size)
			for err := range values {
				if err != nil {
					return fmt.Errorf("core_sources: %w", err)
				}
				source, err := d.ReadString()
				if err != nil {
					return fmt.Errorf("core_sources: %w", err)
				}
				sources = append(sources, source)
			}
			l.value.sources = sources
		default:
			return fmt.Errorf("unexpected key %q in the record payload", key)
		}
	}

	for _, key := range requiredLeafKeys {
		if !l.seen[key] {
			return fmt.Errorf("record is missing the mandatory key %q", key)
		}
	}
	return nil
}

var signalIndex = func() map[string]int {
	index := make(map[string]int, len(signalNames))
	for i, name := range signalNames {
		index[name] = i
	}
	return index
}()

// diff reports every way `got` differs from `want`. It returns all of them
// rather than the first, because a systematic writer bug shows up as a
// pattern across fields and stopping at the first difference hides it.
func (want *payload) diff(got *payload) []string {
	diffs := []string{}

	diffNullable := func(name string, a, b *string) {
		switch {
		case a == nil && b == nil:
		case a == nil:
			diffs = append(diffs, fmt.Sprintf("%s: %q, wanted it absent", name, *b))
		case b == nil:
			diffs = append(diffs, fmt.Sprintf("%s: absent, wanted %q", name, *a))
		case *a != *b:
			diffs = append(diffs, fmt.Sprintf("%s: %q, wanted %q", name, *b, *a))
		}
	}

	switch {
	case want.asn == nil && got.asn == nil:
	case want.asn == nil:
		diffs = append(diffs, fmt.Sprintf("asn: %d, wanted it absent", *got.asn))
	case got.asn == nil:
		diffs = append(diffs, fmt.Sprintf("asn: absent, wanted %d", *want.asn))
	case *want.asn != *got.asn:
		diffs = append(diffs, fmt.Sprintf("asn: %d, wanted %d", *got.asn, *want.asn))
	}

	diffNullable("as_org", want.asOrg, got.asOrg)
	diffNullable("category", want.category, got.category)
	diffNullable("network_role", want.role, got.role)

	for i, name := range signalNames {
		if want.signals[i] != got.signals[i] {
			diffs = append(diffs, fmt.Sprintf("%s: %t, wanted %t", name, got.signals[i], want.signals[i]))
		}
	}

	if want.verdict != got.verdict {
		diffs = append(diffs, fmt.Sprintf("core_verdict: %q, wanted %q", got.verdict, want.verdict))
	}
	if len(want.sources) != len(got.sources) {
		diffs = append(diffs, fmt.Sprintf("core_sources: %v, wanted %v", got.sources, want.sources))
	} else {
		for i := range want.sources {
			if want.sources[i] != got.sources[i] {
				diffs = append(diffs, fmt.Sprintf("core_sources: %v, wanted %v", got.sources, want.sources))
				break
			}
		}
	}

	return diffs
}
