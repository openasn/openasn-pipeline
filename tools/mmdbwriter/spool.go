package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/netip"
	"os"
	"strings"
	"unicode/utf8"
)

// The JSONL spool (PRD §9) is this tool's frozen input format. Its producer is
// pipeline/export/spool.rb; the field names and order below mirror
// Export::Contract::SPOOL_FIELDS exactly.
//
// Endpoints arrive as fixed-width lowercase hex, never as JSON numbers,
// because a 128-bit address in a JSON number field becomes a float64 the
// moment anything parses it with default settings and the corruption is
// silent for exactly the addresses nobody spot-checks. Every scalar below is
// decoded into a typed field for the same reason: an `any` decode would turn
// a 4294967295 ASN into a float64 and hand back 4294967296 on the way out.
//
// The vocabularies are duplicated from Ruby's Export::Contract because Go
// cannot read it. That duplication is deliberate and is exercised from the
// Ruby side: test/export_mmdb_test.rb feeds every Contract token through this
// parser, so a token added there without being added here fails a test rather
// than silently producing an unvalidated export.

const (
	spoolFieldCount = 17
	maxOrgBytes     = 96 // FORMAT.md's OORG bound, re-checked here
)

var (
	validVerdicts = newSet(
		"residential_isp", "mobile", "business", "hosting", "vpn",
		"enterprise_gateway", "education", "government", "unknown",
	)
	validSources = newSet(
		"x4b_vpn", "asn_vpn_provider", "asn_enterprise_gw", "x4b_dc",
		"asn_bad_asn", "asn_hosting_extra", "asn_cdn", "asn_category",
		"asn_mobile_carrier", "isp_transit_ambiguous", "asn_no_category",
		"unrouted",
	)
	validCategories = newSet("isp", "hosting", "business", "education_research", "government_admin")
	validRoles      = newSet(
		"tier1_transit", "major_transit", "midsize_transit",
		"access_provider", "content_network", "stub",
	)
)

func newSet(values ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		set[v] = struct{}{}
	}
	return set
}

// spoolLine is the wire shape. Nullable fields are pointers so that "absent"
// and "null" and "false" stay three distinct things: PRD §12.2 requires every
// boolean to reach the MMDB even when false, so a boolean that is merely
// missing from a line must fail loudly instead of defaulting to false.
type spoolLine struct {
	IPVersion   *int      `json:"ip_version"`
	StartHex    *string   `json:"start_hex"`
	EndHex      *string   `json:"end_hex"`
	ASN         *uint32   `json:"asn"`
	AsOrg       *string   `json:"as_org"`
	Category    *string   `json:"category"`
	NetworkRole *string   `json:"network_role"`
	BadASN      *bool     `json:"bad_asn"`
	VPNProvider *bool     `json:"vpn_provider"`
	MobileCarr  *bool     `json:"mobile_carrier"`
	EnterpriseG *bool     `json:"enterprise_gw"`
	CDN         *bool     `json:"cdn"`
	HostingExtr *bool     `json:"hosting_extra"`
	VPNRange    *bool     `json:"vpn_range"`
	DCRange     *bool     `json:"datacenter_range"`
	CoreVerdict *string   `json:"core_verdict"`
	CoreSources *[]string `json:"core_sources"`
}

// record is one validated logical interval: the payload plus the inclusive
// bounds the writer inserts it over.
type record struct {
	version int
	start   netip.Addr
	end     netip.Addr
	payload payload
}

// payload holds the 14 logical payload fields in the order PRD §6 lists them.
type payload struct {
	asn      *uint32
	asOrg    *string
	category *string
	role     *string
	signals  [8]bool
	verdict  string
	sources  []string
}

// signalNames is the MMDB key order-independent list of the eight booleans,
// indexed the same way payload.signals is.
var signalNames = [8]string{
	"bad_asn", "vpn_provider", "mobile_carrier", "enterprise_gw",
	"cdn", "hosting_extra", "vpn_range", "datacenter_range",
}

// spoolReader streams the spool. Nothing here materializes the whole file:
// 572k records with their payloads is a resident set we do not need, and both
// build and verify are single ordered passes by construction.
type spoolReader struct {
	file    *os.File
	scanner *bufio.Scanner
	line    int

	previous  *record
	sawIPv6   bool
	ipv4Count int
	ipv6Count int
}

func openSpool(path string) (*spoolReader, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening spool: %w", err)
	}
	scanner := bufio.NewScanner(file)
	// Org names are bounded at 96 bytes and sources are a short frozen
	// vocabulary, so a megabyte is orders of magnitude of headroom; a longer
	// line means the spool is not what this tool was told it is.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	return &spoolReader{file: file, scanner: scanner}, nil
}

func (s *spoolReader) Close() error { return s.file.Close() }

// next returns the next validated record, or io.EOF.
func (s *spoolReader) next() (*record, error) {
	if !s.scanner.Scan() {
		if err := s.scanner.Err(); err != nil {
			return nil, fmt.Errorf("reading spool line %d: %w", s.line+1, err)
		}
		return nil, io.EOF
	}
	s.line++

	raw := s.scanner.Bytes()
	if len(raw) == 0 {
		return nil, fmt.Errorf("spool line %d is empty", s.line)
	}

	var line spoolLine
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	// An unknown key means the projection and this writer disagree about the
	// record shape. Guessing at the extra field is how an export silently
	// loses evidence, so it is a build failure.
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&line); err != nil {
		return nil, fmt.Errorf("spool line %d: %w", s.line, err)
	}
	if err := decoder.Decode(new(json.RawMessage)); err != io.EOF {
		return nil, fmt.Errorf("spool line %d: trailing content after the JSON object", s.line)
	}

	rec, err := line.validate()
	if err != nil {
		return nil, fmt.Errorf("spool line %d: %w", s.line, err)
	}
	if err := s.checkOrder(rec); err != nil {
		return nil, fmt.Errorf("spool line %d: %w", s.line, err)
	}

	if rec.version == 4 {
		s.ipv4Count++
	} else {
		s.ipv6Count++
	}
	s.previous = rec
	return rec, nil
}

// checkOrder enforces the spool's ordering contract: all IPv4 then all IPv6,
// each family strictly ascending and disjoint. Verification leans on it (a gap
// probe only means something if the neighbours really are neighbours) and so
// does the writer, which must never insert two payloads over one address.
func (s *spoolReader) checkOrder(rec *record) error {
	if rec.version == 6 {
		s.sawIPv6 = true
	} else if s.sawIPv6 {
		return fmt.Errorf("IPv4 record after an IPv6 record: the spool is ordered IPv4 then IPv6")
	}
	if s.previous == nil || s.previous.version != rec.version {
		return nil
	}
	if !s.previous.end.Less(rec.start) {
		return fmt.Errorf("record starting %s overlaps or precedes the previous record ending %s",
			rec.start, s.previous.end)
	}
	return nil
}

func (l *spoolLine) validate() (*record, error) {
	if l.IPVersion == nil {
		return nil, fmt.Errorf("missing ip_version")
	}
	version := *l.IPVersion
	if version != 4 && version != 6 {
		return nil, fmt.Errorf("ip_version %d is neither 4 nor 6", version)
	}
	if l.StartHex == nil || l.EndHex == nil {
		return nil, fmt.Errorf("missing start_hex or end_hex")
	}
	start, err := parseHexAddr(*l.StartHex, version)
	if err != nil {
		return nil, fmt.Errorf("start_hex: %w", err)
	}
	end, err := parseHexAddr(*l.EndHex, version)
	if err != nil {
		return nil, fmt.Errorf("end_hex: %w", err)
	}
	if end.Less(start) {
		return nil, fmt.Errorf("end %s is below start %s", end, start)
	}

	signals := [8]bool{}
	for i, ptr := range []*bool{
		l.BadASN, l.VPNProvider, l.MobileCarr, l.EnterpriseG,
		l.CDN, l.HostingExtr, l.VPNRange, l.DCRange,
	} {
		if ptr == nil {
			return nil, fmt.Errorf("missing boolean %s: every signal is present in every record, "+
				"including when false", signalNames[i])
		}
		signals[i] = *ptr
	}

	if l.CoreVerdict == nil {
		return nil, fmt.Errorf("missing core_verdict")
	}
	if _, ok := validVerdicts[*l.CoreVerdict]; !ok {
		return nil, fmt.Errorf("core_verdict %q is not a core-v1 verdict", *l.CoreVerdict)
	}
	if l.CoreSources == nil {
		return nil, fmt.Errorf("missing core_sources")
	}
	sources := *l.CoreSources
	if len(sources) == 0 {
		return nil, fmt.Errorf("core_sources is empty: every verdict carries its explanation")
	}
	for _, source := range sources {
		if _, ok := validSources[source]; !ok {
			return nil, fmt.Errorf("core_sources contains %q, which is not a core-v1 source", source)
		}
	}

	if l.Category != nil {
		if _, ok := validCategories[*l.Category]; !ok {
			return nil, fmt.Errorf("category %q is not a core-v1 category", *l.Category)
		}
	}
	if l.NetworkRole != nil {
		if _, ok := validRoles[*l.NetworkRole]; !ok {
			return nil, fmt.Errorf("network_role %q is not a core-v1 network role", *l.NetworkRole)
		}
	}
	if l.AsOrg != nil {
		org := *l.AsOrg
		if org == "" {
			return nil, fmt.Errorf("as_org is present but empty: absent is null, not empty string")
		}
		if len(org) > maxOrgBytes {
			return nil, fmt.Errorf("as_org is %d bytes, over the %d-byte bound", len(org), maxOrgBytes)
		}
		if !utf8.ValidString(org) {
			return nil, fmt.Errorf("as_org is not valid UTF-8")
		}
	}

	// PRD §6: no base row means no ASN-level evidence at all. The overlay
	// flags may still be true - that is what an overlay-only record is.
	if l.ASN == nil {
		if l.AsOrg != nil || l.Category != nil || l.NetworkRole != nil {
			return nil, fmt.Errorf("null asn with org/category/role present")
		}
		for i := 0; i < 6; i++ {
			if signals[i] {
				return nil, fmt.Errorf("null asn with ASN-level signal %s set", signalNames[i])
			}
		}
	}

	return &record{
		version: version,
		start:   start,
		end:     end,
		payload: payload{
			asn:      l.ASN,
			asOrg:    l.AsOrg,
			category: l.Category,
			role:     l.NetworkRole,
			signals:  signals,
			verdict:  *l.CoreVerdict,
			sources:  sources,
		},
	}, nil
}

// parseHexAddr decodes the fixed-width big-endian hex endpoint. The family
// comes from ip_version and nothing else: inferring it from the value would
// make a native IPv6 record that happens to sit low in the space parse as
// IPv4, which is precisely the collapse PRD §12.4 exists to prevent.
func parseHexAddr(text string, version int) (netip.Addr, error) {
	width := 8
	if version == 6 {
		width = 32
	}
	if len(text) != width {
		return netip.Addr{}, fmt.Errorf("%q is %d characters, expected %d for IPv%d",
			text, len(text), width, version)
	}
	var bytes [16]byte
	for i := 0; i < len(text); i++ {
		c := text[i]
		var nibble byte
		switch {
		case c >= '0' && c <= '9':
			nibble = c - '0'
		case c >= 'a' && c <= 'f':
			nibble = c - 'a' + 10
		default:
			// Uppercase is rejected rather than accepted: the spool is
			// canonical, and a tool that tolerates a second spelling stops
			// being able to detect that its producer changed.
			return netip.Addr{}, fmt.Errorf("%q contains %q, which is not a lowercase hex digit", text, c)
		}
		if i%2 == 0 {
			bytes[i/2] = nibble << 4
		} else {
			bytes[i/2] |= nibble
		}
	}
	if version == 4 {
		return netip.AddrFrom4([4]byte{bytes[0], bytes[1], bytes[2], bytes[3]}), nil
	}
	return netip.AddrFrom16(bytes), nil
}

// addrToBig / bigToAddr give exact address arithmetic for interior probes and
// coverage sums. IPv6 counts do not fit in a uint64 and must never round.
func addrToBig(addr netip.Addr) *big.Int {
	slice := addr.AsSlice()
	return new(big.Int).SetBytes(slice)
}

func bigToAddr(value *big.Int, version int) (netip.Addr, error) {
	width := 4
	if version == 6 {
		width = 16
	}
	bytes := value.Bytes()
	if len(bytes) > width {
		return netip.Addr{}, fmt.Errorf("address %s does not fit in IPv%d", value, version)
	}
	buf := make([]byte, width)
	copy(buf[width-len(bytes):], bytes)
	addr, ok := netip.AddrFromSlice(buf)
	if !ok {
		return netip.Addr{}, fmt.Errorf("address %s is not a valid IPv%d address", value, version)
	}
	return addr, nil
}

// addressCount is the inclusive size of [start, end].
func addressCount(start, end netip.Addr) *big.Int {
	count := new(big.Int).Sub(addrToBig(end), addrToBig(start))
	return count.Add(count, big.NewInt(1))
}
