---
license: cc0-1.0
pretty_name: OpenASN — open IP origin intelligence
language:
  - en
tags:
  - networking
  - ip
  - asn
  - vpn
  - datacenter
  - security
  - open-data
size_categories:
  - 100K<n<1M
configs:
  - config_name: default
    data_files: asn-categories.csv
---

# OpenASN — open IP origin intelligence

**Classify any IP as residential, mobile, hosting, VPN, Tor, relay, business,
or unknown — offline, explainably, without API calls.** Current build:
`2026-07-05T14:07:22Z` (re-stamped nightly).

This is a mirror of the canonical GitHub repo:
**https://github.com/openasn/openasn** (issues/contributions go there).
Artifacts are rebuilt and mirrored here **nightly**.

## Why this dataset is different

- **Legally clean.** Compiled only from permissively licensed upstreams;
  every upstream license is pinned by SHA-256 and checked by a build gate.
  The composite data is **CC0** — use it for anything, no attribution
  required (credits in `ATTRIBUTION.md` are appreciated, not demanded).
- **Explainable verdicts.** Every classification traces to an ASN category,
  a network role, and overlay bits you can inspect — no black-box scores.
- **Honest `unknown`.** Mixed-use ASNs and pure tier-1 backbone space stay
  `unknown` on purpose: "we can't tell" beats a confident wrong answer.
- **Not a fraud engine.** A `residential_isp` verdict is absence of
  evidence, not proof of innocence; residential proxies are structurally
  hard to detect offline and OpenASN does not claim to. `vpn`, `hosting`,
  and `tor_exit` are the high-confidence verdicts.

## Files

| file | what |
|---|---|
| `asn-categories.csv` | every routed ASN, and every other ASN we hold a field for → org, country, category, network role, OpenASN flags — the load-me-first table (backs the dataset viewer). `org` and `country` are filled only where we hold a CC0 value (our sourced overrides + Wikidata); they are empty elsewhere. `country` is where the ASN's operator is based (ISO 3166-1 alpha-2), not a registry country |
| `openasn-ipv4.bin` / `openasn-ipv6.bin` | packed classification artifacts: IP→ASN backbone + VPN/datacenter overlays, queryable in microseconds ([byte spec](https://github.com/openasn/openasn/blob/main/FORMAT.md)) |
| `openasn-orgs.bin` | packed ASN→organization names (CC0 sources only; see the data repo's DECISIONS.md D-SRC-2) |
| `manifest.json` | build id, per-file SHA-256, full source provenance |
| `fetch-manifest.json` | the Tier B recipe (sources your server fetches directly — Tor exits, cloud ranges) |
| `ATTRIBUTION.md` / `SHA256SUMS` | credits and checksums |
| `openasn.sqlite.gz` | the same data as one queryable SQLite database (gzipped; `openasn.sqlite` once decompressed) |
| `openasn.csv.gz` | the same data as one range-per-row CSV (gzipped) |
| `openasn.mmdb` | the same data as a MaxMind-format database, read by any MMDB reader |

This mirror carries exactly the files of the corresponding GitHub release,
listed in that release's `manifest.json`. Nothing is assembled by hand
here. The three portable exports are mirrored from the night the dataset's
[export contract](https://github.com/openasn/openasn/blob/main/export-contract.json)
requires them; the binary artifacts and the CSV table above have shipped
since the first release.

### What the portable exports contain (and what they do not)

They are a different **representation** of the same build, not a different
dataset, and their scope is deliberately narrower than a full client:

- **Tier A only.** Everything in them comes from the redistributable
  upstreams compiled into the release. The Tier B overlays a client fetches
  for itself (Tor exit list, cloud provider ranges: see `fetch-manifest.json`)
  are **not** included, so a client with Tier B enabled can legitimately
  return a stronger verdict than these files do.
- **One documented classification profile,** `core-v1`, and one lookup
  policy, version 1. Both are stamped inside every file and in its manifest
  entry, so a consumer can check what it is reading instead of inferring it.
- **Row-level identity across formats.** SQLite, CSV and MMDB carry the same
  coalesced ranges with the same fields; the byte-exact rules, the
  special-address policy (`::1`, private space, CGNAT) and the update
  protocol are specified in
  [EXPORT_FORMATS.md](https://github.com/openasn/openasn/blob/main/EXPORT_FORMATS.md).

One caveat worth reading before using the MMDB file: a combined IPv4+IPv6
MMDB stores IPv4 inside `::/96`, so a raw reader resolves the IPv4 record for
an `::a.b.c.d` literal, and `::ffff:a.b.c.d` returns no data because IPv4
aliasing is deliberately disabled. Normalize mapped addresses before lookup
(EXPORT_FORMATS.md §6.4).

## Quick look

```python
import pandas as pd

df = pd.read_csv("asn-categories.csv")
df[df.category == "vpn_provider"].head(20)
df.groupby("category").size().sort_values(ascending=False)
```

Range lookups with no client library at all, straight out of the SQLite
export. `v4` is keyed by the range start, so you take the one row that starts
at or before the address and then check that it actually reaches it. Ranges
do not cover every address, so the `end >= :ip` test is what makes a gap
return nothing instead of returning the previous range:

```sql
-- 8.8.8.8 = 134744072
SELECT * FROM (
  SELECT * FROM v4 WHERE start <= 134744072 ORDER BY start DESC LIMIT 1
) AS candidate
WHERE end >= 134744072;
```

For microsecond IP lookups use the binary artifacts with a client —
[`openasn` Ruby gem](https://github.com/openasn/openasn-ruby) first, more
languages welcome (the format is public and language-neutral).

## Attribution

> IP origin data by [OpenASN](https://github.com/openasn/openasn) (CC0),
> compiled from permissively licensed sources — full notices in
> [ATTRIBUTION.md](https://github.com/openasn/openasn/blob/main/ATTRIBUTION.md).
