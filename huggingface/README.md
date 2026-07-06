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
| `asn-categories.csv` | every ASN → org, country, category, network role, OpenASN flags — the load-me-first table (backs the dataset viewer) |
| `openasn-ipv4.bin` / `openasn-ipv6.bin` | packed classification artifacts: IP→ASN backbone + VPN/datacenter overlays, queryable in microseconds ([byte spec](https://github.com/openasn/openasn/blob/main/FORMAT.md)) |
| `openasn-orgs.bin` | packed ASN→organization metadata |
| `manifest.json` | build id, per-file SHA-256, full source provenance |
| `fetch-manifest.json` | the Tier B recipe (sources your server fetches directly — Tor exits, cloud ranges) |
| `ATTRIBUTION.md` / `SHA256SUMS` | credits and checksums |

## Quick look

```python
import pandas as pd

df = pd.read_csv("asn-categories.csv")
df[df.category == "vpn_provider"].head(20)
df.groupby("category").size().sort_values(ascending=False)
```

For microsecond IP lookups use the binary artifacts with a client —
[`openasn` Ruby gem](https://github.com/openasn/openasn-ruby) first, more
languages welcome (the format is public and language-neutral).

## Attribution

> IP origin data by [OpenASN](https://github.com/openasn/openasn) (CC0),
> compiled from permissively licensed sources — full notices in
> [ATTRIBUTION.md](https://github.com/openasn/openasn/blob/main/ATTRIBUTION.md).
