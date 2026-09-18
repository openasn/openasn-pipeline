# ⚙️ openasn-pipeline — the compiler behind the OpenASN dataset

This repository builds the [OpenASN](https://github.com/openasn/openasn) data artifacts: it fetches the Tier A sources, runs the legal and quality gates, compiles the packed binary artifacts, validates them, and publishes to the data repo's nightly [`latest` release](https://github.com/openasn/openasn/releases/latest).

**Start at the [data repo](https://github.com/openasn/openasn)** — it owns the story: what OpenASN is, the source catalog and legal design, the artifact format ([FORMAT.md](https://github.com/openasn/openasn/blob/main/FORMAT.md)), the decision log, the curated overrides, and the releases users actually download. This repo is the machinery.

```
openasn/openasn            the dataset: overrides, licenses pins, spec, releases  ← users look here
openasn/openasn-pipeline   this repo: fetch → gates → compile → validate → publish
openasn/openasn-ruby       the Ruby client gem
```

## Layout & repo relationship

The pipeline reads curated inputs from a checkout of the data repo, resolved at run time:

1. `OPENASN_DATA_REPO=/path/to/openasn` (what CI sets), else
2. a sibling `../openasn` checkout (the local-dev convention).

From the data repo it consumes `data/overrides/`, `data/licenses/pins.json`, `spotchecks.yml`, `fetch-manifest.json`, `ATTRIBUTION.md`. Everything it produces lands in this repo's gitignored `build/` workspace, and releases upload to `openasn/openasn` (override with `OPENASN_PUBLISH_REPO` for forks/staging).

The **nightly build workflow lives in the data repo** (`.github/workflows/nightly-build.yml` there): running where the releases live means publishing works with that repo's own `GITHUB_TOKEN`, and once this pipeline repo is public the whole nightly needs zero secrets. This repo's CI runs the unit tests only.

## Stages

| stage | file | job |
|---|---|---|
| fetch | `pipeline/fetch.rb` | Tier A downloads: conditional GET, retries, keep-last-good |
| license gate | `pipeline/lib/license_gate.rb` | SHA-256 of every upstream license text vs pinned hashes; ANY drift fails the build |
| normalize | `pipeline/normalize.rb` | parse everything into canonical rows; overlap sanitizer |
| crosscheck | `pipeline/crosscheck.rb` | ipverse category quality vs the X4B ∪ bad-asn reference set; drift alarms |
| compile | `pipeline/compile.rb` | flags, corrections, gap-fill via as-ip-blocks, pack OASN v1 + OORG v1 |
| validate | `pipeline/validate.rb` | round-trip re-find, size sanity, ±20% deltas, the spot panel, orgs checks |
| publish | `pipeline/publish.rb` | manifest with provenance, SHA256SUMS, convenience CSV, release upload |

## Flags are evidence, not product labels

The compiler packs raw category, network-role, and OpenASN flag bits into the OASN artifacts. Client libraries turn those bits into the public verdict enum. Keep that boundary intact:

- `category=isp` is raw ASN metadata; clients usually expose it as `verdict=residential_isp` unless a stronger overlay wins.
- `bad_asn` means membership in `brianhama/bad-asn-list`, a curated hosting/cloud/colo ASN list. It is an infrastructure signal, not a claim of abuse.
- `x4b_dc`, `x4b_vpn`, cloud-provider overlays, and Tier B overlays may all be true for related ranges. The client precedence ladder decides which source wins and what appears in `Result#sources`.
- Provider attribution belongs to exact overlay hits. Do not widen exact provider IPs to nearby prefixes in the compiler unless the data repo has documented the false-positive tradeoff and exposed it as context-only.

## Running it

```bash
# next to a checkout of openasn/openasn:
ruby pipeline/run.rb             # full build into build/dist/ (~100MB downloads, ~2 min)
OFFLINE=1 ruby pipeline/run.rb   # rebuild from cache (fast dev iteration; gates that
                                 # need the network are skipped LOUDLY — never publish these)
PUBLISH=1 ruby pipeline/run.rb   # + upload to the openasn/openasn rolling release
rake test                        # unit tests (pure logic; no network, no data repo needed)
rake 'lookup[8.8.8.8]'           # classify an IP against your local build
rake overrides:candidates        # curation aid: writes candidate lists to build/work/
rake licenses:check              # verify upstream license pins without building
```

Requirements: Ruby ≥ 3.2, `jq` recommended (streams the ~69MB ipverse JSON; a stdlib fallback exists but is memory-hungry), `gh` CLI for publishing.

### The MMDB writer (build-only Go toolchain)

`tools/mmdbwriter/` is a small Go module that turns the export spool into
`openasn.mmdb`. It is a **build** dependency: no consumer needs Go, existing
native clients are untouched, and the tool has no HTTP client and no file
discovery — every input arrives as an explicit path.

Pinned in `go.mod` / `go.sum` and exercised by CI:

| Dependency | Version | Role |
|---|---|---|
| Go toolchain | `1.24.0` | `go` directive in `go.mod` |
| `github.com/maxmind/mmdbwriter` | `v1.2.0` | writer |
| `github.com/oschwald/maxminddb-golang/v2` | `v2.1.1` | **independent** reader used by `verify` |
| `go4.org/netipx` | `v0.0.0-20231129151722-fdeea329fbba` | indirect (exact range → prefixes) |
| `golang.org/x/sys` | `v0.38.0` | indirect |

The reader is a different codebase from the writer on purpose: a writer
validating its own output with its own reader is one codebase agreeing with
itself, and the point of shipping MMDB is that a stranger's reader can open
the file.

```bash
go -C tools/mmdbwriter build -o ../../build/work/openasn-mmdb .

build/work/openasn-mmdb build  --records build/work/export/<gen>/records.jsonl \
                               --metadata build/work/export/<gen>/metadata.json \
                               --output  build/work/export/<gen>/openasn.mmdb
build/work/openasn-mmdb verify --database build/work/export/<gen>/openasn.mmdb \
                               --records build/work/export/<gen>/records.jsonl \
                               --metadata build/work/export/<gen>/metadata.json

rake exports:mmdb_test   # build + vet + Go unit tests + the Ruby MMDB suite
```

Both modes exit 0 only on full success and print a structured JSON summary on
stdout, with diagnostics on stderr. `verify` runs the independent reader's
structural check, validates the standard metadata, compares the decoded
payload at every interval start and end plus an interior, probes both sides of
every gap, and walks the whole tree to prove the stored prefixes tile the
spool's intervals exactly — which is what catches a widened CIDR or a phantom
alias that a lookup alone would never see.

Two hard gates live in `build` (see `EXPORT_FORMATS.md` §6.4). A combined MMDB
stores IPv4 inside `::/96`, so native IPv6 data overlapping `::/96` or the
mapped prefix `::ffff:0:0/96` would collide with it. Either one fails the
build loudly; the counts are logged on every run so a future violation is
visible before it fails a nightly (both are 0 on the 2026-09-18 snapshot).

## Enrichment tooling (operator-run, never part of the build)

`pipeline/enrich/` is an LLM-assisted **curation aid**: it drafts ASN
classification candidates that humans review and graduate through normal
data-repo PRs. The rule it exists to serve: **LLMs draft labels; OpenASN
publishes reviewed evidence.** Three invariants are load-bearing:

- **The nightly build never calls an LLM.** These tasks spend operator
  money/quota and are always invoked by hand; `rake build` and
  `pipeline/run.rb` do not touch this directory.
- **LLM output never writes to `data/overrides/`.** Everything lands under
  gitignored `build/` as review queues; only human-reviewed, source-commented
  lines reach the data repo, enforced by its lint.
- **Measure before trusting.** The pilot scores the classifier against a gold
  set built from OpenASN's own hand-curated labels before any candidate is
  taken seriously (per-label precision/recall, confidence calibration, and a
  full miss listing land in `build/work/enrich/pilot-*/report.md`).

```bash
rake enrich:pilot                 # score LLM classification vs our gold set
                                  #   ARM=local|enriched|both LIMIT=n BATCH=n FETCH=1
rake 'enrich:resume[pilot-<id>]'  # continue a killed run (per-batch checkpoints)
rake 'enrich:evidence[3352]'      # debug: the evidence packet for one ASN
rake 'enrich:classify[3352]'      # debug: one ASN end-to-end through the LLM
```

Backends (auto-detected, `OPENASN_ENRICH_BACKEND` to force): `claude` CLI (no
key needed), Anthropic API, or OpenAI API — both APIs with strict structured
outputs. Spend is capped per run (`OPENASN_ENRICH_MAX_CALLS`). External
evidence fetchers (RIPEstat, PeeringDB, RDAP, reverse DNS, website titles)
consult sources **per-record** with rate caps and an identifying User-Agent,
cache under `build/cache/enrich/`, and never republish fetched text — the
legal posture is documented at the top of `pipeline/enrich/fetchers.rb`.

## License

MIT (see LICENSE). The compiled data artifacts are CC0 — the open-data contract, gates, and full provenance story live in the [data repo](https://github.com/openasn/openasn).
