# AGENTS.md

Guidance for AI agents (and humans) working in this repository.

This repo is the COMPILER for the OpenASN dataset. The curated inputs,
published spec (FORMAT.md), decision log (DECISIONS.md), and the releases
users download all live in the open data repo:
https://github.com/openasn/openasn — read its README first. This pipeline
expects that repo checked out as a SIBLING directory (or OPENASN_DATA_REPO
set); the nightly build workflow lives over there too (it needs the data
repo's own GITHUB_TOKEN to publish releases).

Hard rules (same as the data repo, enforced here):

1. **Legal invariants**: only sources with explicit redistribution rights
   on the exact redistributed data may enter the artifact (pipeline/lib/
   sources.rb documents each). Aggregators never qualify. When in doubt,
   exclude — fetch-manifest.json (client-side Tier B) exists for a reason.
2. **The license gate is not optional**: never weaken it, never re-pin
   hashes outside a reviewed PR that explains what changed upstream.
3. **FORMAT.md (data repo) is byte law**: any layout change bumps
   FORMAT_VERSION and coordinates with the `openasn` gem's reader.
4. **Gates fail loudly or not at all** — no "publish with warnings" path.

Dev loop: `ruby pipeline/run.rb` (full build), `OFFLINE=1` to iterate from
cache, `rake test` for unit tests, `rake 'lookup[IP]'` to debug a verdict
against build/dist artifacts.
