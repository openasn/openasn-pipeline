#!/usr/bin/env bash
# Push the current build to the HuggingFace dataset mirror.
#
# CI-RUN from the data repo's nightly workflow (HF_TOKEN secret) right after
# `ruby pipeline/run.rb` publishes — HF always mirrors what the release
# ships, never a hand-built tree. Owner-run also works after `hf auth login`.
#
#   ./huggingface/push.sh                       # uses ../build/dist
#   OPENASN_DIST=/path ./huggingface/push.sh    # explicit dist dir
#
# WHAT GETS MIRRORED IS DECIDED BY manifest.json, NOT BY THIS SCRIPT
# (PRD §15.4). This used to be a hardcoded list of eight file names, which
# was fine while a release was exactly those eight files forever. It is not
# fine now: the portable exports are added or withheld by the build's export
# mode, so a hardcoded list either misses a published asset or copies one
# this build never produced. The manifest is the build's own registry of
# what it published (pipeline/lib/release_assets.rb), so the mirror stages
# exactly `.files[].name` plus the two envelope files, plus the mirror-only
# dataset card.
#
# The dist directory also holds things that must NEVER reach a public
# mirror. Nothing here globs a directory, so the export spool
# (records.jsonl), the raw uncompressed openasn.sqlite / openasn.csv, the Go
# writer's leftover .candidate file, build logs and test output cannot be
# copied even when they are sitting right next to the release. And every
# name is checked against the same character class the release registry
# enforces BEFORE it reaches `cp`, so a manifest entry like
# "../../.ssh/id_rsa" or "a b; rm -rf /" is a hard failure rather than a
# file operation.
set -euo pipefail

DIST="${OPENASN_DIST:-$(cd "$(dirname "$0")/.." && pwd)/build/dist}"
REPO_ID="${OPENASN_HF_REPO:-openasn/openasn}"
MANIFEST="$DIST/manifest.json"
CARD="$(cd "$(dirname "$0")" && pwd)/README.md"

[ -f "$MANIFEST" ] || { echo "no manifest.json in $DIST, so there is nothing to mirror" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq is required to read the release manifest" >&2; exit 1; }

BUILD_ID="$(jq -r '.build_id // empty' "$MANIFEST")"
[ -n "$BUILD_ID" ] || { echo "$MANIFEST has no build_id" >&2; exit 1; }

STAGE="$(mktemp -d)"
NAMES="$(mktemp)"
trap 'rm -rf "$STAGE" "$NAMES"' EXIT

# One name per line, read a whole line at a time: a name containing a space
# must reach the validation below as ONE name and be rejected there, not be
# split into two plausible-looking words by the shell. The name list lives
# outside the staging directory so it cannot be uploaded with it.
jq -r '.files[].name' "$MANIFEST" > "$NAMES"
[ -s "$NAMES" ] || { echo "$MANIFEST lists no files" >&2; exit 1; }

# The two envelopes describe the same payload set, from the same registry,
# so they must agree on which names that is. Cross-checking them is what
# turns a single doctored or hand-edited manifest entry into a failure here
# rather than an extra file on a public mirror.
[ -f "$DIST/SHA256SUMS" ] || { echo "no SHA256SUMS in $DIST" >&2; exit 1; }
if ! diff -u <(sort "$NAMES") \
             <(sed 's/^[0-9a-f]\{64\}  //' "$DIST/SHA256SUMS" | sort) >&2; then
  echo "manifest.json and SHA256SUMS do not describe the same payloads" >&2
  exit 1
fi

# The envelope files are not entries in `.files` (a file cannot carry its
# own hash) so they are named here, exactly as the registry names them.
printf 'SHA256SUMS\nmanifest.json\n' >> "$NAMES"

staged=0
while IFS= read -r name; do
  # Same rule as ReleaseAssets::SAFE_NAME: a bare file name that survives a
  # URL, a shell word and a `sha256sum -c` line.
  case "$name" in
    "" | [!A-Za-z0-9]* | *[!A-Za-z0-9._-]*)
      echo "refusing to mirror $(printf '%q' "$name"): not a plain release asset name" >&2
      exit 1
      ;;
  esac
  [ -f "$DIST/$name" ] || { echo "$name is in the manifest but not in $DIST" >&2; exit 1; }

  cp "$DIST/$name" "$STAGE/$name"
  staged=$((staged + 1))
done < "$NAMES"

# The dataset card is the one file the mirror has that the release does not,
# so it is added by name here rather than discovered anywhere.
cp "$CARD" "$STAGE/README.md"

# Keep the card's build line honest without hand-editing.
perl -pi -e "s/Current build: \`[^\`]*\`/Current build: \`${BUILD_ID}\`/" "$STAGE/README.md" || true

# The checksums the release published, re-checked against the bytes about to
# be mirrored. A dist directory can be stale or half-written (an interrupted
# build, an operator copy), and a mirror serving those bytes under a
# valid-looking manifest is worse than a mirror that is one night old.
if command -v sha256sum >/dev/null; then
  (cd "$STAGE" && sha256sum -c --quiet SHA256SUMS)
elif command -v shasum >/dev/null; then
  (cd "$STAGE" && shasum -a 256 -c SHA256SUMS >/dev/null)
else
  echo "warning: no sha256sum/shasum available, mirroring without re-verifying checksums" >&2
fi

echo "mirroring ${staged} release files + dataset card for build ${BUILD_ID}"

hf upload "$REPO_ID" "$STAGE" . --repo-type dataset \
  --commit-message "Nightly build ${BUILD_ID}"

echo "Pushed ${BUILD_ID} to https://huggingface.co/datasets/${REPO_ID}"
