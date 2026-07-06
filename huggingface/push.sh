#!/usr/bin/env bash
# Push the current build to the HuggingFace dataset mirror.
#
# CI-RUN from the data repo's nightly workflow (HF_TOKEN secret) right after
# `ruby pipeline/run.rb` publishes — HF always mirrors what the release
# ships, never a hand-built tree. Owner-run also works after `hf auth login`.
#
#   ./huggingface/push.sh                       # uses ../build/dist
#   OPENASN_DIST=/path ./huggingface/push.sh    # explicit dist dir
set -euo pipefail

DIST="${OPENASN_DIST:-$(cd "$(dirname "$0")/.." && pwd)/build/dist}"
REPO_ID="openasn/openasn"
BUILD_ID="$(jq -r .build_id "$DIST/manifest.json")"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

cp "$(dirname "$0")/README.md" "$STAGE/README.md"
for f in openasn-ipv4.bin openasn-ipv6.bin openasn-orgs.bin \
         asn-categories.csv manifest.json fetch-manifest.json \
         ATTRIBUTION.md SHA256SUMS; do
  cp "$DIST/$f" "$STAGE/"
done

# Keep the card's build line honest without hand-editing.
perl -pi -e "s/Current build: \`[^\`]*\`/Current build: \`${BUILD_ID}\`/" "$STAGE/README.md" || true

hf upload "$REPO_ID" "$STAGE" . --repo-type dataset \
  --commit-message "Nightly build ${BUILD_ID}"

echo "Pushed ${BUILD_ID} to https://huggingface.co/datasets/${REPO_ID}"
