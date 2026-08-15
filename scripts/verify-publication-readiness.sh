#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mode="${1:-source}"
if [[ "$mode" != "source" && "$mode" != "release" ]]; then
  printf '%s\n' 'usage: scripts/verify-publication-readiness.sh [source|release]' >&2
  exit 2
fi

node tools/publication-readiness.test.mjs
node tools/publication-readiness.mjs "$mode"
