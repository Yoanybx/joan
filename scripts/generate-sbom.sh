#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "$#" -ne 2 ]]; then
  printf '%s\n' 'usage: scripts/generate-sbom.sh <target|all> <output-directory>' >&2
  exit 2
fi

for tool in cargo cargo-cyclonedx git node; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'required SBOM tool is unavailable: %s\n' "$tool" >&2
    exit 3
  fi
done

target="$1"
output="$2"
node tools/sbom-evidence.mjs generate "$output" "$target"
