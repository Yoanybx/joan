#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

for tool in cargo cargo-cyclonedx git node; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'required SBOM verification tool is unavailable: %s\n' "$tool" >&2
    exit 3
  fi
done

temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/joan-sbom-verification.XXXXXX")"
trap 'rm -rf -- "$temporary_directory"' EXIT

node --test tools/sbom-evidence.test.mjs
node tools/sbom-evidence.mjs generate "$temporary_directory/sbom" all >/dev/null
node tools/sbom-evidence.mjs verify "$temporary_directory/sbom" >/dev/null
node tools/sbom-evidence.mjs negative-controls "$temporary_directory/sbom"
JOAN_SBOM_ARTIFACT_DIRECTORY="$temporary_directory/sbom" \
  cargo test --quiet --locked -p joan-node --test repository_contracts \
    sbom_artifacts_match_their_schemas_when_supplied

printf '%s\n' 'JOAN reproducible CycloneDX SBOM gate passed: 10 negative controls rejected.'
