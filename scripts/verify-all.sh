#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

evidence_mode="strict"
if [[ $# -eq 1 && "$1" == "--portable-evidence" ]]; then
  evidence_mode="portable"
elif [[ $# -ne 0 ]]; then
  printf '%s\n' 'usage: bash scripts/verify-all.sh [--portable-evidence]' >&2
  exit 2
fi

for tool in cargo-audit cargo-cyclonedx cargo-deny; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'required verification tool is unavailable: %s\n' "$tool" >&2
    exit 3
  fi
done

printf '%s\n' '==> fail-closed publication readiness'
bash scripts/verify-publication-readiness.sh source

printf '%s\n' '==> exact transitive dependency exceptions'
bash scripts/verify-dependency-policy.sh

if [[ -n "${JOAN_VERIFICATION_RECEIPT_OUTPUT:-}" ]]; then
  receipt="$JOAN_VERIFICATION_RECEIPT_OUTPUT"
  mkdir -p "$(dirname "$receipt")"
else
  receipt="$(mktemp "${TMPDIR:-/tmp}/joan-verification-receipt.XXXXXX")"
  trap 'rm -f "$receipt"' EXIT
fi

node tools/verification-runner.mjs "$receipt"

if [[ "$evidence_mode" == "portable" ]]; then
  printf '%s\n' '==> portable historical evidence plus strict current-host receipt'
  node tools/evidence-index.mjs check-portable "$receipt"
else
  printf '%s\n' '==> strict issuer-host machine evidence and receipt drift check'
  node tools/evidence-index.mjs check
  node tools/evidence-index.mjs check-current "$receipt"
fi

printf '%s\n' '==> reproducible CycloneDX software bill of materials'
bash scripts/verify-sbom.sh

printf '%s\n' '==> differential language parser/checker'
bash scripts/test-differential-reference-preflight.sh
bash scripts/verify-differential-language.sh

printf '%s\n' '==> native C ABI and zero-copy borrowed payloads'
bash scripts/verify-native-abi.sh

printf '%s\n' '==> isolated native host process'
bash scripts/verify-host-executor.sh

printf '%s\n' '==> atomic two-binary release installation rollback'
bash scripts/verify-release-installation.sh

printf '%s\n' '==> experimental Cranelift native backend'
bash scripts/verify-native-backend.sh

printf '%s\n' '==> native backend comparative smoke corpus'
bash scripts/verify-native-benchmark.sh

printf '%s\n' '==> independent native rerun package'
bash scripts/verify-independent-rerun.sh

printf '%s\n' '==> AI-agent language scorecard'
bash scripts/verify-agent-scorecard.sh

if [[ "$evidence_mode" == "portable" ]]; then
  printf '%s\n' '==> portable PR trust prerequisite (no issuer-host envelope)'
  bash scripts/verify-pr-trust.sh --portable-evidence "$receipt"
else
  printf '%s\n' '==> offline PR trust envelope'
  bash scripts/verify-pr-trust.sh
fi

printf 'JOAN local verification and evidence-receipt gates passed (%s mode).\n' "$evidence_mode"
