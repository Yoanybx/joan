#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

for tool in cargo-audit cargo-deny; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'required verification tool is unavailable: %s\n' "$tool" >&2
    exit 3
  fi
done

if [[ -n "${JOAN_VERIFICATION_RECEIPT_OUTPUT:-}" ]]; then
  receipt="$JOAN_VERIFICATION_RECEIPT_OUTPUT"
  mkdir -p "$(dirname "$receipt")"
else
  receipt="$(mktemp "${TMPDIR:-/tmp}/joan-verification-receipt.XXXXXX")"
  trap 'rm -f "$receipt"' EXIT
fi

node tools/verification-runner.mjs "$receipt"

printf '%s\n' '==> machine evidence and receipt drift check'
node tools/evidence-index.mjs check

printf '%s\n' '==> differential language parser/checker'
bash scripts/test-differential-reference-preflight.sh
bash scripts/verify-differential-language.sh

printf '%s\n' '==> native C ABI and zero-copy borrowed payloads'
bash scripts/verify-native-abi.sh

printf '%s\n' '==> experimental Cranelift native backend'
bash scripts/verify-native-backend.sh

printf '%s\n' '==> native backend comparative smoke corpus'
bash scripts/verify-native-benchmark.sh

printf '%s\n' '==> independent native rerun package'
bash scripts/verify-independent-rerun.sh

printf '%s\n' '==> AI-agent language scorecard'
bash scripts/verify-agent-scorecard.sh

printf '%s\n' '==> offline PR trust envelope'
bash scripts/verify-pr-trust.sh

printf '%s\n' 'JOAN local verification and evidence-receipt gates passed.'
