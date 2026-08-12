#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

for tool in cargo-audit cargo-deny; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'required verification tool is unavailable: %s\n' "$tool" >&2
    exit 3
  fi
done

receipt="$(mktemp "${TMPDIR:-/tmp}/joan-verification-receipt.XXXXXX")"
trap 'rm -f "$receipt"' EXIT

node tools/verification-runner.mjs "$receipt"

printf '%s\n' '==> machine evidence and receipt drift check'
node tools/evidence-index.mjs check

printf '%s\n' '==> offline PR trust envelope'
bash scripts/verify-pr-trust.sh

printf '%s\n' 'JOAN local verification and evidence-receipt gates passed.'
