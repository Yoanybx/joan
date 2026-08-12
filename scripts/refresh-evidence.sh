#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

for tool in cargo-audit cargo-deny; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'required evidence tool is unavailable: %s\n' "$tool" >&2
    exit 3
  fi
done

receipt_directory='.joan/evidence/runs'
mkdir -p "$receipt_directory"
receipts=()

for ordinal in 1 2 3; do
  receipt="$receipt_directory/run-$ordinal.json"
  printf '==> complete verification receipt %s of 3\n' "$ordinal"
  node tools/verification-runner.mjs "$receipt"
  receipts+=("$receipt")
done

node tools/evidence-index.mjs write "${receipts[@]}"
node tools/evidence-index.mjs check

printf '%s\n' 'JOAN evidence refreshed from three complete local execution receipts.'
