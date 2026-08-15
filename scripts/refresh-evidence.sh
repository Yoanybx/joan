#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

for tool in cargo-audit cargo-cyclonedx cargo-deny; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'required evidence tool is unavailable: %s\n' "$tool" >&2
    exit 3
  fi
done

receipt_directory='.joan/evidence/runs'
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/joan-evidence-refresh.XXXXXX")"
backup_directory="$temporary_directory/previous"
mkdir -p "$receipt_directory"
mkdir -p "$backup_directory/runs"
receipts=()
installed=0
committed=0

cleanup() {
  if (( installed == 1 && committed == 0 )); then
    for ordinal in 1 2 3; do
      receipt="$receipt_directory/run-$ordinal.json"
      backup="$backup_directory/runs/run-$ordinal.json"
      if [[ -f "$backup" ]]; then
        cp "$backup" "$receipt"
      else
        rm -f -- "$receipt"
      fi
    done
    if [[ -f "$backup_directory/latest.json" ]]; then
      cp "$backup_directory/latest.json" '.joan/evidence/latest.json'
    else
      rm -f -- '.joan/evidence/latest.json'
    fi
    printf '%s\n' 'JOAN evidence refresh failed; previous receipts and index restored.' >&2
  fi
  rm -rf -- "$temporary_directory"
}
trap cleanup EXIT

for ordinal in 1 2 3; do
  receipt="$temporary_directory/run-$ordinal.json"
  printf '==> complete verification receipt %s of 3\n' "$ordinal"
  node tools/verification-runner.mjs "$receipt"
done

for ordinal in 1 2 3; do
  current="$receipt_directory/run-$ordinal.json"
  if [[ -f "$current" ]]; then
    cp "$current" "$backup_directory/runs/run-$ordinal.json"
  fi
done
if [[ -f '.joan/evidence/latest.json' ]]; then
  cp '.joan/evidence/latest.json' "$backup_directory/latest.json"
fi

installed=1
for ordinal in 1 2 3; do
  staged="$receipt_directory/.run-$ordinal.next.json"
  cp "$temporary_directory/run-$ordinal.json" "$staged"
  mv "$staged" "$receipt_directory/run-$ordinal.json"
  receipts+=("$receipt_directory/run-$ordinal.json")
done

node tools/evidence-index.mjs write "${receipts[@]}"
node tools/evidence-index.mjs check
committed=1

printf '%s\n' 'JOAN evidence refreshed from three complete local execution receipts.'
