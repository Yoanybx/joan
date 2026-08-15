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
native_report='.joan/evidence/native-abi-v1.json'
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/joan-evidence-refresh.XXXXXX")"
backup_directory="$temporary_directory/previous"
temporary_native_report="$temporary_directory/native-abi-v1.json"
mkdir -p "$receipt_directory"
mkdir -p "$backup_directory/runs"
receipts=()
installed=0
committed=0

cleanup() {
  for ordinal in 1 2 3; do
    rm -f -- "$receipt_directory/.run-$ordinal.next.json"
  done
  rm -f -- "$receipt_directory/.native-abi-v1.next.json"
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
    if [[ -f "$backup_directory/native-abi-v1.json" ]]; then
      cp "$backup_directory/native-abi-v1.json" "$native_report"
    else
      rm -f -- "$native_report"
    fi
    printf '%s\n' 'JOAN evidence refresh failed; previous receipts, index and native ABI report restored.' >&2
  fi
  rm -rf -- "$temporary_directory"
}
trap cleanup EXIT

for ordinal in 1 2 3; do
  receipt="$temporary_directory/run-$ordinal.json"
  printf '==> complete verification receipt %s of 3\n' "$ordinal"
  node tools/verification-runner.mjs "$receipt"
done

printf '%s\n' '==> native ABI evidence'
JOAN_NATIVE_ABI_REPORT="$temporary_native_report" ./scripts/verify-native-abi.sh

for ordinal in 1 2 3; do
  current="$receipt_directory/run-$ordinal.json"
  if [[ -f "$current" ]]; then
    cp "$current" "$backup_directory/runs/run-$ordinal.json"
  fi
done
if [[ -f '.joan/evidence/latest.json' ]]; then
  cp '.joan/evidence/latest.json' "$backup_directory/latest.json"
fi
if [[ -f "$native_report" ]]; then
  cp "$native_report" "$backup_directory/native-abi-v1.json"
fi

installed=1
for ordinal in 1 2 3; do
  staged="$receipt_directory/.run-$ordinal.next.json"
  cp "$temporary_directory/run-$ordinal.json" "$staged"
  mv "$staged" "$receipt_directory/run-$ordinal.json"
  receipts+=("$receipt_directory/run-$ordinal.json")
done
staged_native_report="$receipt_directory/.native-abi-v1.next.json"
cp "$temporary_native_report" "$staged_native_report"
mv "$staged_native_report" "$native_report"

node tools/evidence-index.mjs write "${receipts[@]}"
node tools/evidence-index.mjs check
committed=1

printf '%s\n' 'JOAN evidence refreshed from three complete local execution receipts and native ABI evidence.'
