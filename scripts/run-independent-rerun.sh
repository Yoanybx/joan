#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if [[ $# -ne 1 || "$1" != /* ]]; then
  printf '%s\n' 'usage: bash scripts/run-independent-rerun.sh <absolute-output-directory>' >&2
  exit 2
fi
output="$(node -e 'const path = require("node:path"); process.stdout.write(path.resolve(process.argv[1]));' "$1")"
case "$output/" in
  "$root/"*)
    printf '%s\n' 'independent rerun output must remain outside the checkout' >&2
    exit 2
    ;;
esac
if [[ -e "$output" ]]; then
  printf 'output path already exists: %s\n' "$output" >&2
  exit 2
fi
if [[ -z "${CARGO_TARGET_DIR:-}" || "$CARGO_TARGET_DIR" != /* ]]; then
  printf '%s\n' 'CARGO_TARGET_DIR must be an absolute directory outside the checkout' >&2
  exit 2
fi
case "$CARGO_TARGET_DIR/" in
  "$root/"*)
    printf '%s\n' 'CARGO_TARGET_DIR must remain outside the checkout' >&2
    exit 2
    ;;
esac
if [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
  printf '%s\n' 'independent rerun requires a clean Git checkout' >&2
  exit 2
fi

case "$(uname -s)" in
  Darwin|Linux) ;;
  *)
    printf 'unsupported independent rerun host: %s\n' "$(uname -s)" >&2
    exit 3
    ;;
esac

for tool in bash cargo cargo-audit cargo-cyclonedx cargo-deny cc c++ clang clang++ git nm node rg rustc; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'required independent rerun tool is unavailable: %s\n' "$tool" >&2
    exit 3
  fi
done
if [[ "$(node --version)" != "v24.19.0" ]]; then
  printf 'independent rerun requires Node v24.19.0; found %s\n' "$(node --version)" >&2
  exit 3
fi
if [[ "$(rustc --version)" != "rustc 1.94.1 "* ]]; then
  printf 'independent rerun requires Rust 1.94.1; found %s\n' "$(rustc --version)" >&2
  exit 3
fi
if [[ "$(cargo-audit --version)" != "cargo-audit 0.22.2" ]]; then
  printf 'independent rerun requires cargo-audit 0.22.2; found %s\n' "$(cargo-audit --version)" >&2
  exit 3
fi
if [[ "$(cargo-deny --version)" != "cargo-deny 0.20.2" ]]; then
  printf 'independent rerun requires cargo-deny 0.20.2; found %s\n' "$(cargo-deny --version)" >&2
  exit 3
fi
if [[ "$(cargo-cyclonedx cyclonedx --version)" != "cargo-cyclonedx-cyclonedx 0.5.9" ]]; then
  printf 'independent rerun requires cargo-cyclonedx 0.5.9; found %s\n' \
    "$(cargo-cyclonedx cyclonedx --version)" >&2
  exit 3
fi

mkdir -p "$(dirname "$output")"
stage="$output.tmp-$$"
if [[ -e "$stage" ]]; then
  printf 'staging path already exists: %s\n' "$stage" >&2
  exit 2
fi
mkdir -p "$stage"
work="$stage/.work"
mkdir -p "$work"
trap 'rm -rf "$stage"' EXIT

manifest="$root/audit/independent-rerun-v0/manifest.json"
reference="$root/benchmarks/results/2026-08-13-mac15-4-native-backend.json"
recorded="$stage/native-backend-recorded.json"
verification="$stage/full-verification.json"
native_abi="$stage/native-abi-v1.json"
receipt="$stage/independent-rerun-receipt.json"
started_at="$(node -p 'new Date().toISOString()')"

node tools/independent-rerun.mjs validate-manifest "$manifest"
cargo build --quiet --release --locked -p joan-node -p joan-executor -p joan-native \
  --features joan-native/benchmark-tools --bin joan --bin joan-native-bench

JOAN_NATIVE_BENCHMARK_TMPDIR="$work" node tools/native-backend-benchmark.mjs \
  benchmarks/native-backend/manifest-v0.json "$recorded" --mode recorded

export JOAN_NATIVE_BACKEND_REPORT_INPUT="$recorded"
export JOAN_NATIVE_ABI_REPORT="$native_abi"
export JOAN_NATIVE_ABI_TMPDIR="$work"
export JOAN_NATIVE_BENCHMARK_TMPDIR="$work"
export JOAN_VERIFICATION_RECEIPT_OUTPUT="$verification"
bash scripts/verify-all.sh

node tools/independent-rerun.mjs finalize \
  "$manifest" "$reference" "$recorded" "$verification" "$native_abi" "$receipt" "$started_at"
JOAN_INDEPENDENT_RERUN_RECEIPT_INPUT="$receipt" \
  cargo test --quiet --locked -p joan-node --test repository_contracts \
    independent_rerun_receipt_matches_its_schema_when_supplied

rm -rf "$work"
trap - EXIT
mv "$stage" "$output"
printf 'JOAN technical rerun passed; independence remains unverified: %s\n' \
  "$output/independent-rerun-receipt.json"
