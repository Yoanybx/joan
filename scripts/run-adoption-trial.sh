#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if [[ $# -ne 2 || "$1" != /* ]]; then
  printf '%s\n' 'usage: bash scripts/run-adoption-trial.sh <absolute-output-directory> <independent|affiliated|undisclosed>' >&2
  exit 2
fi
output="$(node -e 'const path = require("node:path"); process.stdout.write(path.resolve(process.argv[1]));' "$1")"
relation="$2"
case "$relation" in
  independent|affiliated|undisclosed) ;;
  *)
    printf '%s\n' 'operator relation must be independent, affiliated or undisclosed' >&2
    exit 2
    ;;
esac
case "$output/" in
  "$root/"*)
    printf '%s\n' 'adoption trial output must remain outside the checkout' >&2
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
  printf '%s\n' 'adoption trial requires a clean Git checkout' >&2
  exit 2
fi

case "$(uname -s)" in
  Darwin|Linux) ;;
  *)
    printf 'unsupported adoption trial host: %s\n' "$(uname -s)" >&2
    exit 3
    ;;
esac
for tool in bash cargo git node rustc; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'required adoption trial tool is unavailable: %s\n' "$tool" >&2
    exit 3
  fi
done
if [[ "$(node --version)" != "v24.19.0" ]]; then
  printf 'adoption trial requires Node v24.19.0; found %s\n' "$(node --version)" >&2
  exit 3
fi
if [[ "$(rustc --version)" != "rustc 1.94.1 "* ]]; then
  printf 'adoption trial requires Rust 1.94.1; found %s\n' "$(rustc --version)" >&2
  exit 3
fi

mkdir -p "$(dirname "$output")"
stage="$output.tmp-$$"
if [[ -e "$stage" ]]; then
  printf 'staging path already exists: %s\n' "$stage" >&2
  exit 2
fi
trap 'rm -rf "$stage"' EXIT

manifest="$root/audit/adoption-trial-v1/manifest.json"
started_at="$(node -p 'new Date().toISOString()')"
build_started="$(node -p 'Date.now()')"
node tools/adoption-trial.mjs validate-manifest "$manifest"
cargo build --quiet --locked -p joan-node --bin joan
build_ms="$(node -p 'Date.now() - Number(process.argv[1])' "$build_started")"
joan_binary="$CARGO_TARGET_DIR/debug/joan"
node tools/adoption-trial.mjs run \
  "$manifest" "$joan_binary" "$stage" "$relation" "$started_at" "$build_ms"
JOAN_ADOPTION_TRIAL_RUN_RECEIPT_INPUT="$stage/adoption-trial-run-receipt.json" \
  cargo test --quiet --locked -p joan-node --test repository_contracts \
    adoption_trial_run_receipt_matches_its_schema_when_supplied

trap - EXIT
mv "$stage" "$output"
printf 'JOAN technical adoption trial passed; external qualification remains unverified: %s\n' \
  "$output/adoption-trial-run-receipt.json"
