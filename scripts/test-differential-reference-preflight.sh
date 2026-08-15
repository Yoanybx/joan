#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

external_tmp="${JOAN_DIFFERENTIAL_TMPDIR:-${TMPDIR:-/tmp}}"
mkdir -p "$external_tmp"
work="$(mktemp -d "$external_tmp/joan-differential-preflight.XXXXXX")"
missing_log="$work/missing.log"
failure_log="$work/failure.log"
trap 'rm -rf "$work"' EXIT

bash scripts/verify-differential-reference-preflight.sh

missing_status=0
JOAN_DIFFERENTIAL_RG_BIN="$work/rg-missing" \
  bash scripts/verify-differential-reference-preflight.sh \
  > /dev/null 2> "$missing_log" || missing_status=$?
if [[ "$missing_status" -ne 3 ]]; then
  printf 'missing scanner returned %s instead of 3\n' "$missing_status" >&2
  exit 1
fi
missing_message="$(<"$missing_log")"
if [[ "$missing_message" != *"required differential scanner is unavailable"* ]]; then
  printf '%s\n' 'missing scanner diagnostic was not emitted' >&2
  exit 1
fi

failure_status=0
JOAN_DIFFERENTIAL_RG_BIN="/bin/sh" \
  bash scripts/verify-differential-reference-preflight.sh \
  > /dev/null 2> "$failure_log" || failure_status=$?
if [[ "$failure_status" -ne 3 ]]; then
  printf 'failing scanner returned %s instead of 3\n' "$failure_status" >&2
  exit 1
fi
failure_message="$(<"$failure_log")"
if [[ "$failure_message" != *"differential import scanner failed with status"* ]]; then
  printf '%s\n' 'scanner failure diagnostic was not emitted' >&2
  exit 1
fi

printf '%s\n' 'JOAN differential reference preflight passed fail-closed dependency controls.'
