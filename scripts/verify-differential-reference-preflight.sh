#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

scanner="${JOAN_DIFFERENTIAL_RG_BIN:-rg}"
if ! command -v "$scanner" >/dev/null 2>&1; then
  printf 'required differential scanner is unavailable: %s\n' "$scanner" >&2
  exit 3
fi

scan_status=0
"$scanner" -n 'from "\.\./(crates|target)|node:(net|http|https|tls|dgram)' \
  reference/joan-ref.mjs || scan_status=$?

case "$scan_status" in
  0)
    printf '%s\n' 'independent reference imports implementation or network modules' >&2
    exit 1
    ;;
  1)
    ;;
  *)
    printf 'differential import scanner failed with status %s\n' "$scan_status" >&2
    exit 3
    ;;
esac
