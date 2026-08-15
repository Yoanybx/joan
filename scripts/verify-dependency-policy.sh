#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v cargo-deny >/dev/null 2>&1; then
  printf '%s\n' 'required dependency policy tool is unavailable: cargo-deny' >&2
  exit 3
fi
if [[ "$(cargo-deny --version)" != "cargo-deny 0.20.2" ]]; then
  printf 'dependency policy requires cargo-deny 0.20.2; found %s\n' "$(cargo-deny --version)" >&2
  exit 3
fi

output="$(mktemp "${TMPDIR:-/tmp}/joan-dependency-policy.XXXXXX")"
trap 'rm -f "$output"' EXIT

if ! cargo deny --locked check -D unmatched-skip bans >"$output" 2>&1; then
  cat "$output" >&2
  exit 1
fi
if ! grep -q '^bans ok$' "$output"; then
  cat "$output" >&2
  printf '%s\n' 'cargo-deny did not report a successful bans result' >&2
  exit 1
fi
if grep -Eq '(warning|error)\[' "$output"; then
  cat "$output" >&2
  printf '%s\n' 'dependency policy emitted an unexpected diagnostic' >&2
  exit 1
fi

printf '%s\n' 'dependency duplicate policy passed with exact reviewed exceptions.'
