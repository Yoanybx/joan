#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v node >/dev/null 2>&1; then
  printf '%s\n' 'JCE1 verification requires Node.js 24 or newer.' >&2
  exit 3
fi

node_major="$(node -p 'Number(process.versions.node.split(".")[0])')"
if (( node_major < 24 )); then
  printf 'JCE1 verification requires Node.js 24 or newer; found %s.\n' "$(node --version)" >&2
  exit 3
fi

temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/joan-jce1.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT

suite='vectors/jce1/conformance-v1.json'
rust_report="$temporary_directory/rust.json"
node_report="$temporary_directory/node.json"

printf '%s\n' '==> JCE1 Rust conformance'
cargo run --quiet -p joan-node -- conformance jce1 "$suite" --json > "$rust_report"

printf '%s\n' '==> JCE1 independent Node conformance'
node tools/jce1-reference.mjs conformance "$suite" > "$node_report"

printf '%s\n' '==> JCE1 cross-implementation comparison'
node tools/compare-jce1-reports.mjs "$rust_report" "$node_report"

printf '%s\n' '==> JCE1 invalid UTF-8 rejection'
invalid_utf8_hex="$(tr -d '\n' < vectors/jce1/invalid-utf8.hex)"
if node -e 'process.stdout.write(Buffer.from(process.argv[1], "hex"))' "$invalid_utf8_hex" \
  | node tools/jce1-reference.mjs canonicalize - >/dev/null 2>&1; then
  printf '%s\n' 'Node reference accepted invalid UTF-8' >&2
  exit 1
fi
if node -e 'process.stdout.write(Buffer.from(process.argv[1], "hex"))' "$invalid_utf8_hex" \
  | cargo run --quiet -p joan-node -- canonicalize-v1 - >/dev/null 2>&1; then
  printf '%s\n' 'Rust implementation accepted invalid UTF-8' >&2
  exit 1
fi

printf '%s\n' 'JCE1 cross-implementation and invalid-byte gates passed.'
