#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

payload_bytes="${1:-4096}"
iterations="${2:-20000}"
target_dir="${CARGO_TARGET_DIR:-target}"
if [[ "$target_dir" != /* ]]; then
  target_dir="$root/$target_dir"
fi
joan_binary="$target_dir/release/joan"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/joan-benchmark.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT
c_binary="$temporary_directory/jce1-digest-c"

case "$(uname -s)" in
  Darwin) cc -O3 -std=c11 -Wall -Wextra -Werror benchmarks/c/jce1_digest.c -o "$c_binary" ;;
  Linux) cc -O3 -std=c11 -Wall -Wextra -Werror benchmarks/c/jce1_digest.c -o "$c_binary" -lcrypto ;;
  *) printf 'unsupported benchmark platform: %s\n' "$(uname -s)" >&2; exit 3 ;;
esac

cargo build --quiet --release -p joan-node
rust_report="$temporary_directory/rust.jsonl"
c_report="$temporary_directory/c.jsonl"
for _ in 1 2 3 4 5; do
  "$joan_binary" benchmark digest-v1 --bytes "$payload_bytes" --iterations "$iterations" --json >> "$rust_report"
  "$c_binary" "$payload_bytes" "$iterations" >> "$c_report"
done

node tools/compare-digest-benchmark.mjs "$rust_report" "$c_report"
