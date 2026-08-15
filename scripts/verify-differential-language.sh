#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

target_dir="${CARGO_TARGET_DIR:-target}"
if [[ "$target_dir" != /* ]]; then
  target_dir="$root/$target_dir"
fi
binary="$target_dir/debug/joan"
external_tmp="${JOAN_DIFFERENTIAL_TMPDIR:-${TMPDIR:-/tmp}}"
mkdir -p "$external_tmp"
work="$(mktemp -d "$external_tmp/joan-language-differential.XXXXXX")"
first="$work/report-first.json"
second="$work/report-second.json"
negative_corpus="$work/negative-corpus.json"
negative_report="$work/negative-report.json"
trap 'rm -rf "$work"' EXIT

bash scripts/verify-differential-reference-preflight.sh

cargo build --quiet --locked -p joan-node

JOAN_DIFFERENTIAL_TMPDIR="$external_tmp" node tools/language-differential-runner.mjs \
  "$binary" vectors/language-differential/corpus-v1.json "$first" >/dev/null
JOAN_DIFFERENTIAL_TMPDIR="$external_tmp" node tools/language-differential-runner.mjs \
  "$binary" vectors/language-differential/corpus-v1.json "$second" >/dev/null
cmp "$first" "$second"

node - "$first" <<'NODE'
const { readFileSync } = require("node:fs");
const report = JSON.parse(readFileSync(process.argv[2], "utf8"));
if (
  report.schema !== "joan.language-differential-report.v1" ||
  report.total !== 76 ||
  report.passed !== 76 ||
  report.failed !== 0 ||
  report.mutation_count !== 32 ||
  report.results.length !== 76
) {
  throw new Error("unexpected differential report totals");
}
if (!report.results.some((item) => item.expected.status === "accepted")) {
  throw new Error("accepted differential coverage is missing");
}
if (!report.results.some((item) => item.expected.phase === "lex")) {
  throw new Error("lex rejection coverage is missing");
}
if (!report.results.some((item) => item.expected.phase === "parse")) {
  throw new Error("parse rejection coverage is missing");
}
if (!report.results.some((item) => item.expected.status === "rejected" && item.expected.phase === "check")) {
  throw new Error("static-check rejection coverage is missing");
}
NODE

node - vectors/language-differential/corpus-v1.json "$negative_corpus" <<'NODE'
const { readFileSync, writeFileSync } = require("node:fs");
const corpus = JSON.parse(readFileSync(process.argv[2], "utf8"));
const target = corpus.cases.find((item) => item.id === "C001");
target.expected = { phase: "check", status: "accepted" };
writeFileSync(process.argv[3], `${JSON.stringify(corpus)}\n`, "utf8");
NODE

if JOAN_DIFFERENTIAL_TMPDIR="$external_tmp" node tools/language-differential-runner.mjs \
  "$binary" "$negative_corpus" "$negative_report" >/dev/null; then
  printf '%s\n' 'deliberate corpus disagreement was not detected' >&2
  exit 1
fi
node - "$negative_report" <<'NODE'
const { readFileSync } = require("node:fs");
const report = JSON.parse(readFileSync(process.argv[2], "utf8"));
const target = report.results.find((item) => item.id === "C001");
if (report.failed !== 1 || target?.status !== "failed") {
  throw new Error("deliberate disagreement did not fail exactly one case");
}
NODE

printf '%s\n' 'JOAN differential language gate passed 76/76 with deterministic replay and fail-closed disagreement detection.'
