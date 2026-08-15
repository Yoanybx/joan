#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

for tool in cargo clang clang++ node rustc; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'required native benchmark tool is unavailable: %s\n' "$tool" >&2
    exit 3
  fi
done

if [[ -n "${JOAN_NATIVE_BENCHMARK_TMPDIR:-}" ]]; then
  benchmark_tmp="$JOAN_NATIVE_BENCHMARK_TMPDIR"
elif [[ -d /Volumes/JOANBuild ]]; then
  benchmark_tmp=/Volumes/JOANBuild/tmp
elif [[ -d "/Volumes/ParallesWin 1/JOAN/tmp" ]]; then
  benchmark_tmp="/Volumes/ParallesWin 1/JOAN/tmp"
else
  benchmark_tmp="${TMPDIR:-/tmp}"
fi
mkdir -p "$benchmark_tmp"
work="$(mktemp -d "$benchmark_tmp/joan-native-benchmark-gate.XXXXXX")"
trap 'rm -rf "$work"' EXIT

node tools/native-backend-benchmark.mjs --self-test >/dev/null

cargo build --quiet --release --locked -p joan-node -p joan-executor -p joan-native \
  --features joan-native/benchmark-tools --bin joan --bin joan-native-bench

report="$work/report.json"
JOAN_NATIVE_BENCHMARK_TMPDIR="$benchmark_tmp" node tools/native-backend-benchmark.mjs \
  benchmarks/native-backend/manifest-v0.json "$report" \
  --mode smoke >/dev/null

if node tools/native-backend-benchmark.mjs \
  benchmarks/native-backend/manifest-v0.json "$root/invalid-in-tree-report.json" \
  --mode smoke >/dev/null 2>&1; then
  printf '%s\n' 'native benchmark accepted a self-referential in-tree report path' >&2
  exit 1
fi

for invalid in \
  "--samples 3 --iterations 1000000 --rss-samples 11" \
  "--samples 101 --iterations 100000 --rss-samples 11" \
  "--samples 101 --iterations 1000000 --rss-samples 3"; do
  if JOAN_NATIVE_BENCHMARK_TMPDIR="$benchmark_tmp" node tools/native-backend-benchmark.mjs \
    benchmarks/native-backend/manifest-v0.json "$work/invalid-recorded.json" \
    --mode recorded $invalid >/dev/null 2>&1; then
    printf '%s\n' "recorded benchmark accepted invalid sampling contract: $invalid" >&2
    exit 1
  fi
done

JOAN_NATIVE_BACKEND_REPORT_INPUT="$report" \
  cargo test --quiet --locked -p joan-node --test repository_contracts \
    native_backend_report_matches_its_schema_when_supplied

node - "$report" <<'NODE'
const { readFileSync } = require("node:fs");
const report = JSON.parse(readFileSync(process.argv[2], "utf8"));
if (
  report.schema !== "joan.native-backend-benchmark-report.v0" ||
  report.status !== "local-benchmark-not-qualified" ||
  report.workloads.length !== 5 ||
  report.workloads.some((workload) => !workload.output_equivalent) ||
  report.qualification.status !== "not-qualified" ||
  report.qualification.independent_rerun !== false ||
  report.qualification.universal_language_superiority_claim !== false ||
  report.oracle.independent_from_measured_implementations !== true ||
  report.oracle.verified_cases !== 15 ||
  report.oracle.observations.length !== 15
) {
  throw new Error("native benchmark qualification guard failed");
}
if (!report.measurement_contract.observation_digest.includes("excluding only compile_ns and runtime_ns")) {
  throw new Error("native benchmark semantic observation digest contract is absent");
}
for (const workload of report.workloads) {
  const positionCounts = Object.fromEntries(
    report.available_implementations.map((id) => [id, Array(report.available_implementations.length).fill(0)]),
  );
  for (const scheduled of workload.schedule) {
    scheduled.order.forEach((id, index) => { positionCounts[id][index] += 1; });
  }
  for (const [id, counts] of Object.entries(positionCounts)) {
    if (Math.max(...counts) - Math.min(...counts) > 1) {
      throw new Error(`${workload.id}/${id} execution order is not position-balanced`);
    }
  }
  for (const result of Object.values(workload.implementations)) {
    if (
      result.inner_runtime.samples_ns.length !== 3 ||
      result.observation_sha256.length !== 3 ||
      result.process_time.samples_ns.length !== 3 ||
      result.peak_rss.samples_bytes.length !== 3
    ) throw new Error("native benchmark raw samples are incomplete");
  }
}
NODE

printf '%s\n' 'JOAN native benchmark smoke passed: 5 equivalent dynamic kernels; qualification remains false.'
