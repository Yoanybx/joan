#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

for tool in cc node rustc; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'required agent-scorecard tool is unavailable: %s\n' "$tool" >&2
    exit 3
  fi
done

node_major="$(node -p 'Number(process.versions.node.split(".")[0])')"
if (( node_major < 24 )); then
  printf 'Node.js 24 or newer is required for native TypeScript stripping\n' >&2
  exit 3
fi

target_dir="${CARGO_TARGET_DIR:-target}"
if [[ "$target_dir" != /* ]]; then
  target_dir="$root/$target_dir"
fi
binary="$target_dir/release/joan"
scorecard_tmp="${JOAN_SCORECARD_TMPDIR:-${TMPDIR:-/tmp}}"
mkdir -p "$scorecard_tmp"
work="$(mktemp -d "$scorecard_tmp/joan-agent-scorecard-gate.XXXXXX")"
trap 'rm -rf "$work"' EXIT

cargo build --quiet --release --locked -p joan-node -p joan-executor

report="$work/report.json"
JOAN_SCORECARD_TMPDIR="$scorecard_tmp" node tools/agent-scorecard-runner.mjs \
  "$binary" benchmarks/agent-scorecard/workloads-v1.json "$report" \
  --samples 3 --prepare-samples 1 --mode smoke >/dev/null

node - "$report" <<'NODE'
const fs = require("node:fs");
const report = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
function assert(condition, message) {
  if (!condition) throw new Error(message);
}
assert(report.schema === "joan.agent-scorecard-report.v1", "unexpected report schema");
assert(report.qualification.status === "baseline-only-not-qualified", "unexpected qualification");
assert(report.qualification.eligible === false, "baseline became eligible");
assert(report.qualification.correctness_equivalent === true, "output equivalence failed");
assert(report.universal_language_superiority_claim === false, "universal claim must remain false");
assert(report.workloads.length === 2, "unexpected workload count");
assert(report.safety.case_count === 4, "unexpected safety case count");
assert(report.safety.protection.joan.protected === 4, "JOAN did not protect every frozen case");
assert(report.safety.protection.joan.total === 4, "unexpected JOAN safety total");
NODE

negative_manifest="$work/negative-workloads.json"
node - benchmarks/agent-scorecard/workloads-v1.json "$negative_manifest" <<'NODE'
const fs = require("node:fs");
const input = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
input.workloads[0].expected_output.result.value = "43";
fs.writeFileSync(process.argv[3], `${JSON.stringify(input)}\n`, { flag: "wx" });
NODE

if JOAN_SCORECARD_TMPDIR="$scorecard_tmp" node tools/agent-scorecard-runner.mjs \
  "$binary" "$negative_manifest" "$work/negative-report.json" \
  --samples 3 --prepare-samples 1 --mode smoke >/dev/null 2>&1; then
  printf 'agent scorecard accepted deliberately inequivalent output\n' >&2
  exit 1
fi

printf '%s\n' 'JOAN AI-agent scorecard gate passed: 2 equivalent workloads, 4 safety probes, negative equivalence control rejected.'
