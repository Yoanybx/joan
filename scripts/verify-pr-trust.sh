#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

target_dir="${CARGO_TARGET_DIR:-target}"
binary="$target_dir/debug/joan"
envelope="$(mktemp "${TMPDIR:-/tmp}/joan-pr-trust-envelope.XXXXXX")"
verified="$(mktemp "${TMPDIR:-/tmp}/joan-pr-trust-verified.XXXXXX")"
trap 'rm -f "$envelope" "$verified"' EXIT

cargo build --quiet --locked -p joan-node

"$binary" trust pr evaluate . --base HEAD^ --head HEAD --json > "$envelope"
"$binary" trust pr verify . "$envelope" --json > "$verified"
cmp --silent "$envelope" "$verified"

node - "$envelope" <<'NODE'
import { readFileSync } from "node:fs";

const path = process.argv[2];
const envelope = JSON.parse(readFileSync(path, "utf8"));
const fail = (message) => {
  throw new Error(message);
};

if (envelope.schema !== "joan.pr-trust-envelope.v0") fail("unexpected envelope schema");
if (envelope.status !== "requirements-satisfied") fail("unexpected assessment status");
if (
  envelope.claim_scope !==
  "offline-local-evidence-binding-not-code-safety-or-pr-approval"
) {
  fail("unexpected claim scope");
}
if (envelope.network_policy !== "denied-no-network-client") fail("network policy drift");
if (envelope.write_policy !== "denied") fail("write policy drift");
if (envelope.telemetry_policy !== "none") fail("telemetry policy drift");
if (envelope.evidence.verification_run_ids.length !== 3) fail("receipt count drift");
if (envelope.evidence.required_gate_ids.length !== 10) fail("gate count drift");
if (envelope.evidence.jce1_passed !== 27) fail("JCE1 count drift");
if (envelope.evidence.dispute_cases !== 10000) fail("dispute count drift");
if (envelope.evidence.vulnerabilities_found !== 0) fail("vulnerability count drift");
if (envelope.program.planned_effect !== "publish_pr_assessment") {
  fail("planned effect drift");
}
if (envelope.program.authority_slot !== "publish_once") fail("authority slot drift");
if (envelope.program.instructions_executed > envelope.program.instruction_budget) {
  fail("instruction budget exceeded");
}
if (!Array.isArray(envelope.limitations) || envelope.limitations.length !== 4) {
  fail("limitations drift");
}
NODE

printf '%s\n' 'JOAN offline PR trust envelope passed deterministic re-verification.'
