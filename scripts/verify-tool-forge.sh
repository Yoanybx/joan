#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

for tool in cargo node; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'required Tool Forge verification tool is unavailable: %s\n' "$tool" >&2
    exit 3
  fi
done

if [[ -n "${JOAN_TOOL_FORGE_TMPDIR:-}" ]]; then
  temporary_root="$JOAN_TOOL_FORGE_TMPDIR"
elif [[ -d /Volumes/JOANBuild ]]; then
  temporary_root=/Volumes/JOANBuild/tmp
else
  temporary_root="${TMPDIR:-/tmp}"
fi
mkdir -p "$temporary_root"
work="$(mktemp -d "$temporary_root/joan-tool-forge.XXXXXX")"
trap 'rm -rf "$work"' EXIT

spec="$root/vectors/tool-forge-v0/pure-add-spec.jce1.json"
invalid="$root/vectors/tool-forge-v0/invalid-no-tests.jce1.json"
spec_receipt="$work/spec-receipt.json"
invalid_receipt="$work/invalid-receipt.json"
bundle_a="$work/bundle-a.json"
bundle_b="$work/bundle-b.json"
verification="$work/verification.json"
forged_verification="$work/forged-verification.json"
candidate="$work/candidate.json"
self_candidate="$work/self-candidate.json"
finalization="$work/finalization.json"
self_finalization="$work/self-finalization.json"
forged_finalization="$work/forged-finalization.json"
fabricated_finalization="$work/fabricated-finalization.json"
promotion="$work/promotion.json"
fabricated_promotion="$work/fabricated-promotion.json"

cargo run --quiet --locked -p joan-node -- tool spec verify "$spec" --json > "$spec_receipt"
cargo run --quiet --locked -p joan-node -- tool spec verify "$invalid" --json > "$invalid_receipt"
cargo run --quiet --locked -p joan-node -- tool forge "$spec" --json > "$bundle_a"
cargo run --quiet --locked -p joan-node -- tool forge "$spec" --json > "$bundle_b"
cmp "$bundle_a" "$bundle_b"
cargo run --quiet --locked -p joan-node -- tool verify "$spec" "$bundle_a" --json > "$verification"

node --input-type=module - "$bundle_a" "$verification" "$forged_verification" "$candidate" "$self_candidate" <<'NODE'
import { readFileSync, writeFileSync } from "node:fs";

const [bundlePath, verificationPath, forgedVerificationPath, candidatePath, selfCandidatePath] = process.argv.slice(2);
const bundle = JSON.parse(readFileSync(bundlePath, "utf8"));
const verification = JSON.parse(readFileSync(verificationPath, "utf8"));
const canonical = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
};
const vote = (guardian_id, role) => ({
  candidate_root: bundle.bundle_digest,
  decision: "approve",
  evidence: [bundle.source_digest, bundle.bytecode_digest],
  guardian_id,
  role,
});
const candidate = {
  approval_threshold: 3,
  candidate_root: bundle.bundle_digest,
  proposer_id: "tool-generator",
  required_roles: ["semantic-verifier", "test-guardian", "policy-gatekeeper"],
  schema: "joan.guardian-candidate.v0",
  votes: [
    vote("semantic-verifier", "semantic-verifier"),
    vote("test-verifier", "test-guardian"),
    vote("policy-verifier", "policy-gatekeeper"),
  ],
};
writeFileSync(candidatePath, `${canonical(candidate)}\n`);
writeFileSync(selfCandidatePath, `${canonical({ ...candidate, proposer_id: "semantic-verifier" })}\n`);
writeFileSync(forgedVerificationPath, `${canonical({ ...verification, tests_passed: 0 })}\n`);
NODE

cargo run --quiet --locked -p joan-node -- tool finalize \
  "$spec" "$bundle_a" "$verification" "$candidate" --json > "$finalization"
cargo run --quiet --locked -p joan-node -- tool finalize \
  "$spec" "$bundle_a" "$verification" "$self_candidate" --json > "$self_finalization"
cargo run --quiet --locked -p joan-node -- tool finalize \
  "$spec" "$bundle_a" "$forged_verification" "$candidate" --json > "$forged_finalization"

node --input-type=module - "$finalization" "$verification" "$fabricated_finalization" <<'NODE'
import { readFileSync, writeFileSync } from "node:fs";
const [finalizationPath, verificationPath, outputPath] = process.argv.slice(2);
const finalization = JSON.parse(readFileSync(finalizationPath, "utf8"));
const verification = JSON.parse(readFileSync(verificationPath, "utf8"));
const canonical = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
};
writeFileSync(outputPath, `${canonical({ ...finalization, receipt_digest: verification.receipt_digest })}\n`);
NODE

cargo run --quiet --locked -p joan-node -- tool promotion evaluate \
  "$spec" "$bundle_a" "$verification" "$candidate" "$finalization" --json > "$promotion"
cargo run --quiet --locked -p joan-node -- tool promotion evaluate \
  "$spec" "$bundle_a" "$verification" "$candidate" "$fabricated_finalization" --json > "$fabricated_promotion"

node - "$spec_receipt" "$invalid_receipt" "$verification" "$finalization" "$self_finalization" "$forged_finalization" "$promotion" "$fabricated_promotion" <<'NODE'
const { readFileSync } = require("node:fs");
const documents = process.argv.slice(2).map((path) => JSON.parse(readFileSync(path, "utf8")));
const [spec, invalid, verification, finalization, selfFinalization, forgedFinalization, promotion, fabricatedPromotion] = documents;
if (
  spec.status !== "verified" ||
  invalid.status !== "rejected" ||
  !invalid.findings.some((finding) => finding.code === "TF0006") ||
  verification.status !== "verified" ||
  verification.tests_passed !== 2 ||
  verification.generations_byte_identical !== true ||
  verification.external_effects_executed !== false ||
  finalization.status !== "finalized" ||
  selfFinalization.status !== "quarantined" ||
  !selfFinalization.findings.some((finding) => finding.code === "TF2006") ||
  forgedFinalization.status !== "quarantined" ||
  !forgedFinalization.findings.some((finding) => finding.code === "TF2002") ||
  promotion.status !== "eligible" ||
  fabricatedPromotion.status !== "quarantined"
) {
  throw new Error("Tool Forge end-to-end qualification guard failed");
}
process.stdout.write(`${JSON.stringify({
  status: "passed",
  generation_passes: 3,
  behavior_tests: 2,
  negative_controls: 4,
  external_effects_executed: 0,
})}\n`);
NODE
