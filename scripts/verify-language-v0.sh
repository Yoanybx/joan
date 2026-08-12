#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

target_dir="${CARGO_TARGET_DIR:-target}"
if [[ "$target_dir" != /* ]]; then
  target_dir="$root/$target_dir"
fi
binary="$target_dir/debug/joan"
receipt="$(mktemp "${TMPDIR:-/tmp}/joan-language-receipt.XXXXXX.json")"
artifact="$(mktemp "${TMPDIR:-/tmp}/joan-language-artifact.XXXXXX.json")"
bytecode="$(mktemp "${TMPDIR:-/tmp}/joan-language-bytecode.XXXXXX.json")"
verification="$(mktemp "${TMPDIR:-/tmp}/joan-language-verification.XXXXXX.json")"
linear_receipt="$(mktemp "${TMPDIR:-/tmp}/joan-linear-language-receipt.XXXXXX.json")"
linear_artifact="$(mktemp "${TMPDIR:-/tmp}/joan-linear-language-artifact.XXXXXX.json")"
flow_receipt="$(mktemp "${TMPDIR:-/tmp}/joan-flow-language-receipt.XXXXXX.json")"
flow_artifact="$(mktemp "${TMPDIR:-/tmp}/joan-flow-language-artifact.XXXXXX.json")"
flow_bytecode="$(mktemp "${TMPDIR:-/tmp}/joan-flow-language-bytecode.XXXXXX.json")"
flow_verification="$(mktemp "${TMPDIR:-/tmp}/joan-flow-language-verification.XXXXXX.json")"
trap 'rm -f "$receipt" "$artifact" "$bytecode" "$verification" "$linear_receipt" "$linear_artifact" "$flow_receipt" "$flow_artifact" "$flow_bytecode" "$flow_verification"' EXIT

cargo build --quiet --locked -p joan-node
"$binary" fmt examples/agent-handoff.joan --check
"$binary" check examples/agent-handoff.joan --json >/dev/null
"$binary" compile examples/agent-handoff.joan --json >"$artifact"
"$binary" run examples/agent-handoff.joan --json >"$receipt"
node -e 'process.stdout.write(JSON.stringify(JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8")).bytecode))' "$artifact" \
  | "$binary" canonicalize-v1 - >"$bytecode"
"$binary" bytecode verify "$bytecode" --json >"$verification"
"$binary" fmt examples/linear-agent-handoff.joan --check
"$binary" check examples/linear-agent-handoff.joan --json >/dev/null
"$binary" compile examples/linear-agent-handoff.joan --json >"$linear_artifact"
"$binary" run examples/linear-agent-handoff.joan --json >"$linear_receipt"
"$binary" fmt examples/tenant-safe-handoff.joan --check
"$binary" check examples/tenant-safe-handoff.joan --json >/dev/null
"$binary" compile examples/tenant-safe-handoff.joan --json >"$flow_artifact"
"$binary" run examples/tenant-safe-handoff.joan --json >"$flow_receipt"
node -e 'process.stdout.write(JSON.stringify(JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8")).bytecode))' "$flow_artifact" \
  | "$binary" canonicalize-v1 - >"$flow_bytecode"
"$binary" bytecode verify "$flow_bytecode" --json >"$flow_verification"

node - "$artifact" "$receipt" "$verification" "$linear_artifact" "$linear_receipt" "$flow_artifact" "$flow_receipt" "$flow_verification" <<'NODE'
const { readFileSync } = require("node:fs");
const artifact = JSON.parse(readFileSync(process.argv[2], "utf8"));
const receipt = JSON.parse(readFileSync(process.argv[3], "utf8"));
const verification = JSON.parse(readFileSync(process.argv[4], "utf8"));
const linearArtifact = JSON.parse(readFileSync(process.argv[5], "utf8"));
const linearReceipt = JSON.parse(readFileSync(process.argv[6], "utf8"));
const flowArtifact = JSON.parse(readFileSync(process.argv[7], "utf8"));
const flowReceipt = JSON.parse(readFileSync(process.argv[8], "utf8"));
const flowVerification = JSON.parse(readFileSync(process.argv[9], "utf8"));
if (artifact.schema !== "joan.compile-artifact.v1" || artifact.status !== "compiled") {
  throw new Error("compile artifact contract failed");
}
if (receipt.schema !== "joan.execution-receipt.v1" || receipt.status !== "completed") {
  throw new Error("execution receipt contract failed");
}
if (receipt.result.type !== "i64" || receipt.result.value !== "42") {
  throw new Error("unexpected deterministic result");
}
if (verification.schema !== "joan.bytecode-verification-receipt.v0" || verification.status !== "verified") {
  throw new Error("standalone bytecode verification contract failed");
}
if (receipt.effect_requests.length !== 1 || receipt.effect_requests[0].effect !== "network_send") {
  throw new Error("effect request was not receipted");
}
if (JSON.stringify(artifact.bytecode.semantic_digest) !== JSON.stringify(receipt.semantic_digest)) {
  throw new Error("compile and execution semantic identities differ");
}
const compiledIdentity = artifact.bytecode.semantic_identity;
const executedIdentity = receipt.semantic_identity;
if (
  compiledIdentity.schema !== "joan.canonical-ast-identity.v0" ||
  compiledIdentity.encoding !== "JCE1" ||
  compiledIdentity.ast_schema !== "joan.canonical-ast.v0" ||
  compiledIdentity.digest.algorithm !== "sha256" ||
  compiledIdentity.digest.profile !== "joan-hash-v1" ||
  compiledIdentity.digest.domain !== "joan.language-canonical-ast.v1"
) {
  throw new Error("compile artifact lacks the canonical AST identity contract");
}
if (JSON.stringify(compiledIdentity) !== JSON.stringify(executedIdentity)) {
  throw new Error("compile and execution canonical AST descriptors differ");
}
if (compiledIdentity.digest.value !== artifact.bytecode.semantic_digest.value) {
  throw new Error("semantic digest is not bound to the canonical AST identity");
}
if (JSON.stringify(artifact.verification) !== JSON.stringify(verification)) {
  throw new Error("compiler and standalone bytecode verification receipts differ");
}
if (JSON.stringify(receipt.bytecode_digest) !== JSON.stringify(verification.bytecode_digest)) {
  throw new Error("execution receipt is not bound to the verified bytecode identity");
}
if (
  linearArtifact.schema !== "joan.compile-artifact.v2" ||
  linearArtifact.bytecode.schema !== "joan.bytecode-program.v2" ||
  linearArtifact.bytecode.canonical_ast.schema !== "joan.canonical-ast.v1" ||
  linearArtifact.bytecode.semantic_identity.schema !== "joan.canonical-ast-identity.v1" ||
  linearArtifact.verification.schema !== "joan.bytecode-verification-receipt.v1" ||
  linearReceipt.schema !== "joan.execution-receipt.v2"
) {
  throw new Error("linear authority artifact profile failed");
}
if (
  linearReceipt.effect_requests.length !== 1 ||
  linearReceipt.effect_requests[0].authority_slot !== "send_once"
) {
  throw new Error("linear authority slot was not bound to the effect request");
}
if (
  flowArtifact.schema !== "joan.compile-artifact.v3" ||
  flowArtifact.bytecode.schema !== "joan.bytecode-program.v3" ||
  flowArtifact.bytecode.canonical_ast.schema !== "joan.canonical-ast.v2" ||
  flowArtifact.bytecode.semantic_identity.schema !== "joan.canonical-ast-identity.v2" ||
  flowArtifact.verification.schema !== "joan.bytecode-verification-receipt.v2" ||
  flowReceipt.schema !== "joan.execution-receipt.v3"
) {
  throw new Error("information-flow artifact profile failed");
}
if (JSON.stringify(flowArtifact.verification) !== JSON.stringify(flowVerification)) {
  throw new Error("flow compiler and standalone verifier receipts differ");
}
const flowRequest = flowReceipt.effect_requests[0];
if (
  flowReceipt.effect_requests.length !== 1 ||
  flowRequest.authority_slot !== "send_once" ||
  flowRequest.information?.class !== "secret" ||
  flowRequest.information?.tenant !== "agent_a" ||
  flowRequest.information?.purpose !== "handoff"
) {
  throw new Error("tenant-purpose request binding failed");
}
NODE

printf '%s\n' 'JOAN legacy, linear-authority, and tenant-purpose flow contracts passed.'
