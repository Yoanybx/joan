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
trap 'rm -f "$receipt" "$artifact" "$bytecode" "$verification"' EXIT

cargo build --quiet --locked -p joan-node
"$binary" fmt examples/agent-handoff.joan --check
"$binary" check examples/agent-handoff.joan --json >/dev/null
"$binary" compile examples/agent-handoff.joan --json >"$artifact"
"$binary" run examples/agent-handoff.joan --json >"$receipt"
node -e 'process.stdout.write(JSON.stringify(JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8")).bytecode))' "$artifact" \
  | "$binary" canonicalize-v1 - >"$bytecode"
"$binary" bytecode verify "$bytecode" --json >"$verification"

node - "$artifact" "$receipt" "$verification" <<'NODE'
const { readFileSync } = require("node:fs");
const artifact = JSON.parse(readFileSync(process.argv[2], "utf8"));
const receipt = JSON.parse(readFileSync(process.argv[3], "utf8"));
const verification = JSON.parse(readFileSync(process.argv[4], "utf8"));
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
NODE

printf '%s\n' 'JOAN language v0 compile and execution contract passed.'
