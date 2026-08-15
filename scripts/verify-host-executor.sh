#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

for tool in cargo cmp node rg; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'required host-executor verification tool is unavailable: %s\n' "$tool" >&2
    exit 3
  fi
done

target_dir="${CARGO_TARGET_DIR:-target}"
if [[ "$target_dir" != /* ]]; then
  target_dir="$root/$target_dir"
fi
joan="$target_dir/debug/joan"
executor="$target_dir/debug/joan-executor"
work="$(mktemp -d "${TMPDIR:-/tmp}/joan-host-executor.XXXXXX")"
trap 'rm -rf "$work"' EXIT

cargo build --quiet --locked -p joan-node -p joan-executor
cargo test --quiet --locked -p joan-host
cargo test --quiet --locked -p joan-executor --test process
cargo test --quiet --locked -p joan-node --test cli native_commands_require_explicit_machine_inputs
cargo test --quiet --locked -p joan-node --test repository_contracts host_protocol_receipts_match_their_schemas

if cargo tree --locked -p joan-node --edges normal | rg -q 'joan-native|cranelift'; then
  printf '%s\n' 'trusted joan-node process unexpectedly links the native backend' >&2
  exit 1
fi
if ! cargo tree --locked -p joan-executor --edges normal | rg -q 'joan-native'; then
  printf '%s\n' 'dedicated executor does not link the native backend' >&2
  exit 1
fi
rg -q '\.env_clear\(\)' crates/joan-host/src/controller.rs
rg -q '\.process_group\(0\)' crates/joan-host/src/controller.rs
if rg -q 'thread::spawn' crates/joan-host/src/controller.rs; then
  printf '%s\n' 'host controller unexpectedly contains detached worker threads' >&2
  exit 1
fi

printf 'host-domain-probe' >"$work/domain-probe"
for domain in \
  joan.host-execution-request.v2 \
  joan.host-executor-response.v2 \
  joan.host-execution-receipt.v2; do
  "$joan" digest-v1 "$domain" "$work/domain-probe" >"$work/rust-domain.json"
  node tools/jce1-reference.mjs digest "$domain" "$work/domain-probe" >"$work/js-domain.json"
  cmp "$work/rust-domain.json" "$work/js-domain.json"
done

expected_self_check='{"profile":"pure-native-v0","schema":"joan.executor-self-check.v0","status":"ready"}'
actual_self_check="$("$executor" --self-check)"
test "$actual_self_check" = "$expected_self_check"

"$joan" native compile vectors/native/pure-v0.joan --json >"$work/compile-one.json"
"$joan" native compile vectors/native/pure-v0.joan --json >"$work/compile-two.json"
cmp "$work/compile-one.json" "$work/compile-two.json"

"$joan" native run vectors/native/pure-v0.joan \
  --function score \
  --arguments vectors/native/arguments-v0.json \
  --budget 100 \
  --json >"$work/run-one.json"
"$joan" native run vectors/native/pure-v0.joan \
  --function score \
  --arguments vectors/native/arguments-v0.json \
  --budget 100 \
  --json >"$work/run-two.json"
cmp "$work/run-one.json" "$work/run-two.json"

if "$joan" native run vectors/native/pure-v0.joan \
  --function score \
  --arguments vectors/native/arguments-v0.json \
  --budget 1 \
  --json >"$work/failed.json" 2>"$work/failed.stderr"; then
  printf '%s\n' 'isolated executor accepted an exhausted instruction budget' >&2
  exit 1
fi

node - "$work/compile-one.json" "$work/run-one.json" "$work/failed.json" <<'NODE'
const { readFileSync } = require("node:fs");
const compile = JSON.parse(readFileSync(process.argv[2], "utf8"));
const run = JSON.parse(readFileSync(process.argv[3], "utf8"));
const failed = JSON.parse(readFileSync(process.argv[4], "utf8"));
function assert(condition, message) {
  if (!condition) throw new Error(message);
}
assert(compile.schema === "joan.native-compile-receipt.v0", "compile compatibility drift");
assert(run.schema === "joan.native-execution-receipt.v0", "run compatibility drift");
assert(run.status === "completed" && run.result.value === "42", "isolated result drift");
assert(failed.schema === "joan.host-execution-receipt.v1", "failure receipt schema drift");
assert(failed.status === "failed", "deterministic rejection is not failed");
assert(failed.reason === "executor_rejected", "deterministic rejection reason drift");
assert(failed.execution_receipt === undefined, "failed attempt fabricated execution success");
assert(failed.receipt_digest.domain === "joan.host-execution-receipt.v2", "receipt identity drift");
assert(failed.request_digest.domain === "joan.host-execution-request.v2", "request identity drift");
assert(failed.executor_response_digest.domain === "joan.host-executor-response.v2", "response identity drift");
assert(failed.child_exit_code === 0 && failed.child_unix_signal === undefined, "exit state drift");
assert(failed.limits.core_size_bytes === 0, "core limit drift");
assert(failed.limits.file_size_bytes === 0, "file limit drift");
assert(["address_space", "data_segment", "unavailable"].includes(failed.limits.memory_limit_kind), "memory limit kind drift");
assert(failed.limits.memory_limit_kind !== "unavailable" || failed.limits.memory_limit_bytes === 0, "unavailable memory limit is contradictory");
NODE

printf '%s\n' 'JOAN host executor gate passed: process groups, POSIX limits, bounded lifecycle, versioned receipts and CLI compatibility.'
