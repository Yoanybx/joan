#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

for tool in cargo cmp node rg; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'required native backend verification tool is unavailable: %s\n' "$tool" >&2
    exit 3
  fi
done

target_dir="${CARGO_TARGET_DIR:-target}"
if [[ "$target_dir" != /* ]]; then
  target_dir="$root/$target_dir"
fi
binary="$target_dir/debug/joan"
if [[ -n "${JOAN_NATIVE_BACKEND_TMPDIR:-}" ]]; then
  native_tmp="$JOAN_NATIVE_BACKEND_TMPDIR"
elif [[ -d /Volumes/JOANBuild ]]; then
  native_tmp=/Volumes/JOANBuild/tmp
elif [[ -d "/Volumes/ParallesWin 1/JOAN/tmp" ]]; then
  native_tmp="/Volumes/ParallesWin 1/JOAN/tmp"
else
  native_tmp="${TMPDIR:-/tmp}"
fi
mkdir -p "$native_tmp"
work="$(mktemp -d "$native_tmp/joan-native-backend.XXXXXX")"
trap 'rm -rf "$work"' EXIT

compile_one="$work/compile-one.json"
compile_two="$work/compile-two.json"
run_one="$work/run-one.json"
run_two="$work/run-two.json"

cargo build --quiet --locked -p joan-node
cargo test --quiet --locked -p joan-native --lib
cargo test --quiet --locked -p joan-native --test differential
cargo test --quiet --locked -p joan-node --test cli native_commands_require_explicit_machine_inputs
cargo test --quiet --locked -p joan-node --test repository_contracts native_receipts_match_their_schemas

"$binary" fmt vectors/native/pure-v0.joan --check
"$binary" check vectors/native/pure-v0.joan --json >/dev/null
"$binary" native compile vectors/native/pure-v0.joan --json >"$compile_one"
"$binary" native compile vectors/native/pure-v0.joan --json >"$compile_two"
cmp "$compile_one" "$compile_two"

"$binary" native run vectors/native/pure-v0.joan \
  --function score \
  --arguments vectors/native/arguments-v0.json \
  --budget 100 \
  --json >"$run_one"
"$binary" native run vectors/native/pure-v0.joan \
  --function score \
  --arguments vectors/native/arguments-v0.json \
  --budget 100 \
  --json >"$run_two"
cmp "$run_one" "$run_two"

if "$binary" native run vectors/native/pure-v0.joan \
  --function score \
  --arguments vectors/native/arguments-v0.json \
  --budget 8 \
  --json >"$work/short-budget.json" 2>"$work/short-budget.stderr"; then
  printf '%s\n' 'native execution accepted a budget below the exact bound' >&2
  exit 1
fi
if ! rg -q 'instruction budget exhausted' "$work/short-budget.stderr"; then
  printf '%s\n' 'native execution did not report the expected budget failure' >&2
  exit 1
fi

node - "$compile_one" "$run_one" <<'NODE'
const { readFileSync } = require("node:fs");
const compile = JSON.parse(readFileSync(process.argv[2], "utf8"));
const run = JSON.parse(readFileSync(process.argv[3], "utf8"));
function assert(condition, message) {
  if (!condition) throw new Error(message);
}
assert(compile.schema === "joan.native-compile-receipt.v0", "compile schema drift");
assert(compile.status === "compiled", "compile status drift");
assert(compile.subset === "joan.native-subset.v0", "native subset drift");
assert(compile.backend === "joan.cranelift-jit.v0", "native backend drift");
assert(compile.codegen_version === "0.134.3", "Cranelift version drift");
assert(compile.optimization_profile === "speed", "Cranelift optimization profile drift");
assert(compile.function_count === 3, "native function count drift");
assert(compile.code_bytes > 0 && compile.code_bytes <= 16777216, "native code size is invalid");
assert(compile.relocation_count > 0, "native relocation evidence is missing");
assert(compile.flags.length > 0, "native codegen flags are missing");
assert(
  JSON.stringify(compile.flags) === JSON.stringify([...new Set(compile.flags)].sort()),
  "native codegen flags are not a canonical set",
);
assert(compile.artifact_digest.domain === "joan.native-artifact.v1", "artifact domain drift");
assert(run.schema === "joan.native-execution-receipt.v0", "execution schema drift");
assert(run.status === "completed", "execution status drift");
assert(run.function === "score", "execution function drift");
assert(run.result.type === "i64" && run.result.value === "42", "native result drift");
assert(run.instructions_executed === 9, "native instruction accounting drift");
assert(
  JSON.stringify(run.artifact_digest) === JSON.stringify(compile.artifact_digest),
  "execution is not bound to the compiled artifact",
);
assert(
  JSON.stringify(run.bytecode_digest) === JSON.stringify(compile.bytecode_digest),
  "execution is not bound to the verified bytecode",
);
NODE

printf '%s\n' 'JOAN native backend gate passed: deterministic JIT artifact, VM differential parity, schemas, and fail-closed budget.'
