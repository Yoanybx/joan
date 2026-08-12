#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

for tool in cargo cc c++ nm node rg; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'required native ABI verification tool is unavailable: %s\n' "$tool" >&2
    exit 3
  fi
done

target_dir="${CARGO_TARGET_DIR:-target}"
if [[ "$target_dir" != /* ]]; then
  target_dir="$root/$target_dir"
fi
if [[ -n "${JOAN_NATIVE_ABI_TMPDIR:-}" ]]; then
  native_tmp="$JOAN_NATIVE_ABI_TMPDIR"
elif [[ -d "/Volumes/ParallesWin 1/JOAN/tmp" ]]; then
  native_tmp="/Volumes/ParallesWin 1/JOAN/tmp"
else
  native_tmp="${TMPDIR:-/tmp}"
fi
mkdir -p "$native_tmp"
temporary_directory="$(mktemp -d "$native_tmp/joan-native-abi.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT

cargo build --quiet --release --locked -p joan-abi

case "$(uname -s)" in
  Darwin)
    library="$target_dir/release/libjoan_abi.dylib"
    runtime_env=(env "DYLD_LIBRARY_PATH=$target_dir/release")
    ;;
  Linux)
    library="$target_dir/release/libjoan_abi.so"
    runtime_env=(env "LD_LIBRARY_PATH=$target_dir/release")
    ;;
  *)
    printf 'unsupported native ABI verification host: %s\n' "$(uname -s)" >&2
    exit 3
    ;;
esac

if [[ ! -f "$library" ]]; then
  printf 'native ABI library was not produced: %s\n' "$library" >&2
  exit 1
fi

for symbol in \
  joan_abi_version_v1 \
  joan_abi_max_buffer_len_v1 \
  joan_abi_program_binding_size_v1 \
  joan_abi_lattice_view_size_v1 \
  joan_lattice_validate_v1; do
  if ! nm -g "$library" | rg -q "[_ ]${symbol}$"; then
    printf 'required native ABI symbol is unavailable: %s\n' "$symbol" >&2
    exit 1
  fi
done

common_flags=(-std=c11 -Wall -Wextra -Werror -pedantic -Iinclude)
link_flags=(-L"$target_dir/release" -ljoan_abi -Wl,-rpath,"$target_dir/release")
cc "${common_flags[@]}" native/corpus/native-abi-v1.c "${link_flags[@]}" -o "$temporary_directory/native-abi-corpus"
c++ -std=c++17 -Wall -Wextra -Werror -pedantic -Iinclude native/corpus/native-abi-header-v1.cpp -c -o "$temporary_directory/native-abi-header-v1.o"

raw_one="$temporary_directory/raw-one.json"
raw_two="$temporary_directory/raw-two.json"
"${runtime_env[@]}" "$temporary_directory/native-abi-corpus" > "$raw_one"
"${runtime_env[@]}" "$temporary_directory/native-abi-corpus" > "$raw_two"
cmp "$raw_one" "$raw_two"

cargo test --quiet --locked -p joan-abi --lib
cargo test --quiet --locked -p joan-abi --test semantic_binding
cargo test --quiet --locked -p joan-abi --test no_alloc -- --test-threads=1

sanitizer_binary="$temporary_directory/native-abi-corpus-sanitized"
printf '%s\n' 'int main(void) { return 0; }' > "$temporary_directory/sanitizer-probe.c"
if cc -std=c11 -fsanitize=address,undefined "$temporary_directory/sanitizer-probe.c" \
    -o "$temporary_directory/sanitizer-probe" >"$temporary_directory/sanitizer-probe.log" 2>&1; then
  "$temporary_directory/sanitizer-probe"
  cc "${common_flags[@]}" -fsanitize=address,undefined -fno-omit-frame-pointer \
      native/corpus/native-abi-v1.c "${link_flags[@]}" -o "$sanitizer_binary"
  "${runtime_env[@]}" "$sanitizer_binary" >/dev/null
  sanitizer_status='passed'
else
  sanitizer_status='unavailable'
fi

report_one="$temporary_directory/report-one.json"
report_two="$temporary_directory/report-two.json"
node tools/native-abi-report.mjs "$raw_one" "$library" "$sanitizer_status" \
  schemas/native-abi-report.v1.schema.json "$report_one"
node tools/native-abi-report.mjs "$raw_two" "$library" "$sanitizer_status" \
  schemas/native-abi-report.v1.schema.json "$report_two"
cmp "$report_one" "$report_two"

JOAN_NATIVE_ABI_REPORT_INPUT="$report_one" \
  cargo test --quiet --locked -p joan-abi --test report_schema

node - schemas/native-abi-report.v1.schema.json "$report_one" <<'NODE'
const fs = require("node:fs");
const schema = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const report = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
function assert(condition, message) {
  if (!condition) throw new Error(message);
}
assert(schema.$id.endsWith("native-abi-report.v1.schema.json"), "unexpected schema contract");
assert(report.schema === "joan.native-abi-report.v1" && report.status === "passed", "native ABI corpus failed");
assert(report.abi_version === 1 && report.binding_size === 64 && report.lattice_view_size === 224, "ABI layout drift");
assert(report.max_buffer_len === 16777216, "buffer bound drift");
assert(report.case_count >= 120 && report.passed === report.case_count, "hostile corpus incomplete");
assert(report.mutation_count === 4096, "mutation count drift");
assert(report.mutation_seed === "0x4a4f414e4c313500", "mutation seed drift");
assert(/^[0-9a-f]{16}$/.test(report.mutation_outcome_fnv1a64), "mutation outcome digest missing");
assert(report.payload_zero_copy === true, "payload zero-copy observation failed");
assert(report.asserted_semantic_binding_preserved === true, "asserted C binding failed");
assert(report.verified_rust_binding_profiles === 3, "verified Rust binding profiles failed");
assert(report.target.pointer_width === 64, "unsupported pointer width");
assert(report.source.tree_digest.profile === "joan-source-tree-v2", "source profile drift");
assert(/^[0-9a-f]{64}$/.test(report.source.tree_digest.value), "source digest missing");
for (const digest of [
  report.artifacts.header_sha256,
  report.artifacts.c_corpus_sha256,
  report.artifacts.rust_api_sha256,
  report.artifacts.gate_files_sha256,
  report.artifacts.library_sha256,
]) assert(/^[0-9a-f]{64}$/.test(digest), "invalid artifact digest");
assert(report.artifacts.tools.length === 7, "tool evidence incomplete");
for (const tool of report.artifacts.tools) {
  assert(/^[0-9a-f]{64}$/.test(tool.sha256) && tool.version.length > 0, "invalid tool evidence");
}
NODE

if [[ -n "${JOAN_NATIVE_ABI_REPORT:-}" ]]; then
  mkdir -p "$(dirname "$JOAN_NATIVE_ABI_REPORT")"
  temporary_report="$JOAN_NATIVE_ABI_REPORT.tmp-$$"
  cp "$report_one" "$temporary_report"
  mv "$temporary_report" "$JOAN_NATIVE_ABI_REPORT"
elif [[ -f .joan/evidence/native-abi-v1.json ]]; then
  cmp "$report_one" .joan/evidence/native-abi-v1.json
else
  printf '%s\n' 'tracked native ABI receipt is unavailable; regenerate with JOAN_NATIVE_ABI_REPORT=.joan/evidence/native-abi-v1.json' >&2
  exit 1
fi

printf 'JOAN native ABI gate passed: %s C cases, 4096 mutations, zero allocations, sanitizers %s.\n' \
  "$(node -p 'JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).case_count' "$report_one")" \
  "$sanitizer_status"
