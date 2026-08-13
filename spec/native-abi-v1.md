# JOAN Native ABI v1

Status: frozen experimental boundary for L15. This contract does not define a
native-code backend and does not authorize any universal performance or security
superiority claim.

## Purpose

The ABI lets C, C++, and future JOAN backends validate one complete JOAN Lattice
frame in caller-owned memory. Validation borrows payloads and returns fixed
metadata plus relative spans. Payload bytes are not copied and the hot validation
path does not allocate.

The normative C declaration is `include/joan.h`. The normative Rust layouts are
the `repr(C)` types in `joan-abi`.

## Fixed contract

- ABI v1 is defined only for 64-bit targets.
- Input bound: 16,777,216 bytes, including the Lattice header.
- Semantic root: 32 SHA-256 bytes under the JCE1 canonical AST domain selected
  by semantic profile `1` legacy, `2` linear, or `3` information flow.
- Level order: frame, shape, intent, authority, evidence, result.
- `joan_program_binding_v1`: size 64, alignment 8.
- `joan_span_v1`: size 16, alignment 8.
- `joan_lattice_view_v1`: size 224, alignment 8.
- Structures contain fixed-width integers, digest bytes, reserved zeros, and
  relative spans. They contain no pointer, allocator handle, callback, file
  descriptor, or host authority.
- Every span is relative to the beginning of `frame`; offset plus length stays
  inside `frame_length`.
- Symbols, statuses, and layouts are frozen. A breaking change requires v2
  symbols and types; these native structures are not a wire format.

## Ownership and lifetime

The caller owns `frame`, `binding`, and `out_view`. JOAN never frees, retains, or
mutates either input. Returned spans remain meaningful only while `frame` is
alive and unchanged. The output range must not overlap either input range.

The frame range must belong to one contiguous allocation, be fully initialized,
mapped and readable, remain live, and have no mutation (including concurrent
mutation) for the complete call. `binding` must be one initialized aligned object.
The output must be mapped and writable for the duration of the call. No portable
in-process C ABI can prove raw allocation provenance, mapping, lifetime, or the
absence of concurrent mutation. Violating those preconditions violates the ABI
before JOAN can inspect the bytes.

Before constructing Rust references or slices, the boundary checks:

1. required pointers and output capacity;
2. the 16 MiB protocol bound before target-width conversion;
3. binding/output alignment;
4. numeric address ranges without arithmetic wraparound;
5. output non-overlap with both input ranges;
6. structure size, ABI version, semantic profile, and reserved fields.

All raw-pointer conversion is isolated in `crates/joan-abi/src/ffi.rs`. The
decoder and view construction remain safe Rust. The output remains unchanged on
every rejection.

## Semantic binding

`binding_from_verified_bytecode_v1` first runs the independent bytecode verifier,
checks that legacy/linear/information schema and digest metadata agree, then
derives the typed 64-byte program binding. That is the strong Rust path.

A binding manually assembled by C is an asserted identity from the caller, not
proof of compiler provenance. A successful result preserves that asserted profile
and root but does
not authenticate Lattice `schema_digest` or `intent_digest`; Lattice v0 only
validates their structural position. Future native artifacts must carry the same
typed root and reject disagreement before execution.

## Effects

This ABI validates bytes only. It performs no network, filesystem, process,
payment, clock, randomness, telemetry, or agent-tool effect. Lattice effect
requests remain inert data and require separate external authority.

## Verification

`scripts/verify-native-abi.sh` checks:

- Rust, C11, and C++17 sizes, alignment, and field offsets;
- strict C/C++ compiler warnings and versioned exported symbols;
- every truncated prefix from 0 through 95 bytes plus null, capacity, alignment,
  overlap, overflow, binding, flags, canonicality, and length failures;
- all three verified JOAN bytecode profiles and tampered-root rejection;
- payload-relative spans and preservation of typed semantic binding;
- zero hot-path allocations for success, rejection, and an exact 16 MiB frame;
- 4,096 deterministic FFI mutations with a frozen seed and outcome digest,
  plus 4,096 bounded Rust property cases;
- AddressSanitizer and UndefinedBehaviorSanitizer when available;
- two byte-identical reports containing source, tool, and native-library hashes.

On macOS the crate fixes the Mach-O install name to
`@rpath/libjoan_abi.dylib`. This keeps the dynamic-library hash independent of
the checkout and `CARGO_TARGET_DIR` paths; the caller still chooses the runtime
search path. Linux uses the platform's path-independent shared-object identity.

The strict report distinguishes `asserted_semantic_binding_preserved` at the C
boundary from `verified_rust_binding_profiles = 3` in the Rust cold path. It uses
`schemas/native-abi-report.v1.schema.json`, is bound to the
complete source-tree digest, and is retained at
`.joan/evidence/native-abi-v1.json`. It is an independent L15 receipt because the
frozen verification receipt v1 contains the original ten gates. Rust code inside
the dynamic library is not sanitizer-instrumented on the stable toolchain; the C
boundary and host corpus are instrumented, while Rust memory behavior is covered
by safe-code separation, tests, Clippy, and the localized unsafe audit. Miri is a
separate optional gate when the toolchain component is available. None of this
may be presented as an independent operator or cross-platform attestation.

Rollback is `git revert` of the L15 commit. Existing syntax, checker, bytecode,
VM, Lattice wire format, and `.joan` programs are unchanged.
