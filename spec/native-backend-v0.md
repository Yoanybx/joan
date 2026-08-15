# JOAN Native Backend v0

Status: experimental, local implementation contract

## Purpose

The v0 backend translates already verified JOAN bytecode into host-native code with Cranelift.
It is a fast-execution experiment and a conformance target. It is not a sandbox, an AOT binary
format, a stable C ABI, or evidence that JOAN universally outperforms another language.

## Required pipeline

1. Parse and statically check canonical JOAN source.
2. Compile the source to deterministic JOAN bytecode.
3. Run the standalone bytecode verifier immediately before native lowering.
4. Apply bytecode-count, function-count, frame, and native-subset checks before creating JIT state.
5. Lower every accepted opcode with VM-equivalent evaluation order and checked failures.
6. Reject non-internal relocations and exact code/relocation limit violations before executable
   finalization, then expose only uniform private wrappers to safe Rust.
7. Own every JIT module through an RAII guard that calls `JITModule::free_memory` on success,
   rejection, and partial compilation failure.
8. Keep the owning JIT module alive for every invocation.

No native entrypoint accepts unverified bytecode. The VM remains the default `joan run` backend.

## Frozen subset

The exact identifier is `joan.native-subset.v0`. It accepts only
`joan.bytecode-program.v1` with:

- `i64`, `bool`, and `unit` values;
- immutable parameters and locals;
- constants, local load/store, pop, unary negate/not;
- checked add, subtract, multiply, divide, and remainder;
- equality, ordered integer comparisons, eager boolean and/or;
- statically resolved acyclic calls and return.

It rejects strings, request instructions, effect rows, authority slots, linear bytecode,
information-flow bytecode, unknown schemas, and any artifact that fails exact codegen binding.

## Execution semantics

Values use a private normalized `i64` representation inside generated code: `i64` is unchanged,
`false` is 0, `true` is 1, and `unit` is 0. Typed host validation occurs before invocation and
typed canonicalization occurs after a successful return.

Every bytecode instruction charges one fuel unit before its semantics, including call and return.
All calls share one fuel pointer. An instruction with no remaining fuel returns
`instruction budget exhausted` without performing that instruction. Integer failures match the VM
and never intentionally use wrapping arithmetic or CPU traps.

The private internal signature is conceptually:

```text
fn joan_internal(arg0_i64, ..., fuel_ptr) -> (status_i32, value_i64)
```

The only pointer converted to a host function pointer uses this uniform wrapper signature:

```text
fn joan_wrapper(args_ptr, fuel_ptr, output_ptr) -> status_u32
```

The safe host owns aligned live storage for all pointers and validates the exact argument count.
The wrapper writes the output only on status zero.

## Resource envelope

- at most 256 functions;
- at most 10,000 bytecode instructions per function;
- at most 50,000 bytecode instructions per program;
- at most 10,000 frame slots per function;
- at most 1 MiB generated code per internal function or wrapper;
- at most 16 MiB generated code per program;
- at most 10,000 relocations per internal function or wrapper.
- at most 5,120,000 relocations per program.

These are native-backend limits in addition to bytecode-verifier limits. Exceeding one fails before
the affected native artifact can be invoked.

## Artifact identity

`joan.native-artifact.v1` binds:

- native subset and backend identifiers;
- exact Cranelift crate version;
- the frozen Cranelift `speed` optimization profile;
- target triple;
- every shared and ISA-specific Cranelift flag value;
- semantic and verified-bytecode digests;
- function/wrapper names, code byte count and `joan.native-code.v1` digest;
- address-independent relocation offset, kind, target, and addend.

Runtime addresses are intentionally excluded because address-space layout varies by process.
The receipt identifies the relocatable generated image and link requirements, not a persistent AOT
file. Source-tree and tool-binary digests belong in the verification evidence that encloses it.

## Security boundary

The crate forbids unsafe Rust except in `unsafe_boundary.rs`, which owns executable-memory release,
retrieves finalized function pointers, and invokes them through typed borrowed storage. Raw pointers
and untyped entrypoints are not exposed to the rest of the crate. Generated code may relocate only
to Cranelift user functions declared inside the same module; libcalls, known symbols, and test-case
symbols fail closed before finalization. The official `joan native compile` and `joan native run`
commands execute this crate through the adjacent `joan-executor` process and the bounded protocol
defined in `host-executor-v1.md`; `joan-node` does not link this crate or Cranelift. The low-level
Rust API remains available for conformance tests and therefore does not itself isolate generated
code. Process separation and an empty inherited environment are not an operating-system sandbox:
kernel-enforced filesystem, network, syscall, process-tree and memory limits remain H08 work.

## Claims

Passing native conformance proves only that the tested host generated VM-equivalent behavior for
the frozen corpus. Performance claims require equivalent dynamic workloads, raw randomized
samples, separate compile/warmup/runtime metrics, memory and size observations, source/toolchain
digests, safety-regression gates, clean-clone reproduction, and an independent rerun.

Independent reruns compare a canonical semantic-observation digest. The digest binds all emitted
observation fields except `compile_ns` and `runtime_ns`, whose values are retained as measurements
but cannot be execution identity because they vary with host load. Any checksum, seed, instruction
count, artifact identity, generated-code size, status, workload, or iteration change remains fatal.
