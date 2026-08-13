# JOAN Benchmark Policy v0

JOAN performance claims require equivalent observable work, identical outputs, pinned inputs, repeated samples, recorded toolchains and an executable reproducer. A failed equivalence check invalidates every timing result.

## Current C comparison

`scripts/benchmark-digest.sh` compares the exact JCE1 `joan.source.v1` SHA-256 preimage over a deterministic payload:

- Rust implementation: raw JCE1 digest bytes from `joan-canonical` with `sha2 0.11.0`;
- C implementation: the same preimage using CommonCrypto on macOS or OpenSSL EVP on Linux;
- five timed samples after warmup;
- median elapsed nanoseconds;
- no pass/fail speed threshold.

The comparison is an implementation microbenchmark. It is not evidence that Rust, JOAN or C is universally faster, safer or better.

## First recorded result

The evidence file `benchmarks/results/2026-08-11-mac15-4-jce1-digest.json` records an Apple M3 run with a 4,096-byte payload and 5,000 iterations per sample. Both implementations time raw digest production and create the typed report outside the timing window. The recorded result must be read directly from that evidence file.

This is a baseline and an optimization target. It disproves any current claim that JOAN already outperforms C on this operation.

## Required benchmark families

Future claims must separately measure:

1. canonical encoding throughput and rejection cost;
2. typed hash throughput at multiple payload sizes;
3. semantic-set canonicalization;
4. semantic patch validation and rollback cost;
5. end-to-end agent task correctness, interventions, latency and resource use;
6. effect authorization and recovery overhead.

Memory, startup, binary size, energy, adversarial worst case and cross-platform variance must be reported alongside throughput before any broad comparison.

## Experimental native scalar corpus

`benchmarks/native-backend/manifest-v0.json` freezes five dynamic scalar workloads for JOAN
native, C, C++, Rust, and Julia. Every implementation uses SplitMix64 inputs, checked arithmetic,
the same per-opcode fuel accounting, and the same FNV-1a outcome accumulator. Output equivalence
requires both checksum and instruction-count equality.

The smoke gate retains raw inner-runtime, process-time, RSS, compile, ordering, source, toolchain,
and environment observations. Julia is marked unavailable when its toolchain is absent. Executable
size and generated JIT code size are separate scopes and must not be compared as if equivalent.
Recorded mode is fail-closed at exactly 101 runtime samples, 1,000,000 iterations per sample, and
11 RSS samples. The report is always `local-benchmark-not-qualified`; a conforming independent
host rerun is required before any workload-specific performance statement.

Workload names are resolved before timing and all timed harnesses use an enum selector. C, C++,
Rust, and Cranelift target the current host CPU. Execution order is balanced by position in complete
implementation-sized blocks. A separate dependency-free Node/BigInt oracle freezes samples 0, 50,
and 100 for every workload; all remaining samples require exact cross-implementation agreement.
Reports bind source, compiler flags, artifacts, generated native identity, raw observation hashes,
and the oracle source. They must be written outside the source tree to avoid self-referential hashes.
Process time is retained for operations analysis but is not cross-lifecycle comparable because JOAN
and Julia compile source on process start while C, C++, and Rust execute prebuilt artifacts.

## AI-agent task paths

`spec/agent-scorecard-v1.md` defines a non-compensable comparison against C,
Rust, and TypeScript for complete agent workflows. It measures preparation,
process launch, exact semantic output, inert tool/memory/handoff requests,
resident memory, artifact size, output bytes, and four scoped safety probes.

The scorecard has no weighted aggregate. Incorrect output or a failed JOAN
safety invariant invalidates qualification regardless of speed. The initial
two-workload corpus is a baseline only; it cannot support a language-wide claim.
