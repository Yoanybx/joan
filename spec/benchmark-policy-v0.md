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

## AI-agent task paths

`spec/agent-scorecard-v1.md` defines a non-compensable comparison against C,
Rust, and TypeScript for complete agent workflows. It measures preparation,
process launch, exact semantic output, inert tool/memory/handoff requests,
resident memory, artifact size, output bytes, and four scoped safety probes.

The scorecard has no weighted aggregate. Incorrect output or a failed JOAN
safety invariant invalidates qualification regardless of speed. The initial
two-workload corpus is a baseline only; it cannot support a language-wide claim.
