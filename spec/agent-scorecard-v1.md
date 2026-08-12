# JOAN AI-Agent Scorecard v1

## Status

This contract defines an executable baseline. It does not establish that JOAN
is faster than C, Rust, TypeScript, or any other language. The current JOAN
implementation executes source through a Rust parser, checker, compiler, and
bounded VM; it has no native backend.

## Intended user

JOAN is intended primarily for AI agents and machine runtimes, not for manual
human authoring. Human-readable `.joan` source is a bootstrap, review, and
debugging representation. The long-term machine path is:

```text
agent intent -> canonical typed IR -> bounded authority -> execution -> receipt
                         |
                         +-> JOAN Lattice knowledge-difference capsule
```

A symbolic or glyph spelling does not make execution faster. Stable semantic
identities, compact canonical forms, machine-readable diagnostics, bounded
resource behavior, explicit effects, one-use authority, and omitted known
content can reduce total agent work.

## Measured objective

The unit is an AI task path rather than an isolated arithmetic kernel:

```text
task completion = prepare + launch + validate + compute + encode requests + receipt
```

v1 freezes two equivalent-output workloads:

1. `tool-memory-workflow`: compute a result and encode inert API and memory
   requests after consuming separate one-shot authorities.
2. `tenant-safe-handoff`: preserve a secret tenant-purpose label and encode an
   inert network handoff after consuming one network authority.

No benchmark performs a network request, API call, memory write, payment, or
other external effect. The output is data only.

## Implementations

- JOAN runs `.joan` source through the current release CLI.
- C and Rust compile optimized native executables.
- TypeScript uses Node 24 native type stripping. Node does not perform a
  TypeScript static type check in this profile; `strip-check` means strip plus
  JavaScript syntax validation only.

Each implementation must emit the same normalized semantic result. JOAN's
additional semantic and bytecode digests remain in its full receipt and are
reported as actual output bytes, but are excluded from normalized equivalence.
Any equivalence failure invalidates all timing results.

## Measurements

For every implementation and workload the report records:

- source and executable/tool digests;
- preparation and runtime raw samples;
- p50, p95, p99, minimum, and maximum elapsed nanoseconds;
- peak resident memory where the host exposes it;
- source, artifact, normalized output, and actual stdout bytes;
- exact normalized output digest.

The runtime measurement includes process launch. JOAN v1 also reparses, checks,
compiles, and executes source on each `run`; C and Rust execute previously built
binaries. This is an honest current task-path comparison, not a same-backend
kernel comparison. L15 must add equivalent native artifact execution.

## Scoped safety probes

The corpus checks authority replay, tenant crossing, unbounded recursion, and
signed 64-bit overflow. A rejection counts only when the tested compiler or
runtime fails closed and expected diagnostic evidence is present.

These four probes do not rank overall language safety. C, Rust, and TypeScript
can gain additional guarantees through libraries, analyzers, profiles, and
application code. The report describes only the checked source and tool flags.

## Non-compensable qualification

There is no weighted aggregate score. Fast execution cannot compensate for an
incorrect result or a failed JOAN safety invariant. A future scoped
qualification requires all of the following:

- exact output equivalence for every workload;
- JOAN protection on every frozen safety probe;
- at least five representative agent workloads;
- at least 21 recorded runtime samples per implementation and workload;
- a JOAN native backend;
- JOAN p95 runtime no worse than 1.05x the best C/Rust baseline on every task;
- JOAN peak RSS no worse than 1.10x the best C/Rust baseline on every task;
- at least two material wins at or below 0.90x;
- an independent rerun on separate hardware;
- separate M2M wire comparisons against the baselines in
  `spec/lattice-m2m-v0.md`.

Until every condition passes, the machine status is
`baseline-only-not-qualified` and both broad and universal superiority claims
remain false.

## Reproduction

```bash
export CARGO_TARGET_DIR=/absolute/external/path/cargo-target
export JOAN_SCORECARD_TMPDIR=/absolute/external/path/tmp
./scripts/verify-agent-scorecard.sh
```

The full recorded run uses `--mode recorded --samples 21`. Timings are expected
to vary; outputs, source digests, tool digests, qualification rules, and safety
observations are the reproducibility anchors.
