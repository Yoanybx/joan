# JOAN Differential Language Validation v1

## Status

This document freezes the first differential parser/checker gate for JOAN v0.
It adds evidence against implementation-correlated defects. It does not prove
that either implementation is correct, independent in an organizational sense,
or superior to C.

## Implementations

The production preview is the Rust pipeline in `joan-syntax` and `joan-check`.
The reference is `reference/joan-ref.mjs`, a handwritten Node.js 24 program
with no package dependencies, JOAN workspace imports, native addons, network
modules, effect execution, or production compiler reuse.

Both implementations consume the exact same UTF-8 source bytes. The reference
independently implements the frozen grammar, primitive types, effect rows,
acyclic-call termination, linear one-shot authority, and exact tenant-purpose
information-flow rules. It is validation code and is not a second production
compiler.

## Corpus contract

`vectors/language-differential/corpus-v1.json` contains 44 frozen cases:

- 7 accepted programs across legacy, linear, and flow profiles;
- 7 lexical or parse rejections with exact stable diagnostic codes;
- 30 static-check rejections covering names, types, effects, termination,
  linear authority, and information flow.

The runner derives 32 accepted trivia mutations from the frozen seed
`0x123456789abcdef0`. Mutation IDs, source bytes, and results are deterministic.
Mutations exercise whitespace and nested-comment invariance without changing
program semantics.

## Comparison

Every case must satisfy three conditions:

1. Rust agrees with the frozen expected status, phase, and normalized diagnostic
   code set.
2. The reference agrees with that same expectation.
3. Rust and the reference agree exactly on rejected observations or on the
   complete accepted check receipt.

The report binds SHA-256 digests of the corpus, each source, the reference
implementation, and the exact Rust binary. Paths and timestamps are excluded.
Two consecutive runs must produce byte-identical reports. A deliberately wrong
expectation must be detected and fail exactly one case.

## Security and claim boundary

The gate performs no network request, payment, host effect, compilation of
untrusted native code, or modification of source files. Temporary programs and
reports are bounded and placed under the configured external temporary root.

Agreement can still preserve the same specification misunderstanding, and both
implementations were produced under the same project. Independent external
reruns, fuzzing, formal semantics, native backend work, ABI design, and
equivalent C/Rust/TypeScript benchmarks remain separate gates.
