# JOAN Standalone Bytecode Verification v0

## Status

This document freezes the first non-executing verifier for externally supplied
JOAN bytecode. The legacy artifact is `joan.bytecode-program.v1`; the additive
linear-authority artifact is `joan.bytecode-program.v2`. Successful verification
emits the matching v0 or v1 receipt.

The verifier reduces trust in serialized bytecode. It does not prove that the
verifier, compiler, VM or specification has no defects, and it does not grant
authority for a requested effect.

## Bound artifact

A v1 program contains:

- the exact legacy `joan.canonical-ast.v0` or linear `joan.canonical-ast.v1` projection;
- its `joan.language-canonical-ast.v1` identity descriptor and compatibility digest;
- sorted functions with parameter and local slot types;
- deterministic instructions and one `main` entry index.

The v2 profile additionally binds sorted effect-specific authority slots to
every function and an exact slot name to every request instruction.

The complete typed artifact identity is the JCE1 digest in matching domain
`joan.bytecode-program.v1` or `joan.bytecode-program.v2`. Bytecode `i64`
constants use canonical decimal text, not JSON numbers, so the complete signed
64-bit range remains interoperable.

## Required verification

Before execution, an implementation must:

1. accept only the exact v1 schema and bounded canonical AST shape;
2. reconstruct a diagnostic AST and rerun JOAN static checks;
3. recompute exact JCE1 canonical AST bytes and identity;
4. validate module, entrypoint, function names, sorted effects and typed frames;
5. abstractly execute each instruction to prove stack and local-slot types;
6. reject uninitialized loads, immutable-local overwrites, bad calls, undeclared effects, instructions after return and wrong return stack shapes;
7. prove the bytecode call graph is acyclic;
8. independently emit bytecode from the embedded AST and require exact equality;
9. hash the complete verified artifact and emit a receipt without executing it.
10. for v2, abstractly consume every authority slot exactly once and reject
    missing, unknown, wrong-effect, duplicate or unconsumed slots.

`joan-compiler` and `joan-bytecode` contain separate emitters. Equality closes
the previous boundary where valid AST metadata could be attached to arbitrary
instructions. This is diverse code inside one Rust workspace, not an
independent implementation or formal compiler-correctness proof.

## Limits

- canonical transport input: at most 1 MiB plus one optional final LF;
- functions: 1,024;
- parameters per function: 64;
- local slots per function: 100,064;
- statements: 100,000;
- expression nodes: 200,000, depth 256;
- instructions per function: 100,000;
- total instructions: 1,000,000;
- abstract stack depth: 65,536.

Any overflow, malformed decimal, unknown field, digest mismatch, type mismatch,
limit violation or code-generation difference rejects the complete artifact.

## CLI

```bash
joan bytecode verify bytecode.json --json
```

The input must be exact canonical JCE1 with at most one final LF. The command is
offline, performs no writes and never executes bytecode or effects.

## Compatibility boundary

Legacy source still emits byte-for-byte compatible v0 canonical AST and v1
bytecode shapes. A module that explicitly enables authority slots emits
`joan.canonical-ast.v1`, `joan.bytecode-program.v2`, and separate digest domains.
Schema/profile pairs cannot be mixed or upgraded silently.
