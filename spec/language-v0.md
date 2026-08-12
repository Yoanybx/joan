# JOAN Language Preview v0

## Status

This document specifies the executable JOAN v0 preview implemented by
`joan-syntax`, `joan-ast`, `joan-check`, `joan-compiler`, and the `joan` CLI.
It is not a native-code compiler, a complete ownership/type system, or evidence
that JOAN outperforms C or any other language.

## Design contract

JOAN v0 is a small deterministic language for bounded agent decisions. The
compiler accepts only programs whose names, primitive types, effect rows, call
graph, and explicit returns pass static checks. The compiler emits JOAN
bytecode. The VM evaluates that bytecode with checked integer arithmetic,
bounded instructions, bounded call depth, and no ambient host access.

An effect declaration does not grant authority. `request network_send(...)`
creates an `EffectRequest` in the execution receipt. A separate host policy must
authorize and perform it. The preview VM never performs I/O.

The additive linear profile declares external requirements with
`authorities [send_once: network_send]` and moves one requirement with
`request network_send(...) using send_once`. Repository source still cannot
create authority: the slot is a semantic obligation that must match an exact
host-supplied one-shot approval before any external executor can act.

The additive information-flow profile begins with `module <name> flow;` and
requires a `public` or exact `secret` tenant-purpose label at every parameter,
return, local and request boundary. It includes the linear-authority profile and
has no declassification operation.

## Source grammar

```text
program       := "module" identifier "flow"? ";" function+
function      := "fn" identifier "(" parameters? ")"
                 "->" type information? "effects" "[" effects? "]"
                 authorities? block
authorities   := "authorities" "[" authority-list? "]"
authority-list:= authority ("," authority)*
authority     := identifier ":" identifier
parameters    := parameter ("," parameter)*
parameter     := identifier ":" type information?
information   := "flow" "[" ("public" | secret-label) "]"
secret-label  := "secret" "," "tenant" ":" identifier
                 "," "purpose" ":" identifier
effects       := identifier ("," identifier)*
type          := "i64" | "bool" | "string" | "unit"
block         := "{" statement+ "}"
statement     := "let" identifier ":" type information? "=" expression ";"
               | "return" expression? ";"
               | "request" identifier arguments ("using" identifier)?
                 information? ";"
               | expression ";"
arguments     := "(" (expression ("," expression)*)? ")"
expression    := literals, immutable locals, calls, unary operators,
                 arithmetic, comparisons, equality, &&, and ||
```

Identifiers are ASCII and source strings are UTF-8. Comments use `//` and
nested `/* ... */`; unterminated blocks fail during lexing. Inputs are bounded
to 1 MiB and 200,000 tokens.

## Static invariants

- Exactly one callable `main` name must exist and it accepts no parameters.
- Every function declares an effect row, including pure functions with `[]`.
- Every local is immutable and explicitly typed.
- Every function ends in an explicit type-correct return.
- Calls are statically resolved and argument types are checked.
- A caller's effect row must include every effect of each callee.
- A request must name an effect declared by its function.
- A module either uses the legacy receipt-only profile throughout or every
  function declares `authorities [...]` and every request moves one slot.
- A linear authority slot names one declared effect and is consumed exactly
  once on every invocation; reuse, omission, dropping, widening and mixed
  profiles are static errors.
- Loops and recursive call cycles are rejected in v0.
- Unit parameters and unit local bindings are rejected.
- An explicit flow module requires complete labels and complete linear
  authority declarations; labels outside that profile reject the module.
- Public values may enter any boundary. Secret values may enter only the exact
  same tenant-purpose boundary. Operators join compatible labels, calls enforce
  parameter/return labels, and request arguments enforce the sink label.

The no-loop, acyclic-call-graph rule is intentionally restrictive. It gives the
first preview a simple bounded-termination argument while future loop and
recursion proposals are developed with explicit decreasing measures.

## Compilation and execution

The pipeline is:

```text
UTF-8 source -> bounded lexer -> parser -> AST -> static checker
             -> bytecode compiler -> bounded deterministic VM -> receipt
```

Source spans and trivia are excluded from legacy `joan.canonical-ast.v0`,
linear `joan.canonical-ast.v1`, and information-flow `joan.canonical-ast.v2`.
Function declarations, effect rows and authority slots are sorted only for
identity calculation, so
equivalent whitespace, comments, formatting, function order, and effect order
yield identical JCE1 bytes within one profile. Legacy, linear and information
ASTs use digest domains `joan.language-canonical-ast.v1`, `.v2` and `.v3`
respectively. Execution order still follows compiled bytecode. Exact normalization,
integer encoding, verifier limits, and non-equivalence boundaries are frozen in
`spec/canonical-ast-v0.md` and `spec/bytecode-verification-v0.md`.

The default instruction budget is 1,000,000 and maximum call depth is 1,024.
All `i64` arithmetic is checked. Overflow, division failure, unverified or malformed bytecode,
stack underflow, budget exhaustion, and invalid call targets fail closed.

## CLI

```bash
joan check program.joan --json
joan fmt program.joan
joan fmt program.joan --check
joan compile program.joan --json
joan run program.joan --json
```

`fmt` writes canonical source to stdout and never changes the input file.
Rejected parse or check operations write a machine-readable
`joan.diagnostic-report.v0` to stdout and exit nonzero.

## Implemented versus planned

Implemented in v0:

- real `.joan` parsing and canonical formatting;
- primitive static types and immutable locals;
- explicit effect rows and effect attenuation across calls;
- acyclic bounded termination profile;
- deterministic bytecode compilation and VM execution;
- standalone typed bytecode verification with exact independent-emitter binding;
- additive linear one-shot authority slots checked in source, canonical AST,
  bytecode, execution receipts and host approval planning;
- additive explicit tenant-purpose labels checked and bound across those same
  source, bytecode, receipt and approval boundaries;
- versioned JCE1 canonical AST identities, structured diagnostics, and
  execution receipts bound to those identities.

Not implemented in v0:

- native AOT/JIT code generation, LLVM, Cranelift, Wasm, or C backends;
- general linear values, authority delegation through ordinary parameters, and
  durable multi-process approval storage;
- control-flow labels, declassification, endorsement, dynamic principals, and
  timing, resource, host or other side-channel protection;
- arrays, records, variants, generics, modules across files, loops, or recursion;
- networked package manager, standard library, LSP, debugger, optimizer, or stable ABI;
- cross-file imports (the separate offline package resolver verifies exact source graphs but does not link them yet);
- JOAN Lattice transport, distributed execution, payments, or a global network.

## Claim boundary

Passing the v0 gate proves agreement with these implemented examples and tests.
It does not prove absence of defects, security against every attacker, native
performance, distributed reliability, or language superiority.
