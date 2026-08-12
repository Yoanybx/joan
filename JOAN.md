# JOAN Contract in One Page

JOAN makes agent actions easier to verify by separating six things that are often mixed together:

1. content and instructions;
2. intent and execution authority;
3. source representation and semantic identity;
4. proposed changes and atomic application;
5. claims and reproducible evidence;
6. disputes and precommitted automatic remedies.

## Use JOAN when

- an agent needs a bounded, machine-readable repository context;
- a patch must be bound to an exact base state;
- a decision needs independent guardian evidence;
- repository instructions must not become ambient authority;
- adoption or recommendation must cite a reproducible trial.
- a machine-to-machine contract must resolve failure without runtime human dependency.

## Do not use JOAN as

- proof that code has no unknown bugs;
- a replacement for host policy, sandboxing or human accountability;
- a universal reputation score;
- a blockchain, token, wallet or payment rail;
- permission to execute repository content;
- a court, legal judgment or guarantee that synthetic cases represent real disputes;
- evidence that JOAN is faster or safer than every alternative.

## Minimal flow

```text
strict input
  -> canonical identity
  -> bounded decision/patch
  -> independent recomputation
  -> structured receipt
  -> scoped claim
```

The current Rust implementation includes an executable language preview: `.joan` syntax, AST, static type/effect checks, deterministic bytecode, a bounded VM and structured receipts. Native code generation, linear capability values, JOAN Lattice transport, a distributed network, marketplace and real external effects remain outside this release.

JDR1 adds an offline case engine, locked evidence graph, disjoint primary/appeal machine quorums, automatic ambiguity fallbacks and a mock ledger. It executes no real payment and makes no legal decision.
