# JOAN 1.0 Completion Blueprint

Status: active, evidence-gated roadmap  
Owner: LED ACTION LLC  
Original creator: Joan Alberto Barrios Cruz  
Public core license: Apache-2.0  

## Meaning of complete

No living language is literally finished. For JOAN, `1.0 complete` means the
versioned contract below is implemented, documented, reproducible, supported,
and independently exercised. It does not mean zero defects, universal security,
universal performance superiority, or feature parity with every library in C,
C++, Rust, Python, or Julia.

JOAN 1.0 is complete only when all `J1` gates are checked and the exact release
is bound to source, toolchain, conformance, security, and platform evidence.
Network and economy layers are separate profiles and cannot delay or weaken the
core language contract.

Legend:

- `[x]` implemented and locally verified in the current lineage;
- `[-]` partially implemented or locally verified with a material open gate;
- `[ ]` not implemented or not independently verified.

## Current public-alpha foundation

- [x] `A01` Rust workspace with pinned toolchain and lockfile.
- [x] `A02` Real `.joan` lexer, parser, AST, formatter, checker, compiler, bytecode, and bounded VM.
- [x] `A03` Stable structured JSON diagnostics.
- [x] `A04` Canonical semantic identity with JCE1 Rust/Node conformance.
- [x] `A05` Effects are explicit and inert without host authority.
- [x] `A06` Linear one-use authority checking.
- [x] `A07` Tenant and purpose information-flow checking.
- [x] `A08` Offline content-addressed package resolution and atomic patches.
- [x] `A09` Experimental pure scalar Cranelift JIT.
- [x] `A10` Versioned C ABI and bounded Lattice frame validation.
- [x] `A11` Adjacent executor process with process-group cleanup and bounded canonical IPC.
- [-] `A12` POSIX limits: CPU, file, descriptors, and core are enforced; macOS memory limit is unavailable in the current profile.
- [x] `A13` Three local full evidence receipts and reproducible clean-clone machinery.
- [x] `A14` Apache-2.0 source license, copyright notice, trademark boundary, and CODEOWNERS.
- [x] `A15` Official GitHub push, hosted macOS/Linux CI, branch/tag rules, and private vulnerability reporting.
- [ ] `A16` Independent second-host rerun and three external agent trials.

## J1 language semantics

- [ ] `J1-L01` Records, tuples, enums, option/result, and exhaustive pattern matching.
- [ ] `J1-L02` Fixed arrays, slices, bytes, UTF-8 strings, bounded maps, and bounded sets.
- [ ] `J1-L03` `if`, `match`, iterators, fuel-bounded loops, `break`, and `continue`.
- [ ] `J1-L04` Controlled recursion with explicit stack/depth limits and measured tail-call policy.
- [ ] `J1-L05` Generics and traits/interfaces with explicit static or dynamic dispatch.
- [ ] `J1-L06` Ownership, borrowing/regions, arenas, and a specified memory model.
- [ ] `J1-L07` Typed errors, propagation, cleanup, cancellation, and panic-free trusted profile.
- [ ] `J1-L08` Modules, visibility, editions, package namespaces, and version-skew rules.
- [ ] `J1-L09` Numeric model for signed/unsigned integers, floats, overflow, conversions, and SIMD eligibility.
- [ ] `J1-L10` Formal executable semantics for authority, effects, information flow, and termination budgets.

Exit gate: valid programs have one specified parse, type/effect result,
canonical identity, and observable result across two independent
implementations for the published profile.

## J1 concurrency and agent workflows

- [ ] `J1-C01` Structured tasks with parent-child lifetime ownership.
- [ ] `J1-C02` Actors/channels with typed messages and bounded queues.
- [ ] `J1-C03` Futures, async functions, streams, deadlines, and cancellation.
- [ ] `J1-C04` Backpressure is mandatory at every bounded asynchronous edge.
- [ ] `J1-C05` Data-race policy and shared-state rules are statically enforceable.
- [ ] `J1-C06` Deterministic scheduler and virtual clock for tests.
- [ ] `J1-C07` Distributed task identity, idempotency, retry, and replay contracts.
- [ ] `J1-C08` Agent memory API with tenant/purpose/retention labels and canonical receipts.

Exit gate: concurrent workloads survive cancellation, overload, retry, crash,
and replay without authority duplication, unbounded queues, or cross-tenant
data flow in the tested contract.

## J1 trusted host and adapters

- [x] `J1-H01` Native work runs outside the authority-holding controller process.
- [-] `J1-H02` Filesystem, network, process, environment, clock, randomness, device, and dynamic-library effects default to denied logically; syscall confinement remains open.
- [ ] `J1-H03` Non-forgeable capability handles with scope, expiry, one-use consumption, and semantic task binding.
- [-] `J1-H04` Per-task wall, CPU, file, descriptor, output, and child limits; portable RSS/memory enforcement remains open.
- [-] `J1-H05` Timeout, signal, crash, and live-descendant states are fail-closed; OS-proven OOM classification remains open.
- [x] `J1-H06` Bounded canonical controller/executor IPC rejects malformed, truncated, duplicate, and oversized frames in the current profile.
- [ ] `J1-H07` Tenant/purpose labels survive compile, IPC, host call, result, cache, and logs.
- [ ] `J1-H08` Linux seccomp/namespaces/cgroups and a documented macOS App Sandbox or equivalent profile.
- [ ] `J1-H09` W^X lifecycle, relocation binding, JIT pointer ABI, and executable-memory audit.
- [ ] `J1-H10` Durable effect journal, crash recovery, exactly-once reconciliation, and revoked-capability behavior.
- [ ] `J1-H11` Stable adapters for filesystem, network, process, clock, randomness, database/API, GPU, and robot/device I/O.
- [ ] `J1-H12` C, Wasm Component Model, Rust, Python, and JavaScript host interoperability suites.

Exit gate: no `.joan` source or repository text can acquire an external effect
without an exact host capability, and crash/retry cannot create duplicate
authority or a false success receipt.

## J1 standard library

- [ ] `J1-S01` Numeric primitives, checked arithmetic, parsing, and conversions.
- [ ] `J1-S02` Collections, iterators, sorting, searching, and bounded caches.
- [ ] `J1-S03` UTF-8 text, bytes, canonical JSON, schemas, and content digests.
- [ ] `J1-S04` Time/deadline abstractions with deterministic test clock.
- [ ] `J1-S05` Typed paths, URLs, identities, capabilities, and error contexts.
- [ ] `J1-S06` Testing, assertions, property tests, deterministic fixtures, and benchmarks.
- [ ] `J1-S07` Agent-native task, tool, memory, policy, receipt, and evidence types.
- [ ] `J1-S08` Cryptography only through reviewed libraries and versioned safe APIs; no custom primitives.

Exit gate: the five reference applications use published standard APIs instead
of private compiler hooks or unversioned host shortcuts.

## J1 compiler and runtime portfolio

- [x] `J1-B01` Deterministic bytecode compiler and verifier.
- [x] `J1-B02` Bounded interpreter.
- [-] `J1-B03` Cranelift JIT for pure scalar subset.
- [ ] `J1-B04` Full-profile Cranelift JIT.
- [ ] `J1-B05` Reproducible AOT object/executable backend.
- [ ] `J1-B06` Wasm component backend/profile.
- [ ] `J1-B07` Optimization pipeline with differential and metamorphic equivalence gates.
- [ ] `J1-B08` Incremental compilation and content-addressed cache.
- [ ] `J1-B09` Debug information, stack traces, source maps, and deterministic crash records.
- [ ] `J1-B10` Cross-compilation matrix for macOS, Linux, Windows, Wasm, and one embedded/robot profile.

Exit gate: each supported backend agrees on observable results and receipts for
the conformance corpus; performance wins are reported only for equivalent
workloads and recorded hosts.

## J1 developer and agent toolchain

- [x] `J1-T01` `joan check`, `fmt`, `compile`, `run`, native commands, and JSON output.
- [-] `J1-T02` Offline package resolver and content-addressed store; public registry and signed index are absent.
- [ ] `J1-T03` Language server with diagnostics, navigation, completion, rename, and semantic tokens.
- [ ] `J1-T04` Debugger for VM, async tasks, capabilities, and receipts.
- [ ] `J1-T05` Profiler for CPU, allocation, queues, effects, wire bytes, and agent workflow latency.
- [ ] `J1-T06` Documentation generator with versioned API and examples.
- [ ] `J1-T07` Test runner, coverage, fuzz targets, mutation targets, and benchmark harness in one CLI.
- [ ] `J1-T08` Edition migration, formatter migration, package audit, and rollback tools.
- [ ] `J1-T09` Hermetic bootstrap packages and signed checksums for supported platforms.
- [ ] `J1-T10` Machine-readable quickstart that an external agent completes without private context.

Exit gate: a new agent can install an explicit release, build, test, debug,
profile, package, and upgrade a nontrivial project using only public artifacts.

## J1 security, quality, and conformance

- [x] `J1-Q01` Strict schemas reject unknown fields for current contracts.
- [x] `J1-Q02` Rust and independent Node JCE1 implementation agree on frozen vectors.
- [x] `J1-Q03` Dependency policy and vulnerability audit are automated locally.
- [-] `J1-Q04` ABI mutation, sanitizers, parser/checker differential corpus, and deterministic simulations exist; continuous multi-host fuzzing is absent.
- [ ] `J1-Q05` Threat model covers confused deputy, replay, downgrade, cache poisoning, TOCTOU, Sybil, resource exhaustion, and supply chain.
- [ ] `J1-Q06` Continuous fuzzing, mutation testing, sanitizers, and Miri where applicable.
- [ ] `J1-Q07` Reproducible release, SBOM, provenance attestation, signed tag, and verified installer.
- [ ] `J1-Q08` Independent security review with all critical/high findings closed.
- [ ] `J1-Q09` Compatibility, deprecation, security support, and release policies.
- [ ] `J1-Q10` Incident response, revocation, recovery drill, and compromised-release exercise.

Exit gate: the release has no open known critical/high finding, all supported
platform gates pass, and a separate operator can reproduce the published
evidence from GitHub.

## J1 reference applications

- [ ] `J1-A01` Portable CLI with files, structured data, packages, and tests.
- [ ] `J1-A02` Concurrent service with async I/O, cancellation, overload, and observability.
- [ ] `J1-A03` Agent workflow using tools, typed memory, authorities, retries, and receipts.
- [ ] `J1-A04` Data pipeline with bounded parallelism, streaming, and deterministic replay.
- [ ] `J1-A05` Robot/device simulator with deadlines, safety interlocks, and hardware adapter boundary.

Exit gate: all five applications build from the public release on macOS, Linux,
and one additional supported target; they survive the published hostile-input,
crash, cancellation, and version-skew corpus.

## J1 adoption and governance

- [x] `J1-G01` Founder, corporate owner, governance, commercial boundaries, and non-claims are documented.
- [x] `J1-G02` Apache-2.0 public-core decision and trademark boundary are documented.
- [ ] `J1-G03` Independent legal review of ownership, license, contribution terms, name clearance, and release custody.
- [ ] `J1-G04` Contributor provenance policy before any external patch is merged.
- [ ] `J1-G05` Three external agent trials complete and at least two intend to repeat or recommend.
- [ ] `J1-G06` Three independent projects ship JOAN code without compiler modification.
- [ ] `J1-G07` Maintainer/reviewer succession, security contact, and recovery procedure are tested.
- [ ] `J1-G08` Compatibility and conformance governance can evolve without a single machine or hidden service.

Exit gate: adoption evidence is external, contribution rights are traceable, and
loss of the founder's Mac does not destroy source, releases, keys, or recovery.

## Separate post-1.0 profiles

These are products built on the language, not prerequisites for JOAN Language
1.0:

- [ ] `P-LINK` JOAN Link private peer sessions, discovery, relay, mailbox, and recovery.
- [ ] `P-WORK` JOAN Work service offers, task contracts, results, and acceptance.
- [ ] `P-CLEAR` JOAN Clearing mock obligations, netting, external rails, and disputes.
- [ ] `P-ROBOT` Certified robot/device profiles and safety adapters.
- [ ] `P-ENTERPRISE` Proprietary or commercial policy, custody, fleet, compliance, and support modules.

No real-money, production-network, or safety-critical claim is permitted until
the applicable profile has its own legal, security, recovery, and operational
evidence.

## Critical execution order

1. Publish the source alpha and obtain hosted macOS/Linux evidence.
2. Run three external agent trials before broad language expansion.
3. Close host isolation and durable effect authority.
4. Implement language slices vertically: data types -> control flow -> memory -> errors/modules -> concurrency/async.
5. Build one reference application with each slice instead of postponing integration.
6. Expand the standard library and backend portfolio behind conformance gates.
7. Complete tools, platform matrix, independent audit, and migration policy.
8. Freeze `1.0-rc`, run external projects, close findings, then sign `1.0.0`.

## Time and staffing reality

A public alpha is a near-term release operation. A credible general-purpose 1.0
is a multi-month engineering program even with AI assistance because platform
ports, independent review, ecosystem use, compatibility time, and security
evidence cannot be compressed into code generation alone. The roadmap should be
re-estimated after each vertical slice and after the first three external
trials. Adding agents can accelerate independent modules and test generation;
it cannot replace independent operators, elapsed reliability evidence, or legal
and security review.
