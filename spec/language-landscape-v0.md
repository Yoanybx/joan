# JOAN Language Landscape and Experiment Program v0

## Scope

No finite review can compare every programming language, dialect, DSL, runtime,
and implementation ever created. This matrix covers the major design families
that constrain an agent-native systems language. Every conclusion is a research
hypothesis until a JOAN implementation and equivalent-work benchmark exist.

## Representative strengths and costs

| Family | Strength to learn from | Cost or limit to avoid | JOAN experiment |
|---|---|---|---|
| C | Small runtime model, direct layout, mature native toolchains | Undefined behavior and ambient machine authority make untrusted agent code dangerous | Native kernel baseline with byte-for-byte outputs |
| C++ | Zero-overhead abstractions, templates, mature optimizers | Very large language surface and difficult safety boundary | Keep core semantics small; use backend optimizers later |
| Rust | Ownership enables memory safety without a garbage collector | Borrowing complexity and long compile paths can obstruct generated code | Linear values in IR, simpler source rules, Rust reference implementation |
| Zig | Explicit allocation and cross-compilation focus | Safety depends on selected modes and disciplined APIs | No hidden allocator or host effect in core semantics |
| Go | Simple concurrency and fast builds | GC and runtime scheduling reduce latency control | Measure compile latency and tail latency, not only throughput |
| Java, Kotlin, C# | Productive managed ecosystems, reflection, mature VMs | Warmup, GC, and large ambient runtime surface | Optional managed hosts; deterministic core remains portable |
| Swift | Ownership evolution and strong native ergonomics | Large compiler/runtime and platform emphasis | Study ergonomic ownership diagnostics |
| Python, JavaScript | Agent-friendly generation, ubiquitous libraries, fast iteration | Dynamic errors and runtime overhead | Use as orchestration adapters, not the trusted execution kernel |
| Julia | Specialization and numerical expressiveness | Compilation latency and specialization unpredictability | Shape-specialized numeric kernels as a later benchmark |
| Haskell, OCaml | Algebraic types, pattern matching, immutable defaults | Effect models and runtime behavior can be unfamiliar operationally | Add algebraic data only with exhaustive machine diagnostics |
| Erlang, Elixir | Isolation, message passing, supervision, upgrade practice | Per-message/runtime overhead versus native kernels | Typed supervisor receipts and deterministic restart policy |
| Pony | Actors plus reference capabilities prevent data races statically | Capability concepts are difficult to learn and ecosystem is small | Machine-generated capability diagnostics and ownership visualization |
| Koka, Unison | Typed effects; Unison also content-addresses definitions | Less mature deployment ecosystems than mainstream languages | Effect rows plus content-addressed semantic identities |
| Move | Linear resources make important values non-copyable/non-droppable | Domain focus and VM/storage assumptions | Linear service claims and one-use authority in a later IR |
| Lean | Small proof-checking kernel and dependent types | Proof authoring and elaboration can be expensive | Proof-carrying high-risk contracts checked by a small optional kernel |
| Dafny | Specifications, functional verification, termination measures | Solver cost and proof brittleness can impede routine code | Explicit decreasing measures for future loops and recursion |
| WebAssembly | Compact, safe, portable, sandboxed low-level target | Host interface and capability policy remain embedder concerns | Primary portable execution target after v0 semantics freeze |
| LLVM, MLIR, Cranelift | Mature optimization and multi-level lowering infrastructure | Backend complexity does not define safe source semantics | Use multiple backends and require equivalent receipt roots |
| Protobuf | Compact schema-driven tagged wire format and broad tooling | Serialization is not canonical by default and authority is out of scope | Canonical M2M frame with schema digest and authority section |
| FlatBuffers, Cap'n Proto | Random access and low-copy decoding | Trust validation and evolution rules remain application concerns | Borrowed frame views plus strict bounds before field access |

## Primary references

- [C standard working group](https://open-std.org/jtc1/sc22/wg14/)
- [Rust ownership](https://doc.rust-lang.org/stable/book/ch04-00-understanding-ownership.html)
- [WebAssembly core design goals](https://webassembly.github.io/spec/core/intro/introduction.html)
- [Protocol Buffers encoding](https://protobuf.dev/programming-guides/encoding/)
- [Erlang/OTP supervision trees](https://www.erlang.org/doc/system/design_principles.html)
- [Pony reference capabilities](https://www.ponylang.io/learn/reference-capabilities/)
- [Move abilities](https://move-language.github.io/move/abilities.html)
- [Unison content-addressed code](https://www.unison-lang.org/docs/the-big-idea/)
- [Lean kernel](https://lean-lang.org/doc/reference/latest/Elaboration-and-Compilation/)
- [Dafny verification and termination](https://dafny.org/dafny/DafnyRef/DafnyRef)
- [MLIR canonicalization](https://mlir.llvm.org/docs/Canonicalization/)

## Original JOAN synthesis

The intended contribution is not a new spelling for familiar code. JOAN aims to
make a program, a machine message, its requested authority, its useful-service
obligation, and its reproducible receipt share one semantic identity model.

The working design name is **JOAN Lattice**. A Lattice exchange carries only the
knowledge difference between peers: intent, unknown content blocks, attenuated
authority, evidence, and expected result. Known blocks are referenced by digest.
This is inspired by content addressing, effect systems, linear resources,
capability security, compact wire formats, and proof checking, but their
composition must be evaluated as a JOAN-specific protocol rather than claimed as
globally unique without a prior-art review.

## Required experiment ladder

1. Freeze source semantics and observable receipts.
2. Implement linear authority values in the checker and bytecode verifier.
3. Implement a borrowed JOAN Lattice frame codec with strict bounds.
4. Compare bytes, allocations, encode/decode throughput, p50/p99 latency, schema
   negotiation, and end-to-end round trips against JSON, Protobuf, FlatBuffers,
   Cap'n Proto, and CBOR on identical messages.
5. Lower one corpus to Cranelift, LLVM AOT, and WebAssembly.
6. Compare runtime, compile latency, binary size, peak memory, energy, and
   deterministic output with C, Rust, Zig, Go, and Wasm baselines.
7. Run fuzzing, differential execution, mutation testing, and hostile-input
   campaigns before any security or speed claim.
8. Require two independent implementations to produce identical semantic roots.

JOAN may claim a win only for the exact workload, hardware, toolchains, inputs,
and output equivalence recorded by a reproducible experiment.
