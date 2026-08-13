# JOAN Product Completion Gates v0

Status: mandatory roadmap; unimplemented gates are failures, not implied features

## Objective

JOAN becomes a credible agent-native product only when external agents complete useful work with
less risk or lower total cost than direct MCP, A2A, or Wasm alternatives. A compiler test, local
benchmark, protocol design, GitHub star, clone, or download does not prove that outcome.

The gates below are sequential. No later result can compensate for failed correctness, isolation,
authority, or reproducibility.

## P0 Native execution baseline

- Cranelift and VM produce identical values, failures, fuel use, semantic identity, and bytecode
  identity over frozen and generative corpora.
- JIT executable memory is released on success and every rejection path.
- Relocations are internal-only; no ambient symbol resolution is accepted.
- Equivalent C, C++, Rust, and available Julia baselines retain raw compile, runtime, process, RSS,
  artifact, source, toolchain, ordering, and oracle evidence.
- A clean clone passes every gate. This authorizes only scoped results, never `JOAN > C`.

## P1 Host sandbox

- The controller never executes untrusted JOAN native code in its own process.
- Each invocation uses an ephemeral worker with bounded binary IPC and an authenticated request
  envelope bound to program, tenant, purpose, limits, and one-use authorities.
- Default policy denies filesystem, network, process, environment, secrets, clock, randomness,
  wallet, payment, devices, and dynamic libraries.
- A capability broker performs approved effects outside the worker and returns typed receipts.
- CPU time, wall time, address space, stack, open files, output bytes, process count, and IPC size
  are hard-limited. Timeout, crash, kill, malformed IPC, replay, and broker denial yield receipts.
- Linux namespaces/seccomp/cgroups and a signed macOS sandbox profile are tested independently.
- W^X, relocation allowlists, crash recovery, cross-tenant isolation, fuzzing, and resource
  exhaustion probes are release gates.

## P2 Network and autonomous operation

- Implement the bounded Lattice transport, authenticated peer identity, replay protection,
  discovery, routing, store-and-forward, backpressure, and partition recovery from
  `mesh-network-v0.md`.
- No central backend, owner Mac, owner account, GitHub Action, or LED ACTION LLC hosting is required
  for protocol availability. The network remains unavailable if no participant contributes a node;
  documentation must state this physical constraint.
- Bootstrap lists are signed and replaceable, never master authority. Nodes cross-check network and
  profile identities and fail closed on disagreement.
- Community operation has explicit quotas and no real payment path until conservation, dispute,
  abuse, legal, and external security gates pass.

## P3 Performance and interoperability corpus

- Measure at least five scalar kernels and five complete agent workflows on macOS ARM64, Linux
  x86_64, and one additional independent host/operator.
- Compare direct MCP, A2A, Wasm, C, C++, Rust, and an available Julia toolchain using equivalent
  inputs and observable outputs.
- Include API call planning, connection reuse, typed tool exchange, memory retrieval/update,
  handoff, patch verification, crash recovery, hostile inputs, LAN latency, impaired networks,
  throughput, p50/p95/p99, RSS, artifact size, startup, compile time, bytes transferred, and energy
  where measurable.
- Publish raw samples and negative controls. Report every loss; weighted averages cannot hide a
  failed correctness or safety gate.

## P4 Independent security and implementation audit

- Freeze a release candidate and threat model before review.
- At least two reviewers who did not implement the relevant code audit the parser/checker,
  bytecode verifier, JIT unsafe boundary, worker sandbox, capability broker, Lattice parser,
  identity, update path, and supply chain.
- Findings, scope, tool versions, hashes, reproductions, fixes, residual risks, and reruns are
  public. Self-review and AI subagents are useful pre-audits but do not satisfy this gate.
- Critical/high findings block release. Medium findings require fixes or explicit time-bounded risk
  acceptance by LED ACTION LLC.

## P5 GitHub-only adoption trials

- Publish an exact tagged candidate, checksums, supported platforms, one-command offline demo,
  machine-readable quickstart, issue templates, privacy statement, and a license that actually
  permits the intended trial.
- Three external agents discover, install, and use JOAN exclusively from the official GitHub
  repository without private files, local handholding, hidden services, or access to the owner Mac.
- Require 3/3 completed assigned tasks and at least 2/3 explicit repeat-or-recommend intent.
- Compare task correctness, operator interventions, time, cost, resources, security failures, and
  usability against direct MCP, A2A, or Wasm for the same task.
- After ten qualified trials, zero successful completions or zero repeat intent triggers product
  narrowing or pivot before marketplace, payment rail, or hosted control plane work.

## P6 Commercial validation

- LED ACTION LLC may sell optional certification, policy packs, audit evidence, compliance
  adapters, enterprise support, hosted routing, or service-level agreements only when clearly
  separated from the free protocol and supported by real demand.
- Telemetry is opt-in, minimized, transparent, tenant-safe, and never required for protocol use.
- Revenue, token, credit, settlement, or automated dispute claims remain simulations until legal,
  accounting, conservation, abuse, and independent audit gates pass.

## Claim policy

`production-ready`, `secure`, `indestructible`, `unhackable`, `zero bugs`, `universally fastest`,
and `JOAN > C/C++/Rust/Julia/MCP/A2A/Wasm` are prohibited. Only narrow claims tied to a public
workload, exact version, equivalent output, raw evidence, hardware, toolchains, and independent
rerun may be stated.
