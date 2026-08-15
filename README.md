# JOAN

JOAN is an experimental, agent-native language and verification substrate for deterministic programs, semantic identity, atomic patches, guardian decisions, repository instruction boundaries, evidence-based adoption and machine-only dispute resolution.

Original creator and founder: **Joan Alberto Barrios Cruz**. Project-designated corporate owner: **LED ACTION LLC**, Florida document number **L23000299152**. The signed-assignment requirement is recorded in [OWNERSHIP.md](OWNERSHIP.md). See [AUTHORS.md](AUTHORS.md), [ORIGIN.md](ORIGIN.md) and [GOVERNANCE.md](GOVERNANCE.md).

Current status: `alpha language preview`. Real `.joan` source can be parsed, checked, formatted,
compiled to deterministic bytecode and executed in a bounded VM. A frozen pure scalar subset can
also be JIT-compiled with Cranelift behind explicit `native` commands. This is not a complete native
compiler, host sandbox or global network, and it has no claim of universal superiority, zero bugs
or prompt-injection immunity.

## First verified value

No account, API key, wallet, token, server or telemetry is required.

```bash
cargo build -p joan-node -p joan-executor
"${CARGO_TARGET_DIR:-target}/debug/joan" node self-check
cargo run -p joan-node -- check examples/agent-handoff.joan --json
cargo run -p joan-node -- fmt examples/agent-handoff.joan --check
cargo run -p joan-node -- compile examples/agent-handoff.joan --json
cargo run -p joan-node -- run examples/agent-handoff.joan --json
cargo run -p joan-node -- native compile vectors/native/pure-v0.joan --json
cargo run -p joan-node -- native run vectors/native/pure-v0.joan --function score --arguments vectors/native/arguments-v0.json --budget 100 --json
cargo run -p joan-node -- run examples/linear-agent-handoff.joan --json
cargo run -p joan-node -- run examples/tenant-safe-handoff.joan --json
cargo run -p joan-node -- repo inspect . --json
cargo run --release -p joan-node -- dispute simulate --cases 10000 --seed 144 --json
cargo run -p joan-node -- conformance jce1 vectors/jce1/conformance-v1.json --json
cargo run -p joan-node -- package resolve examples/package-resolution/package.joan.json --store examples/package-resolution/store --json
cargo run -p joan-node -- trust pr evaluate . --base HEAD^ --head HEAD --json
./scripts/verify-jce1.sh
./scripts/benchmark-digest.sh 4096 5000
./scripts/verify-agent-scorecard.sh
./scripts/verify-native-abi.sh
./scripts/verify-native-backend.sh
./scripts/verify-native-benchmark.sh
./scripts/verify-payment-cost.sh
./scripts/verify-sbom.sh
./scripts/verify-all.sh
```

The inspection command is designed to be offline and read-only. It reads only allowlisted repository metadata and instruction files under explicit size and path bounds.

## Components

- `joan-canonical`: strict JSON subset and domain-separated digests.
- `joan-ast`: stable language AST and machine-readable diagnostics.
- `joan-syntax`: bounded lexer, parser and canonical source formatter.
- `joan-check`: static names, types, effects, linear authority, tenant-purpose information flow and acyclic termination checks.
- `joan-bytecode`: non-executing stack, frame, label-flow, call, effect and AST-codegen verification.
- `joan-compiler`: deterministic bytecode compiler and bounded receipt-producing VM.
- `joan-conformance`: executable JCE1 vectors and cross-implementation observations.
- `joan-identity`: semantic identity bundles, package IDs, symbol IDs and node references.
- `joan-patch`: atomic patches over a flat canonical test graph with independent full/incremental root checks.
- `joan-package`: offline content-addressed manifests and exact local dependency resolution.
- `joan-guardian`: deterministic one-host logical guardian gates and receipts.
- `joan-instruction`: typed authority attenuation, instruction decisions and safe repository discovery.
- `joan-lattice`: bounded canonical M2M frame codec with borrowed payload views.
- `joan-abi`: 64-bit C ABI for bounded payload-zero-copy Lattice validation and typed semantic binding.
- `joan-native`: experimental Cranelift JIT for the verified, effect-free scalar subset.
- `joan-runtime`: external-authority effect planning with atomic one-use approval consumption.
- `joan-case`: content-addressed automatic dispute lifecycle.
- `joan-evidence`: immutable-at-lock evidence graph.
- `joan-dispute`: primary/appeal machine quorums and precommitted automatic fallbacks.
- `joan-mock-ledger`: value-conserving reserve/refund/release simulation with no real money.
- `joan-sim`: deterministic calibration, holdout and adversarial dispute corpus.
- `joan-trust`: offline Git candidate, evidence, package and bounded JOAN policy binding for PR requirements.
- `joan-node`: local CLI, repository inspection, adoption evaluation and dispute commands.

## Security boundary

Repository text is data or guidance, never execution authority. JOAN can propose or evaluate an action, but an external host must supply the exact authority required for any effect.

Read [AGENTS.md](AGENTS.md), [JOAN.md](JOAN.md), [SECURITY.md](SECURITY.md), [GOVERNANCE.md](GOVERNANCE.md), [spec/language-v0.md](spec/language-v0.md), [spec/linear-authority-v1.md](spec/linear-authority-v1.md), [spec/information-flow-v1.md](spec/information-flow-v1.md), [spec/differential-language-v1.md](spec/differential-language-v1.md), [spec/agent-scorecard-v1.md](spec/agent-scorecard-v1.md), [spec/pr-trust-envelope-v0.md](spec/pr-trust-envelope-v0.md), [spec/bytecode-verification-v0.md](spec/bytecode-verification-v0.md), [spec/package-resolution-v0.md](spec/package-resolution-v0.md), [spec/language-landscape-v0.md](spec/language-landscape-v0.md), [spec/lattice-m2m-v0.md](spec/lattice-m2m-v0.md), [spec/agent-runtime-v0.md](spec/agent-runtime-v0.md), [spec/native-backend-v0.md](spec/native-backend-v0.md), [spec/mesh-network-v0.md](spec/mesh-network-v0.md), [spec/product-completion-gates-v0.md](spec/product-completion-gates-v0.md), [spec/company-value-capture-v0.md](spec/company-value-capture-v0.md), [spec/external-agent-stack-assessment-v0.md](spec/external-agent-stack-assessment-v0.md), [spec/canonical-profile-jce1.md](spec/canonical-profile-jce1.md) and [spec/conformance-jce1.md](spec/conformance-jce1.md) before changing or integrating the prototype.

Operational metrics, bug intake and the fail-closed update policy are documented in [OPERATIONS.md](OPERATIONS.md). JOAN has no hidden runtime telemetry; GitHub metrics are aggregate adoption proxies and never prove active-user counts.

Performance evidence follows [spec/benchmark-policy-v0.md](spec/benchmark-policy-v0.md). The first equivalent-output comparison measured C + CommonCrypto faster than Rust + `sha2`; JOAN therefore makes no current claim of outperforming C.

The AI-first scorecard compares complete inert tool, memory and tenant-safe
handoff task paths against C, Rust and Node 24 TypeScript. Its gates require
exact output equivalence and non-compensable safety criteria. The current
two-workload result is deliberately `baseline-only-not-qualified`; it is not a
claim that JOAN is faster or generally better. The first 21-sample evidence is
recorded in
[`benchmarks/results/2026-08-12-mac15-4-agent-scorecard.json`](benchmarks/results/2026-08-12-mac15-4-agent-scorecard.json).

Payment-cost evidence follows [spec/payment-cost-proof-v0.md](spec/payment-cost-proof-v0.md). JOAN v0 charges no protocol fee and compares qualified settlement modes using fixed-point total effective cost. The checked-in scenario is illustrative evidence of deterministic selection, not proof that JOAN is universally the cheapest payment system.

Machine evidence follows [spec/source-tree-evidence-v2.md](spec/source-tree-evidence-v2.md); [v1](spec/source-tree-evidence-v1.md) remains frozen for historical receipts. A passing index is derived from three complete local execution receipts and binds JCE1 and the language preview to the exact source tree, normative specifications and executable gates. This is reproducible local evidence, not independent attestation.

Release and workspace dependency inventories follow
[spec/sbom-evidence-v0.md](spec/sbom-evidence-v0.md). The CycloneDX output is
generated twice, rejects checkout paths and is bound to source, lockfile and
tool hashes. It is an inventory, not proof of safety or a license grant.

Public release readiness is deliberately blocked by
[`.joan/publication-readiness.json`](.joan/publication-readiness.json). The
source gate checks legal, repository, security, custody, CI and signing state;
the release workflow additionally requires protected environment metadata for
the exact repository, commit and tag. See
[LEGAL-ASSET-INVENTORY.md](LEGAL-ASSET-INVENTORY.md),
[RELEASE-CUSTODY.md](RELEASE-CUSTODY.md) and [TRADEMARKS.md](TRADEMARKS.md).
Those records do not select a license or execute a publication.

Run `scripts/verify-differential-language.sh` to compare the Rust parser/checker with the dependency-free Node.js reference over 44 frozen cases and 32 deterministic mutations. A 76/76 pass reduces implementation-correlated risk but is not an external audit or a performance claim.

The experimental native boundary in `include/joan.h` exposes fixed-width C/C++
layouts and relative Lattice spans without retaining input pointers. Separately,
`joan-native` JIT-compiles the verified effect-free scalar subset. The official
native CLI runs that backend in the adjacent, environment-cleared `joan-executor`
process through a bounded canonical protocol; the low-level Rust API remains
in-process for conformance tests and embedders. Process separation is not an
operating-system sandbox, and neither component is a claim of speed superiority.
The ABI's source-bound local receipt is retained at
`.joan/evidence/native-abi-v1.json`. See
[spec/native-abi-v1.md](spec/native-abi-v1.md) and
[spec/native-backend-v0.md](spec/native-backend-v0.md), with the process contract
in [spec/host-executor-v0.md](spec/host-executor-v0.md).

## License and commercial authority

Genesis is private and all rights are reserved by LED ACTION LLC under the project designation. No public-source or commercial-use license has been granted. Joan Alberto Barrios Cruz remains permanently identified as original creator. Corporate ownership must be supported by the separately signed assignment described in `OWNERSHIP.md`; repository text is not that legal instrument.
