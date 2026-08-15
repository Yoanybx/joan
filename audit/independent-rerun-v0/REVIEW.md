# JOAN Independent Rerun v0

This package reproduces the five native pure-kernel benchmarks from an exact Git checkout. It does not prove that JOAN is generally faster than C, C++, Rust, or Julia.

## Reviewer procedure

1. Clone the repository from its official GitHub remote without receiving files by another channel.
2. Record the commit SHA and keep the checkout clean.
3. Install the toolchains listed in `manifest.json`. Node.js 24.19.0 is the pinned JavaScript runtime; `cargo-cyclonedx 0.5.9` is required for the reproducible SBOM gate.
4. Set `CARGO_TARGET_DIR` to an absolute directory outside the checkout.
5. Run `bash scripts/run-independent-rerun.sh <absolute-output-directory>`.
6. Preserve every JSON artifact and its GitHub artifact attestation, when available.
7. Report disagreements without changing the source, reference report, or generated receipt.

The runner executes a recorded benchmark, the complete repository verification gate, a platform-local native ABI report, and a fatal semantic comparison. Timing samples may vary. Program identities, oracle results, required implementation checksums, and semantic observation digests must not vary. A semantic observation digest binds every canonical observation field except `compile_ns` and `runtime_ns`; those measurements remain present as raw samples but are intentionally excluded from cross-host identity.

## Independence boundary

The generated receipt always says that independence is unverified. A GitHub-hosted run proves machine provenance, not that the operator is independent from LED ACTION LLC. L17 closes only after another host and operator publishes the artifacts with verifiable provenance.

## Review boundary

The package intentionally excludes credentials, legal signatures, private planning notes, and all real payment or network effects. The benchmark exercises the published pure native subset only.
