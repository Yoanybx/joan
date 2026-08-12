# JOAN Genesis Conformance v0

The Rust repository is an alpha reference slice. Passing local tests proves only the covered inputs and exact build.

Required local gates:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test --doc --workspace
cargo build --workspace --release
```

Supply-chain gates require `cargo-deny` and `cargo-audit`; if unavailable they must be reported as unexecuted, never silently treated as passing.

No `J*1` public claim is authorized until its exact schema, vectors, command log, source digest, failures and limitations are recorded in `.joan/evidence/latest.json`. Independent levels require an implementation or evaluator not derived from this codebase.
