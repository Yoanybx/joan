# JOAN Automatic Dispute Simulation v0

Status: local deterministic calibration corpus; not production training evidence.

The `joan-sim` crate generates unique content-addressed contracts, cases, policies and evidence from an exact seed. Cases are partitioned by index into calibration (70%), holdout (20%) and adversarial (10%) splits.

The v0 corpus rotates through honest provider, non-delivery, acceptance failure, duplicate charge, budget excess, unauthorized scope, settlement mismatch, repair failure, contradictory evidence, primary-quorum collusion, replay and binding attacks.

```bash
cargo run --release -p joan-node -- dispute simulate --cases 10000 --seed 144 --json
```

The output is a bounded summary plus an incremental corpus hash chain. A single oversized JSON array is intentionally avoided so canonical defensive limits remain unchanged.

The current machine-bound repository claim is exactly 10,000 cases at seed 144, executed by `crates/joan-sim/tests/corpus.rs` during the required workspace test gate. Larger prior runs are historical observations unless a current source-bound receipt records them.

## Interpretation

- `final_incorrect = 0` proves only agreement with the deterministic synthetic ground truth encoded by this generator.
- It does not prove correctness on real disputes.
- It does not train a model.
- Future learned adjudicators must never train on their own unverified decisions.
- Calibration and holdout artifacts must remain separated and independently reproducible.
- Any real-data training requires consent, privacy controls, provenance, bias analysis and an external evaluation corpus.
