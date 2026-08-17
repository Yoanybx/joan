# JOAN GitHub-only Adoption Trial v1

This package measures one bounded task: safe repository metadata and instruction-file discovery.
It compares a dependency-free Node.js reference with the JOAN repository inspector over a frozen
fixture and rejects any correctness disagreement.

## External operator procedure

1. Clone `https://github.com/Yoanybx/joan.git` without receiving files by another channel.
2. Check out the exact 40-character commit under review and keep the checkout clean.
3. Set `CARGO_TARGET_DIR` to an absolute directory outside the checkout.
4. Run `bash scripts/run-adoption-trial.sh <absolute-output-directory> <operator-relation>`.
5. Use `independent` only when the operator is not affiliated with LED ACTION LLC; otherwise use
   `affiliated` or `undisclosed`.
6. Preserve the generated JSON artifacts and submit an Adoption report issue from the GitHub
   account that performed the evaluation.

The task runtime is offline, read-only, has no telemetry, and requires no account, secret, wallet,
payment, owner-host access, listener or JOAN service. Cargo may download public dependencies while
building; that build phase is recorded separately from task duration.

## Qualification boundary

Every automatic receipt says `independence.status=unverified`,
`counts_toward_external_trial_gate=false`, and `f08_complete=false`. A declaration or GitHub-hosted
run identifies an actor and machine path, but it does not prove organizational independence.

F08 closes only after reviewable evidence shows three external operators completed the task and at
least two explicitly intend to repeat or recommend it. Self-runs, owner-operated workflows, copied
JSON, private assistance, or access to the owner Mac do not count. This trial does not establish a
release, production readiness, security completeness, adoption, or universal language superiority.
