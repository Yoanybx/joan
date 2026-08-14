# JOAN Tool Forge TF-V0

Status: experimental, offline, pure-only, fail-closed.

TF-V0 turns one exact canonical ToolSpec into auditable JOAN Source and complete
verified bytecode. It then requires a separate verification call, externally
supplied guardian votes, finalization, and a derived promotion decision.

## Pipeline

```text
ToolSpec
  -> static spec verification
  -> three deterministic generation passes
  -> ToolBundle (Source + complete bytecode)
  -> independent regeneration + bytecode verification + behavior tests
  -> external GuardianCandidate
  -> finalization
  -> eligible or quarantined
```

The generator cannot create or approve guardian votes. Eligibility does not
authorize publication, deployment, installation, network access, filesystem
access, processes, secrets, payment, devices, telemetry, or any host effect.

## ToolSpec

Inputs are exact canonical JCE1 JSON, limited by the CLI to 1 MiB. A ToolSpec
binds a lowercase tool name, tenant, purpose, instruction budget, one pure
operation, and 1 to 64 mandatory behavior tests.

TF-V0 operations are:

- `identity-i64`
- `add-i64`
- `subtract-i64`
- `multiply-i64`
- `equal-i64`
- `and-bool`

Strings, bytes, effects, loops, recursion, imports, dynamic code, host calls and
unbounded allocation are outside TF-V0. Arithmetic inherits JOAN checked i64
semantics.

## Identities

All TF-V0 identities use the registered JCE1 hash construction and exact
domains:

- `joan.tool-spec.v1`
- `joan.tool-spec-verification.v1`
- `joan.tool-bundle.v1`
- `joan.tool-verification.v1`
- `joan.tool-finalization.v1`
- `joan.tool-promotion.v1`

Source and bytecode retain their existing registered JOAN identities. A bundle
contains the complete bytecode, not only a digest, so another process can verify
and execute the declared tests without trusting the generator.

## Verification

`tool verify` independently regenerates three times, requires byte-identical
bundles, recompiles Source, compares complete bytecode, invokes the standalone
bytecode verifier, rejects every effect row or request instruction, and executes
all tests under the declared instruction budget. Effects remain absent and
`external_effects_executed` is always false.

## Guardian and promotion

`tool finalize` accepts a GuardianCandidate created outside Tool Forge, reexecutes
verification, and requires the supplied receipt to be byte-equivalent to the
derived receipt. TF-V0 fixes three logical guardian identities and roles, a
threshold of three, and evidence bound to Source and bytecode. Existing guardian
invariants also reject duplicate voters, mismatched roots and proposer
self-approval. This is a one-host logical policy, not cryptographic or
organizational independence.

Pending, denied, malformed, downgraded or mismatched candidates quarantine the
bundle. `tool promotion evaluate` rederives the complete chain from ToolSpec
through finalization before returning eligibility and does not apply any external
effect.

## CLI

```text
joan tool spec verify <spec.jce1> --json
joan tool forge <spec.jce1> --json
joan tool verify <spec.jce1> <bundle.jce1> --json
joan tool finalize <spec.jce1> <bundle.jce1> <verification.jce1> <guardian-candidate.jce1> --json
joan tool promotion evaluate <spec.jce1> <bundle.jce1> <verification.jce1> <guardian-candidate.jce1> <finalization.jce1> --json
```

Outputs are canonical JCE1 JSON. The correct claim is that the tested artifacts
had zero observed failures in the frozen gates, never that generated tools have
zero bugs or are production-safe.
