# JOAN PR Trust Envelope v0

Status: experimental local profile.

The PR Trust Envelope is JOAN's first composed agent-native program. It binds an
exact local Git candidate, current source-tree evidence, three verification
receipts, an offline content-addressed package and a bounded `.joan` policy into
one deterministic JCE1 artifact.

Its successful status is `requirements-satisfied`. It never means `safe`,
`approved`, `mergeable`, `reviewed`, `signed` or `trusted`. Source, pull-request
text, issues and tool output remain untrusted data.

## Commands

```text
joan trust pr evaluate <repo> --base <commit> --head <commit> --json
joan trust pr verify <repo> <envelope.json> --json
```

Both commands are offline and read-only. `evaluate` requires a clean index and
worktree, requires `head` to equal checked-out `HEAD`, resolves both references
to full commit IDs and requires `base` to be an ancestor of `head`. `verify`
decodes exact canonical JCE1, validates the envelope digest, reruns evaluation
and requires byte-for-byte semantic equality.

## Candidate boundary

- Git subprocesses use fixed argument vectors, `--no-optional-locks`, disabled
  terminal prompting and no shell.
- Only added, modified and deleted regular files are accepted. Renames are
  represented as delete plus add; symlinks, submodules and special files fail.
- Paths must be relative, normalized, UTF-8 and free of controls, backslashes,
  `.git`, AppleDouble and Finder metadata components.
- Base and head blob bytes, typed content digests, status and path are bound.
- Changed-file count and the sum of base plus head bytes are policy bounded.
- Checked-out bytes for current files must equal the exact head Git blob.

## Evidence boundary

The evaluator independently reconstructs `joan-source-tree-v2`. It validates
the current evidence index, exact index digest, three unique receipt files and
their raw SHA-256, source identity, ordered 11/11 gate outcomes, repeatability,
JCE1 27/27, JDR1 10,000-case observation and zero known vulnerabilities in the
recorded `cargo-audit` result. It also binds the current runner and gate-config
file hashes in both the index and each current receipt.

The current authorization path requires the checked-out source tree, runner,
gate configuration and 11-gate profile to match exactly. A separate internal
historical verifier can inspect legacy 10-gate receipts after the source tree
advances, but that path never produces a PR Trust Envelope or authorizes the
current checkout.

These are three local runs from one host and operator. They are not independent
attestations. A modified implementation can generate new self-consistent local
receipts, so external review, signatures and protected CI remain separate.

## JOAN policy composition

`.joan/pr-trust.json` pins the policy source and package manifest by JCE1 typed
digests. The local store resolves without network access or writes. The policy
program must compile as information-flow bytecode v3, execute within its exact
instruction budget and emit only:

```text
publish_pr_assessment("requirements-satisfied")
authority slot: publish_once
label: secret / tenant github / purpose pr_review
```

An in-process one-shot approval is created for that exact request and consumed
while producing an effect-plan receipt. The effect remains data. JOAN never
posts a review, changes a pull request, pushes, merges or calls GitHub.

## Identity

The profile registers four JCE1 domains:

- `joan.pr-candidate.v1`;
- `joan.pr-trust-policy.v1`;
- `joan.pr-trust-evidence.v1`;
- `joan.pr-trust-envelope.v1`.

The final envelope digest covers every field except itself. Unknown JSON fields,
annotation deletion, policy substitution, evidence substitution and candidate
substitution fail closed.

## Explicit limitations

- Local Git identity is not a signature or official remote identity.
- Passing gates cannot prove absence of bugs or malicious behavior.
- The current evaluator has no GitHub API, hosted bot or branch-protection role.
- Receipt timestamps are evidence text, not trusted time authority.
- The Rust compiler, verifier and trust evaluator are not independent formal
  implementations.
- This profile provides no claim of zero bugs, unhackability, adoption or
  superiority over C or any network.
