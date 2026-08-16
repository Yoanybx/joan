# JOAN Source Tree Evidence v2

Status: current frozen local evidence profile.

`joan-source-tree-v2` binds repository-relative paths to exact file bytes
without relying on Git history. It supersedes v1 for new receipts after v1 was
shown to be non-portable on macOS exFAT checkouts. It is not a replacement for
a signed Git tree or release attestation.

## Input set

Walk every regular file below the repository root and exclude exactly:

- `.git` and its descendants;
- root `target` and its descendants;
- `.joan/evidence` and all descendants;
- a `.DS_Store` path component at any depth;
- a path component beginning with `._` at any depth.

The last two classes are macOS Finder and AppleDouble metadata. They cannot be
JOAN source, executable gates, manifests, specifications, schemas, vectors, or
receipts under this profile. All other dotfiles remain included.

Symbolic links are rejected. Paths use `/`, are relative to the root and are
sorted by unsigned UTF-8 bytes.

## Digest

For each included file:

```text
record = u64be(pathByteLength)
      || pathUtf8
      || SHA256(fileBytes)
```

The tree digest is:

```text
SHA256("JOAN\0SOURCE-TREE\0V2" || record[0] || ... || record[n])
```

The evidence index records the profile, digest, file count and exclusion
classes. File permissions, timestamps, owners, extended attributes, Git
configuration, ignored build outputs and excluded platform metadata are outside
this profile.

## Gate

`node tools/evidence-index.mjs source` prints only the current source snapshot.
`node tools/evidence-index.mjs check` is the issuer-host gate: it recomputes
inventory and validates three complete local run receipts against the exact
gate configuration, runner and executable hashes on the host that emitted
them.

`node tools/evidence-index.mjs check-current <current-receipt>` validates one
new external receipt strictly against the current host, source, inventory,
tool versions and executable bytes. The default `scripts/verify-all.sh` path
requires both `check` and `check-current`, so its newly generated receipt is
never left unvalidated.

`node tools/evidence-index.mjs check-portable <current-receipt>` is the
cross-host gate. It validates a newly generated receipt strictly against the
current host and validates the three checked-in historical receipts against
their source, inventory, gate, runner, stream-digest and recorded-executable
bindings without requiring those historical executable paths to exist on the
new host. The current receipt must be outside `.joan/evidence/runs`, have a new
run identifier and bind the current host's executable bytes. Twelve negative
controls must be rejected on every invocation.

Repository scripts in historical receipts are bound to the current source
bytes. Non-repository gates are cross-bound to the historical tool inventory.
Historical test counts remain host-specific observations and are not compared
to the current host. Because the checked-in receipts do not yet carry an
external signature or GitHub attestation, the portable report marks those
records as unauthenticated and does not use them to claim operator identity.

`scripts/verify-all.sh` defaults to the issuer-host gate. Hosted CI and the
independent rerun package must select the portable contract explicitly with
`--portable-evidence`; no environment variable can change that decision. A
portable pass proves cross-host reproducibility of the declared contracts. It
does not prove operator independence, organizational independence, release
authorization, production readiness or universal language superiority.

The final PR-trust step preserves the same boundary. In strict mode it validates
the issuer-host index and emits and byte-reverifies the local PR Trust Envelope.
In portable mode it revalidates the current-host receipt but intentionally does
not emit an issuer-host envelope from historical receipts created on another
platform. The mode and receipt are positional arguments propagated by
`verify-all.sh`; environment variables cannot silently select the policy.

The v2 index also binds the recorded AI-agent scorecard file, its
`baseline-only-not-qualified` status, workload count, frozen JOAN safety total,
and false broad/universal superiority claims. This binding is evidence of the
recorded result, not evidence that the result qualifies JOAN as superior.

`scripts/refresh-evidence.sh` is the only supported refresh path. It executes
every verification and supply-chain gate three times, writes each receipt
atomically, builds the evidence index only from those receipts, then checks it
again. No environment variable can bypass or self-assert a passing refresh.
