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
`node tools/evidence-index.mjs check` additionally recomputes inventory and
validates three complete local run receipts against the exact gate
configuration, runner and executable hashes.

The v2 index also binds the recorded AI-agent scorecard file, its
`baseline-only-not-qualified` status, workload count, frozen JOAN safety total,
and false broad/universal superiority claims. This binding is evidence of the
recorded result, not evidence that the result qualifies JOAN as superior.

`scripts/refresh-evidence.sh` is the only supported refresh path. It executes
every verification and supply-chain gate three times, writes each receipt
atomically, builds the evidence index only from those receipts, then checks it
again. No environment variable can bypass or self-assert a passing refresh.
