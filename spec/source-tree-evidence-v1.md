# JOAN Source Tree Evidence v1

Status: frozen local evidence profile.

`joan-source-tree-v1` binds repository-relative paths to exact file bytes without relying on Git history. It is a pre-commit Genesis profile, not a replacement for a signed Git tree or release attestation.

## Input set

Walk every regular file below the repository root and exclude exactly:

- `.git` and its descendants;
- `target` and its descendants;
- `.joan/evidence` and all descendants.

Symbolic links are rejected. Paths use `/`, are relative to the root and are sorted by unsigned UTF-8 bytes.

## Digest

For each file:

```text
record = u64be(pathByteLength)
      || pathUtf8
      || SHA256(fileBytes)
```

The tree digest is:

```text
SHA256("JOAN\0SOURCE-TREE\0V1" || record[0] || ... || record[n])
```

The evidence index records the profile, digest, file count and exclusions. File permissions, timestamps, owners, extended attributes, Git configuration and ignored build outputs are outside this profile.

## Gate

`node tools/evidence-index.mjs check` recomputes the tree, workspace-crate count, schema count, Rust test count, JCE1 suite and specification identities, source-bound simulation test and recorded benchmark-file identity. It also validates three complete run receipts against the exact gate configuration, runner and executable hashes. Any mismatch fails closed.

`scripts/refresh-evidence.sh` is the only supported refresh path. It executes every verification and supply-chain gate three times, writes each receipt atomically, builds the evidence index only from those receipts, then checks it again. No environment variable can bypass or self-assert a passing refresh.
