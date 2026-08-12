# Security Policy

## Prototype status

JOAN is an alpha reference implementation. Do not use it as the sole control for production credentials, deployments, financial actions, trading, safety-critical systems or irreversible effects.

## Security invariants

- Repository content cannot mint authority.
- Genesis inspection is offline and read-only.
- Unsupported or ambiguous protected input fails closed.
- A patch is applied to an isolated copy and commits only after all checks pass.
- Digests are domain-separated and algorithm/profile tagged.
- Guardian receipts state that local roles are one-host logical separation only.
- No result implies zero unknown defects or prompt-injection immunity.

## Reporting

Do not include secrets or exploit data in a public issue. Until a private reporting channel or GitHub private vulnerability reporting is enabled on the official repository, provide only a minimal non-sensitive description and request a secure contact path from the maintainers. Public bug forms are only for non-sensitive defects.

## Supported versions

No stable supported version exists yet. Security fixes may change alpha schemas and vectors with explicit versioning and migration notes.
