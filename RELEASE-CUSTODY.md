# JOAN Release Custody

Status: private Genesis control policy. No secret, private key, recovery code,
token, or signed legal instrument belongs in this repository.

## Corporate control boundary

LED ACTION LLC controls designation of the official repository, protected
release environment, signing identity, recovery custodians, and emergency
revocation procedure. Joan Alberto Barrios Cruz remains recorded as original
creator and founder. Repository access alone does not transfer either status or
authorize publication.

During Genesis one person may perform several operational roles, but that must
be recorded honestly and must not be represented as independent review. Before
public release, the company must document outside Git who can:

- administer the official GitHub organization and repository;
- approve a protected release environment;
- use and revoke the release signing identity;
- recover the organization, domain, and signing accounts;
- receive private vulnerability reports;
- stop publication after suspected compromise.

## Fail-closed release authorization

The `release` GitHub environment must be protected by required reviewers and
must define these non-secret environment variables for one release candidate:

- `JOAN_RELEASE_APPROVAL_ID`: company authorization or change-record identity;
- `JOAN_RELEASE_APPROVED_COMMIT`: exact 40-character Git commit;
- `JOAN_RELEASE_APPROVED_TAG`: exact immutable release tag.

The workflow compares those values with GitHub's checked-out repository,
commit, and tag. It also requires every machine-readable readiness control to be
true. Missing or mismatched metadata aborts before build or publication.

These variables are evidence references, not a substitute for environment
protection, company authorization, a signed tag, or secure account recovery.
They must never contain credentials or private legal text.

## Minimum external controls

1. Use a company-controlled GitHub organization with recovery methods not tied
   to a single device.
2. Require protected default and release branches, immutable protected tags,
   CODEOWNERS review, hosted macOS/Linux CI, and private vulnerability reporting.
3. Keep signing and recovery material in independently backed-up corporate
   custody; publish only public verification material.
4. Revoke credentials, pause releases, preserve evidence, and publish a bounded
   incident notice after suspected compromise.
5. Test recovery and revocation before the first public release and at a defined
   recurring interval.

No remote, environment, key, tag, push, release, or deployment is created by
this policy.
