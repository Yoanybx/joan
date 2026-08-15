# JOAN SBOM Evidence v0

Status: experimental, release-gating contract.

## Purpose

JOAN publishes a reproducible CycloneDX 1.5 inventory for the executable release
and for every Cargo package in the verified workspace. The inventory identifies
components and dependency edges; it does not prove that a component is safe,
vulnerability-free, correctly licensed or independently audited.

## Generator identity

The only accepted v0 generator is `cargo-cyclonedx 0.5.9`. Its executable
SHA-256 and exact version are recorded in `receipt.json`. Generation runs with
Cargo offline and with `SOURCE_DATE_EPOCH` derived from the source commit. A
random CycloneDX serial number is forbidden.

## Outputs

`scripts/generate-sbom.sh <target|all> <output-directory>` produces:

- `release-runtime.cdx.json`: dependency graph for the `joan-node` executable;
- `workspace/<crate>.cdx.json`: one package-level SBOM for every workspace crate;
- `workspace-index.json`: deterministic paths, hashes, byte sizes and graph counts;
- `receipt.json`: source, commit, lockfile, tool, target and reproducibility binding.

The output directory must remain outside the source checkout. Generation occurs
twice from separate source projections and every JSON byte must match. The
runtime target is explicit; the workspace inventory covers all supported target
dependencies.

## Canonical local identity

Upstream Cargo metadata represents path dependencies with checkout-specific
`path+file://` references. JOAN replaces package references with Cargo PURLs and
nested target references with deterministic `urn:joan:cargo-target` identifiers.
Any remaining `/Users/`, `/Volumes/`, `path+file://` or `file://` string is fatal.

## Verification

`scripts/verify-sbom.sh` requires:

1. exact generator version;
2. two byte-identical generations;
3. no random serial or local path;
4. complete component and dependency references;
5. exact source-tree v2, commit and `Cargo.lock` hashes;
6. exact artifact hashes, sizes and package counts;
7. schema-valid receipt and workspace index;
8. rejection of timestamp drift, missing components, dangling edges and path leaks.

The frozen v0 gate rejects ten negative controls: five document-level semantic
mutations and five artifact-set/binding mutations.

The release package carries the complete `SBOM/` directory. GitHub provenance
attests the enclosing archive after hosted release gates are enabled; v0 does
not claim that the SBOM itself has an independent signature.

## Rollback and evolution

B04 can be rolled back by reverting the additive generator, schemas, workflows
and package integration. CycloneDX versions newer than 1.5, a different
generator, or a changed normalization rule require a new JOAN SBOM contract and
new conformance evidence.
