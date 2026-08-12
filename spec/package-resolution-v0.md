# JOAN Content-Addressed Package Resolution v0

## Status

This document specifies the local resolver implemented by `joan-package` and
`joan package resolve`. It verifies package graphs; it is not a package registry,
network installer, dependency solver, source linker, payment system, or claim of
supply-chain invulnerability.

## Identity model

A package name is a human label. Package authority is the JCE1 digest of the
exact canonical `joan.package-manifest.v0` bytes in the registered
`joan.package-manifest.v1` domain.

Each manifest pins:

- one or more modules by exact `joan.source.v1` digest;
- one root module name;
- zero or more dependencies by exact `joan.package-manifest.v1` digest.

There are no version ranges, mutable tags, registry precedence rules, implicit
upgrades, or fallback names. Changing one source byte changes its source digest,
which changes its manifest digest and every transitive parent manifest digest.

## Canonical contract

Manifest payload JSON must already be exact JCE1. A file may add one final LF
as Git-compatible text framing; that LF is not part of the package digest. A
second LF, CRLF, or any other whitespace is rejected. Unknown fields, noncanonical bytes,
wrong digest tags, malformed lowercase names, unsorted arrays, duplicate paths,
duplicate dependency identities, missing roots, absolute paths, `.`/`..`
components, and non-`.joan` module paths fail closed.

Within one graph, one `namespace/name@edition` coordinate may map to only one
manifest digest. A second identity claiming the same coordinate fails closed,
preventing a future linker from receiving an ambiguous human name.

Coordinates use a lowercase reverse-DNS-style namespace, lowercase package
name, and lowercase edition label. Module declarations use JOAN ASCII identifier
syntax. Module and dependency arrays are strictly sorted by module name and
alias so independent producers converge on one representation.

## Local store

Resolution reads only these exact paths beneath a caller-supplied store:

```text
manifests/sha256/<manifest-digest>.json
sources/sha256/<source-digest>.joan
```

Every component is checked with `symlink_metadata`; symlinks and unexpected file
types are rejected. Object bytes are verified against the requested typed digest
before use. JOAN source must parse and its declared module must match the
manifest. The resolver does not write to the store and contains no network
client.

A GitHub release, future JOAN Mesh peer, removable disk, or any other transport
may populate this store. Transport provenance does not replace content
verification. A future fetcher must place an object only after checking its
typed digest and must remain outside compiler authority.

## Defensive bounds

- manifest or source object: at most 1 MiB;
- root manifest file: at most 1 MiB plus its optional final LF, bounded before decode;
- packages per graph: at most 1,024;
- modules per graph: at most 4,096;
- dependency depth: at most 64;
- unique source bytes per graph: at most 64 MiB;
- modules per manifest: at most 1,024;
- dependencies per manifest: at most 256.

Cycles, missing objects, size overflow, arithmetic overflow, parse failures and
digest mismatches reject the entire resolution.

## Receipt and CLI

```bash
joan package resolve package.joan.json --store .joan/store --json
```

Success emits `joan.package-resolution-receipt.v0` with the exact transitive
root, all resolved package identities, unique source identities, module count,
source bytes, explicit no-network policy and read-only store mode. Lists are
ordered by digest for deterministic output.

## Boundary

The v0 resolver proves that one bounded local graph matches exact content
addresses. It does not yet compile imports across files, publish packages,
discover names, establish author identity, revoke malicious content, prove that
review occurred, or make untrusted code safe to execute.
