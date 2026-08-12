# JCE1 Cross-Implementation Conformance

## Implementations

- Rust: `joan-canonical` executed through `joan-conformance` and the `joan` CLI.
- Node: `tools/jce1-reference.mjs`, using only Node built-ins and no Rust, WebAssembly or JOAN package.

The implementations share the JSON vector file, not parser, canonicalizer, set or hash code. This is structural independence level I1 for the tested profile, not organizational independence.

## Gate

```bash
./scripts/verify-jce1.sh
```

The gate requires Node.js 24 or newer, executes exactly 27 vectors in each implementation and compares normalized reports after removing only the implementation name. Any failed vector, digest difference, observation difference, missing runtime or malformed report fails the gate.

The guardian and release workflows run this gate. A release package includes the exact vector suite used by its source revision.

## Vector groups

- `J001` through `J008`: canonical output and Unicode ordering.
- `N001` through `N010`: unsafe numbers, malformed Unicode, duplicate keys, schema closure and defensive bounds.
- `H001` through `H005`: domain separation, fixed digest, typed substitution, registry closure and payload bounds.
- `S001` through `S004`: set permutation, duplicate rejection and deterministic tie-breaking.

The suite must be versioned, never silently rewritten. Any incompatible semantic change requires a new profile and migration contract.
