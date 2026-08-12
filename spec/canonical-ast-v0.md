# JOAN Canonical AST Profile v0

## Status

This document freezes the first structural identity profile for checked JOAN
language programs. Its AST schema is `joan.canonical-ast.v0`, its encoding is
JCE1, and its registered typed-hash domain is
`joan.language-canonical-ast.v1`.

The profile identifies one normalized program structure. It does not prove
behavioral equivalence, optimizer correctness, absence of bugs, or security of
host effects.

## Projection

Only a parsed program accepted by `joan-check` is eligible. The projection from
the diagnostic AST to the canonical AST performs exactly these operations:

1. remove every source span and all source trivia;
2. sort function declarations by their ASCII identifier;
3. sort each declared effect row by its ASCII identifier;
4. preserve module, function, parameter, local, callee, and effect names;
5. preserve parameter order, statement order, expression tree shape, argument
   order, types, operators, and literal values;
6. encode every `i64` literal as its exact base-10 string.

The string representation for `i64` is required because JCE1 numeric values are
limited to the exact interoperable JSON range, while JOAN supports the complete
signed 64-bit range. The parser already rejects non-`i64` literals and source
spellings with a sign or leading zero are normalized by integer parsing.

This profile deliberately does not normalize local names, parameter names,
function names, commutative expressions, constant expressions, dead code, or
equivalent call graphs. Those transformations require separately versioned
optimizer proofs rather than silent identity changes.

## Encoding and identity

The projected value must match `schemas/canonical-ast.v0.schema.json` and is
serialized as exact JCE1 bytes. The identity descriptor is:

```json
{
  "schema": "joan.canonical-ast-identity.v0",
  "encoding": "JCE1",
  "ast_schema": "joan.canonical-ast.v0",
  "digest": {
    "algorithm": "sha256",
    "profile": "joan-hash-v1",
    "domain": "joan.language-canonical-ast.v1",
    "value": "<64 lowercase hexadecimal characters>"
  }
}
```

Verification fails unless the bytes are valid UTF-8, parse as strict JCE1,
re-encode byte-for-byte identically, contain the exact AST schema, and match the
typed digest. JCE1's 1 MiB hash-payload bound applies.

## Compiler binding

`joan-compiler` copies the descriptor's digest into the existing
`semantic_digest` field and carries the complete descriptor as
`semantic_identity` in bytecode and execution receipts. Before VM execution,
the descriptor tags and equality of both digest fields are checked. Effect
request IDs continue to derive from that exact semantic digest.

The v0 VM does not yet recompute bytecode from embedded canonical AST bytes and
there is no standalone bytecode verifier. Therefore, this profile proves the
compiler's declared AST identity and detects inconsistent identity metadata; it
does not prove that arbitrary externally supplied instructions were generated
from that AST. A future bytecode-verification profile must close that boundary.

## Required tests

- whitespace, accepted comments, formatting, function order, and effect order
  preserve canonical bytes and digest;
- literal, operator, callee, function, type, statement, and effect changes alter
  the digest;
- full-range `i64` literals remain exact;
- noncanonical bytes, altered payloads, incorrect domains, and inconsistent
  bytecode identity metadata fail closed;
- compile and execution outputs carry the same typed AST identity.
