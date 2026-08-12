# JOAN Canonical Encoding Profile 1

Status: frozen alpha interoperability profile. Identifier: `JCE1`.

JCE1 is additive. JCE0 remains available for Genesis contracts that have not migrated. A producer must never label JCE0 bytes or hashes as JCE1.

## Data model

JCE1 accepts JSON null, booleans, strings, arrays, objects and integers in the inclusive range `-9007199254740991` through `9007199254740991`. Input bytes must be valid UTF-8. It rejects floating point values, exponent notation, negative zero, duplicate object keys, malformed UTF-8 or Unicode and trailing data.

Object properties are ordered by lexicographic comparison of their UTF-16 code units, matching the JSON Canonicalization Scheme property-sorting rule. Array order is preserved. JCE1 performs no Unicode normalization; canonically equivalent Unicode strings with different code-point sequences remain different values.

Strings use JSON escaping. No insignificant whitespace is emitted.

## Defensive limits

- encoded input: 1,048,576 bytes;
- recursive depth: 64;
- aggregate values: 100,000;
- one string or key: 262,144 UTF-8 bytes;
- one JCE1 hash payload: 1,048,576 bytes.

Exceeding any limit fails closed.

## Typed hash

The only JCE1 hash profile is `joan-hash-v1` with SHA-256. The byte preimage is:

```text
"JOAN\0HASH\0V1"
|| u64be(length("joan-hash-v1")) || "joan-hash-v1"
|| u64be(length(domain))          || domain
|| u64be(length(payload))         || payload
```

The algorithm, profile, exact registered domain and lowercase 64-character digest value are mandatory parts of the typed digest. Verification rejects any substitution before accepting the payload identity.

Registered domains are enumerated by `schemas/digest.v1.schema.json` and `RegisteredDomainV1`. Unknown, differently cased or colon-delimited domains are invalid.

## Semantic sets

Each set element is independently JCE1-encoded and hashed in `joan.canonical-set-element.v1`. Elements are ordered first by lowercase digest bytes and then by canonical bytes. Duplicate canonical elements are rejected. This gives permutation invariance without relying on host map or locale order.

## Conformance

The normative executable suite is `vectors/jce1/conformance-v1.json`. It contains exactly 27 positive, negative, hash and semantic-set vectors. The suite's `spec_freeze_sha256` must equal the plain SHA-256 of this file. Both implementations reject a suite whose binding is stale. Conformance reports emit the JCE1 typed digest of the exact suite bytes.

Conformance requires all vectors to pass in both the Rust implementation and the independent Node reference, followed by equality of every observation and suite digest. The gate also feeds an invalid UTF-8 byte sequence to both command-line implementations and requires fail-closed behavior. Run `./scripts/verify-jce1.sh`.

Passing this suite proves agreement only for the frozen vectors and properties tested. It does not prove freedom from defects, cryptographic invulnerability or superiority over another language.
