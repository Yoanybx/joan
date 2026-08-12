# JOAN Canonical Encoding Profile JCE0

Status: implemented experimental subset, not an independent standard.

## Accepted values

- `null` and booleans;
- signed and unsigned 64-bit JSON integers;
- UTF-8 strings;
- ordered arrays;
- objects with lexicographically sorted unique keys.

## Rejected values

- duplicate object keys;
- floating-point numbers, NaN and infinity;
- integers outside the parser's exact 64-bit range unless represented by an application-validated string;
- trailing data, comments and recovery parsing;
- inputs exceeding configured byte, depth, node or string bounds.

Canonical output is compact UTF-8 JSON. Array order is preserved. Object order is sorted. Typed schemas, not generic JSON, determine whether an array semantically represents a set.

JCE0 is inspired by deterministic JSON work but intentionally narrows the numeric domain. It does not claim full RFC 8785 compatibility.
