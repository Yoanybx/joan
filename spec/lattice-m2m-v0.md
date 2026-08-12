# JOAN Lattice M2M Design v0

## Status

This is an experimental design contract, not an implemented network protocol.
`joan-lattice` implements the bounded v0 frame codec and borrowed level views.
It does not implement peer sessions, encryption, replay protection, block
exchange, transport, routing, or language-to-network execution.

## Objective

Minimize machine-to-machine time-to-trusted-result, not parser time in
isolation. The measured objective is:

```text
TTR = negotiation + bytes_on_wire + decode + verify + execute + receipt
```

Optimizing one term while hiding work in another does not establish a win.

## Knowledge-differential capsule

A sender should transmit only what the receiver does not already know. Every
capsule is divided into six independently bounded levels:

| Level | Meaning | Required property |
|---|---|---|
| L0 Frame | version, bounds, level map | single-pass rejection before allocation |
| L1 Shape | schema and type identities | digest-addressed, no field names on hot path |
| L2 Intent | requested computation and deadline | canonical and replay-scoped |
| L3 Authority | attenuated one-use capabilities | non-minting and externally authorized |
| L4 Evidence | unknown input blocks and proofs | known blocks sent as digest references |
| L5 Result | output, resource use, effects, receipt root | deterministic where profile requires it |

The informal “wormhole” is a content reference: when both peers possess and
verify the same digest, the payload does not cross the wire again. The protocol
must still handle cache misses, eviction, collisions, replay, and adversarial
claims without trusting the sender.

## Fast path

1. Peers exchange supported profile digests once per authenticated session.
2. The sender chooses an already-known schema and implementation profile.
3. Fixed-size L0 bounds are validated before any variable section is touched.
4. Known L1/L4 blocks are references; unknown blocks are contiguous inline data.
5. L3 capabilities are checked before execution and consumed at most once.
6. The receiver executes locally and returns L5 or a bounded rejection receipt.
7. Receipts update peer knowledge sets in batches.

No human-readable symbol, JSON key, blockchain consensus, global lookup, or
payment token is required on this hot path.

## Safety invariants

- No repository text, model output, or frame field grants ambient authority.
- Lengths and counts are checked before allocation or indexing.
- Noncanonical encodings, duplicate sections, trailing bytes, unknown critical
  levels, stale replay scopes, and capability reuse fail closed.
- Digests identify bytes under a versioned domain; they are not authorization.
- A reference miss requests the exact block or aborts; it never guesses.
- Determinism profiles pin arithmetic, clocks, randomness, locale, and host calls.
- Every externally performed effect binds to one approved request and receipt.

## Performance contract

The initial benchmark corpus must include tiny control messages, agent tool
calls, 4 KiB evidence, 1 MiB payloads, repeated known-content exchanges, and
adversarial malformed frames. Report:

- encoded bytes and compression separately;
- allocations and bytes copied;
- encode, bounded-validate, decode, execute, and receipt times;
- p50, p95, p99, and worst observed latency;
- cold and warm schema/cache behavior;
- local, loopback, LAN, and impaired-network round trips;
- CPU, peak memory, and energy where measurable;
- rejected-input cost and maximum resource bounds.

Required baselines are canonical JSON/JCE1, Protocol Buffers, CBOR, FlatBuffers,
and Cap'n Proto. Equivalent meaning and validation are mandatory. JOAN Lattice
must not be called faster until checked-in evidence supports a scoped claim.

## Adoption property

The wire specification must be royalty-free to implement and test. LED ACTION
LLC can sell hosted routing, enterprise policy, observability, compliance,
support, and certified conformance without making protocol interoperability
depend on a proprietary server.
