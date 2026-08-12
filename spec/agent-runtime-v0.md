# JOAN Agent Runtime Design v0

## Status

The language VM and Lattice frame codec are experimental implementations. Call
Fabric and Continuum Memory are design contracts only. No real API call, secret,
network connection, vector index, or durable agent memory is provided yet.

## One execution model, three engines

### Call Fabric

Call Fabric turns a checked JOAN effect request into a host-executed API plan.
The `.joan` program never contains credentials and cannot open a socket. A plan
binds the provider profile, request/response schema digests, deadline, retry and
idempotency policy, privacy class, cost ceiling, authority proof, and expected
receipt to the program's semantic identity.

The host may optimize without changing meaning:

- reuse authenticated HTTP/2 or HTTP/3 connections;
- use a binary provider adapter where supported;
- batch compatible requests and coalesce duplicate in-flight calls;
- send content references for context already known by the provider adapter;
- cache only when policy, identity, freshness, and privacy permit it;
- hedge or retry only idempotent calls inside the declared budget;
- stream validated output while preserving a final receipt root.

Provider latency is external. JOAN performance reports must separate local
planning overhead from DNS, connection, provider queue, model compute, network,
streaming, and receipt verification.

### Lattice communication

Lattice carries the knowledge difference between machines in six bounded
levels. Its v0 Rust codec uses one exact-size allocation to encode and returns
borrowed payload slices when decoding. It currently provides framing only; peer
authentication, sessions, replay protection, block exchange, encryption,
congestion control, and transports remain unimplemented.

### Continuum Memory

Continuum Memory stores immutable, content-addressed blocks plus typed links. It
uses four rings rather than one unbounded conversation log:

| Ring | Contents | Retrieval path |
|---|---|---|
| R0 Working | current task state, budgets, pending effects | direct local slots |
| R1 Episode | ordered events and execution receipts | task/session identity |
| R2 Knowledge | normalized facts, code identities, contracts, relationships | digest and typed graph |
| R3 Archive | cold evidence blocks and snapshots | explicit restore policy |

A memory reference carries tenant, authority scope, provenance, creation and
expiry policy, content digest, type digest, and links to supporting receipts.
Embeddings are optional indexes, never canonical truth. Retrieval proceeds in
this order: exact digest, typed links, lexical/structured filters, then semantic
search. This avoids expensive approximate search when the machine already knows
the identity it needs.

## Context capsule

Before an API or M2M call, the runtime builds a bounded context capsule:

```text
goal + accepted constraints + relevant memory references
     + unknown blocks + one-use authority + output contract
```

The capsule excludes duplicated history, expired claims, secrets, unrelated
tenant data, and unverified model summaries. Every included item records why it
was selected so memory retrieval can be audited and evaluated.

## Required measurements

- API plans per second and local p50/p99 overhead;
- bytes and tokens avoided by context deduplication;
- connection reuse, batching, cache hit, and coalescing rates;
- exact-digest, graph, lexical, and semantic memory hit rates;
- retrieval precision, recall, stale-result rate, and cross-tenant leakage count;
- total time-to-first-byte and time-to-verified-result;
- cost per accepted result, not cost per attempted request;
- deterministic replay agreement for all local stages.

No optimization is accepted if it changes the output contract, weakens
authority, leaks a tenant, hides provider cost, or makes a receipt unreproducible.
