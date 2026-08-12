# JOAN Mesh Network v0

## Status

This is a target architecture, not an implemented network. The current
`joan-node` is a local CLI and `joan-lattice` is a frame codec. There is no peer
discovery, transport, replication, remote execution, public seed, or autonomous
global service yet.

## Constraint

JOAN must not require LED ACTION LLC or Joan Alberto Barrios Cruz to operate a
central backend. Every active network operation still consumes resources on
some participant's machine. The design can make owner hosting cost zero by
having users and service providers supply those resources; it cannot make
computation, storage, bandwidth, or availability physically free.

If no participant runs a node, the network is unavailable. That fact must never
be hidden by marketing.

## Roles

| Role | Contribution | Benefit |
|---|---|---|
| Consumer node | submits bounded jobs and verifies receipts | obtains agent services without adopting a provider stack |
| Provider node | offers compute, storage, data, or tools | receives useful-service claims or external settlement |
| Relay node | forwards encrypted frames without reading payloads | receives bounded relay/storage service claims |
| Archive node | retains selected immutable content blocks | receives storage claims and improves availability |
| Verifier node | recomputes or verifies selected receipts | receives verification claims and improves trust |
| Seed publisher | signs a peer/profile snapshot | enables bootstrap but has no execution authority |

One node may perform multiple roles. No role grants protocol governance or
authority over another participant's machine.

## No mandatory backend

The runtime data plane is peer-to-peer:

```text
local agent -> local JOAN node -> authenticated peer session
            -> provider executes locally -> signed/verifiable receipt
```

The protocol requires no central account database, global transaction order,
blockchain, always-on LED server, or owner-held wallet. Each job is scoped to its
participants and its precommitted verification/settlement policy.

## GitHub's limited role

The official repository may distribute:

- source, specifications, conformance vectors, and security policy;
- signed release manifests and platform binaries;
- a small signed bootstrap snapshot containing multiple independent seed
  addresses and expiry times;
- protocol profile registries and revocations released through governed commits;
- public CI evidence and reproducible build instructions.

GitHub is never used as the live message bus, transaction ledger, memory store,
payment processor, dispute runtime, or liveness oracle. Nodes cache releases and
seed snapshots and continue operating when GitHub is unavailable. A release
asset URL is a distribution convenience, not part of consensus.

Public GitHub Actions can validate releases without paid minutes on standard
runners under current GitHub terms, but quotas and policies can change. CI must
be budget-capped and the network must not depend on Actions for runtime work.

## Bootstrap without owner hosting

1. A node installs a signed JOAN release from GitHub or another mirror.
2. It verifies the release manifest and embedded conformance root offline.
3. It loads a bounded, expiring list of independent seeds from the release.
4. It contacts several seeds in parallel and cross-checks network/profile IDs.
5. It discovers additional peers using a decentralized peer-routing mechanism.
6. It stores only verified peer records with expiry and reputation local to the
   observing node.
7. It can export/import peer snapshots so communities can bootstrap from other
   mirrors if every official seed disappears.

No seed is trusted for program authority, payment truth, or global state. A
malicious seed can at most lie about peer discovery; multi-seed comparison,
signed identities, diversity requirements, and out-of-band snapshots limit that
attack.

## State model

JOAN Mesh avoids global consensus. State is divided by ownership:

- immutable blocks are content-addressed and may be replicated;
- mutable service offers are signed, short-lived advertisements;
- job state belongs to the exact requester/provider contract;
- authority is local and one-use, never inferred from network membership;
- receipts form a job-local causal chain;
- clearing is scoped to consenting participants and settlement adapters;
- governance releases define compatibility, not ownership of participant data.

Global consensus is required only if a future feature truly needs one. It is not
paid on every two-party API call.

## Availability without free riding

Replication is contractual, not assumed. A block's availability profile states
replica count, regions or failure domains, expiry, audit schedule, maximum size,
and useful-service compensation. A node may decline work before accepting a
contract. Once accepted, missed audits produce the precommitted remedy but do
not create unlimited debt.

The first network mode should also support uncompensated community relays with
strict quotas. This permits experimentation without money while preventing one
participant from consuming the entire network.

## Security baseline

- authenticated encrypted peer sessions with forward secrecy;
- algorithm agility and a versioned post-quantum migration profile;
- no ambient filesystem, process, secret, wallet, or network authority;
- Lattice frame bounds before allocation and semantic validation before effect;
- replay windows and durable consumption for one-use approvals;
- per-peer quotas, proof-of-resource admission, backpressure, and circuit breakers;
- Sybil-resistant policy based on cost, diversity, prior bilateral evidence, or
  accountable identity, not one universal reputation number;
- multi-tenant memory isolation and local deletion/retention policy;
- signed releases, reproducible builds, rollback, and independent mirrors;
- no automatic protocol mutation on the production compatibility profile.

## Owner control and adoption

LED ACTION LLC can retain copyright, trademarks, official release signing keys,
conformance marks, and authority over official hosted services. It cannot both
give participants a genuinely decentralized protocol and retain technical power
to stop, rewrite, or seize every independently operated node. The durable model
is governance and brand authority over the official distribution, not a hidden
master key over the network.

Commercial revenue can come later from optional certified releases, enterprise
policy, managed observability, compliance adapters, support, clearing, dispute
automation, and service-level agreements. The base protocol must remain useful
without those services or decentralized adoption will be weak.

## Implementation sequence

1. Freeze Lattice canonical frames and hostile-input corpus.
2. Add durable local identity and one-use approval storage.
3. Implement encrypted loopback and LAN sessions behind a feature flag.
4. Add multi-seed bootstrap and signed expiring peer records.
5. Implement content-reference exchange and bounded block cache.
6. Run 3, 10, 100, and 1,000-node deterministic simulations.
7. Deploy independent test nodes operated by at least three parties.
8. Measure churn, partition recovery, Sybil pressure, replay, data loss,
   bandwidth, tail latency, cost, and operator effort.
9. Only then define a public test network and external settlement adapters.

## Exit criteria

JOAN Mesh is not “autonomous” until three independent operators can install from
the official release, discover each other without an LED server, exchange and
verify jobs across restart/partition, rotate keys, update and roll back, and
recover from loss of all official seeds using a mirror snapshot.
