# External Agent Stack Assessment v0

## Source and decision rule

This note assesses the ideas supplied in the user document titled “Stack de
Protocolos para Agentes” on 2026-08-12. Names, code snippets, and performance
claims are not accepted as facts without primary evidence and an equivalent-work
JOAN reproducer.

## Adopt now as contracts

| Idea | JOAN decision | Reason |
|---|---|---|
| Compact typed packets | Adopt through JOAN Lattice | Binary hot path, bounded validation, content references, and a separate human view are stronger than decorative Unicode |
| Cost/quality API routing | Adopt in Call Fabric roadmap | Provider choice should optimize accepted-result quality, latency, privacy, reliability, and total cost under hard budgets |
| Reciprocal service chains | Adopt through Useful-Service Clearing | Typed service obligations and netting avoid inventing a speculative universal token |
| Predictive prefetch | Adopt behind policy | Useful only with privacy, cancellation, idempotency, waste, and spend budgets plus measured hit rate |
| Version adaptation | Adopt as governed experiments | Candidate profiles may be generated, shadow-tested, signed, canaried, and rolled back; live peers never mutate semantics unilaterally |
| Tiered verification | Adopt | Deterministic replay and signatures first, TEE/ZK adapters only when value and threat justify their cost |

## Optional interoperability adapters

### x402 and MPP

x402 is a real HTTP payment protocol. Its v2 flow returns `402` plus payment
requirements, then receives a signed payment payload and can use a facilitator
for verification and settlement. MPP also has a published HTTP authentication
specification. JOAN should support both only as optional settlement adapters.

Neither protocol replaces JOAN's contract, acceptance evidence, dispute,
exposure, privacy, or clearing layers. On-chain payment is not the default and
the JOAN VM never holds a wallet or signs autonomously.

### Ratify

Ratify is relevant prior art for delegated agent authorization and hybrid
Ed25519 plus ML-DSA-65 signatures. JOAN should test compatibility rather than
copy an implementation. ML-DSA-65 keys and signatures are large for a hot M2M
frame, so sessions should exchange them out of band and reference validated
delegations by digest when policy permits.

### zkAgent

zkAgent is a 2026 Cryptology ePrint preprint, not proof that arbitrary modern
agents can be verified cheaply. The reported evaluation is scoped to GPT-2 and
specific agents; its abstract reports approximately 240 seconds to prove some
end-to-end agents, about 0.5 seconds to verify, and 42 MB proofs. JOAN should
retain a proof-adapter interface and benchmark it only for high-value tasks.

## Learn from, do not depend on

### EAP and m2m-protocol

EAP demonstrates compact ASCII packets and context references. Its own material
notes that Unicode token cost depends on the tokenizer. `m2m-protocol` is an
experimental learned/multi-codec implementation. JOAN Lattice should include
both projects in future comparisons, but its canonical wire contract cannot
depend on a learned lossy codec or another project's unstable vocabulary.

### FrugalML

FrugalML is credible research showing workload-specific cost/accuracy routing;
the published “up to 90%” result is not universal. JOAN should reproduce the
principle with current agent APIs and optimize cost per accepted result under
quality, privacy, latency, reliability, and budget constraints.

## Reject or quarantine

| Proposal | Decision | Failure mode |
|---|---|---|
| VAE/LASE lossy contract encoding | Reject for authority, money, code, evidence, and receipts | Approximate reconstruction changes meaning and cannot be canonical |
| Unilateral self-healing protocol mutation | Reject in production | Splits peers, invalidates receipts, enables downgrade and supply-chain attacks |
| “Same security” from sampled verification | Reject claim | Sampling provides probabilistic detection under assumptions, not full-execution equivalence |
| Dynamic arbitrary-token liquidity routing | Quarantine as external finance | Slippage, bridges, custody, oracle, sanctions, tax, credit, and smart-contract risk |
| Cognitive state/gradient fusion | Reject as core | Provider APIs do not expose compatible internal state; it leaks IP/data and increases bandwidth |
| Zero latency or infinite bandwidth | Reject as physically false | Transport, synchronization, compute, and information limits remain |
| Compute futures and negative effective cost | Reject from autonomous core | Creates financial exposure and can lose principal |
| “Holographic consensus” | Reject until formalized | The example combines erasure coding, replication, Merkle roots, and voting without a consensus or security proof |
| Compute/attention as universal money | Reject | Hardware, quality, energy, timing, and usefulness are not fungible; Sybil and verification problems remain |

## Revised JOAN stack

```text
JOAN source + static effects
  -> deterministic bytecode + execution receipt
  -> Call Fabric plan (no secret or socket in VM)
  -> Lattice knowledge-differential frame
  -> delegated one-use authority
  -> tiered verification policy
  -> cost/quality/privacy/reliability router
  -> useful-service clearing
  -> optional MPP, x402, bank, or Stripe settlement adapter
```

## Primary references

- [x402 official documentation](https://docs.cdp.coinbase.com/x402/welcome)
- [Machine Payments Protocol specifications](https://paymentauth.org/)
- [FrugalML paper](https://papers.nips.cc/paper_files/paper/2020/hash/789ba2ae4d335e8a2ad283a3f7effced-Abstract.html)
- [zkAgent Cryptology ePrint 2026/199](https://eprint.iacr.org/2026/199)
- [Ratify protocol](https://identities.ai/faq)
- [EAP repository](https://github.com/kagioneko/esoteric-ai-protocol)
- [m2m-protocol crate](https://docs.rs/crate/m2m-protocol/latest)
