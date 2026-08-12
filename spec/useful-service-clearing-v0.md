# JOAN Useful-Service Clearing v0

## Status and boundary

This is an economic and protocol design, not a deployed payment system. JOAN v0
does not hold money, issue a token, operate a wallet, extend credit, or settle
regulated funds. Legal, tax, sanctions, money-transmission, lending, securities,
privacy, and consumer-protection analysis is required before real deployment.

## Better than a speculative token

The proposed native exchange object is a **Proof of Useful Service** receipt.
It is a non-transferable, typed claim that one machine delivered measurable work
to another under a precommitted contract. A receipt is denominated in the work
unit, not in a floating universal coin.

Examples include verified CPU-milliseconds under a pinned runtime, byte-hours of
durable storage, accepted data records, availability windows, tool outcomes, or
resolved cases. Different units are never silently converted.

## Lifecycle

1. Requester publishes a bounded service contract, acceptance test, maximum
   obligation, deadline, dispute profile, and external settlement preference.
2. Provider accepts by semantic digest and reserves only the stated resources.
3. JOAN records execution evidence and the deterministic acceptance result.
4. An accepted result creates matched debit/credit service obligations.
5. Reciprocal obligations of the same unit and policy class are netted in a
   clearing window.
6. Only the residual is routed to barter, prepaid enterprise balance, or a
   regulated external USD settlement provider.
7. Settlement and dispute receipts close the obligation without creating a
   freely tradable asset.

## Why machines use it

- A requester can buy a one-time service without adopting the provider's entire
  software stack.
- A provider receives a verifiable claim or external payment for accepted work.
- Bilateral and multilateral netting reduce transfer count and fixed fees.
- Typed units prevent misleading conversion between unlike services.
- Deterministic acceptance and precommitted remedies reduce negotiation cost.
- No protocol gas, mining, or speculative inventory is required.

## Required protections

- service claims cannot be copied, replayed, or transferred as bearer money;
- issuance requires paired contract and acceptance evidence;
- conservation checks cover every debit, credit, reserve, release, and refund;
- colluding machines cannot manufacture externally redeemable value without an
  accountable payer and configured exposure limit;
- identity, rate limits, credit limits, reserves, deadlines, and circuit breakers
  are explicit policy inputs;
- disputes cannot create value and cannot exceed the original obligation;
- insolvency, unavailable providers, partial delivery, quality drift, and oracle
  failure have precommitted bounded outcomes;
- external money moves only through an authorized provider and jurisdictional
  policy, never through the language VM.

## Business model

The protocol fee remains zero. LED ACTION LLC can charge for optional managed
clearing, regulated-provider adapters, enterprise policy packs, certification,
fraud analysis, observability, dispute automation, support, and service-level
agreements. Self-hosted interoperability and paid corporate services remain
distinct.

## Evidence required before launch

Simulation must cover honest exchange, partial delivery, duplicate receipts,
replay, collusion, identity rotation, quality manipulation, provider failure,
requester insolvency, dispute abuse, netting cycles, rounding, clock skew, and
external settlement failure. A successful simulation is evidence about tested
invariants, not regulatory approval or proof of economic stability.
