# JOAN Minimum-Cost Settlement Proof v0

Status: executable local design baseline; no payment rail or custody is implemented.

## Objective

JOAN does not claim that one rail is universally cheapest. A private ledger can report a zero transfer fee while moving fraud, liquidity, dispute, infrastructure or withdrawal cost elsewhere. JOAN instead minimizes the total effective cost for each qualified settlement scenario and preserves the inputs needed to reproduce that selection.

JOAN protocol fee is zero in v0. External rail, compliance, hosting and optional commercial service charges are separate and must never be hidden inside a zero-fee claim.

## Unit and arithmetic

All v0 values are non-negative integers. Money uses `micro_usd`; rates and probabilities use parts per million. Floating-point arithmetic is forbidden.

For candidate `r`:

```text
TEC(r) = external fixed fees
       + external variable fees
       + FX and slippage cost
       + verification cost
       + infrastructure and operations cost
       + expected dispute cost
       + capital lock cost
       + expected failure or fraud loss
       + JOAN protocol fee
```

The comparison metric is `ceil(unsubsidized TEC / expected successful gross instruction count)`. Every division rounds cost upward. An explicit subsidy reduces the separately reported buyer cost but cannot improve the efficiency ranking. The executable formula is in `tools/payment-cost-reference.mjs`.

## Settlement router

The future JOAN Minimum-Cost Settlement Router evaluates only candidates that already satisfy policy, identity, exposure, finality, jurisdiction, asset and deadline requirements.

1. Repeated bilateral work: signed obligations plus bounded bilateral netting.
2. Repeated many-party work: multilateral netting when legal and exposure rules permit it.
3. Very small tasks: aggregate signed receivables until a configured threshold.
4. Immediate settlement: direct external rail or pre-funded channel.
5. Untrusted one-shot work: reserve or escrow adapter with explicit cost.
6. Missing or expired quote: exclude the candidate; never substitute zero.

JOAN is a non-custodial coordination and evidence layer in this design. A regulated external provider moves money. Netting obligations may themselves be regulated in some jurisdictions and require legal review before implementation.

## Proof levels

- `illustrative-local-only`: arithmetic and selection are reproducible, but at least one cost is a declared fixture.
- `scenario-local-qualified-quotes-only`: all admitted candidates use official fixed fees or measured live quotes that are valid at the scenario timestamp.
- No report may set `universal_cheapest_claim` to true.

The checked-in vector proves deterministic integer accounting and selection only. It does not prove current market superiority.

## External facts that inform adapters

- [Lightning BOLT 7](https://github.com/lightning/bolts/blob/master/07-routing-gossip.md) defines routing fees as a base fee plus a proportional millionths fee, so cost is route-dependent.
- [Lightning's protocol introduction](https://github.com/lightning/bolts/blob/master/00-introduction.md) describes off-chain transfers with an on-chain enforcement path, so liquidity and settlement costs remain relevant.
- [Circle Nanopayments](https://developers.circle.com/gateway/nanopayments) and its [batched-settlement model](https://developers.circle.com/gateway/nanopayments/concepts/batched-settlement) document gas-free signed nanopayments, but gas-free authorization is not by itself a complete all-in price.
- The [2026 FedACH fee schedule](https://www.frbservices.org/resources/fees/ach-2026) lists per-item fees plus other participation and monthly charges; eligibility and full pricing must be represented before admission.

These facts are adapter requirements, not hard-coded market prices. Live comparisons must capture source, observation time, expiry, volume tier, asset conversion, withdrawal, compliance and infrastructure cost.

## Commercial model

The zero JOAN protocol fee does not prevent LED ACTION LLC from selling optional services: hosted routing, enterprise policy packs, dispute automation, compliance adapters, observability, support and service-level agreements. Self-hosted protocol use and paid services must remain distinguishable.

## Required next gates

1. Validate input and output against their Draft 2020-12 schemas.
2. Add property tests for monotonicity, tie-breaking, overflow bounds and excluded candidates.
3. Build read-only quote adapters for at least three rails.
4. Run dated scenario matrices for microtasks, one-shot work, recurring work and cross-currency work.
5. Add failure, stale-quote, liquidity and dispute stress tests.
6. Obtain legal review before any real netting, custody, escrow, credit or money movement.
