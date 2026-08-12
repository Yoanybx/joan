import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { evaluate } from "./payment-cost-reference.mjs";

const FIXTURE = JSON.parse(
  readFileSync(new URL("../vectors/payment-cost/scenario-v0.json", import.meta.url), "utf8"),
);

function cloneFixture() {
  return JSON.parse(JSON.stringify(FIXTURE));
}

function evaluateObject(value) {
  return evaluate(Buffer.from(`${JSON.stringify(value)}\n`, "utf8"));
}

test("fixture selects a qualified mode without a universal claim", () => {
  const report = evaluateObject(cloneFixture());
  assert.equal(report.selected_candidate_id, "multilateral-netting");
  assert.equal(report.universal_cheapest_claim, false);
  assert.deepEqual(report.excluded_candidates, [
    {
      id: "unpriced-gas-free-batch",
      reason: "Excluded because gas-free signing alone is not an all-in provider price",
    },
  ]);
});

test("lower fixed cost cannot increase total effective cost", () => {
  const baseline = evaluateObject(cloneFixture());
  const modified = cloneFixture();
  const candidate = modified.candidates.find((item) => item.id === "multilateral-netting");
  assert.ok(candidate);
  candidate.fixed_fee_per_settlement_micro_usd = 0;
  const lowered = evaluateObject(modified);
  const baselineCost = BigInt(
    baseline.ranked_qualified_candidates.find((item) => item.id === candidate.id)
      .unsubsidized_total_effective_cost_micro_usd,
  );
  const loweredCost = BigInt(
    lowered.ranked_qualified_candidates.find((item) => item.id === candidate.id)
      .unsubsidized_total_effective_cost_micro_usd,
  );
  assert.ok(loweredCost <= baselineCost);
});

test("equal costs use bytewise candidate id ordering", () => {
  const input = cloneFixture();
  const template = input.candidates[0];
  input.candidates = [
    { ...template, id: "tie-b" },
    { ...template, id: "tie-a" },
  ];
  const report = evaluateObject(input);
  assert.equal(report.selected_candidate_id, "tie-a");
});

test("nonzero JOAN protocol fee is rejected", () => {
  const input = cloneFixture();
  input.candidates[0].joan_protocol_fee_per_gross_item_micro_usd = 1;
  assert.throws(() => evaluateObject(input), /zero protocol fee invariant/u);
});

test("subsidy is reported but cannot change efficiency ranking", () => {
  const input = cloneFixture();
  input.candidates[0].explicit_subsidy_micro_usd = 100000000;
  const report = evaluateObject(input);
  assert.equal(report.selected_candidate_id, "multilateral-netting");
  const subsidized = report.ranked_qualified_candidates.find(
    (candidate) => candidate.id === "direct-per-instruction",
  );
  assert.ok(subsidized);
  assert.equal(subsidized.explicit_subsidy_micro_usd, "100000000");
  assert.ok(
    BigInt(subsidized.buyer_cost_after_explicit_subsidy_micro_usd) <
      BigInt(subsidized.unsubsidized_total_effective_cost_micro_usd),
  );
});

test("expired live quote is rejected", () => {
  const input = cloneFixture();
  input.candidates[0].provenance = {
    kind: "measured-live-quote",
    observed_at: "2026-08-10T00:00:00Z",
    expires_at: "2026-08-10T01:00:00Z",
    source: "expired-test-quote",
  };
  assert.throws(() => evaluateObject(input), /expired before the benchmark/u);
});

test("empty economic scenario is rejected", () => {
  const input = cloneFixture();
  input.scenario.gross_item_count = 0;
  assert.throws(() => evaluateObject(input), /gross_item_count must be positive/u);
});
