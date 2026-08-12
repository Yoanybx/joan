#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

const PPM = 1_000_000n;
const SECONDS_PER_YEAR = 31_557_600n;

function fail(message) {
  throw new Error(message);
}

function integer(value, label, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    fail(`${label} must be a non-negative safe integer`);
  }
  return BigInt(value);
}

function ppm(value, label) {
  return integer(value, label, 1_000_000);
}

function timestamp(value, label) {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
    fail(`${label} must be a valid date-time`);
  }
  return Date.parse(value);
}

function ceilDivide(numerator, denominator) {
  if (denominator <= 0n) fail("division denominator must be positive");
  return (numerator + denominator - 1n) / denominator;
}

function evaluateCandidate(scenario, candidate) {
  const grossItems = integer(scenario.gross_item_count, "gross_item_count");
  const grossVolume = integer(scenario.gross_volume_micro_usd, "gross_volume_micro_usd");
  const settlementItems = integer(candidate.settlement_item_count, `${candidate.id}.settlement_item_count`);
  const settlementVolume = integer(
    candidate.settlement_volume_micro_usd,
    `${candidate.id}.settlement_volume_micro_usd`,
  );
  const fixedFee = integer(
    candidate.fixed_fee_per_settlement_micro_usd,
    `${candidate.id}.fixed_fee_per_settlement_micro_usd`,
  );
  const variableFeePpm = ppm(candidate.variable_fee_ppm, `${candidate.id}.variable_fee_ppm`);
  const verificationFee = integer(
    candidate.verification_fee_per_gross_item_micro_usd,
    `${candidate.id}.verification_fee_per_gross_item_micro_usd`,
  );
  const infrastructureFee = integer(
    candidate.infrastructure_cost_per_gross_item_micro_usd,
    `${candidate.id}.infrastructure_cost_per_gross_item_micro_usd`,
  );
  const fxSlippagePpm = ppm(
    candidate.fx_slippage_ppm_on_settlement_volume,
    `${candidate.id}.fx_slippage_ppm_on_settlement_volume`,
  );
  const disputeProbability = ppm(
    candidate.dispute_probability_ppm,
    `${candidate.id}.dispute_probability_ppm`,
  );
  const disputeCaseCost = integer(
    candidate.dispute_case_cost_micro_usd,
    `${candidate.id}.dispute_case_cost_micro_usd`,
  );
  const annualCapitalCost = ppm(
    candidate.annual_capital_cost_ppm,
    `${candidate.id}.annual_capital_cost_ppm`,
  );
  const settlementDelay = integer(
    candidate.settlement_delay_seconds,
    `${candidate.id}.settlement_delay_seconds`,
  );
  const expectedLossPpm = ppm(
    candidate.expected_loss_ppm_on_gross_volume,
    `${candidate.id}.expected_loss_ppm_on_gross_volume`,
  );
  const failureProbability = ppm(
    candidate.failure_probability_ppm,
    `${candidate.id}.failure_probability_ppm`,
  );
  const protocolFee = integer(
    candidate.joan_protocol_fee_per_gross_item_micro_usd,
    `${candidate.id}.joan_protocol_fee_per_gross_item_micro_usd`,
  );
  const explicitSubsidy = integer(
    candidate.explicit_subsidy_micro_usd,
    `${candidate.id}.explicit_subsidy_micro_usd`,
  );
  if (protocolFee !== 0n) fail(`${candidate.id} violates the JOAN v0 zero protocol fee invariant`);
  if (failureProbability === PPM) fail(`${candidate.id} cannot have zero expected successful items`);
  if (settlementVolume > grossVolume) {
    fail(`${candidate.id}.settlement_volume_micro_usd exceeds gross volume`);
  }

  const components = {
    external_fixed_micro_usd: settlementItems * fixedFee,
    external_variable_micro_usd: ceilDivide(settlementVolume * variableFeePpm, PPM),
    fx_slippage_micro_usd: ceilDivide(settlementVolume * fxSlippagePpm, PPM),
    verification_micro_usd: grossItems * verificationFee,
    infrastructure_micro_usd: grossItems * infrastructureFee,
    expected_dispute_micro_usd: ceilDivide(
      grossItems * disputeProbability * disputeCaseCost,
      PPM,
    ),
    capital_lock_micro_usd: ceilDivide(
      settlementVolume * annualCapitalCost * settlementDelay,
      PPM * SECONDS_PER_YEAR,
    ),
    expected_loss_micro_usd: ceilDivide(grossVolume * expectedLossPpm, PPM),
    joan_protocol_micro_usd: grossItems * protocolFee,
  };
  const unsubsidizedTotal = Object.values(components).reduce((sum, value) => sum + value, 0n);
  if (explicitSubsidy > unsubsidizedTotal) {
    fail(`${candidate.id}.explicit_subsidy_micro_usd exceeds unsubsidized cost`);
  }
  const buyerCost = unsubsidizedTotal - explicitSubsidy;
  const expectedSuccessfulItemDenominator = grossItems * (PPM - failureProbability);
  const unsubsidizedPerSuccessfulItem = ceilDivide(
    unsubsidizedTotal * PPM,
    expectedSuccessfulItemDenominator,
  );
  const buyerPerSuccessfulItem = ceilDivide(buyerCost * PPM, expectedSuccessfulItemDenominator);

  return {
    id: candidate.id,
    mode: candidate.mode,
    qualification: candidate.qualification,
    provenance: candidate.provenance,
    settlement_item_count: settlementItems.toString(),
    settlement_volume_micro_usd: settlementVolume.toString(),
    components: Object.fromEntries(
      Object.entries(components).map(([key, value]) => [key, value.toString()]),
    ),
    explicit_subsidy_micro_usd: explicitSubsidy.toString(),
    unsubsidized_total_effective_cost_micro_usd: unsubsidizedTotal.toString(),
    buyer_cost_after_explicit_subsidy_micro_usd: buyerCost.toString(),
    unsubsidized_cost_per_expected_successful_item_micro_usd:
      unsubsidizedPerSuccessfulItem.toString(),
    buyer_cost_per_expected_successful_item_micro_usd: buyerPerSuccessfulItem.toString(),
  };
}

export function evaluate(inputBytes) {
  const input = JSON.parse(inputBytes.toString("utf8"));
  if (input.schema !== "joan.payment-cost-scenario.v0") fail("unsupported payment scenario schema");
  if (!Array.isArray(input.candidates) || input.candidates.length === 0) fail("candidates are required");
  const scenarioObservedAt = timestamp(input.observed_at, "observed_at");
  if (integer(input.scenario.gross_item_count, "gross_item_count") === 0n) {
    fail("gross_item_count must be positive");
  }
  const ids = new Set();
  for (const candidate of input.candidates) {
    if (typeof candidate.id !== "string" || candidate.id.length === 0) fail("candidate id is required");
    if (ids.has(candidate.id)) fail(`duplicate candidate id: ${candidate.id}`);
    ids.add(candidate.id);
  }

  const qualified = input.candidates.filter((candidate) => candidate.qualified === true);
  if (qualified.length === 0) fail("at least one qualified candidate is required");
  for (const candidate of qualified) {
    const quoteObservedAt = timestamp(
      candidate.provenance.observed_at,
      `${candidate.id}.provenance.observed_at`,
    );
    if (quoteObservedAt > scenarioObservedAt) {
      fail(`${candidate.id} quote was observed after the benchmark timestamp`);
    }
    if (
      candidate.provenance.kind === "measured-live-quote" &&
      candidate.provenance.expires_at === null
    ) {
      fail(`${candidate.id} live quote requires an expiry timestamp`);
    }
    if (candidate.provenance.expires_at !== null) {
      const expiresAt = timestamp(
        candidate.provenance.expires_at,
        `${candidate.id}.provenance.expires_at`,
      );
      if (expiresAt < scenarioObservedAt) fail(`${candidate.id} quote expired before the benchmark`);
    }
  }
  const evaluated = qualified.map((candidate) => evaluateCandidate(input.scenario, candidate));
  evaluated.sort((left, right) => {
    const costDifference =
      BigInt(left.unsubsidized_cost_per_expected_successful_item_micro_usd) -
      BigInt(right.unsubsidized_cost_per_expected_successful_item_micro_usd);
    if (costDifference < 0n) return -1;
    if (costDifference > 0n) return 1;
    return Buffer.compare(Buffer.from(left.id, "utf8"), Buffer.from(right.id, "utf8"));
  });
  const excluded = input.candidates
    .filter((candidate) => candidate.qualified !== true)
    .map((candidate) => ({ id: candidate.id, reason: candidate.qualification }))
    .sort((left, right) => Buffer.compare(Buffer.from(left.id), Buffer.from(right.id)));
  const illustrative = qualified.some(
    (candidate) => candidate.provenance.kind === "declared-fixture",
  );

  return {
    schema: "joan.payment-cost-report.v0",
    scenario_id: input.scenario.id,
    input_sha256: createHash("sha256").update(inputBytes).digest("hex"),
    unit: "micro_usd",
    metric: "unsubsidized_total_effective_cost_per_expected_successful_item",
    claim_scope: illustrative ? "illustrative-local-only" : "scenario-local-qualified-quotes-only",
    universal_cheapest_claim: false,
    joan_protocol_fee: "zero",
    selected_candidate_id: evaluated[0].id,
    ranked_qualified_candidates: evaluated,
    excluded_candidates: excluded,
  };
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 3) {
      fail("usage: node tools/payment-cost-reference.mjs <scenario.json>");
    }
    const inputBytes = readFileSync(resolve(process.argv[2]));
    process.stdout.write(`${JSON.stringify(evaluate(inputBytes), null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`payment-cost-reference: ${String(error.message ?? error)}\n`);
    process.exitCode = 1;
  }
}
