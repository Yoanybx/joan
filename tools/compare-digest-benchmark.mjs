#!/usr/bin/env node

import { readFileSync } from "node:fs";

function fail(message) {
  process.stderr.write(`compare-digest-benchmark: ${message}\n`);
  process.exit(1);
}

function reports(path) {
  return readFileSync(path, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function median(values) {
  const sorted = values.slice().sort((left, right) => left - right);
  return sorted[Math.floor(sorted.length / 2)];
}

const [, , rustPath, cPath] = process.argv;
if (!rustPath || !cPath) fail("usage: compare-digest-benchmark.mjs <rust.jsonl> <c.jsonl>");
const rust = reports(rustPath);
const c = reports(cPath);
if (rust.length !== 5 || c.length !== 5) fail("exactly five samples per implementation are required");

const all = [...rust, ...c];
const first = all[0];
for (const report of all) {
  if (report.schema !== "joan.digest-benchmark.v1") fail("unexpected benchmark schema");
  if (report.payload_bytes !== first.payload_bytes || report.iterations !== first.iterations) {
    fail("benchmark parameters differ");
  }
  for (const field of ["algorithm", "profile", "domain", "value"]) {
    if (report.digest?.[field] !== first.digest?.[field]) fail(`digest ${field} differs`);
  }
  if (report.claim_scope !== "implementation-microbenchmark-not-language-superiority") {
    fail("benchmark omitted the required claim scope");
  }
}

const rustMedian = median(rust.map((report) => report.elapsed_ns));
const cMedian = median(c.map((report) => report.elapsed_ns));
const comparison = {
  schema: "joan.digest-benchmark-comparison.v1",
  status: "equivalent-output",
  payload_bytes: first.payload_bytes,
  iterations: first.iterations,
  samples_per_implementation: 5,
  rust_median_elapsed_ns: rustMedian,
  c_median_elapsed_ns: cMedian,
  rust_to_c_elapsed_parts_per_million: Math.round((rustMedian * 1_000_000) / cMedian),
  digest: first.digest,
  faster_observed_implementation: rustMedian < cMedian ? rust[0].implementation : c[0].implementation,
  language_superiority_claim: false,
  limitations: [
    "This compares two implementations and cryptographic backends, not entire languages.",
    "Results are valid only for the recorded machine, toolchains, payload and sample count.",
    "A faster result does not establish safety, utility, adoption or total-system superiority.",
  ],
};
process.stdout.write(`${JSON.stringify(comparison)}\n`);
