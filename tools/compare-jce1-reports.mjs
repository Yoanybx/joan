#!/usr/bin/env node

import { readFileSync } from "node:fs";

function fail(message) {
  process.stderr.write(`compare-jce1-reports: ${message}\n`);
  process.exit(1);
}

function readReport(path) {
  let report;
  try {
    report = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    fail(`cannot read ${path}: ${String(error)}`);
  }
  if (report.schema !== "joan.jce1-conformance-report.v1") {
    fail(`${path} has an unsupported report schema`);
  }
  if (report.total !== 27 || report.passed !== 27 || report.failed !== 0) {
    fail(`${path} does not prove 27/27 passing vectors`);
  }
  return report;
}

function normalized(report) {
  const copy = structuredClone(report);
  delete copy.implementation;
  return JSON.stringify(copy);
}

const [, , rustPath, nodePath] = process.argv;
if (!rustPath || !nodePath) {
  fail("usage: node tools/compare-jce1-reports.mjs <rust-report> <node-report>");
}

const rust = readReport(rustPath);
const node = readReport(nodePath);
if (rust.implementation === node.implementation) {
  fail("implementation names must be distinct");
}
if (normalized(rust) !== normalized(node)) {
  fail("independent reports disagree");
}

process.stdout.write(
  `${JSON.stringify({
    schema: "joan.cross-implementation-conformance.v1",
    profile: "JCE1",
    status: "passed",
    vector_count: rust.total,
    suite_digest: rust.suite_digest,
    implementations: [rust.implementation, node.implementation],
  })}\n`,
);
