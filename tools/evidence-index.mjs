#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const EVIDENCE_PATH = join(ROOT, ".joan/evidence/latest.json");
const RECEIPT_DIRECTORY = join(ROOT, ".joan/evidence/runs");
const RUNNER_RELATIVE = "tools/verification-runner.mjs";
const RUNNER_PATH = join(ROOT, RUNNER_RELATIVE);
const GATES_RELATIVE = "tools/verification-gates.v1.json";
const GATES_PATH = join(ROOT, GATES_RELATIVE);
const JCE1_SUITE_RELATIVE = "vectors/jce1/conformance-v1.json";
const JCE1_SUITE_PATH = join(ROOT, JCE1_SUITE_RELATIVE);
const JCE1_SPEC_RELATIVE = "spec/canonical-profile-jce1.md";
const JCE1_SPEC_PATH = join(ROOT, JCE1_SPEC_RELATIVE);
const SIMULATION_TEST_RELATIVE = "crates/joan-sim/tests/corpus.rs";
const SIMULATION_TEST_PATH = join(ROOT, SIMULATION_TEST_RELATIVE);
const BENCHMARK_RELATIVE = "benchmarks/results/2026-08-11-mac15-4-jce1-digest.json";
const BENCHMARK_PATH = join(ROOT, BENCHMARK_RELATIVE);
const AGENT_SCORECARD_RELATIVE = "benchmarks/results/2026-08-12-mac15-4-agent-scorecard.json";
const AGENT_SCORECARD_PATH = join(ROOT, AGENT_SCORECARD_RELATIVE);
const PAYMENT_REPORT_RELATIVE = "vectors/payment-cost/report-v0.json";
const PAYMENT_REPORT_PATH = join(ROOT, PAYMENT_REPORT_RELATIVE);
const EXCLUDES = [".git", "target", ".joan/evidence", "**/.DS_Store", "**/._*"];
const SOURCE_PREFIX = Buffer.from("JOAN\0SOURCE-TREE\0V2", "ascii");
const JCE1_PREFIX = Buffer.from("JOAN\0HASH\0V1", "ascii");
const JCE1_PROFILE = "joan-hash-v1";
const JCE1_DOMAIN = "joan.conformance-vector.v1";
const REQUIRED_RUNS = 3;

function fail(message) {
  throw new Error(message);
}

function run(command, argumentsList) {
  return execFileSync(command, argumentsList, {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 128 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function fileSha256(path) {
  return sha256(readFileSync(path));
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function readStrictJson(path) {
  const canonical = run(process.execPath, ["tools/jce1-reference.mjs", "canonicalize", path]);
  return JSON.parse(canonical);
}

function relativePath(path) {
  return relative(ROOT, path).split(sep).join("/");
}

function isExcluded(path) {
  if ([".git", "target", ".joan/evidence"].some(
    (excluded) => path === excluded || path.startsWith(`${excluded}/`),
  )) {
    return true;
  }
  return path.split("/").some((segment) => segment === ".DS_Store" || segment.startsWith("._"));
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function collectFiles(directory = ROOT) {
  const files = [];
  const entries = readdirSync(directory, { withFileTypes: true }).sort((left, right) =>
    compareUtf8(left.name, right.name),
  );
  for (const entry of entries) {
    const absolute = join(directory, entry.name);
    const path = relativePath(absolute);
    if (isExcluded(path)) continue;
    if (entry.isSymbolicLink() || lstatSync(absolute).isSymbolicLink()) {
      fail(`source tree contains unsupported symbolic link: ${path}`);
    }
    if (entry.isDirectory()) {
      files.push(...collectFiles(absolute));
    } else if (entry.isFile()) {
      files.push({ absolute, path });
    } else {
      fail(`source tree contains unsupported file type: ${path}`);
    }
  }
  return files.sort((left, right) => compareUtf8(left.path, right.path));
}

function u64be(value) {
  const output = Buffer.alloc(8);
  output.writeBigUInt64BE(BigInt(value));
  return output;
}

function sourceTree() {
  const files = collectFiles();
  const tree = createHash("sha256");
  tree.update(SOURCE_PREFIX);
  for (const file of files) {
    const path = Buffer.from(file.path, "utf8");
    const contentDigest = createHash("sha256").update(readFileSync(file.absolute)).digest();
    tree.update(u64be(path.length));
    tree.update(path);
    tree.update(contentDigest);
  }
  return {
    tree_digest: {
      algorithm: "sha256",
      profile: "joan-source-tree-v2",
      value: tree.digest("hex"),
    },
    file_count: files.length,
    excludes: EXCLUDES,
  };
}

function jce1Digest(payload) {
  const hash = createHash("sha256");
  hash.update(JCE1_PREFIX);
  for (const bytes of [
    Buffer.from(JCE1_PROFILE, "ascii"),
    Buffer.from(JCE1_DOMAIN, "ascii"),
    payload,
  ]) {
    hash.update(u64be(bytes.length));
    hash.update(bytes);
  }
  return {
    algorithm: "sha256",
    profile: JCE1_PROFILE,
    domain: JCE1_DOMAIN,
    value: hash.digest("hex"),
  };
}

function workspaceCrateCount() {
  const metadata = JSON.parse(run("cargo", ["metadata", "--no-deps", "--format-version", "1"]));
  return metadata.packages.length;
}

function schemaCount() {
  return readdirSync(join(ROOT, "schemas")).filter((name) => name.endsWith(".schema.json")).length;
}

function rustTestCount() {
  const listing = run("cargo", ["test", "--workspace", "--all-features", "--locked", "--", "--list"]);
  return listing.split(/\r?\n/u).filter((line) => line.endsWith(": test")).length;
}

function currentState() {
  const suiteBytes = readFileSync(JCE1_SUITE_PATH);
  const suite = JSON.parse(suiteBytes.toString("utf8"));
  const specSha256 = fileSha256(JCE1_SPEC_PATH);
  const benchmarkBytes = readFileSync(BENCHMARK_PATH);
  const benchmark = JSON.parse(benchmarkBytes.toString("utf8"));
  const agentScorecardBytes = readFileSync(AGENT_SCORECARD_PATH);
  const agentScorecard = JSON.parse(agentScorecardBytes.toString("utf8"));
  const paymentReportBytes = readFileSync(PAYMENT_REPORT_PATH);
  const paymentReport = JSON.parse(paymentReportBytes.toString("utf8"));
  return {
    source: sourceTree(),
    inventory: {
      workspace_crates: workspaceCrateCount(),
      json_schemas: schemaCount(),
      rust_tests: rustTestCount(),
    },
    jce1: {
      total: suite.cases.length,
      suite_digest: jce1Digest(suiteBytes),
      normative_spec_path: JCE1_SPEC_RELATIVE,
      normative_spec_sha256: specSha256,
      declared_spec_sha256: suite.spec_freeze_sha256,
      spec_binding: suite.spec_freeze_sha256 === specSha256,
    },
    simulation: {
      status: "current-source-test-bound",
      cases: 10_000,
      seed: 144,
      test_path: SIMULATION_TEST_RELATIVE,
      test_file_sha256: fileSha256(SIMULATION_TEST_PATH),
    },
    benchmark: {
      path: BENCHMARK_RELATIVE,
      file_sha256: sha256(benchmarkBytes),
      status: benchmark.comparison.status,
      faster_observed: benchmark.comparison.faster_observed_implementation,
      language_superiority_claim: benchmark.comparison.language_superiority_claim,
    },
    agent_scorecard: {
      path: AGENT_SCORECARD_RELATIVE,
      file_sha256: sha256(agentScorecardBytes),
      status: agentScorecard.qualification.status,
      workload_count: agentScorecard.workloads.length,
      joan_safety_cases_protected: agentScorecard.qualification.joan_safety_cases_protected,
      joan_safety_cases_total: agentScorecard.qualification.joan_safety_cases_total,
      broad_language_superiority_claim:
        agentScorecard.qualification.broad_language_superiority_claim,
      universal_language_superiority_claim:
        agentScorecard.universal_language_superiority_claim,
    },
    payment_cost: {
      path: PAYMENT_REPORT_RELATIVE,
      file_sha256: sha256(paymentReportBytes),
      status: paymentReport.claim_scope,
      selected_candidate_id: paymentReport.selected_candidate_id,
      universal_cheapest_claim: paymentReport.universal_cheapest_claim,
    },
  };
}

function equal(left, right) {
  return isDeepStrictEqual(left, right);
}

function requireEqual(observed, expected, label) {
  if (!equal(observed, expected)) fail(`${label} mismatch`);
}

function parseTime(value, label) {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) fail(`${label} is not a valid timestamp`);
  return parsed;
}

function configuredGates() {
  const config = readStrictJson(GATES_PATH);
  if (config.schema !== "joan.verification-gates.v1" || config.gates.length !== 10) {
    fail("verification gate configuration is invalid");
  }
  if (new Set(config.gates.map((gate) => gate.id)).size !== config.gates.length) {
    fail("verification gate IDs must be unique");
  }
  return config.gates;
}

function validateExecutable(receipt, label) {
  const path = realpathSync(receipt.executable_path);
  if (path !== receipt.executable_path) fail(`${label} executable path is not canonical`);
  if (fileSha256(path) !== receipt.executable_sha256) fail(`${label} executable hash drift detected`);
}

function validateReceipt(path, state, gates) {
  const absolute = realpathSync(resolve(ROOT, path));
  const receiptRoot = `${realpathSync(RECEIPT_DIRECTORY)}${sep}`;
  if (!absolute.startsWith(receiptRoot) || !statSync(absolute).isFile()) {
    fail(`receipt must be a regular file below ${relativePath(RECEIPT_DIRECTORY)}`);
  }
  const receipt = readStrictJson(absolute);
  requireEqual(receipt.schema, "joan.verification-run-receipt.v1", "receipt schema");
  requireEqual(receipt.version, "0.1.0-alpha.1", "receipt version");
  requireEqual(receipt.status, "passed", "receipt status");
  requireEqual(receipt.source, state.source, "receipt source");
  requireEqual(receipt.observations, state, "receipt observations");
  requireEqual(receipt.environment.runner_sha256, fileSha256(RUNNER_PATH), "runner hash");
  requireEqual(receipt.gates.length, gates.length, "executed gate count");
  requireEqual(receipt.summary, { required: 10, executed: 10, passed: 10, failed: 0 }, "gate summary");
  if (parseTime(receipt.started_at, "receipt start") > parseTime(receipt.completed_at, "receipt completion")) {
    fail("receipt completion precedes its start");
  }
  for (const [index, expected] of gates.entries()) {
    const observed = receipt.gates[index];
    requireEqual(observed.id, expected.id, `gate ${index} identifier`);
    requireEqual(observed.argv, expected.argv, `gate ${expected.id} argv`);
    requireEqual(observed.status, "passed", `gate ${expected.id} status`);
    requireEqual(observed.exit_code, 0, `gate ${expected.id} exit code`);
    requireEqual(observed.signal, null, `gate ${expected.id} signal`);
    if (parseTime(observed.started_at, `${expected.id} start`) > parseTime(observed.completed_at, `${expected.id} completion`)) {
      fail(`gate ${expected.id} completion precedes its start`);
    }
    validateExecutable(observed, `gate ${expected.id}`);
  }
  const requiredTools = ["node", "cargo", "rustc", "cargo-audit", "cargo-deny"];
  requireEqual(
    receipt.environment.tools.map((tool) => tool.id),
    requiredTools,
    "receipt tool inventory",
  );
  for (const tool of receipt.environment.tools) validateExecutable({
    executable_path: tool.path,
    executable_sha256: tool.sha256,
  }, `tool ${tool.id}`);
  requireEqual(receipt.supply_chain.cargo_audit.status, "passed", "cargo audit status");
  requireEqual(receipt.supply_chain.cargo_audit.vulnerabilities_found, 0, "cargo audit vulnerabilities");
  requireEqual(receipt.supply_chain.cargo_deny.status, "passed", "cargo deny status");
  return { absolute, receipt };
}

function receiptSummary(validated, ordinal) {
  const { absolute, receipt } = validated;
  return {
    ordinal,
    run_id: receipt.run_id,
    path: relativePath(absolute),
    file_sha256: fileSha256(absolute),
    status: receipt.status,
    started_at: receipt.started_at,
    completed_at: receipt.completed_at,
    source_digest: receipt.source.tree_digest.value,
    gate_count: receipt.gates.length,
  };
}

function buildEvidence(receiptPaths) {
  if (receiptPaths.length !== REQUIRED_RUNS) fail(`write requires exactly ${REQUIRED_RUNS} receipt paths`);
  const state = currentState();
  if (!state.jce1.spec_binding) fail("JCE1 suite is not bound to the current normative specification");
  const gates = configuredGates();
  const validated = receiptPaths.map((path) => validateReceipt(path, state, gates));
  if (new Set(validated.map(({ receipt }) => receipt.run_id)).size !== REQUIRED_RUNS) {
    fail("verification receipt run IDs must be unique");
  }
  const runs = validated.map((receipt, index) => receiptSummary(receipt, index + 1));
  const finalReceipt = validated.at(-1).receipt;
  return {
    schema: "joan.evidence-index.v2",
    version: "0.1.0-alpha.1",
    status: "local-verification-passed-with-receipts",
    generated_at: new Date().toISOString(),
    source: state.source,
    inventory: state.inventory,
    conformance: {
      jce1: {
        status: "passed-local-cross-implementation",
        total: state.jce1.total,
        passed: state.jce1.total,
        suite_digest: state.jce1.suite_digest,
        specification: {
          path: state.jce1.normative_spec_path,
          file_sha256: state.jce1.normative_spec_sha256,
          declared_sha256: state.jce1.declared_spec_sha256,
          binding: "matched",
        },
        implementations: ["rust-joan-canonical", "node-independent-reference"],
      },
      jdr1: state.simulation,
    },
    supply_chain: finalReceipt.supply_chain,
    verification: {
      runner: { path: RUNNER_RELATIVE, file_sha256: fileSha256(RUNNER_PATH) },
      gate_config: { path: GATES_RELATIVE, file_sha256: fileSha256(GATES_PATH) },
      required_gate_ids: gates.map((gate) => gate.id),
      runs,
      repeatability: {
        required_runs: REQUIRED_RUNS,
        completed_runs: runs.length,
        unique_run_ids: new Set(runs.map((run) => run.run_id)).size,
        same_source: runs.every((run) => run.source_digest === state.source.tree_digest.value),
        same_observations: validated.every(({ receipt }) => equal(receipt.observations, state)),
      },
    },
    benchmark: {
      ...state.benchmark,
      agent_scorecard: state.agent_scorecard,
      payment_cost: state.payment_cost,
    },
    limitations: [
      "Three local receipts on one host and operator are not independent external attestations",
      "Local evidence is not an official release, external audit or hostile reproduction",
      "No official remote, public adoption, native-code backend, distributed network or real payment exists",
      "JDR1 synthetic results do not authorize effects; JDR2 remains unimplemented",
      "The recorded digest benchmark does not establish language superiority",
      "The two-workload agent scorecard is baseline-only and does not establish language superiority",
      "The payment-cost vector proves local integer accounting only, not universal market superiority",
    ],
  };
}

function atomicWrite(path, value) {
  const temporary = `${path}.tmp-${process.pid}`;
  try {
    writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o644 });
    renameSync(temporary, path);
  } catch (error) {
    try {
      unlinkSync(temporary);
    } catch {
      // The temporary file may not have been created.
    }
    throw error;
  }
}

function writeEvidence(receiptPaths) {
  const evidence = buildEvidence(receiptPaths);
  atomicWrite(EVIDENCE_PATH, evidence);
  process.stdout.write(`${JSON.stringify({
    status: "written",
    path: relativePath(EVIDENCE_PATH),
    receipts: evidence.verification.runs.length,
  })}\n`);
}

function checkEvidence() {
  const evidence = readStrictJson(EVIDENCE_PATH);
  const state = currentState();
  const gates = configuredGates();
  requireEqual(evidence.schema, "joan.evidence-index.v2", "evidence schema");
  requireEqual(evidence.status, "local-verification-passed-with-receipts", "evidence status");
  requireEqual(evidence.source, state.source, "source tree");
  requireEqual(evidence.inventory, state.inventory, "inventory");
  requireEqual(evidence.conformance.jce1.total, state.jce1.total, "JCE1 vector count");
  requireEqual(evidence.conformance.jce1.passed, state.jce1.total, "JCE1 passed count");
  requireEqual(evidence.conformance.jce1.suite_digest, state.jce1.suite_digest, "JCE1 suite digest");
  requireEqual(evidence.conformance.jce1.specification, {
    path: state.jce1.normative_spec_path,
    file_sha256: state.jce1.normative_spec_sha256,
    declared_sha256: state.jce1.declared_spec_sha256,
    binding: "matched",
  }, "JCE1 specification binding");
  requireEqual(evidence.conformance.jdr1, state.simulation, "JDR1 current-source simulation claim");
  requireEqual(evidence.benchmark, {
    ...state.benchmark,
    agent_scorecard: state.agent_scorecard,
    payment_cost: state.payment_cost,
  }, "benchmark evidence");
  requireEqual(evidence.verification.runner, {
    path: RUNNER_RELATIVE,
    file_sha256: fileSha256(RUNNER_PATH),
  }, "verification runner");
  requireEqual(evidence.verification.gate_config, {
    path: GATES_RELATIVE,
    file_sha256: fileSha256(GATES_PATH),
  }, "verification gate configuration");
  requireEqual(evidence.verification.required_gate_ids, gates.map((gate) => gate.id), "required gates");
  requireEqual(evidence.verification.runs.length, REQUIRED_RUNS, "verification receipt count");
  const validated = evidence.verification.runs.map((summary, index) => {
    const result = validateReceipt(summary.path, state, gates);
    requireEqual(summary, receiptSummary(result, index + 1), `receipt ${index + 1} summary`);
    return result;
  });
  if (new Set(validated.map(({ receipt }) => receipt.run_id)).size !== REQUIRED_RUNS) {
    fail("verification receipt run IDs are not unique");
  }
  requireEqual(evidence.verification.repeatability, {
    required_runs: REQUIRED_RUNS,
    completed_runs: REQUIRED_RUNS,
    unique_run_ids: REQUIRED_RUNS,
    same_source: true,
    same_observations: true,
  }, "verification repeatability");
  requireEqual(evidence.supply_chain, validated.at(-1).receipt.supply_chain, "supply-chain evidence");
  process.stdout.write(`${JSON.stringify({
    schema: "joan.evidence-drift-check.v2",
    status: "passed",
    source_digest: state.source.tree_digest.value,
    receipts: REQUIRED_RUNS,
    inventory: state.inventory,
    jce1_suite_digest: state.jce1.suite_digest.value,
    jce1_spec_sha256: state.jce1.normative_spec_sha256,
    simulation_cases: state.simulation.cases,
  })}\n`);
}

const [, , command, ...argumentsList] = process.argv;
try {
  if (command === "source" && argumentsList.length === 0) {
    process.stdout.write(`${JSON.stringify(sourceTree())}\n`);
  } else if (command === "state" && argumentsList.length === 0) {
    process.stdout.write(`${JSON.stringify(currentState())}\n`);
  } else if (command === "write") {
    writeEvidence(argumentsList);
  } else if (command === "check" && argumentsList.length === 0) {
    checkEvidence();
  } else {
    fail("usage: node tools/evidence-index.mjs <source|state|write <receipt-1> <receipt-2> <receipt-3>|check>");
  }
} catch (error) {
  process.stderr.write(`evidence-index: ${String(error.message ?? error)}\n`);
  process.exitCode = 1;
}
