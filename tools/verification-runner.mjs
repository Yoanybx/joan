#!/usr/bin/env node

import { execFileSync, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { arch, platform, release } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const RUNNER_PATH = fileURLToPath(import.meta.url);
const GATES_PATH = join(ROOT, "tools/verification-gates.v1.json");
const MAX_OUTPUT_BYTES = 128 * 1024 * 1024;
const EXPECTED_GATES = [
  { id: "format", argv: ["cargo", "fmt", "--check"] },
  { id: "clippy", argv: ["cargo", "clippy", "--workspace", "--all-targets", "--all-features", "--locked", "--", "-D", "warnings"] },
  { id: "tests", argv: ["cargo", "test", "--workspace", "--all-features", "--locked"] },
  { id: "doc-tests", argv: ["cargo", "test", "--doc", "--workspace", "--locked"] },
  { id: "release-build", argv: ["cargo", "build", "--workspace", "--release", "--locked"] },
  { id: "jce1", argv: ["./scripts/verify-jce1.sh"] },
  { id: "c-digest-smoke", argv: ["./scripts/benchmark-digest.sh", "1024", "1000"] },
  { id: "payment-cost-vector", argv: ["./scripts/verify-payment-cost.sh"] },
  { id: "tool-forge", argv: ["./scripts/verify-tool-forge.sh"] },
  { id: "cargo-deny", argv: ["cargo", "deny", "--locked", "check"] },
  { id: "cargo-audit", argv: ["cargo", "audit", "--json"] },
];

function fail(message) {
  throw new Error(message);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function runText(command, args) {
  return execFileSync(command, args, {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: MAX_OUTPUT_BYTES,
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

function executablePath(command) {
  if (command.includes("/")) return realpathSync(resolve(ROOT, command));
  return realpathSync(runText("which", [command]));
}

function tool(id, command, versionArgs) {
  const path = executablePath(command);
  return {
    id,
    path,
    sha256: sha256(readFileSync(path)),
    version: runText(command, versionArgs),
  };
}

function streamEvidence(bytes) {
  return { bytes: bytes.length, sha256: sha256(bytes) };
}

function readState() {
  return JSON.parse(runText(process.execPath, ["tools/evidence-index.mjs", "state"]));
}

function runGate(gate) {
  const [command, ...args] = gate.argv;
  const resolvedExecutable = executablePath(command);
  const started = new Date();
  const startedMonotonic = process.hrtime.bigint();
  const result = spawnSync(command, args, {
    cwd: ROOT,
    encoding: null,
    env: process.env,
    maxBuffer: MAX_OUTPUT_BYTES,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const completed = new Date();
  const durationMs = Number((process.hrtime.bigint() - startedMonotonic) / 1_000_000n);
  const stdout = result.stdout ?? Buffer.alloc(0);
  const stderr = result.stderr ?? Buffer.alloc(0);
  process.stdout.write(stdout);
  process.stderr.write(stderr);
  const passed = result.status === 0 && result.signal === null && result.error === undefined;
  return {
    receipt: {
      id: gate.id,
      argv: gate.argv,
      executable_path: resolvedExecutable,
      executable_sha256: sha256(readFileSync(resolvedExecutable)),
      started_at: started.toISOString(),
      completed_at: completed.toISOString(),
      duration_ms: durationMs,
      status: passed ? "passed" : "failed",
      exit_code: result.status,
      signal: result.signal,
      stdout: streamEvidence(stdout),
      stderr: streamEvidence(stderr),
    },
    stdout,
    error: result.error,
  };
}

function atomicWrite(path, value) {
  mkdirSync(dirname(path), { recursive: true });
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

function relativePath(path) {
  const result = relative(ROOT, path).split(sep).join("/");
  return result.length === 0 ? "." : result;
}

function supplyChain(gates, outputs, tools) {
  const auditIndex = gates.findIndex((gate) => gate.id === "cargo-audit");
  const denyReceipt = gates.find((gate) => gate.id === "cargo-deny");
  const auditReceipt = gates[auditIndex];
  if (auditIndex < 0 || auditReceipt?.status !== "passed" || denyReceipt?.status !== "passed") {
    return {
      cargo_audit: {
        status: "failed",
        tool_version: tools.find((item) => item.id === "cargo-audit")?.version ?? "unavailable",
        advisory_database_commit: "0000000000000000000000000000000000000000",
        dependency_count: 0,
        vulnerabilities_found: 0,
      },
      cargo_deny: {
        status: "failed",
        tool_version: tools.find((item) => item.id === "cargo-deny")?.version ?? "unavailable",
        checks: ["advisories", "bans", "licenses", "sources"],
      },
    };
  }
  const audit = JSON.parse(outputs[auditIndex].toString("utf8"));
  if (audit.vulnerabilities.found || audit.vulnerabilities.count !== 0) {
    fail("cargo audit reported vulnerabilities despite a successful exit");
  }
  return {
    cargo_audit: {
      status: "passed",
      tool_version: tools.find((item) => item.id === "cargo-audit").version,
      advisory_database_commit: audit.database["last-commit"],
      dependency_count: audit.lockfile["dependency-count"],
      vulnerabilities_found: audit.vulnerabilities.count,
    },
    cargo_deny: {
      status: "passed",
      tool_version: tools.find((item) => item.id === "cargo-deny").version,
      checks: ["advisories", "bans", "licenses", "sources"],
    },
  };
}

function main() {
  if (process.argv.length !== 3) {
    fail("usage: node tools/verification-runner.mjs <receipt-output.json>");
  }
  const outputPath = resolve(process.argv[2]);
  if (outputPath === RUNNER_PATH || outputPath === GATES_PATH) fail("unsafe receipt output path");
  const gateConfig = JSON.parse(readFileSync(GATES_PATH, "utf8"));
  if (
    gateConfig.schema !== "joan.verification-gates.v1" ||
    JSON.stringify(gateConfig.gates) !== JSON.stringify(EXPECTED_GATES)
  ) {
    fail("verification gate configuration is invalid");
  }
  const ids = new Set(gateConfig.gates.map((gate) => gate.id));
  if (ids.size !== gateConfig.gates.length) fail("verification gate IDs must be unique");

  const initialState = readState();
  const tools = [
    tool("node", process.execPath, ["--version"]),
    tool("cargo", "cargo", ["--version", "--verbose"]),
    tool("rustc", "rustc", ["--version", "--verbose"]),
    tool("cargo-audit", "cargo-audit", ["--version"]),
    tool("cargo-deny", "cargo-deny", ["--version"]),
  ];
  const started = new Date();
  const gateReceipts = [];
  const gateOutputs = [];
  let runnerError = null;
  for (const gate of gateConfig.gates) {
    process.stdout.write(`==> ${gate.id}\n`);
    const result = runGate(gate);
    gateReceipts.push(result.receipt);
    gateOutputs.push(result.stdout);
    if (result.receipt.status !== "passed") {
      runnerError = result.error ?? new Error(`gate failed: ${gate.id}`);
      break;
    }
  }

  const finalState = readState();
  if (JSON.stringify(initialState) !== JSON.stringify(finalState)) {
    runnerError = new Error("source or deterministic observations changed during verification");
  }
  const passed = gateReceipts.filter((gate) => gate.status === "passed").length;
  const status = runnerError === null && passed === gateConfig.gates.length ? "passed" : "failed";
  const receipt = {
    schema: "joan.verification-run-receipt.v1",
    version: "0.1.0-alpha.1",
    run_id: randomUUID(),
    status,
    started_at: started.toISOString(),
    completed_at: new Date().toISOString(),
    source: initialState.source,
    environment: {
      platform: platform(),
      arch: arch(),
      os_release: release(),
      runner_sha256: sha256(readFileSync(RUNNER_PATH)),
      tools,
    },
    gates: gateReceipts,
    summary: {
      required: gateConfig.gates.length,
      executed: gateReceipts.length,
      passed,
      failed: gateReceipts.filter((gate) => gate.status === "failed").length,
    },
    observations: finalState,
    supply_chain: supplyChain(gateReceipts, gateOutputs, tools),
  };
  atomicWrite(outputPath, receipt);
  process.stdout.write(
    `${JSON.stringify({
      schema: receipt.schema,
      run_id: receipt.run_id,
      status: receipt.status,
      source_digest: receipt.source.tree_digest.value,
      receipt: isAbsolute(process.argv[2]) ? outputPath : relativePath(outputPath),
    })}\n`,
  );
  if (status !== "passed") throw runnerError ?? new Error("verification run failed");
}

try {
  main();
} catch (error) {
  process.stderr.write(`verification-runner: ${String(error.message ?? error)}\n`);
  process.exitCode = 1;
}
