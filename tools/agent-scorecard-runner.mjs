#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { arch, platform, release, tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const IMPLEMENTATIONS = ["joan", "c", "rust", "typescript"];
const SCRIPT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MAX_BUFFER = 8 * 1_048_576;
const TIMEOUT_MS = 30_000;

function fail(message) {
  throw new Error(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]),
    );
  }
  return value;
}

function canonicalBytes(value) {
  return Buffer.from(JSON.stringify(canonicalize(value)), "utf8");
}

function integerOption(argumentsList, name, fallback, minimum, maximum) {
  const index = argumentsList.indexOf(name);
  if (index === -1) return fallback;
  const value = Number(argumentsList[index + 1]);
  assert(Number.isInteger(value) && value >= minimum && value <= maximum, `${name} is invalid`);
  return value;
}

function stringOption(argumentsList, name, fallback) {
  const index = argumentsList.indexOf(name);
  if (index === -1) return fallback;
  const value = argumentsList[index + 1];
  assert(typeof value === "string" && value.length > 0, `${name} is invalid`);
  return value;
}

function run(command, argumentsList, options = {}) {
  const started = process.hrtime.bigint();
  const execution = spawnSync(command, argumentsList, {
    cwd: SCRIPT_ROOT,
    encoding: "utf8",
    env: {
      ...process.env,
      NODE_NO_WARNINGS: "1",
      RUST_BACKTRACE: "0",
      ...options.env,
    },
    maxBuffer: MAX_BUFFER,
    timeout: TIMEOUT_MS,
  });
  const elapsed = Number(process.hrtime.bigint() - started);
  assert(execution.error === undefined, `${options.label ?? command} failed to start: ${execution.error}`);
  assert(execution.signal === null, `${options.label ?? command} terminated by ${execution.signal}`);
  assert(execution.status !== null, `${options.label ?? command} has no exit status`);
  return {
    elapsed_ns: elapsed,
    status: execution.status,
    stderr: execution.stderr,
    stdout: execution.stdout,
  };
}

function requireSuccess(execution, label) {
  if (execution.status !== 0) {
    fail(`${label} failed with exit ${execution.status}: ${execution.stderr || execution.stdout}`);
  }
}

function executable(name) {
  const found = run("/usr/bin/which", [name], { label: `locate ${name}` });
  requireSuccess(found, `locate ${name}`);
  return resolve(found.stdout.trim());
}

function toolchain(id, command, versionArguments, versionOverride) {
  const digestPath = realpathSync(command);
  const version = versionOverride ?? run(command, versionArguments, { label: `${id} version` }).stdout.trim();
  return {
    executable: basename(command),
    executable_sha256: sha256(readFileSync(digestPath)),
    id,
    version,
  };
}

function quantile(sorted, fraction) {
  return sorted[Math.max(0, Math.ceil(sorted.length * fraction) - 1)];
}

function timingSummary(samples) {
  assert(samples.length > 0, "timing samples are empty");
  const sorted = [...samples].sort((left, right) => left - right);
  return {
    max_ns: sorted.at(-1),
    min_ns: sorted[0],
    p50_ns: quantile(sorted, 0.50),
    p95_ns: quantile(sorted, 0.95),
    p99_ns: quantile(sorted, 0.99),
    samples_ns: samples,
  };
}

function ratioPpm(numerator, denominator) {
  assert(denominator > 0, "ratio denominator must be positive");
  return Number((BigInt(numerator) * 1_000_000n + BigInt(Math.floor(denominator / 2))) / BigInt(denominator));
}

function validateManifest(manifest) {
  assert(manifest.schema === "joan.agent-scorecard-workloads.v1", "unsupported workload manifest");
  assert(manifest.profile === "ai-agent-task-path-v1", "unsupported scorecard profile");
  assert(JSON.stringify(manifest.implementation_order) === JSON.stringify(IMPLEMENTATIONS), "implementation order drift");
  assert(Array.isArray(manifest.workloads) && manifest.workloads.length >= 2, "at least two workloads are required");
  assert(Array.isArray(manifest.safety_cases) && manifest.safety_cases.length >= 4, "at least four safety cases are required");
  const ids = new Set();
  for (const workload of manifest.workloads) {
    assert(/^[a-z0-9-]+$/.test(workload.id), `invalid workload id ${workload.id}`);
    assert(!ids.has(workload.id), `duplicate workload id ${workload.id}`);
    ids.add(workload.id);
    for (const implementation of IMPLEMENTATIONS) {
      assert(typeof workload.sources?.[implementation] === "string", `${workload.id} has no ${implementation} source`);
    }
  }
  for (const safetyCase of manifest.safety_cases) {
    assert(/^[a-z0-9-]+$/.test(safetyCase.id), `invalid safety case id ${safetyCase.id}`);
    for (const implementation of IMPLEMENTATIONS) {
      const probe = safetyCase.probes?.[implementation];
      assert(typeof probe?.path === "string", `${safetyCase.id} has no ${implementation} probe`);
      assert(["check", "compile", "run", "strip-check"].includes(probe.stage), `${safetyCase.id} has invalid ${implementation} stage`);
      assert(["accepted", "rejected"].includes(probe.expected_status), `${safetyCase.id} has invalid expected status`);
      assert(Array.isArray(probe.evidence_contains), `${safetyCase.id} has invalid evidence list`);
    }
  }
  const policy = manifest.qualification_policy;
  for (const field of [
    "minimum_workloads",
    "minimum_recorded_samples",
    "maximum_runtime_ratio_ppm",
    "maximum_peak_rss_ratio_ppm",
    "material_win_ratio_ppm",
    "minimum_material_wins",
    "require_joan_safety_protection_ppm",
  ]) {
    assert(Number.isInteger(policy?.[field]) && policy[field] >= 0, `invalid policy ${field}`);
  }
}

function sourcePath(relativePath) {
  const path = resolve(SCRIPT_ROOT, relativePath);
  assert(path.startsWith(`${SCRIPT_ROOT}/`), `source escapes repository: ${relativePath}`);
  statSync(path);
  return path;
}

function stripCheckCommand(node, path) {
  return {
    argumentsList: ["--no-warnings", "--experimental-strip-types", "tools/typescript-strip-check.mjs", path],
    command: node,
  };
}

function prepareCommand(implementation, path, artifact, tools) {
  if (implementation === "joan") {
    return { command: tools.joan, argumentsList: ["compile", path, "--json"] };
  }
  if (implementation === "c") {
    return {
      command: tools.cc,
      argumentsList: ["-O3", "-std=c11", "-Wall", "-Wextra", "-Werror", path, "-o", artifact],
    };
  }
  if (implementation === "rust") {
    return {
      command: tools.rustc,
      argumentsList: ["--edition=2024", "-C", "opt-level=3", "-C", "overflow-checks=yes", path, "-o", artifact],
    };
  }
  return stripCheckCommand(tools.node, path);
}

function runtimeCommand(implementation, path, artifact, tools) {
  if (implementation === "joan") return { command: tools.joan, argumentsList: ["run", path, "--json"] };
  if (implementation === "c" || implementation === "rust") return { command: artifact, argumentsList: [] };
  return { command: tools.node, argumentsList: ["--no-warnings", "--experimental-strip-types", path] };
}

function normalizeOutput(implementation, stdout) {
  let decoded;
  try {
    decoded = JSON.parse(stdout);
  } catch (error) {
    fail(`${implementation} emitted invalid JSON: ${error.message}`);
  }
  if (implementation !== "joan") return canonicalize(decoded);
  assert(decoded.status === "completed", "JOAN workload did not complete");
  return canonicalize({
    effect_requests: decoded.effect_requests.map((request) => ({
      arguments: request.arguments,
      authority_slot: request.authority_slot,
      effect: request.effect,
      information: request.information,
    })),
    result: decoded.result,
  });
}

function measurePeakRss(descriptor, expected, implementation) {
  if (platform() !== "darwin" && platform() !== "linux") return null;
  const timeArguments = platform() === "darwin" ? ["-l"] : ["-v"];
  const execution = run("/usr/bin/time", [...timeArguments, descriptor.command, ...descriptor.argumentsList], {
    label: `${implementation} peak RSS`,
  });
  requireSuccess(execution, `${implementation} peak RSS`);
  const normalized = normalizeOutput(implementation, execution.stdout);
  assert(canonicalBytes(normalized).equals(expected), `${implementation} peak RSS output drift`);
  const pattern = platform() === "darwin"
    ? /^\s*([0-9]+)\s+maximum resident set size$/m
    : /^\s*Maximum resident set size \(kbytes\):\s*([0-9]+)$/m;
  const match = execution.stderr.match(pattern);
  if (!match) return null;
  const observed = Number(match[1]);
  return platform() === "linux" ? observed * 1024 : observed;
}

function measureWorkload(workload, sampleCount, preparationSampleCount, work, tools) {
  const expected = canonicalBytes(workload.expected_output);
  const results = [];
  for (const implementation of IMPLEMENTATIONS) {
    const path = sourcePath(workload.sources[implementation]);
    const source = readFileSync(path);
    const artifact = join(work, `${workload.id}-${implementation}`);
    const preparationDescriptor = prepareCommand(implementation, path, artifact, tools);
    const preparationSamples = [];
    let preparationStdout = "";
    for (let index = 0; index < preparationSampleCount; index += 1) {
      const execution = run(preparationDescriptor.command, preparationDescriptor.argumentsList, {
        label: `${workload.id} ${implementation} prepare`,
      });
      requireSuccess(execution, `${workload.id} ${implementation} prepare`);
      preparationSamples.push(execution.elapsed_ns);
      preparationStdout = execution.stdout;
    }
    const descriptor = runtimeCommand(implementation, path, artifact, tools);
    const warmup = run(descriptor.command, descriptor.argumentsList, {
      label: `${workload.id} ${implementation} warmup`,
    });
    requireSuccess(warmup, `${workload.id} ${implementation} warmup`);
    const warmupNormalized = normalizeOutput(implementation, warmup.stdout);
    assert(canonicalBytes(warmupNormalized).equals(expected), `${workload.id} ${implementation} output is not equivalent`);
    const runtimeSamples = [];
    let stdout = warmup.stdout;
    for (let index = 0; index < sampleCount; index += 1) {
      const execution = run(descriptor.command, descriptor.argumentsList, {
        label: `${workload.id} ${implementation} sample ${index + 1}`,
      });
      requireSuccess(execution, `${workload.id} ${implementation} runtime`);
      const normalized = normalizeOutput(implementation, execution.stdout);
      assert(canonicalBytes(normalized).equals(expected), `${workload.id} ${implementation} sample output drift`);
      runtimeSamples.push(execution.elapsed_ns);
      stdout = execution.stdout;
    }
    let artifactBytes;
    let artifactScope;
    if (implementation === "joan") {
      artifactBytes = Buffer.byteLength(preparationStdout);
      artifactScope = "serialized-bytecode-and-verification-receipt";
    } else if (implementation === "typescript") {
      artifactBytes = source.length;
      artifactScope = "typescript-source-native-strip-runtime";
    } else {
      artifactBytes = statSync(artifact).size;
      artifactScope = "native-executable";
    }
    results.push({
      actual_stdout_bytes: Buffer.byteLength(stdout),
      artifact_bytes: artifactBytes,
      artifact_scope: artifactScope,
      implementation,
      normalized_output_bytes: expected.length,
      output_sha256: sha256(expected),
      peak_rss_bytes: measurePeakRss(descriptor, expected, implementation),
      preparation: timingSummary(preparationSamples),
      runtime: timingSummary(runtimeSamples),
      source_bytes: source.length,
      source_sha256: sha256(source),
    });
  }
  const outputDigests = new Set(results.map((result) => result.output_sha256));
  const joan = results.find((result) => result.implementation === "joan");
  const native = results.filter((result) => result.implementation === "c" || result.implementation === "rust");
  const bestNativeRuntime = Math.min(...native.map((result) => result.runtime.p95_ns));
  const nativeRss = native.map((result) => result.peak_rss_bytes).filter((value) => value !== null);
  const bestNativeRss = nativeRss.length === 0 ? null : Math.min(...nativeRss);
  return {
    comparison: {
      best_native_p95_ns: bestNativeRuntime,
      best_native_peak_rss_bytes: bestNativeRss,
      joan_p95_ns: joan.runtime.p95_ns,
      joan_peak_rss_bytes: joan.peak_rss_bytes,
      joan_to_best_native_peak_rss_ratio_ppm:
        bestNativeRss === null || joan.peak_rss_bytes === null ? null : ratioPpm(joan.peak_rss_bytes, bestNativeRss),
      joan_to_best_native_runtime_ratio_ppm: ratioPpm(joan.runtime.p95_ns, bestNativeRuntime),
    },
    equivalence_passed: outputDigests.size === 1 && results[0].output_sha256 === sha256(expected),
    expected_output_sha256: sha256(expected),
    id: workload.id,
    results,
  };
}

function safetyCompileDescriptor(implementation, path, artifact, tools) {
  if (implementation === "c") {
    return { command: tools.cc, argumentsList: ["-O3", "-std=c11", path, "-o", artifact] };
  }
  if (implementation === "rust") {
    return {
      command: tools.rustc,
      argumentsList: ["--edition=2024", "-C", "opt-level=3", "-C", "overflow-checks=yes", path, "-o", artifact],
    };
  }
  fail(`compile is unsupported for ${implementation}`);
}

function observeSafetyProbe(caseId, implementation, probe, work, tools) {
  const path = sourcePath(probe.path);
  const artifact = join(work, `safety-${caseId}-${implementation}`);
  let execution;
  if (implementation === "joan") {
    const command = probe.stage === "run" ? "run" : "check";
    execution = run(tools.joan, [command, path, "--json"], { label: `${caseId} JOAN ${command}` });
  } else if (implementation === "typescript") {
    const descriptor = probe.stage === "run"
      ? { command: tools.node, argumentsList: ["--no-warnings", "--experimental-strip-types", path] }
      : stripCheckCommand(tools.node, path);
    execution = run(descriptor.command, descriptor.argumentsList, { label: `${caseId} TypeScript ${probe.stage}` });
  } else {
    const compilation = safetyCompileDescriptor(implementation, path, artifact, tools);
    execution = run(compilation.command, compilation.argumentsList, { label: `${caseId} ${implementation} compile` });
    if (execution.status === 0 && probe.stage === "run") {
      execution = run(artifact, [], { label: `${caseId} ${implementation} run` });
    }
  }
  const status = execution.status === 0 ? "accepted" : "rejected";
  const evidence = `${execution.stdout}\n${execution.stderr}`;
  const evidenceMatches = probe.evidence_contains.every((fragment) => evidence.includes(fragment));
  assert(status === probe.expected_status, `${caseId} ${implementation} expected ${probe.expected_status}, observed ${status}`);
  assert(evidenceMatches, `${caseId} ${implementation} diagnostic evidence drift`);
  return {
    diagnostic_evidence_sha256: sha256(Buffer.from(evidence, "utf8")),
    expected_status_match: true,
    implementation,
    protects: status === "rejected",
    stage: probe.stage,
    status,
  };
}

function evaluateSafety(manifest, work, tools) {
  const results = manifest.safety_cases.map((safetyCase) => ({
    id: safetyCase.id,
    observations: IMPLEMENTATIONS.map((implementation) =>
      observeSafetyProbe(safetyCase.id, implementation, safetyCase.probes[implementation], work, tools)),
    rule: safetyCase.rule,
  }));
  const protection = Object.fromEntries(IMPLEMENTATIONS.map((implementation) => {
    const protectedCount = results.filter((result) =>
      result.observations.find((observation) => observation.implementation === implementation).protects).length;
    return [implementation, {
      protected: protectedCount,
      protection_ppm: ratioPpm(protectedCount, results.length),
      total: results.length,
    }];
  }));
  return { case_count: results.length, protection, results };
}

function platformDescriptor() {
  function optional(command, argumentsList) {
    const result = run(command, argumentsList, { label: command });
    return result.status === 0 ? result.stdout.trim() : "unavailable";
  }
  return {
    arch: arch(),
    model: platform() === "darwin" ? optional("/usr/sbin/sysctl", ["-n", "hw.model"]) : "unavailable",
    os: platform(),
    processor: platform() === "darwin"
      ? optional("/usr/sbin/sysctl", ["-n", "machdep.cpu.brand_string"])
      : optional("/usr/bin/uname", ["-p"]),
    release: release(),
  };
}

function qualification(manifest, workloads, safety, sampleCount, mode) {
  const policy = manifest.qualification_policy;
  const correctness = workloads.every((workload) => workload.equivalence_passed);
  const joanSafety = safety.protection.joan;
  const runtimeTargets = workloads.every((workload) =>
    workload.comparison.joan_to_best_native_runtime_ratio_ppm <= policy.maximum_runtime_ratio_ppm);
  const memoryTargets = workloads.every((workload) =>
    workload.comparison.joan_to_best_native_peak_rss_ratio_ppm !== null &&
    workload.comparison.joan_to_best_native_peak_rss_ratio_ppm <= policy.maximum_peak_rss_ratio_ppm);
  let materialWins = 0;
  for (const workload of workloads) {
    if (workload.comparison.joan_to_best_native_runtime_ratio_ppm <= policy.material_win_ratio_ppm) materialWins += 1;
    if (workload.comparison.joan_to_best_native_peak_rss_ratio_ppm !== null &&
        workload.comparison.joan_to_best_native_peak_rss_ratio_ppm <= policy.material_win_ratio_ppm) materialWins += 1;
  }
  const blockers = [];
  if (!correctness) blockers.push("observable-output-equivalence-failed");
  if (joanSafety.protection_ppm !== policy.require_joan_safety_protection_ppm) blockers.push("joan-safety-protection-below-required-threshold");
  if (workloads.length < policy.minimum_workloads) blockers.push("workload-corpus-below-minimum");
  if (sampleCount < policy.minimum_recorded_samples || mode !== "recorded") blockers.push("recorded-sample-threshold-not-met");
  blockers.push("native-backend-not-implemented");
  blockers.push("independent-hardware-rerun-missing");
  if (!runtimeTargets) blockers.push("runtime-target-not-met");
  if (!memoryTargets) blockers.push("peak-rss-target-not-met");
  if (materialWins < policy.minimum_material_wins) blockers.push("material-win-count-below-minimum");
  blockers.push("typescript-static-typecheck-not-measured");
  blockers.push("m2m-wire-protocol-baselines-not-measured");
  return {
    blockers,
    broad_language_superiority_claim: false,
    correctness_equivalent: correctness,
    eligible: false,
    independent_rerun: false,
    joan_safety_cases_protected: joanSafety.protected,
    joan_safety_cases_total: joanSafety.total,
    material_wins: materialWins,
    native_backend: false,
    peak_rss_targets_met: memoryTargets,
    runtime_targets_met: runtimeTargets,
    status: "baseline-only-not-qualified",
  };
}

function main() {
  const [joanArgument, manifestArgument, reportArgument, ...options] = process.argv.slice(2);
  if (!joanArgument || !manifestArgument || !reportArgument) {
    fail("usage: node tools/agent-scorecard-runner.mjs <joan-binary> <workloads.json> <report.json> [--samples N] [--prepare-samples N] [--mode smoke|recorded]");
  }
  const sampleCount = integerOption(options, "--samples", 3, 3, 101);
  const preparationSampleCount = integerOption(options, "--prepare-samples", 1, 1, 21);
  const mode = stringOption(options, "--mode", "smoke");
  assert(mode === "smoke" || mode === "recorded", "--mode must be smoke or recorded");
  const manifestPath = resolve(manifestArgument);
  const manifestBytes = readFileSync(manifestPath);
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  validateManifest(manifest);
  const temporaryRoot = resolve(process.env.JOAN_SCORECARD_TMPDIR ?? tmpdir());
  const work = mkdtempSync(join(temporaryRoot, "joan-agent-scorecard-"));
  const tools = {
    cc: executable("cc"),
    joan: realpathSync(resolve(joanArgument)),
    node: realpathSync(process.execPath),
    rustc: executable("rustc"),
  };
  try {
    const workloads = manifest.workloads.map((workload) =>
      measureWorkload(workload, sampleCount, preparationSampleCount, work, tools));
    const safety = evaluateSafety(manifest, work, tools);
    const report = {
      claim_scope: "ai-agent-task-path-baseline-only",
      generated_at: new Date().toISOString(),
      manifest_sha256: sha256(manifestBytes),
      mode,
      platform: platformDescriptor(),
      preparation_sample_count: preparationSampleCount,
      qualification: qualification(manifest, workloads, safety, sampleCount, mode),
      safety,
      sample_count: sampleCount,
      schema: "joan.agent-scorecard-report.v1",
      toolchains: [
        toolchain("joan", tools.joan, [], "alpha-language-preview; release binary digest bound"),
        toolchain("c", tools.cc, ["--version"]),
        toolchain("rust", tools.rustc, ["--version", "--verbose"]),
        toolchain("typescript-runtime", tools.node, ["--version"]),
      ],
      universal_language_superiority_claim: false,
      workloads,
    };
    const encoded = `${JSON.stringify(report, null, 2)}\n`;
    writeFileSync(resolve(reportArgument), encoded, { encoding: "utf8" });
    process.stdout.write(JSON.stringify({
      report_sha256: sha256(Buffer.from(encoded, "utf8")),
      safety: report.safety.protection,
      schema: report.schema,
      status: report.qualification.status,
      workloads: report.workloads.length,
    }) + "\n");
  } finally {
    rmSync(work, { force: true, recursive: true });
  }
}

try {
  main();
} catch (error) {
  process.stderr.write(`agent-scorecard-runner: ${String(error.message ?? error)}\n`);
  process.exitCode = 1;
}
