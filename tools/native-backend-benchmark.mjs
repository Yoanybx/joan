#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { arch, cpus, platform, release, totalmem } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const IMPLEMENTATIONS = ["joan-native", "c", "cpp", "rust", "julia"];
const MAX_BUFFER = 8 * 1_048_576;
const TIMEOUT_MS = 120_000;
const EXPECTED_INSTRUCTIONS = {
  "cost-model": 6,
  "deadline-slack": 6,
  "dispatch-decision": 6,
  "route-score": 11,
  "split-budget": 8,
};

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  return value;
}

function semanticObservationDigest(observation) {
  const semantic = structuredClone(observation);
  delete semantic.compile_ns;
  delete semantic.runtime_ns;
  return sha256(JSON.stringify(canonicalize(semantic)));
}

function selfTestSemanticObservationDigest() {
  const baseline = {
    schema: "joan.native-kernel-observation.v0",
    status: "completed",
    workload: "cost-model",
    iterations: 1_000_000,
    seed: "5354584147903952384",
    checksum: "044b3d44f787f7b3",
    compile_ns: 10,
    runtime_ns: 20,
    instructions_executed: 6_000_000,
    artifact_digest: "1f3cbbeded357aebe50985ad7eddbe3ced227ea1ebd726b37c3981ffb610e70e",
    generated_code_bytes: 2_296,
  };
  const timingMutation = { ...baseline, compile_ns: 30, runtime_ns: 40 };
  const semanticMutation = { ...baseline, checksum: "144b3d44f787f7b3" };
  assert(
    semanticObservationDigest(baseline) === semanticObservationDigest(timingMutation),
    "semantic observation digest includes timing",
  );
  assert(
    semanticObservationDigest(baseline) !== semanticObservationDigest(semanticMutation),
    "semantic observation digest ignores result drift",
  );
}

function run(command, argumentsList, label) {
  const started = process.hrtime.bigint();
  const execution = spawnSync(command, argumentsList, {
    cwd: ROOT,
    encoding: "utf8",
    env: { ...process.env, RUST_BACKTRACE: "0" },
    maxBuffer: MAX_BUFFER,
    timeout: TIMEOUT_MS,
  });
  const elapsedNs = Number(process.hrtime.bigint() - started);
  assert(execution.error === undefined, `${label} failed to start: ${execution.error}`);
  assert(execution.signal === null, `${label} terminated by ${execution.signal}`);
  assert(execution.status === 0, `${label} failed with ${execution.status}: ${execution.stderr || execution.stdout}`);
  return { elapsed_ns: elapsedNs, stderr: execution.stderr, stdout: execution.stdout };
}

function locate(name) {
  const result = spawnSync("/usr/bin/which", [name], { encoding: "utf8" });
  if (result.status !== 0) return null;
  return resolve(result.stdout.trim());
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

function sourcePath(relativePath) {
  const path = resolve(ROOT, relativePath);
  assert(path.startsWith(`${ROOT}/`), `source escapes repository: ${relativePath}`);
  statSync(path);
  return path;
}

function timingSummary(samples) {
  assert(samples.length > 0, "timing samples are empty");
  const sorted = [...samples].sort((left, right) => left - right);
  const quantile = (fraction) => sorted[Math.max(0, Math.ceil(sorted.length * fraction) - 1)];
  return {
    max_ns: sorted.at(-1),
    min_ns: sorted[0],
    p50_ns: quantile(0.50),
    p95_ns: quantile(0.95),
    p99_ns: quantile(0.99),
    samples_ns: samples,
  };
}

function byteSummary(samples) {
  const timing = timingSummary(samples);
  return {
    max_bytes: timing.max_ns,
    min_bytes: timing.min_ns,
    p50_bytes: timing.p50_ns,
    p95_bytes: timing.p95_ns,
    p99_bytes: timing.p99_ns,
    samples_bytes: timing.samples_ns,
  };
}

function deterministicOrder(values, seed) {
  return [...values].sort((left, right) => {
    const leftHash = sha256(`${seed}:${left}`);
    const rightHash = sha256(`${seed}:${right}`);
    return leftHash.localeCompare(rightHash);
  });
}

function balancedOrder(values, seed, sample) {
  const block = Math.floor(sample / values.length);
  const base = deterministicOrder(values, `${seed}:block:${block}`);
  const offset = sample % values.length;
  return [...base.slice(offset), ...base.slice(0, offset)];
}

function oracleSampleIndices(sampleCount) {
  return [...new Set([0, Math.floor((sampleCount - 1) / 2), sampleCount - 1])].sort((left, right) => left - right);
}

function parseObservation(execution, implementation, workload, iterations, seed) {
  let observation;
  try {
    observation = JSON.parse(execution.stdout);
  } catch (error) {
    throw new Error(`${implementation}/${workload} emitted invalid JSON: ${error.message}`);
  }
  assert(observation.status === "completed", `${implementation}/${workload} did not complete`);
  assert(observation.workload === workload, `${implementation}/${workload} workload drift`);
  assert(observation.iterations === iterations, `${implementation}/${workload} iteration drift`);
  assert(/^[0-9a-f]{16}$/.test(observation.checksum), `${implementation}/${workload} checksum is invalid`);
  assert(Number.isSafeInteger(observation.runtime_ns) && observation.runtime_ns > 0, `${implementation}/${workload} runtime is invalid`);
  assert(
    observation.instructions_executed === EXPECTED_INSTRUCTIONS[workload] * iterations,
    `${implementation}/${workload} instruction accounting is not equivalent`,
  );
  if (implementation === "joan-native") {
    assert(observation.schema === "joan.native-kernel-observation.v0", "JOAN native observation schema drift");
    assert(observation.seed === seed, "JOAN native seed drift");
  }
  return observation;
}

function parseOracleObservation(execution, workload, iterations, seed) {
  let observation;
  try {
    observation = JSON.parse(execution.stdout);
  } catch (error) {
    throw new Error(`oracle/${workload} emitted invalid JSON: ${error.message}`);
  }
  assert(observation.schema === "joan.native-benchmark-oracle-observation.v0", "oracle schema drift");
  assert(observation.status === "completed", `oracle/${workload} did not complete`);
  assert(observation.workload === workload, `oracle/${workload} workload drift`);
  assert(observation.iterations === iterations, `oracle/${workload} iteration drift`);
  assert(observation.seed === seed, `oracle/${workload} seed drift`);
  assert(/^[0-9a-f]{16}$/.test(observation.checksum), `oracle/${workload} checksum is invalid`);
  assert(
    observation.instructions_executed === EXPECTED_INSTRUCTIONS[workload] * iterations,
    `oracle/${workload} instruction accounting drift`,
  );
  return observation;
}

function compileDescriptor(implementation, source, output, tools) {
  if (implementation === "joan-native") {
    return { command: tools.joan, arguments: ["native", "compile", source, "--json"] };
  }
  if (implementation === "c") {
    return { command: tools.c, arguments: ["-O3", "-march=native", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", source, "-o", output] };
  }
  if (implementation === "cpp") {
    return { command: tools.cpp, arguments: ["-O3", "-march=native", "-std=c++20", "-Wall", "-Wextra", "-Werror", "-pedantic", source, "-o", output] };
  }
  if (implementation === "rust") {
    return { command: tools.rust, arguments: ["--edition=2024", "-C", "opt-level=3", "-C", "target-cpu=native", "-C", "overflow-checks=yes", source, "-o", output] };
  }
  return null;
}

function runtimeDescriptor(implementation, source, artifact, tools, workload, iterations, seed) {
  if (implementation === "joan-native") {
    return { command: tools.nativeBench, arguments: [source, workload, String(iterations), seed] };
  }
  if (implementation === "julia") {
    return { command: tools.julia, arguments: ["--startup-file=no", source, workload, String(iterations), seed] };
  }
  return { command: artifact, arguments: [workload, String(iterations), seed] };
}

function peakRss(descriptor, implementation, workload, iterations, seed) {
  const timeArguments = platform() === "darwin"
    ? ["-l", descriptor.command, ...descriptor.arguments]
    : platform() === "linux"
      ? ["-v", descriptor.command, ...descriptor.arguments]
      : null;
  assert(timeArguments !== null, `peak RSS is unsupported on ${platform()}`);
  const execution = run("/usr/bin/time", timeArguments, `${implementation}/${workload} RSS`);
  parseObservation(execution, implementation, workload, iterations, seed);
  const match = platform() === "darwin"
    ? execution.stderr.match(/^\s*([0-9]+)\s+maximum resident set size$/m)
    : execution.stderr.match(/^\s*Maximum resident set size \(kbytes\):\s*([0-9]+)$/m);
  assert(match !== null, `${implementation}/${workload} RSS was not reported`);
  return platform() === "darwin" ? Number(match[1]) : Number(match[1]) * 1024;
}

function compileFlags(implementation) {
  if (implementation === "joan-native") return ["native", "compile", "--json", "opt_level=speed"];
  if (implementation === "c") return ["-O3", "-march=native", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"];
  if (implementation === "cpp") return ["-O3", "-march=native", "-std=c++20", "-Wall", "-Wextra", "-Werror", "-pedantic"];
  if (implementation === "rust") return ["--edition=2024", "-Copt-level=3", "-Ctarget-cpu=native", "-Coverflow-checks=yes"];
  return ["--startup-file=no", "jit-at-runtime"];
}

function toolEvidence(id, executable, versionArguments) {
  if (executable === null) return { available: false, id, reason: "toolchain-not-installed" };
  const real = realpathSync(executable);
  const version = run(executable, versionArguments, `${id} version`).stdout.trim();
  return { available: true, executable: basename(executable), executable_sha256: sha256(readFileSync(real)), id, version };
}

function validateManifest(manifest) {
  assert(manifest.schema === "joan.native-backend-benchmark-manifest.v0", "manifest schema drift");
  assert(manifest.profile === "dynamic-pure-kernels-v0", "manifest profile drift");
  assert(JSON.stringify(manifest.implementation_order) === JSON.stringify(IMPLEMENTATIONS), "implementation order drift");
  assert(manifest.workloads.length === 5, "exactly five workloads are required");
  assert(new Set(manifest.workloads.map((item) => item.id)).size === 5, "workload IDs must be unique");
  assert(manifest.qualification.universal_superiority_claim_allowed === false, "manifest cannot authorize a universal claim");
}

const argumentsList = process.argv.slice(2);
if (argumentsList.length === 1 && argumentsList[0] === "--self-test") {
  selfTestSemanticObservationDigest();
  process.stdout.write(`${JSON.stringify({ status: "passed", timing_fields_excluded: ["compile_ns", "runtime_ns"] })}\n`);
  process.exit(0);
}
assert(argumentsList.length >= 2, "usage: native-backend-benchmark.mjs <manifest> <report> [options]");
const manifestPath = sourcePath(argumentsList[0]);
const reportPath = resolve(argumentsList[1]);
assert(!reportPath.startsWith(`${ROOT}/`), "benchmark reports must be written outside the source tree");
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
validateManifest(manifest);
const mode = stringOption(argumentsList, "--mode", "smoke");
assert(["smoke", "recorded"].includes(mode), "--mode is invalid");
const defaultSamples = mode === "recorded" ? manifest.sampling.recorded_samples : manifest.sampling.smoke_samples;
const defaultIterations = mode === "recorded" ? manifest.sampling.recorded_iterations : manifest.sampling.smoke_iterations;
const sampleCount = integerOption(argumentsList, "--samples", defaultSamples, 3, 101);
const iterations = integerOption(argumentsList, "--iterations", defaultIterations, 100, 10_000_000);
const rssSampleCount = Math.min(sampleCount, integerOption(argumentsList, "--rss-samples", manifest.sampling.rss_samples, 1, 21));
if (mode === "recorded") {
  assert(sampleCount === manifest.sampling.recorded_samples, "recorded sample count must match the manifest");
  assert(iterations === manifest.sampling.recorded_iterations, "recorded iteration count must match the manifest");
  assert(rssSampleCount === manifest.sampling.rss_samples, "recorded RSS sample count must match the manifest");
}

const targetDir = resolve(process.env.CARGO_TARGET_DIR ?? join(ROOT, "target"));
const temporaryRoot = resolve(process.env.JOAN_NATIVE_BENCHMARK_TMPDIR ?? "/Volumes/JOANBuild/tmp");
mkdirSync(temporaryRoot, { recursive: true });
const work = mkdtempSync(join(temporaryRoot, "joan-native-benchmark."));
try {
  const tools = {
    c: locate("clang"),
    cpp: locate("clang++"),
    rust: locate("rustc"),
    julia: locate("julia"),
    joan: resolve(process.env.JOAN_BINARY ?? join(targetDir, "release", "joan")),
    nativeBench: resolve(process.env.JOAN_NATIVE_BENCH_BINARY ?? join(targetDir, "release", "joan-native-bench")),
    oracle: sourcePath("reference/native-benchmark-oracle.mjs"),
  };
  for (const key of ["c", "cpp", "rust", "joan", "nativeBench"]) statSync(tools[key]);
  const available = IMPLEMENTATIONS.filter((id) => id !== "julia" || tools.julia !== null);
  const sourcePaths = Object.fromEntries(IMPLEMENTATIONS.map((id) => [id, sourcePath(manifest.sources[id])]));
  const artifacts = {};
  const preparation = {};
  for (const implementation of available) {
    if (implementation === "julia") {
      preparation[implementation] = {
        artifact_bytes: statSync(sourcePaths[implementation]).size,
        artifact_scope: "julia-source-file-jit-runtime",
        artifact_sha256: sha256(readFileSync(sourcePaths[implementation])),
        compile: null,
        compile_flags: compileFlags(implementation),
        generated_code_bytes: null,
        native_artifact_digest: null,
        note: "Julia JIT compilation is part of process execution.",
      };
      artifacts[implementation] = sourcePaths[implementation];
      continue;
    }
    const samples = [];
    let nativeCodeBytes = null;
    let nativeArtifactDigest = null;
    let artifact = implementation === "joan-native" ? tools.nativeBench : join(work, `${implementation}-runtime`);
    for (let sample = 0; sample < Math.min(sampleCount, mode === "recorded" ? 21 : sampleCount); sample += 1) {
      const sampleArtifact = implementation === "joan-native" ? artifact : join(work, `${implementation}-compile-${sample}`);
      const descriptor = compileDescriptor(implementation, sourcePaths[implementation], sampleArtifact, tools);
      const execution = run(descriptor.command, descriptor.arguments, `${implementation} compile sample ${sample}`);
      if (implementation === "joan-native") {
        const receipt = JSON.parse(execution.stdout);
        assert(receipt.schema === "joan.native-compile-receipt.v0", "JOAN native compile receipt drift");
        assert(receipt.optimization_profile === "speed", "JOAN native optimization profile drift");
        if (nativeCodeBytes === null) nativeCodeBytes = receipt.code_bytes;
        assert(receipt.code_bytes === nativeCodeBytes, "JOAN generated code size drift");
        if (nativeArtifactDigest === null) nativeArtifactDigest = receipt.artifact_digest.value;
        assert(receipt.artifact_digest.value === nativeArtifactDigest, "JOAN native artifact identity drift");
      }
      samples.push(execution.elapsed_ns);
      if (implementation !== "joan-native") artifact = sampleArtifact;
    }
    artifacts[implementation] = artifact;
    preparation[implementation] = {
      artifact_bytes: statSync(artifact).size,
      artifact_scope: implementation === "joan-native"
        ? "prebuilt-joan-native-benchmark-host"
        : "single-dynamic-executable-not-transitive-runtime",
      artifact_sha256: sha256(readFileSync(artifact)),
      compile: timingSummary(samples),
      compile_flags: compileFlags(implementation),
      generated_code_bytes: nativeCodeBytes,
      native_artifact_digest: nativeArtifactDigest,
      note: implementation === "joan-native"
        ? "Measures release JOAN source-to-finalized-JIT in a fresh process; runnable host was prebuilt."
        : "Measures source-to-runnable optimized executable with warm filesystem caches.",
    };
  }

  const workloadReports = [];
  const oracleCases = [];
  const oracleIndices = oracleSampleIndices(sampleCount);
  const baseSeed = BigInt(manifest.sampling.seed);
  for (let workloadIndex = 0; workloadIndex < manifest.workloads.length; workloadIndex += 1) {
    const workload = manifest.workloads[workloadIndex];
    const schedule = [];
    const observations = Object.fromEntries(available.map((id) => [id, {
      inner: [], process: [], rss: [], checksum: null, observationHashes: [],
    }]));
    for (let sample = 0; sample < sampleCount; sample += 1) {
      const seed = (baseSeed + BigInt(workloadIndex * 100_000 + sample)).toString();
      const order = balancedOrder(available, `${manifest.sampling.seed}:${workload.id}`, sample);
      const oracleVerified = oracleIndices.includes(sample);
      schedule.push({ oracle_verified: oracleVerified, order, sample, seed });
      let expectedChecksum = null;
      if (oracleVerified) {
        const oracleExecution = run(
          process.execPath,
          [tools.oracle, workload.id, String(iterations), seed],
          `oracle/${workload.id} sample ${sample}`,
        );
        const oracle = parseOracleObservation(oracleExecution, workload.id, iterations, seed);
        expectedChecksum = oracle.checksum;
        oracleCases.push({
          checksum: oracle.checksum,
          instructions_executed: oracle.instructions_executed,
          observation_sha256: semanticObservationDigest(oracle),
          sample,
          seed,
          workload: workload.id,
        });
      }
      for (const implementation of order) {
        const descriptor = runtimeDescriptor(
          implementation,
          sourcePaths[implementation],
          artifacts[implementation],
          tools,
          workload.id,
          iterations,
          seed,
        );
        const execution = run(descriptor.command, descriptor.arguments, `${implementation}/${workload.id} sample ${sample}`);
        const observation = parseObservation(execution, implementation, workload.id, iterations, seed);
        if (expectedChecksum === null) expectedChecksum = observation.checksum;
        assert(observation.checksum === expectedChecksum, `${implementation}/${workload.id} output is not equivalent`);
        observations[implementation].checksum = observation.checksum;
        observations[implementation].inner.push(observation.runtime_ns);
        observations[implementation].process.push(execution.elapsed_ns);
        observations[implementation].observationHashes.push(semanticObservationDigest(observation));
        if (sample < rssSampleCount) {
          observations[implementation].rss.push(peakRss(descriptor, implementation, workload.id, iterations, seed));
        }
      }
    }
    workloadReports.push({
      description: workload.description,
      id: workload.id,
      implementations: Object.fromEntries(available.map((implementation) => [implementation, {
        checksum: observations[implementation].checksum,
        inner_runtime: timingSummary(observations[implementation].inner),
        observation_sha256: observations[implementation].observationHashes,
        peak_rss: byteSummary(observations[implementation].rss),
        process_time: timingSummary(observations[implementation].process),
      }])),
      output_equivalent: true,
      schedule,
    });
  }

  const sourceTree = JSON.parse(run(process.execPath, ["tools/evidence-index.mjs", "source"], "source tree identity").stdout);
  const report = canonicalize({
    schema: "joan.native-backend-benchmark-report.v0",
    status: "local-benchmark-not-qualified",
    mode,
    samples: sampleCount,
    iterations,
    rss_samples: rssSampleCount,
    available_implementations: available,
    unavailable_implementations: IMPLEMENTATIONS.filter((id) => !available.includes(id)).map((id) => ({ id, reason: "toolchain-not-installed" })),
    environment: {
      architecture: arch(),
      cpu: cpus()[0]?.model ?? "unknown",
      logical_cpus: cpus().length,
      memory_bytes: totalmem(),
      os: platform(),
      os_release: release(),
    },
    identities: {
      manifest_sha256: sha256(readFileSync(manifestPath)),
      oracle_sha256: sha256(readFileSync(tools.oracle)),
      runner_sha256: sha256(readFileSync(fileURLToPath(import.meta.url))),
      source_tree: sourceTree.tree_digest,
      sources: Object.fromEntries(IMPLEMENTATIONS.map((id) => [id, sha256(readFileSync(sourcePaths[id]))])),
    },
    measurement_contract: {
      compile: "Fresh compiler process: source-to-finalized JIT for JOAN; source-to-executable for C, C++, and Rust.",
      inner_runtime: "Dynamic input generation, enum dispatch, bounded checked kernel call, fuel accounting, and checksum; excludes compilation and JSON.",
      observation_digest: "SHA-256 over canonical observation JSON excluding only compile_ns and runtime_ns; all semantic fields remain bound.",
      peak_rss: "Peak resident bytes for the complete fresh process; not generated-code-only memory.",
      process_time: "JOAN and Julia include source compilation; C, C++, and Rust execute prepared artifacts, so this field is not cross-lifecycle comparable.",
    },
    oracle: {
      id: "node-bigint-independent-v0",
      independent_from_measured_implementations: true,
      observations: oracleCases,
      sample_indices: oracleIndices,
      source_sha256: sha256(readFileSync(tools.oracle)),
      verified_cases: oracleCases.length,
    },
    preparation,
    qualification: {
      independent_rerun: false,
      julia_measured: available.includes("julia"),
      output_equivalent: workloadReports.every((item) => item.output_equivalent),
      status: "not-qualified",
      universal_language_superiority_claim: false,
    },
    toolchains: [
      toolEvidence("clang-c", tools.c, ["--version"]),
      toolEvidence("clang-cpp", tools.cpp, ["--version"]),
      toolEvidence("rustc", tools.rust, ["--version", "--verbose"]),
      toolEvidence("julia", tools.julia, ["--version"]),
      toolEvidence("node", process.execPath, ["--version"]),
      toolEvidence("joan", tools.joan, ["node", "self-check"]),
      toolEvidence("joan-native-bench", tools.nativeBench, [sourcePaths["joan-native"], "cost-model", "1", manifest.sampling.seed]),
    ],
    workloads: workloadReports,
  });
  writeFileSync(reportPath, `${JSON.stringify(report)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify(report.qualification)}\n`);
} finally {
  rmSync(work, { force: true, recursive: true });
}
