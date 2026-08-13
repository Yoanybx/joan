#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, dirname, relative, resolve, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_MANIFEST = "audit/independent-rerun-v0/manifest.json";
const REQUIRED_IMPLEMENTATIONS = ["joan-native", "c", "cpp", "rust"];

function fail(message) {
  throw new Error(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function fileSha256(path) {
  return sha256(readFileSync(path));
}

function equal(left, right) {
  return isDeepStrictEqual(left, right);
}

function requireEqual(left, right, label) {
  assert(equal(left, right), `${label} mismatch`);
}

function runText(command, args) {
  return execFileSync(command, args, {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

function repositoryPath(path) {
  const absolute = resolve(ROOT, path);
  assert(absolute.startsWith(`${ROOT}${sep}`), `path escapes repository: ${path}`);
  statSync(absolute);
  return absolute;
}

function validateManifest(manifest, manifestPath) {
  requireEqual(manifest.schema, "joan.independent-rerun-manifest.v0", "manifest schema");
  requireEqual(manifest.version, "0.1.0-alpha.1", "manifest version");
  requireEqual(manifest.profile, "native-backend-independent-rerun-v0", "manifest profile");
  requireEqual(manifest.execution.required_implementations, REQUIRED_IMPLEMENTATIONS, "required implementations");
  requireEqual(manifest.execution.supported_hosts, ["darwin", "linux"], "supported hosts");
  requireEqual(manifest.execution.pinned_versions, {
    node: "v24.19.0",
    rustc_prefix: "rustc 1.94.1 ",
    cargo_audit: "cargo-audit 0.22.2",
    cargo_deny: "cargo-deny 0.20.2",
  }, "pinned tool versions");
  requireEqual(manifest.qualification.external_operator_required, true, "external operator requirement");
  requireEqual(manifest.qualification.machine_provenance_is_independence, false, "provenance boundary");
  requireEqual(manifest.qualification.universal_superiority_claim_allowed, false, "claim boundary");
  const referencePath = repositoryPath(manifest.reference.path);
  requireEqual(fileSha256(referencePath), manifest.reference.sha256, "reference report digest");
  assert(manifest.scope.review_paths.includes(relative(ROOT, manifestPath).split(sep).join("/")), "manifest is absent from its review scope");
  for (const path of manifest.scope.review_paths) repositoryPath(path);
  return referencePath;
}

function validateReport(report, label) {
  requireEqual(report.schema, "joan.native-backend-benchmark-report.v0", `${label} schema`);
  requireEqual(report.status, "local-benchmark-not-qualified", `${label} status`);
  requireEqual(report.mode, "recorded", `${label} mode`);
  requireEqual(report.samples, 101, `${label} samples`);
  requireEqual(report.iterations, 1_000_000, `${label} iterations`);
  requireEqual(report.rss_samples, 11, `${label} RSS samples`);
  requireEqual(report.qualification.independent_rerun, false, `${label} raw independence flag`);
  requireEqual(report.qualification.output_equivalent, true, `${label} output equivalence`);
  requireEqual(report.qualification.status, "not-qualified", `${label} qualification`);
  requireEqual(report.qualification.universal_language_superiority_claim, false, `${label} universal claim`);
  requireEqual(report.workloads.length, 5, `${label} workload count`);
  for (const id of REQUIRED_IMPLEMENTATIONS) {
    assert(report.available_implementations.includes(id), `${label} lacks required implementation ${id}`);
  }
}

function compareReports(reference, rerun) {
  validateReport(reference, "reference report");
  validateReport(rerun, "rerun report");
  for (const key of ["schema", "status", "mode", "samples", "iterations", "rss_samples", "measurement_contract"]) {
    requireEqual(rerun[key], reference[key], `report ${key}`);
  }
  for (const key of ["manifest_sha256", "oracle_sha256", "runner_sha256", "sources"]) {
    requireEqual(rerun.identities[key], reference.identities[key], `identity ${key}`);
  }
  requireEqual(rerun.oracle.id, reference.oracle.id, "oracle identifier");
  requireEqual(rerun.oracle.source_sha256, reference.oracle.source_sha256, "oracle source");
  requireEqual(rerun.oracle.observations, reference.oracle.observations, "oracle observations");

  const referenceWorkloads = new Map(reference.workloads.map((workload) => [workload.id, workload]));
  for (const rerunWorkload of rerun.workloads) {
    const referenceWorkload = referenceWorkloads.get(rerunWorkload.id);
    assert(referenceWorkload !== undefined, `unexpected workload ${rerunWorkload.id}`);
    requireEqual(rerunWorkload.description, referenceWorkload.description, `${rerunWorkload.id} description`);
    requireEqual(rerunWorkload.output_equivalent, true, `${rerunWorkload.id} output equivalence`);
    for (const implementation of REQUIRED_IMPLEMENTATIONS) {
      const expected = referenceWorkload.implementations[implementation];
      const observed = rerunWorkload.implementations[implementation];
      assert(expected !== undefined && observed !== undefined, `${rerunWorkload.id}/${implementation} is absent`);
      requireEqual(observed.checksum, expected.checksum, `${rerunWorkload.id}/${implementation} checksum`);
      requireEqual(
        observed.observation_sha256,
        expected.observation_sha256,
        `${rerunWorkload.id}/${implementation} observations`,
      );
    }
  }
  return {
    reference_contract_match: true,
    source_bindings_match: true,
    oracle_observations_match: true,
    implementation_observations_match: true,
    output_equivalent: true,
    required_implementations: REQUIRED_IMPLEMENTATIONS,
    workload_count: 5,
  };
}

function artifact(file, path) {
  return { file, sha256: fileSha256(path) };
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

function resolvePaths(paths) {
  return paths.map((path) => resolve(path));
}

function finalize(paths, startedAt) {
  const [manifestPath, referencePath, rerunPath, verificationPath, nativeAbiPath, outputPath] = resolvePaths(paths);
  for (const path of [rerunPath, verificationPath, nativeAbiPath, outputPath]) {
    assert(!path.startsWith(`${ROOT}${sep}`), "generated rerun artifacts must be written outside the source tree");
  }
  const manifest = readJson(manifestPath);
  const expectedReferencePath = validateManifest(manifest, manifestPath);
  requireEqual(referencePath, expectedReferencePath, "reference report path");
  const reference = readJson(referencePath);
  const rerun = readJson(rerunPath);
  const verification = readJson(verificationPath);
  const nativeAbi = readJson(nativeAbiPath);
  const comparison = compareReports(reference, rerun);

  requireEqual(verification.schema, "joan.verification-run-receipt.v1", "verification receipt schema");
  requireEqual(verification.status, "passed", "verification receipt status");
  requireEqual(verification.source.tree_digest, rerun.identities.source_tree, "verification source binding");
  requireEqual(nativeAbi.schema, "joan.native-abi-report.v1", "native ABI schema");
  requireEqual(nativeAbi.status, "passed", "native ABI status");
  requireEqual(nativeAbi.source.tree_digest, rerun.identities.source_tree, "native ABI source binding");
  assert(runText("git", ["status", "--porcelain=v1", "--untracked-files=all"]) === "", "worktree changed during rerun");
  assert(Number.isFinite(Date.parse(startedAt)), "rerun start timestamp is invalid");

  const github = process.env.GITHUB_ACTIONS === "true";
  if (github) {
    for (const name of [
      "GITHUB_REPOSITORY",
      "GITHUB_RUN_ID",
      "GITHUB_RUN_ATTEMPT",
      "GITHUB_WORKFLOW_REF",
      "GITHUB_ACTOR",
      "GITHUB_ACTOR_ID",
    ]) assert(process.env[name], `GitHub provenance is missing ${name}`);
  }
  const receipt = {
    schema: "joan.independent-rerun-receipt.v0",
    version: "0.1.0-alpha.1",
    run_id: randomUUID(),
    status: "technical-rerun-passed-independence-unverified",
    started_at: startedAt,
    completed_at: new Date().toISOString(),
    source: {
      git_commit: runText("git", ["rev-parse", "HEAD"]),
      worktree_clean: true,
      tree_digest: verification.source.tree_digest,
      file_count: verification.source.file_count,
    },
    provenance: {
      execution_class: github ? "github-hosted-runner" : "local-simulation",
      github_repository: github ? (process.env.GITHUB_REPOSITORY ?? null) : null,
      github_run_id: github ? (process.env.GITHUB_RUN_ID ?? null) : null,
      github_run_attempt: github ? (process.env.GITHUB_RUN_ATTEMPT ?? null) : null,
      github_workflow_ref: github ? (process.env.GITHUB_WORKFLOW_REF ?? null) : null,
      github_actor: github ? (process.env.GITHUB_ACTOR ?? null) : null,
      github_actor_id: github ? (process.env.GITHUB_ACTOR_ID ?? null) : null,
    },
    independence: {
      status: "unverified",
      external_operator_attestation: false,
      reason: "Machine provenance cannot establish that the operator is organizationally independent from LED ACTION LLC.",
    },
    artifacts: {
      manifest: artifact(relative(ROOT, manifestPath).split(sep).join("/"), manifestPath),
      reference_report: artifact(manifest.reference.path, referencePath),
      rerun_report: artifact(basename(rerunPath), rerunPath),
      verification_receipt: artifact(basename(verificationPath), verificationPath),
      native_abi_report: artifact(basename(nativeAbiPath), nativeAbiPath),
    },
    comparison,
    qualification: {
      benchmark_claim_qualified: false,
      external_independence_verified: false,
      universal_language_superiority_claim: false,
    },
  };
  atomicWrite(outputPath, receipt);
  process.stdout.write(`${JSON.stringify({ status: receipt.status, receipt: outputPath })}\n`);
}

function selfTest(manifestPath, referencePath) {
  const manifest = readJson(manifestPath);
  validateManifest(manifest, manifestPath);
  const pathResolutionInputs = ["manifest", "reference", "rerun", "verification", "native-abi", "receipt"];
  const resolvedPaths = resolvePaths(pathResolutionInputs);
  requireEqual(resolvedPaths.length, pathResolutionInputs.length, "path resolution count");
  for (let index = 0; index < pathResolutionInputs.length; index += 1) {
    requireEqual(resolvedPaths[index], resolve(pathResolutionInputs[index]), `path resolution ${index}`);
  }
  const reference = readJson(referencePath);
  const first = compareReports(reference, structuredClone(reference));
  const second = compareReports(reference, structuredClone(reference));
  requireEqual(first, second, "deterministic comparison");

  const observationMutation = structuredClone(reference);
  const observations = observationMutation.workloads[0].implementations["joan-native"].observation_sha256;
  observations[0] = `${observations[0][0] === "0" ? "1" : "0"}${observations[0].slice(1)}`;
  let rejected = 0;
  for (const mutation of [
    observationMutation,
    { ...structuredClone(reference), status: "qualified" },
    {
      ...structuredClone(reference),
      identities: { ...structuredClone(reference.identities), oracle_sha256: "0".repeat(64) },
    },
  ]) {
    try {
      compareReports(reference, mutation);
    } catch {
      rejected += 1;
    }
  }
  requireEqual(rejected, 3, "negative control rejection count");
  process.stdout.write(`${JSON.stringify({
    status: "passed",
    path_resolution_cases: resolvedPaths.length,
    negative_controls: rejected,
  })}\n`);
}

const [, , command, ...argumentsList] = process.argv;
try {
  if (command === "validate-manifest" && argumentsList.length <= 1) {
    const manifestPath = resolve(argumentsList[0] ?? DEFAULT_MANIFEST);
    validateManifest(readJson(manifestPath), manifestPath);
    process.stdout.write(`${JSON.stringify({ status: "passed", manifest: relative(ROOT, manifestPath) })}\n`);
  } else if (command === "self-test" && argumentsList.length <= 2) {
    const manifestPath = resolve(argumentsList[0] ?? DEFAULT_MANIFEST);
    const manifest = readJson(manifestPath);
    const referencePath = resolve(argumentsList[1] ?? manifest.reference.path);
    selfTest(manifestPath, referencePath);
  } else if (command === "finalize" && argumentsList.length === 7) {
    finalize(argumentsList.slice(0, 6), argumentsList[6]);
  } else {
    fail("usage: independent-rerun.mjs <validate-manifest [manifest]|self-test [manifest reference]|finalize manifest reference rerun verification native-abi output started-at>");
  }
} catch (error) {
  process.stderr.write(`independent-rerun: ${String(error.message ?? error)}\n`);
  process.exitCode = 1;
}
