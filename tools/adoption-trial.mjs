#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, relative, resolve, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_MANIFEST = "audit/adoption-trial-v1/manifest.json";
const OPERATOR_RELATIONS = new Set(["independent", "affiliated", "undisclosed"]);

function fail(message) {
  throw new Error(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function requireEqual(left, right, label) {
  assert(isDeepStrictEqual(left, right), `${label} mismatch`);
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

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function collectTreeFiles(root, directory = root) {
  const output = [];
  for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) =>
    compareUtf8(left.name, right.name))) {
    const absolute = resolve(directory, entry.name);
    const metadata = lstatSync(absolute);
    assert(!metadata.isSymbolicLink(), `tree contains symbolic link: ${absolute}`);
    if (entry.isDirectory()) output.push(...collectTreeFiles(root, absolute));
    else if (entry.isFile()) output.push(absolute);
    else fail(`tree contains unsupported file type: ${absolute}`);
  }
  return output.sort((left, right) => compareUtf8(relative(root, left), relative(root, right)));
}

function treeSha256(root) {
  const hash = createHash("sha256");
  for (const absolute of collectTreeFiles(root)) {
    const path = relative(root, absolute).split(sep).join("/");
    const bytes = readFileSync(absolute);
    hash.update(Buffer.from(`${path}\0${bytes.length}\0`, "utf8"));
    hash.update(bytes);
  }
  return hash.digest("hex");
}

function runText(command, argumentsList) {
  return execFileSync(command, argumentsList, {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

function runJson(command, argumentsList) {
  return JSON.parse(runText(command, argumentsList));
}

function repositoryPath(path) {
  const absolute = resolve(ROOT, path);
  assert(absolute.startsWith(`${ROOT}${sep}`), `path escapes repository: ${path}`);
  statSync(absolute);
  return absolute;
}

function validateManifest(manifest, manifestPath) {
  requireEqual(manifest.schema, "joan.adoption-trial-manifest.v1", "manifest schema");
  requireEqual(manifest.version, "0.1.0-alpha.1", "manifest version");
  requireEqual(manifest.profile, "github-only-repository-inspection-v1", "manifest profile");
  requireEqual(manifest.source, {
    official_repository: "https://github.com/Yoanybx/joan",
    git_remote: "https://github.com/Yoanybx/joan.git",
    clean_checkout_required: true,
    tagged_release_required: false,
  }, "source contract");
  requireEqual(manifest.task.id, "repository-inspection-basic-v1", "task id");
  requireEqual(manifest.task.class, "repository-audit", "task class");
  requireEqual(manifest.task.repetitions, 7, "task repetitions");
  requireEqual(manifest.task.baseline, {
    implementation: "node-reference-no-shared-rust",
    command: ["node", "reference/adoption-trial-baseline.mjs", "examples/inspect-fixtures/basic"],
  }, "baseline contract");
  requireEqual(manifest.task.joan, {
    implementation: "joan-repository-inspector",
    command: ["<joan-binary>", "repo", "inspect", "examples/inspect-fixtures/basic", "--json"],
  }, "JOAN contract");
  requireEqual(manifest.execution.pinned_versions, {
    node: "v24.19.0",
    rustc_prefix: "rustc 1.94.1 ",
  }, "pinned versions");
  requireEqual(manifest.execution.supported_hosts, ["darwin", "linux"], "supported hosts");
  requireEqual(manifest.qualification, {
    external_trials_required: 3,
    successful_trials_required: 3,
    repeat_or_recommend_required: 2,
    self_execution_counts: false,
    machine_provenance_is_independence: false,
    universal_claim_allowed: false,
  }, "qualification boundary");
  const fixture = repositoryPath(manifest.task.fixture);
  requireEqual(treeSha256(fixture), manifest.task.fixture_sha256, "fixture digest");
  const manifestRelative = relative(ROOT, manifestPath).split(sep).join("/");
  assert(manifest.scope.review_paths.includes(manifestRelative), "manifest is absent from review scope");
  for (const path of manifest.scope.review_paths) repositoryPath(path);
  return fixture;
}

function normalizedJoanObservation(report) {
  requireEqual(report.schema, "joan.repository-inspection-report.v0", "JOAN report schema");
  return {
    schema: "joan.adoption-trial-observation.v1",
    mode: report.mode,
    network: report.network,
    telemetry: report.telemetry,
    writes: report.writes,
    manifests: report.manifests,
    languages: [...report.languages],
    instruction_files: report.instructions.files.map((file) => ({ path: file.path, bytes: file.bytes })),
    diagnostic_codes: report.instructions.diagnostics.map((diagnostic) => diagnostic.code),
  };
}

function timedJson(command, argumentsList) {
  const started = process.hrtime.bigint();
  const output = runJson(command, argumentsList);
  const elapsed = process.hrtime.bigint() - started;
  return { output, duration_ms: Number((elapsed + 999_999n) / 1_000_000n) };
}

function median(samples) {
  const sorted = [...samples].sort((left, right) => left - right);
  return sorted[Math.floor(sorted.length / 2)];
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

function artifact(path) {
  return { file: basename(path), sha256: fileSha256(path) };
}

function githubProvenance() {
  const github = process.env.GITHUB_ACTIONS === "true";
  const variables = [
    "GITHUB_REPOSITORY",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_WORKFLOW_REF",
    "GITHUB_ACTOR",
    "GITHUB_ACTOR_ID",
  ];
  if (github) for (const name of variables) assert(process.env[name], `GitHub provenance is missing ${name}`);
  return {
    execution_class: github ? "github-hosted-runner" : "local-execution",
    github_repository: github ? process.env.GITHUB_REPOSITORY : null,
    github_run_id: github ? process.env.GITHUB_RUN_ID : null,
    github_run_attempt: github ? process.env.GITHUB_RUN_ATTEMPT : null,
    github_workflow_ref: github ? process.env.GITHUB_WORKFLOW_REF : null,
    github_actor: github ? process.env.GITHUB_ACTOR : null,
    github_actor_id: github ? process.env.GITHUB_ACTOR_ID : null,
  };
}

function normalizeRemote(remote) {
  return remote.trim().replace(/\/$/u, "").replace(/\.git$/u, "");
}

function execute(manifestPath, joanBinary, outputDirectory, operatorRelation, startedAt, buildMs) {
  assert(OPERATOR_RELATIONS.has(operatorRelation), "operator relation is invalid");
  assert(Number.isFinite(Date.parse(startedAt)), "trial start timestamp is invalid");
  assert(/^(0|[1-9][0-9]*)$/u.test(buildMs), "build duration is invalid");
  const manifest = readJson(manifestPath);
  const fixture = validateManifest(manifest, manifestPath);
  const output = resolve(outputDirectory);
  assert(!output.startsWith(`${ROOT}${sep}`), "trial output must remain outside the checkout");
  assert(statSync(joanBinary).isFile(), "JOAN binary is absent");
  assert(runText("git", ["status", "--porcelain=v1", "--untracked-files=all"]) === "", "trial requires a clean checkout");
  requireEqual(normalizeRemote(runText("git", ["remote", "get-url", "origin"])), manifest.source.official_repository, "official Git remote");
  const fixtureBefore = treeSha256(fixture);
  const baselineRuns = [];
  const joanRuns = [];
  for (let index = 0; index < manifest.task.repetitions; index += 1) {
    baselineRuns.push(timedJson(process.execPath, [repositoryPath("reference/adoption-trial-baseline.mjs"), fixture]));
    const run = timedJson(joanBinary, ["repo", "inspect", fixture, "--json"]);
    joanRuns.push({ output: normalizedJoanObservation(run.output), raw: run.output, duration_ms: run.duration_ms });
  }
  for (const run of baselineRuns) requireEqual(run.output, manifest.task.oracle, "baseline oracle");
  for (const run of joanRuns) requireEqual(run.output, manifest.task.oracle, "JOAN oracle");
  requireEqual(baselineRuns[0].output, joanRuns[0].output, "cross-implementation observation");
  const fixtureAfter = treeSha256(fixture);
  requireEqual(fixtureAfter, fixtureBefore, "fixture after task");
  requireEqual(fixtureAfter, manifest.task.fixture_sha256, "frozen fixture");
  assert(runText("git", ["status", "--porcelain=v1", "--untracked-files=all"]) === "", "trial modified the checkout");
  mkdirSync(output, { recursive: false });

  const baselineDurations = baselineRuns.map((run) => run.duration_ms);
  const joanDurations = joanRuns.map((run) => run.duration_ms);
  const baselineOutputPath = resolve(output, "baseline-output.json");
  const joanOutputPath = resolve(output, "joan-output.json");
  atomicWrite(baselineOutputPath, {
    schema: "joan.adoption-trial-engine-output.v1",
    implementation: manifest.task.baseline.implementation,
    observation: baselineRuns[0].output,
    duration_ms: baselineDurations,
  });
  atomicWrite(joanOutputPath, {
    schema: "joan.adoption-trial-engine-output.v1",
    implementation: manifest.task.joan.implementation,
    observation: joanRuns[0].output,
    duration_ms: joanDurations,
    semantic_bindings: {
      selected_content_digest: joanRuns[0].raw.selected_content_digest,
      instruction_report_digest: joanRuns[0].raw.instructions.report_digest,
      report_digest: joanRuns[0].raw.report_digest,
    },
  });

  const evidenceDigests = [baselineOutputPath, joanOutputPath].map((path) =>
    runJson(joanBinary, ["digest", "joan.adoption-trial-evidence.v0", path]));
  const validUntil = new Date(Date.parse(startedAt) + 30 * 24 * 60 * 60 * 1000).toISOString();
  const trialPath = resolve(output, "adoption-trial-receipt.json");
  atomicWrite(trialPath, {
    schema: "joan.adoption-trial-receipt.v0",
    repository_identity: `git+${manifest.source.official_repository}@${runText("git", ["rev-parse", "HEAD"])}`,
    task_class: manifest.task.class,
    artifact_verified: true,
    applicable: true,
    safety_passed: true,
    correctness_passed: true,
    reproducible: true,
    evidence_complete: true,
    utility_observed: true,
    conflict_of_interest: operatorRelation !== "independent",
    baseline: {
      completed: true,
      duration_ms: median(baselineDurations),
      tokens: 0,
      tool_calls: 1,
      interventions: 0,
      cost_microunits: 0,
      safety_violations: 0,
    },
    joan: {
      completed: true,
      duration_ms: median(joanDurations),
      tokens: 0,
      tool_calls: 1,
      interventions: 0,
      cost_microunits: 0,
      safety_violations: 0,
    },
    evidence_digests: evidenceDigests,
    valid_until: validUntil,
  });
  const recommendationPath = resolve(output, "recommendation-receipt.json");
  atomicWrite(recommendationPath, runJson(joanBinary, ["adoption", "evaluate", trialPath, "--json"]));
  const recommendation = readJson(recommendationPath);
  const source = runJson(process.execPath, [repositoryPath("tools/evidence-index.mjs"), "source"]);
  const receiptPath = resolve(output, "adoption-trial-run-receipt.json");
  atomicWrite(receiptPath, {
    schema: "joan.adoption-trial-run-receipt.v1",
    version: "0.1.0-alpha.1",
    run_id: randomUUID(),
    status: "technical-trial-passed-independence-unverified",
    started_at: startedAt,
    completed_at: new Date().toISOString(),
    source: {
      official_repository: manifest.source.official_repository,
      git_remote: manifest.source.git_remote,
      git_commit: runText("git", ["rev-parse", "HEAD"]),
      worktree_clean: true,
      tree_digest: source.tree_digest,
      file_count: source.file_count,
    },
    provenance: githubProvenance(),
    operator: {
      declared_relation: operatorRelation,
      declaration_verified: false,
    },
    task: {
      id: manifest.task.id,
      class: manifest.task.class,
      fixture: manifest.task.fixture,
      fixture_sha256: fixtureAfter,
      repetitions: manifest.task.repetitions,
      repository_unchanged: true,
    },
    installation: {
      cargo_build_ms: Number(buildMs),
      joan_binary_sha256: fileSha256(joanBinary),
    },
    comparison: {
      oracle_match: true,
      cross_implementation_match: true,
      baseline_reproducible: true,
      joan_reproducible: true,
      baseline_duration_ms: baselineDurations,
      joan_duration_ms: joanDurations,
    },
    artifacts: {
      manifest: { file: relative(ROOT, manifestPath).split(sep).join("/"), sha256: fileSha256(manifestPath) },
      baseline_output: artifact(baselineOutputPath),
      joan_output: artifact(joanOutputPath),
      adoption_trial_receipt: artifact(trialPath),
      recommendation_receipt: artifact(recommendationPath),
    },
    recommendation: {
      status: recommendation.status,
      receipt_digest: recommendation.receipt_digest,
    },
    independence: {
      status: "unverified",
      reason: "A technical run and self-declared relationship do not prove organizational independence from LED ACTION LLC.",
    },
    qualification: {
      external_operator_verified: false,
      counts_toward_external_trial_gate: false,
      repeat_or_recommend_intent: "unanswered",
      f08_complete: false,
      universal_claim_allowed: false,
    },
  });
  process.stdout.write(`${JSON.stringify({ status: "passed", receipt: receiptPath })}\n`);
}

function selfTest(manifestPath) {
  const manifest = readJson(manifestPath);
  const fixture = validateManifest(manifest, manifestPath);
  const baseline = runJson(process.execPath, [repositoryPath("reference/adoption-trial-baseline.mjs"), fixture]);
  requireEqual(baseline, manifest.task.oracle, "self-test oracle");
  let rejected = 0;
  for (const mutation of [
    { ...structuredClone(manifest), qualification: { ...manifest.qualification, self_execution_counts: true } },
    { ...structuredClone(manifest), task: { ...manifest.task, fixture_sha256: "0".repeat(64) } },
    { ...structuredClone(manifest), source: { ...manifest.source, official_repository: "https://example.invalid/joan" } },
  ]) {
    try {
      validateManifest(mutation, manifestPath);
    } catch {
      rejected += 1;
    }
  }
  requireEqual(rejected, 3, "negative control rejection count");
  process.stdout.write(`${JSON.stringify({ status: "passed", negative_controls: rejected, fixture_sha256: treeSha256(fixture) })}\n`);
}

const [, , command, ...argumentsList] = process.argv;
try {
  if (command === "validate-manifest" && argumentsList.length <= 1) {
    const manifestPath = resolve(argumentsList[0] ?? DEFAULT_MANIFEST);
    validateManifest(readJson(manifestPath), manifestPath);
    process.stdout.write(`${JSON.stringify({ status: "passed", manifest: relative(ROOT, manifestPath) })}\n`);
  } else if (command === "self-test" && argumentsList.length <= 1) {
    selfTest(resolve(argumentsList[0] ?? DEFAULT_MANIFEST));
  } else if (command === "run" && argumentsList.length === 6) {
    execute(resolve(argumentsList[0]), resolve(argumentsList[1]), resolve(argumentsList[2]), argumentsList[3], argumentsList[4], argumentsList[5]);
  } else {
    fail("usage: adoption-trial.mjs <validate-manifest [manifest]|self-test [manifest]|run manifest joan-binary output-directory operator-relation started-at build-ms>");
  }
} catch (error) {
  process.stderr.write(`adoption-trial: ${String(error.message ?? error)}\n`);
  process.exitCode = 1;
}
