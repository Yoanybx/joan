#!/usr/bin/env node

import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  cpSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const VERSION = "0.1.0-alpha.1";
const TOOL_VERSION = "cargo-cyclonedx-cyclonedx 0.5.9";
const SPEC_VERSION = "1.5";
const MAX_OUTPUT_BYTES = 128 * 1024 * 1024;
const EXCLUDED_ROOTS = new Set([".git", "target"]);

function fail(message) {
  throw new Error(message);
}

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function sortObject(value) {
  if (Array.isArray(value)) return value.map(sortObject);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort(compareUtf8)
      .map((key) => [key, sortObject(value[key])]),
  );
}

export function canonicalJson(value) {
  return `${JSON.stringify(sortObject(value), null, 2)}\n`;
}

function runText(command, args, cwd = ROOT, env = process.env) {
  return execFileSync(command, args, {
    cwd,
    env,
    encoding: "utf8",
    maxBuffer: MAX_OUTPUT_BYTES,
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

function executablePath(command) {
  return realpathSync(runText("/usr/bin/which", [command]));
}

function relativePath(root, path) {
  return relative(root, path).split(sep).join("/");
}

function isExcluded(path) {
  if (path === ".joan/evidence" || path.startsWith(".joan/evidence/")) return true;
  const segments = path.split("/");
  return (
    EXCLUDED_ROOTS.has(segments[0]) ||
    segments.some((segment) => segment === ".DS_Store" || segment.startsWith("._"))
  );
}

function copySource(source, destination, directory = source) {
  const entries = readdirSync(directory, { withFileTypes: true }).sort((left, right) =>
    compareUtf8(left.name, right.name),
  );
  for (const entry of entries) {
    const absolute = join(directory, entry.name);
    const path = relativePath(source, absolute);
    if (isExcluded(path)) continue;
    if (entry.isSymbolicLink() || lstatSync(absolute).isSymbolicLink()) {
      fail(`SBOM source contains unsupported symbolic link: ${path}`);
    }
    const output = join(destination, path);
    if (entry.isDirectory()) {
      mkdirSync(output, { recursive: true });
      copySource(source, destination, absolute);
    } else if (entry.isFile()) {
      mkdirSync(dirname(output), { recursive: true });
      copyFileSync(absolute, output);
    } else {
      fail(`SBOM source contains unsupported file type: ${path}`);
    }
  }
}

function parsePurlName(purl) {
  const match = /^pkg:cargo\/([^@?]+)@([^?]+)(?:\?.*)?$/u.exec(purl ?? "");
  if (!match) fail(`local component has invalid Cargo purl: ${String(purl)}`);
  return { name: decodeURIComponent(match[1]), version: match[2] };
}

function allComponents(sbom) {
  return [sbom.metadata?.component, ...(sbom.components ?? [])].filter(Boolean);
}

function componentTree(sbom) {
  const components = [];
  function visit(component, parentCoordinate = null) {
    if (!component) return;
    components.push({ component, parentCoordinate });
    const coordinate = component.purl ? parsePurlName(component.purl) : parentCoordinate;
    for (const child of component.components ?? []) visit(child, coordinate);
  }
  visit(sbom.metadata?.component);
  for (const component of sbom.components ?? []) visit(component);
  return components;
}

export function normalizeSbom(input) {
  const sbom = structuredClone(input);
  const replacements = new Map();
  for (const { component, parentCoordinate } of componentTree(sbom)) {
    if (typeof component["bom-ref"] === "string" && component["bom-ref"].startsWith("path+file://")) {
      const coordinate = component.purl ? parsePurlName(component.purl) : parentCoordinate;
      if (!coordinate) fail("local target component has no Cargo coordinate");
      const purl = `pkg:cargo/${coordinate.name}@${coordinate.version}`;
      const nestedTarget = component["bom-ref"].includes("-target-");
      const canonicalRef = nestedTarget
        ? `urn:joan:cargo-target:${encodeURIComponent(coordinate.name)}:${encodeURIComponent(component.name)}`
        : purl;
      replacements.set(component["bom-ref"], canonicalRef);
      component["bom-ref"] = canonicalRef;
      component.purl = purl;
    }
  }

  function replaceReferences(value) {
    if (Array.isArray(value)) return value.map(replaceReferences);
    if (value !== null && typeof value === "object") {
      for (const [key, child] of Object.entries(value)) value[key] = replaceReferences(child);
      return value;
    }
    if (typeof value === "string" && replacements.has(value)) return replacements.get(value);
    return value;
  }
  replaceReferences(sbom);

  if (Array.isArray(sbom.components)) {
    sbom.components.sort((left, right) => compareUtf8(left["bom-ref"], right["bom-ref"]));
  }
  if (Array.isArray(sbom.dependencies)) {
    for (const dependency of sbom.dependencies) {
      if (Array.isArray(dependency.dependsOn)) dependency.dependsOn.sort(compareUtf8);
    }
    sbom.dependencies.sort((left, right) => compareUtf8(left.ref, right.ref));
  }
  return sbom;
}

function walkStrings(value, visit) {
  if (typeof value === "string") {
    visit(value);
  } else if (Array.isArray(value)) {
    for (const item of value) walkStrings(item, visit);
  } else if (value !== null && typeof value === "object") {
    for (const item of Object.values(value)) walkStrings(item, visit);
  }
}

export function validateSbomDocument(sbom, expectedTimestamp) {
  if (sbom.bomFormat !== "CycloneDX" || sbom.specVersion !== SPEC_VERSION || sbom.version !== 1) {
    fail("SBOM format/version contract mismatch");
  }
  if (Object.hasOwn(sbom, "serialNumber")) fail("reproducible SBOM must omit serialNumber");
  if (sbom.metadata?.timestamp !== expectedTimestamp) fail("SBOM timestamp is not source-derived");
  if (
    !Array.isArray(sbom.metadata?.tools) ||
    !sbom.metadata.tools.some(
      (tool) => tool.name === "cargo-cyclonedx" && tool.version === "0.5.9",
    )
  ) {
    fail("SBOM generator identity is missing");
  }
  const components = allComponents(sbom);
  if (components.length < 1 || !Array.isArray(sbom.dependencies) || sbom.dependencies.length < 1) {
    fail("SBOM component/dependency graph is empty");
  }
  const refs = new Set(components.map((component) => component["bom-ref"]));
  if (refs.size !== components.length || refs.has(undefined)) fail("SBOM component refs are invalid");
  const dependencyRefs = new Set(sbom.dependencies.map((dependency) => dependency.ref));
  for (const ref of refs) {
    if (!dependencyRefs.has(ref)) fail(`SBOM dependency graph omits component: ${ref}`);
  }
  for (const dependency of sbom.dependencies) {
    if (!refs.has(dependency.ref)) fail(`SBOM dependency ref is unknown: ${dependency.ref}`);
    for (const child of dependency.dependsOn ?? []) {
      if (!refs.has(child)) fail(`SBOM dependency edge points to unknown component: ${child}`);
    }
  }
  walkStrings(sbom, (value) => {
    if (
      value.includes("/Users/") ||
      value.includes("/Volumes/") ||
      value.includes("path+file://") ||
      value.includes("file://")
    ) {
      fail(`SBOM leaks a local path: ${value}`);
    }
  });
  return {
    componentCount: components.length,
    dependencyCount: sbom.dependencies.length,
  };
}

function expectedTimestamp(epoch) {
  return `${new Date(epoch * 1000).toISOString().replace(".000Z", ".000000000Z")}`;
}

function atomicWrite(path, bytes) {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = `${path}.tmp-${process.pid}`;
  writeFileSync(temporary, bytes, { mode: 0o644 });
  renameSync(temporary, path);
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function artifact(path, relativeName, sbom) {
  const bytes = readFileSync(path);
  const summary = validateSbomDocument(sbom, sbom.metadata.timestamp);
  return {
    path: relativeName,
    sha256: sha256(bytes),
    bytes: bytes.length,
    component_count: summary.componentCount,
    dependency_count: summary.dependencyCount,
  };
}

function cargoMetadata() {
  return JSON.parse(runText("cargo", ["metadata", "--offline", "--format-version", "1"]));
}

function sourceIdentity() {
  return JSON.parse(runText(process.execPath, ["tools/evidence-index.mjs", "source"]));
}

function generateRaw(projection, mode, target, tool, epoch) {
  const args = [
    "cyclonedx",
    "--manifest-path",
    "Cargo.toml",
    "--format",
    "json",
    "--describe",
    mode,
    "--all-features",
    "--target",
    target,
    "--spec-version",
    SPEC_VERSION,
    "--quiet",
  ];
  const result = spawnSync(tool, args, {
    cwd: projection,
    env: {
      ...process.env,
      CARGO_NET_OFFLINE: "true",
      SOURCE_DATE_EPOCH: String(epoch),
    },
    encoding: "utf8",
    maxBuffer: MAX_OUTPUT_BYTES,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.status !== 0 || result.signal !== null || result.error !== undefined) {
    fail(`cargo-cyclonedx ${mode} generation failed: ${result.stderr || result.error}`);
  }
}

function collectNamedFiles(root, suffix) {
  const files = [];
  function visit(directory) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const absolute = join(directory, entry.name);
      if (entry.isDirectory()) visit(absolute);
      else if (entry.isFile() && entry.name.endsWith(suffix)) files.push(absolute);
    }
  }
  visit(root);
  return files.sort((left, right) => compareUtf8(relativePath(root, left), relativePath(root, right)));
}

function collectArtifactFiles(root) {
  const files = [];
  function visit(directory) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const absolute = join(directory, entry.name);
      if (entry.isDirectory()) {
        visit(absolute);
      } else if (entry.isFile()) {
        files.push(absolute);
      } else {
        fail(`SBOM artifact set contains unsupported file type: ${relativePath(root, absolute)}`);
      }
    }
  }
  visit(root);
  return files.sort((left, right) => compareUtf8(relativePath(root, left), relativePath(root, right)));
}

function normalizeToFile(input, output, timestamp) {
  const normalized = normalizeSbom(readJson(input));
  validateSbomDocument(normalized, timestamp);
  atomicWrite(output, canonicalJson(normalized));
  return normalized;
}

function buildOnce(stage, target, context) {
  const workspaceProjection = join(stage, "workspace-source");
  const runtimeProjection = join(stage, "runtime-source");
  copySource(ROOT, workspaceProjection);
  copySource(ROOT, runtimeProjection);
  const output = join(stage, "output");
  const workspaceOutput = join(output, "workspace");
  mkdirSync(workspaceOutput, { recursive: true });

  generateRaw(workspaceProjection, "crate", "all", context.tool, context.epoch);
  const rawWorkspace = collectNamedFiles(join(workspaceProjection, "crates"), ".cdx.json");
  const crateFiles = rawWorkspace.filter((path) => !basename(path).includes("_bin"));
  if (crateFiles.length !== context.workspacePackages.length) {
    fail(`workspace SBOM count mismatch: ${crateFiles.length}`);
  }
  const packages = [];
  for (const packageInfo of context.workspacePackages) {
    const input = crateFiles.find((path) => basename(path) === `${packageInfo.name}.cdx.json`);
    if (!input) fail(`workspace SBOM missing package: ${packageInfo.name}`);
    const relativeName = `workspace/${packageInfo.name}.cdx.json`;
    const destination = join(output, relativeName);
    const sbom = normalizeToFile(input, destination, context.timestamp);
    packages.push({
      name: packageInfo.name,
      version: packageInfo.version,
      ...artifact(destination, relativeName, sbom),
    });
  }
  packages.sort((left, right) => compareUtf8(left.name, right.name));
  const workspaceIndex = {
    schema: "joan.sbom-workspace-index.v0",
    version: VERSION,
    format: "CycloneDX JSON",
    spec_version: SPEC_VERSION,
    packages,
  };
  const workspaceIndexPath = join(output, "workspace-index.json");
  atomicWrite(workspaceIndexPath, canonicalJson(workspaceIndex));

  generateRaw(runtimeProjection, "binaries", target, context.tool, context.epoch);
  const runtimeInput = join(runtimeProjection, "crates/joan-node/joan_bin.cdx.json");
  if (!statSync(runtimeInput).isFile()) fail("joan-node runtime SBOM was not generated");
  const runtimePath = join(output, "release-runtime.cdx.json");
  const runtimeSbom = normalizeToFile(runtimeInput, runtimePath, context.timestamp);
  const executorRuntimeInput = join(
    runtimeProjection,
    "crates/joan-executor/joan-executor_bin.cdx.json",
  );
  if (!statSync(executorRuntimeInput).isFile()) fail("joan-executor runtime SBOM was not generated");
  const executorRuntimePath = join(output, "release-executor-runtime.cdx.json");
  const executorRuntimeSbom = normalizeToFile(
    executorRuntimeInput,
    executorRuntimePath,
    context.timestamp,
  );

  const receipt = {
    schema: "joan.sbom-evidence.v0",
    version: VERSION,
    status: "passed",
    source: context.source,
    source_commit: context.commit,
    source_date_epoch: context.epoch,
    cargo_lock_sha256: context.lockSha256,
    generator: {
      name: "cargo-cyclonedx",
      version: "0.5.9",
      executable_sha256: context.toolSha256,
    },
    target,
    runtime: artifact(runtimePath, "release-runtime.cdx.json", runtimeSbom),
    executor_runtime: artifact(
      executorRuntimePath,
      "release-executor-runtime.cdx.json",
      executorRuntimeSbom,
    ),
    workspace: {
      index: {
        path: "workspace-index.json",
        sha256: sha256(readFileSync(workspaceIndexPath)),
        bytes: statSync(workspaceIndexPath).size,
        component_count: packages.length,
        dependency_count: packages.reduce((sum, item) => sum + item.dependency_count, 0),
      },
      package_count: packages.length,
      external_dependency_count: context.externalCount,
    },
    reproducibility: {
      runs: 2,
      byte_identical: true,
      random_serial_omitted: true,
      local_paths_absent: true,
    },
  };
  atomicWrite(join(output, "receipt.json"), canonicalJson(receipt));
  return output;
}

function directoryManifest(root) {
  return collectArtifactFiles(root).map((path) => ({
    path: relativePath(root, path),
    sha256: sha256(readFileSync(path)),
  }));
}

function compareOutputs(left, right) {
  const leftManifest = directoryManifest(left);
  const rightManifest = directoryManifest(right);
  if (JSON.stringify(leftManifest) !== JSON.stringify(rightManifest)) {
    fail("SBOM generation is not byte-reproducible");
  }
}

function validateIndex(root, index) {
  if (
    index.schema !== "joan.sbom-workspace-index.v0" ||
    index.version !== VERSION ||
    index.format !== "CycloneDX JSON" ||
    index.spec_version !== SPEC_VERSION ||
    !Array.isArray(index.packages) ||
    index.packages.length < 1
  ) {
    fail("workspace SBOM index contract mismatch");
  }
  const names = new Set();
  for (const item of index.packages) {
    if (names.has(item.name)) fail(`duplicate workspace SBOM package: ${item.name}`);
    names.add(item.name);
    const path = join(root, item.path);
    if (!statSync(path).isFile()) fail(`workspace SBOM file is missing: ${item.path}`);
    const bytes = readFileSync(path);
    if (sha256(bytes) !== item.sha256) fail(`workspace SBOM digest mismatch: ${item.path}`);
    const summary = validateSbomDocument(readJson(path), readJson(path).metadata.timestamp);
    if (
      summary.componentCount !== item.component_count ||
      summary.dependencyCount !== item.dependency_count
    ) {
      fail(`workspace SBOM count mismatch: ${item.path}`);
    }
  }
}

export function verifyArtifactDirectory(root) {
  const receipt = readJson(join(root, "receipt.json"));
  const index = readJson(join(root, "workspace-index.json"));
  if (
    receipt.schema !== "joan.sbom-evidence.v0" ||
    receipt.version !== VERSION ||
    receipt.status !== "passed" ||
    receipt.generator?.name !== "cargo-cyclonedx" ||
    receipt.generator?.version !== "0.5.9" ||
    receipt.reproducibility?.runs !== 2 ||
    receipt.reproducibility?.byte_identical !== true ||
    receipt.reproducibility?.random_serial_omitted !== true ||
    receipt.reproducibility?.local_paths_absent !== true
  ) {
    fail("SBOM receipt contract mismatch");
  }
  if (receipt.cargo_lock_sha256 !== sha256(readFileSync(join(ROOT, "Cargo.lock")))) {
    fail("SBOM receipt Cargo.lock binding mismatch");
  }
  const source = sourceIdentity();
  if (canonicalJson(receipt.source) !== canonicalJson(source)) {
    fail("SBOM receipt source binding mismatch");
  }
  const expectedCommit = runText("git", ["rev-parse", "HEAD"]);
  if (receipt.source_commit !== expectedCommit) fail("SBOM receipt commit binding mismatch");
  for (const [name, runtime] of [
    ["runtime", receipt.runtime],
    ["executor runtime", receipt.executor_runtime],
  ]) {
    if (!runtime || typeof runtime.path !== "string") fail(`${name} SBOM receipt is absent`);
    const runtimePath = join(root, runtime.path);
    const runtimeBytes = readFileSync(runtimePath);
    if (sha256(runtimeBytes) !== runtime.sha256 || runtimeBytes.length !== runtime.bytes) {
      fail(`${name} SBOM artifact binding mismatch`);
    }
    const runtimeSummary = validateSbomDocument(
      JSON.parse(runtimeBytes.toString("utf8")),
      expectedTimestamp(receipt.source_date_epoch),
    );
    if (
      runtimeSummary.componentCount !== runtime.component_count ||
      runtimeSummary.dependencyCount !== runtime.dependency_count
    ) {
      fail(`${name} SBOM graph count mismatch`);
    }
  }
  const indexPath = join(root, receipt.workspace.index.path);
  const indexBytes = readFileSync(indexPath);
  if (
    sha256(indexBytes) !== receipt.workspace.index.sha256 ||
    indexBytes.length !== receipt.workspace.index.bytes
  ) {
    fail("workspace SBOM index binding mismatch");
  }
  validateIndex(root, index);
  if (index.packages.length !== receipt.workspace.package_count) {
    fail("workspace SBOM package count mismatch");
  }
  const expectedFiles = new Set([
    "receipt.json",
    "release-runtime.cdx.json",
    "release-executor-runtime.cdx.json",
    "workspace-index.json",
    ...index.packages.map((item) => item.path),
  ]);
  const actualFiles = new Set(directoryManifest(root).map((item) => item.path));
  if (JSON.stringify([...expectedFiles].sort()) !== JSON.stringify([...actualFiles].sort())) {
    fail("SBOM artifact set contains missing or unexpected files");
  }
  return receipt;
}

function installOutput(source, destination) {
  if (statSync(destination, { throwIfNoEntry: false })) fail("SBOM output directory already exists");
  mkdirSync(dirname(destination), { recursive: true });
  renameSync(source, destination);
}

function negativeControls(root) {
  const temporary = mkdtempSync(join(tmpdir(), "joan-sbom-negative."));
  let rejected = 0;
  const mutations = [
    (directory) => {
      const receiptPath = join(directory, "receipt.json");
      const receipt = readJson(receiptPath);
      receipt.cargo_lock_sha256 = "0".repeat(64);
      atomicWrite(receiptPath, canonicalJson(receipt));
    },
    (directory) => {
      const receiptPath = join(directory, "receipt.json");
      const receipt = readJson(receiptPath);
      receipt.runtime.sha256 = "0".repeat(64);
      atomicWrite(receiptPath, canonicalJson(receipt));
    },
    (directory) => {
      const runtimePath = join(directory, "release-runtime.cdx.json");
      const receiptPath = join(directory, "receipt.json");
      const runtime = readJson(runtimePath);
      runtime.metadata.component.description = "leak /Users/private/joan";
      atomicWrite(runtimePath, canonicalJson(runtime));
      const bytes = readFileSync(runtimePath);
      const receipt = readJson(receiptPath);
      receipt.runtime.sha256 = sha256(bytes);
      receipt.runtime.bytes = bytes.length;
      atomicWrite(receiptPath, canonicalJson(receipt));
    },
    (directory) => {
      const indexPath = join(directory, "workspace-index.json");
      const receiptPath = join(directory, "receipt.json");
      const index = readJson(indexPath);
      index.packages.pop();
      atomicWrite(indexPath, canonicalJson(index));
      const bytes = readFileSync(indexPath);
      const receipt = readJson(receiptPath);
      receipt.workspace.index.sha256 = sha256(bytes);
      receipt.workspace.index.bytes = bytes.length;
      receipt.workspace.index.component_count = index.packages.length;
      receipt.workspace.index.dependency_count = index.packages.reduce(
        (sum, item) => sum + item.dependency_count,
        0,
      );
      receipt.workspace.package_count = index.packages.length;
      atomicWrite(receiptPath, canonicalJson(receipt));
    },
    (directory) => {
      atomicWrite(join(directory, "unexpected.txt"), "untrusted side artifact\n");
    },
  ];
  try {
    for (const [index, mutate] of mutations.entries()) {
      const directory = join(temporary, `case-${index + 1}`);
      cpSync(root, directory, { recursive: true, errorOnExist: true });
      mutate(directory);
      try {
        verifyArtifactDirectory(directory);
      } catch {
        rejected += 1;
      }
    }
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
  if (rejected !== mutations.length) fail(`SBOM negative controls rejected ${rejected}/5`);
  return rejected;
}

function generate(destination, target) {
  if (!/^(all|[A-Za-z0-9_.-]+)$/u.test(target)) fail(`invalid SBOM target: ${target}`);
  const tool = executablePath("cargo-cyclonedx");
  const version = runText(tool, ["cyclonedx", "--version"]);
  if (version !== TOOL_VERSION) fail(`cargo-cyclonedx version mismatch: ${version}`);
  const metadata = cargoMetadata();
  const workspaceIds = new Set(metadata.workspace_members);
  const workspacePackages = metadata.packages
    .filter((item) => workspaceIds.has(item.id))
    .map((item) => ({ name: item.name, version: item.version }))
    .sort((left, right) => compareUtf8(left.name, right.name));
  const epoch = Number(runText("git", ["show", "-s", "--format=%ct", "HEAD"]));
  if (!Number.isSafeInteger(epoch) || epoch < 1) fail("source commit epoch is invalid");
  const context = {
    tool,
    toolSha256: sha256(readFileSync(tool)),
    workspacePackages,
    externalCount: metadata.packages.length - workspacePackages.length,
    epoch,
    timestamp: expectedTimestamp(epoch),
    commit: runText("git", ["rev-parse", "HEAD"]),
    lockSha256: sha256(readFileSync(join(ROOT, "Cargo.lock"))),
    source: sourceIdentity(),
  };
  const temporary = mkdtempSync(join(tmpdir(), "joan-sbom-v0."));
  try {
    const first = buildOnce(join(temporary, "run-1"), target, context);
    const second = buildOnce(join(temporary, "run-2"), target, context);
    compareOutputs(first, second);
    verifyArtifactDirectory(first);
    installOutput(first, destination);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

function main() {
  const [command, path, target] = process.argv.slice(2);
  if (command === "generate" && path && target && process.argv.length === 5) {
    const destination = resolve(path);
    if (destination === ROOT || destination.startsWith(`${ROOT}${sep}`)) {
      fail("SBOM output must be outside the source repository");
    }
    generate(destination, target);
    const receipt = verifyArtifactDirectory(destination);
    process.stdout.write(`${canonicalJson(receipt)}`);
    return;
  }
  if (command === "verify" && path && process.argv.length === 4) {
    const receipt = verifyArtifactDirectory(resolve(path));
    process.stdout.write(`${canonicalJson(receipt)}`);
    return;
  }
  if (command === "negative-controls" && path && process.argv.length === 4) {
    const rejected = negativeControls(resolve(path));
    process.stdout.write(`${JSON.stringify({ status: "passed", rejected })}\n`);
    return;
  }
  fail(
    "usage: node tools/sbom-evidence.mjs <generate <output-directory> <target>|verify <directory>|negative-controls <directory>>",
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`sbom-evidence: ${String(error.message ?? error)}\n`);
    process.exitCode = 1;
  }
}
