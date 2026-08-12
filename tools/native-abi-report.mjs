#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, realpathSync, writeFileSync } from "node:fs";
import { arch, platform } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function fail(message) {
  throw new Error(message);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function fileDigest(path) {
  return sha256(readFileSync(path));
}

function run(command, args) {
  return execFileSync(command, args, {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 128 * 1024 * 1024,
  }).trim();
}

function executablePath(command) {
  if (command.includes("/")) return realpathSync(command);
  return realpathSync(run("which", [command]));
}

function combinedDigest(paths) {
  const hash = createHash("sha256");
  for (const path of paths) {
    hash.update(`${path}\0`, "utf8");
    hash.update(readFileSync(resolve(ROOT, path)));
  }
  return hash.digest("hex");
}

function tool(id, command, versionArgs) {
  const path = executablePath(command);
  return {
    id,
    version: run(command, versionArgs),
    sha256: fileDigest(path),
  };
}

function main() {
  if (process.argv.length !== 7) {
    fail("usage: native-abi-report.mjs <raw-report> <library> <sanitizers> <schema> <output>");
  }
  const [rawPath, libraryPath, sanitizers, schemaPath, outputPath] = process.argv.slice(2);
  const raw = JSON.parse(readFileSync(rawPath, "utf8"));
  const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
  if (raw.schema !== "joan.native-abi-report.v1" || raw.status !== "passed") fail("C ABI corpus failed");
  if (raw.passed !== raw.case_count || raw.case_count < 120) fail("C ABI corpus is incomplete");
  if (raw.mutation_count !== 4096 || !/^[0-9a-f]{16}$/u.test(raw.mutation_outcome_fnv1a64)) {
    fail("deterministic mutation evidence is incomplete");
  }
  if (schema.$id !== "https://joan.invalid/schemas/native-abi-report.v1.schema.json") fail("schema mismatch");
  if (!new Set(["passed", "unavailable"]).has(sanitizers)) fail("invalid sanitizer status");
  const source = JSON.parse(run(process.execPath, ["tools/evidence-index.mjs", "source"]));
  const report = {
    ...raw,
    sanitizers,
    target: {
      platform: platform(),
      arch: arch(),
      pointer_width: 64,
    },
    source,
    artifacts: {
      header_sha256: fileDigest(resolve(ROOT, "include/joan.h")),
      c_corpus_sha256: combinedDigest([
        "native/corpus/native-abi-v1.c",
        "native/corpus/native-abi-header-v1.cpp",
      ]),
      rust_api_sha256: combinedDigest([
        "crates/joan-abi/Cargo.toml",
        "crates/joan-abi/src/lib.rs",
        "crates/joan-abi/src/ffi.rs",
        "crates/joan-abi/tests/no_alloc.rs",
        "crates/joan-abi/tests/report_schema.rs",
        "crates/joan-abi/tests/semantic_binding.rs",
      ]),
      gate_files_sha256: combinedDigest([
        "scripts/verify-native-abi.sh",
        "tools/native-abi-report.mjs",
        "schemas/native-abi-report.v1.schema.json",
        "spec/native-abi-v1.md",
        "Cargo.lock",
      ]),
      library_sha256: fileDigest(libraryPath),
      tools: [
        tool("c-compiler", "cc", ["--version"]),
        tool("cpp-compiler", "c++", ["--version"]),
        tool("cargo", "cargo", ["--version", "--verbose"]),
        tool("nm", "nm", ["--version"]),
        tool("node", process.execPath, ["--version"]),
        tool("rg", "rg", ["--version"]),
        tool("rustc", "rustc", ["--version", "--verbose"]),
      ],
    },
  };
  writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`, { flag: "wx" });
}

try {
  main();
} catch (error) {
  process.stderr.write(`native-abi-report: ${String(error.message ?? error)}\n`);
  process.exitCode = 1;
}
