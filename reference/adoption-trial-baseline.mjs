#!/usr/bin/env node

import { lstatSync, readFileSync, readdirSync, realpathSync, statSync } from "node:fs";
import { relative, resolve, sep } from "node:path";
import { TextDecoder } from "node:util";

const KNOWN_MANIFESTS = [
  ["Cargo.toml", "Rust"],
  ["package.json", "JavaScript/TypeScript"],
  ["pyproject.toml", "Python"],
  ["requirements.txt", "Python"],
  ["go.mod", "Go"],
  ["pom.xml", "Java"],
  ["build.gradle", "Java/Kotlin"],
  ["Gemfile", "Ruby"],
];
const MAX_MANIFEST_BYTES = 1_048_576;
const MAX_INSTRUCTION_BYTES = 131_072;

function fail(message) {
  throw new Error(message);
}

function relativePath(root, path) {
  return relative(root, path).split(sep).join("/");
}

function regularFile(path, maximumBytes) {
  try {
    const metadata = lstatSync(path);
    return metadata.isFile() && !metadata.isSymbolicLink() && metadata.size <= maximumBytes;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

function inspect(fixtureArgument) {
  const root = realpathSync(resolve(fixtureArgument));
  if (!statSync(root).isDirectory()) fail("fixture is not a directory");
  const manifests = [];
  const languages = new Set();
  for (const [name, language] of KNOWN_MANIFESTS) {
    const path = resolve(root, name);
    if (regularFile(path, MAX_MANIFEST_BYTES)) {
      readFileSync(path);
      manifests.push(name);
      languages.add(language);
    }
  }

  const candidates = [resolve(root, "AGENTS.md"), resolve(root, ".github/copilot-instructions.md")];
  const instructionDirectory = resolve(root, ".github/instructions");
  try {
    for (const entry of readdirSync(instructionDirectory, { withFileTypes: true })) {
      if (entry.name.endsWith(".instructions.md")) candidates.push(resolve(instructionDirectory, entry.name));
    }
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }

  const instructionFiles = [];
  const diagnosticCodes = [];
  for (const path of [...new Set(candidates)].sort()) {
    let metadata;
    try {
      metadata = lstatSync(path);
    } catch (error) {
      if (error.code === "ENOENT") continue;
      throw error;
    }
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      diagnosticCodes.push("JINST002");
      continue;
    }
    if (metadata.size > MAX_INSTRUCTION_BYTES) fail(`instruction file is too large: ${relativePath(root, path)}`);
    const canonical = realpathSync(path);
    if (!(canonical === root || canonical.startsWith(`${root}${sep}`))) fail("instruction path escapes fixture");
    new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(canonical));
    instructionFiles.push({ path: relativePath(root, path), bytes: metadata.size });
  }

  return {
    schema: "joan.adoption-trial-observation.v1",
    mode: "read-only-offline",
    network: "denied-by-design-no-network-client",
    telemetry: "none",
    writes: "none",
    manifests: manifests.sort(),
    languages: [...languages].sort(),
    instruction_files: instructionFiles.sort((left, right) => left.path.localeCompare(right.path, "en")),
    diagnostic_codes: diagnosticCodes.sort(),
  };
}

try {
  if (process.argv.length !== 3) fail("usage: adoption-trial-baseline.mjs <fixture-directory>");
  process.stdout.write(`${JSON.stringify(inspect(process.argv[2]))}\n`);
} catch (error) {
  process.stderr.write(`adoption-trial-baseline: ${String(error.message ?? error)}\n`);
  process.exitCode = 1;
}
