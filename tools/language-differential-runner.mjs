#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { analyze } from "../reference/joan-ref.mjs";

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

function encode(value) {
  return `${JSON.stringify(canonicalize(value))}\n`;
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function validateCorpus(corpus) {
  assert(corpus.schema === "joan.language-differential-corpus.v1", "invalid corpus schema");
  assert(/^0x[0-9a-f]{16}$/.test(corpus.seed), "invalid deterministic seed");
  assert(Number.isInteger(corpus.mutation_count) && corpus.mutation_count >= 1, "invalid mutation count");
  assert(Array.isArray(corpus.mutation_base_ids) && corpus.mutation_base_ids.length > 0, "missing mutation bases");
  assert(Array.isArray(corpus.cases) && corpus.cases.length >= 40, "corpus is too small");
  const ids = new Set();
  for (const item of corpus.cases) {
    assert(/^[APC][0-9]{3}$/.test(item.id), `invalid case id: ${item.id}`);
    assert(!ids.has(item.id), `duplicate case id: ${item.id}`);
    ids.add(item.id);
    assert(typeof item.source === "string", `case ${item.id} has no source`);
    assert(["lex", "parse", "check"].includes(item.expected.phase), `case ${item.id} has invalid phase`);
    assert(["accepted", "rejected"].includes(item.expected.status), `case ${item.id} has invalid status`);
    if (item.expected.status === "rejected") {
      assert(
        Array.isArray(item.expected.diagnostic_codes) && item.expected.diagnostic_codes.length > 0,
        `case ${item.id} has no expected diagnostics`,
      );
      assert(
        item.expected.diagnostic_codes.every((code) => /^J[0-9]{4}$/.test(code)),
        `case ${item.id} has invalid diagnostic codes`,
      );
    }
  }
  for (const id of corpus.mutation_base_ids) {
    const item = corpus.cases.find((candidate) => candidate.id === id);
    assert(item?.expected.status === "accepted", `mutation base ${id} is not accepted`);
  }
}

function normalize(result) {
  if (result.status === "accepted") {
    return { phase: "check", receipt: result.receipt, status: "accepted" };
  }
  return {
    diagnostic_codes: [...new Set(result.diagnostic_codes)].sort(),
    phase: result.phase,
    status: "rejected",
  };
}

function expectedProjection(expected) {
  if (expected.status === "accepted") return { phase: "check", status: "accepted" };
  return {
    diagnostic_codes: [...new Set(expected.diagnostic_codes)].sort(),
    phase: expected.phase,
    status: "rejected",
  };
}

function agreesWithExpected(result, expected) {
  if (result.phase !== expected.phase || result.status !== expected.status) return false;
  if (expected.status === "accepted") return true;
  return JSON.stringify(result.diagnostic_codes) === JSON.stringify(expected.diagnostic_codes);
}

function runRust(binary, sourcePath) {
  const execution = spawnSync(binary, ["check", sourcePath, "--json"], {
    encoding: "utf8",
    env: { ...process.env, RUST_BACKTRACE: "0" },
    maxBuffer: 4 * 1_048_576,
    timeout: 15_000,
  });
  assert(execution.error === undefined, `Rust checker failed to start: ${execution.error}`);
  assert(execution.signal === null, `Rust checker terminated by ${execution.signal}`);
  assert(execution.status === 0 || execution.status === 2, `Rust checker exit ${execution.status}`);
  let decoded;
  try {
    decoded = JSON.parse(execution.stdout);
  } catch (error) {
    throw new Error(`Rust checker emitted invalid JSON: ${error.message}`);
  }
  if (decoded.status === "accepted") {
    return normalize({ phase: "check", receipt: decoded, status: "accepted" });
  }
  assert(decoded.status === "rejected", "Rust checker emitted unknown status");
  return normalize({
    diagnostic_codes: decoded.diagnostics.map((diagnostic) => diagnostic.code),
    phase: decoded.phase,
    status: "rejected",
  });
}

function mutate(source, index, state) {
  let next = state;
  next ^= (next << 13n) & 0xffff_ffff_ffff_ffffn;
  next ^= next >> 7n;
  next ^= (next << 17n) & 0xffff_ffff_ffff_ffffn;
  next &= 0xffff_ffff_ffff_ffffn;
  const marker = `/* differential-${index}-${next.toString(16).padStart(16, "0")} */`;
  const mode = Number(next % 5n);
  let mutated;
  if (mode === 0) mutated = `${marker}\n${source}`;
  else if (mode === 1) mutated = source.replace("module ", `module ${marker} `);
  else if (mode === 2) mutated = source.replace("fn ", `fn ${marker} `);
  else if (mode === 3) mutated = source.replace(" effects ", ` ${marker} effects `);
  else mutated = `${source}\n/* outer ${marker} /* nested */ end */\n`;
  return [mutated, next];
}

function main() {
  const [binaryArgument, corpusArgument, reportArgument] = process.argv.slice(2);
  if (!binaryArgument || !corpusArgument || !reportArgument) {
    throw new Error("usage: node tools/language-differential-runner.mjs <joan-binary> <corpus.json> <report.json>");
  }
  const binary = resolve(binaryArgument);
  const corpusPath = resolve(corpusArgument);
  const reportPath = resolve(reportArgument);
  const corpusBytes = readFileSync(corpusPath);
  const corpus = JSON.parse(corpusBytes.toString("utf8"));
  validateCorpus(corpus);
  const referenceBytes = readFileSync(new URL("../reference/joan-ref.mjs", import.meta.url));
  const binaryBytes = readFileSync(binary);
  const work = mkdtempSync(join(process.env.JOAN_DIFFERENTIAL_TMPDIR ?? tmpdir(), "joan-differential-"));
  const cases = [...corpus.cases];
  let randomState = BigInt(corpus.seed);
  for (let index = 0; index < corpus.mutation_count; index += 1) {
    const baseId = corpus.mutation_base_ids[index % corpus.mutation_base_ids.length];
    const base = corpus.cases.find((item) => item.id === baseId);
    const [source, nextState] = mutate(base.source, index, randomState);
    randomState = nextState;
    cases.push({
      expected: { phase: "check", status: "accepted" },
      id: `M${String(index + 1).padStart(3, "0")}`,
      source,
    });
  }
  const results = [];
  let passed = 0;
  try {
    for (const item of cases) {
      const sourcePath = join(work, `${item.id}.joan`);
      writeFileSync(sourcePath, item.source, { encoding: "utf8", flag: "wx" });
      const reference = normalize(analyze(item.source));
      const rust = runRust(binary, sourcePath);
      const expected = expectedProjection(item.expected);
      const expectedPass = agreesWithExpected(reference, expected) && agreesWithExpected(rust, expected);
      const agreement = reference.status === rust.status
        && reference.phase === rust.phase
        && (reference.status === "rejected"
          ? JSON.stringify(reference.diagnostic_codes) === JSON.stringify(rust.diagnostic_codes)
          : JSON.stringify(canonicalize(reference.receipt))
            === JSON.stringify(canonicalize(rust.receipt)));
      const status = expectedPass && agreement ? "passed" : "failed";
      if (status === "passed") passed += 1;
      results.push({
        expected,
        id: item.id,
        reference,
        rust,
        source_digest: sha256(Buffer.from(item.source, "utf8")),
        status,
      });
    }
  } finally {
    rmSync(work, { force: true, recursive: true });
  }
  const report = {
    corpus_digest: sha256(corpusBytes),
    failed: results.length - passed,
    implementation: {
      reference: `node-${process.versions.node}-independent-js`,
      reference_digest: sha256(referenceBytes),
      rust: basename(binary),
      rust_binary_digest: sha256(binaryBytes),
    },
    mutation_count: corpus.mutation_count,
    passed,
    results,
    schema: "joan.language-differential-report.v1",
    seed: corpus.seed,
    total: results.length,
  };
  writeFileSync(reportPath, encode(report), { encoding: "utf8" });
  process.stdout.write(encode(report));
  if (report.failed !== 0) process.exitCode = 1;
}

main();
