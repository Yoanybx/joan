#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { TextDecoder } from "node:util";

const SPEC_PATH = new URL("../spec/canonical-profile-jce1.md", import.meta.url);

const LIMITS = Object.freeze({
  maxBytes: 1_048_576,
  maxDepth: 64,
  maxNodes: 100_000,
  maxStringBytes: 262_144,
});
const MAX_SAFE_INTEGER = 9_007_199_254_740_991n;
const HASH_PREFIX = Buffer.from("JOAN\0HASH\0V1", "ascii");
const HASH_PROFILE = "joan-hash-v1";
const DOMAINS = new Set([
  "joan.canonical-set-element.v1",
  "joan.language-canonical-ast.v1",
  "joan.conformance-vector.v1",
  "joan.source.v1",
  "joan.package-manifest.v1",
  "joan.bytecode-program.v1",
  "joan.dispute-case.v1",
  "joan.dispute-claim.v1",
  "joan.resolution-profile.v1",
  "joan.evidence-graph.v1",
  "joan.machine-finding.v1",
  "joan.decision-authorization-proof.v1",
  "joan.effect-application.v1",
  "joan.mock-ledger.v1",
  "joan.benchmark-manifest.v1",
]);

class Jce1Error extends Error {
  constructor(code, message) {
    super(message);
    this.name = "Jce1Error";
    this.code = code;
  }
}

function fail(code, message) {
  throw new Jce1Error(code, message);
}

class StrictParser {
  constructor(text, limits = LIMITS) {
    this.text = text;
    this.index = 0;
    this.nodes = 0;
    this.limits = limits;
  }

  parse() {
    const bytes = Buffer.byteLength(this.text, "utf8");
    if (bytes > this.limits.maxBytes) {
      fail("resource", `input has ${bytes} bytes`);
    }
    const value = this.parseValue(1);
    this.skipWhitespace();
    if (this.index !== this.text.length) {
      fail("json", "trailing JSON data");
    }
    return value;
  }

  parseValue(depth) {
    if (depth > this.limits.maxDepth) {
      fail("resource", `depth ${depth} exceeds limit`);
    }
    this.nodes += 1;
    if (this.nodes > this.limits.maxNodes) {
      fail("resource", `node count ${this.nodes} exceeds limit`);
    }
    this.skipWhitespace();
    const character = this.text[this.index];
    if (character === "{") return this.parseObject(depth);
    if (character === "[") return this.parseArray(depth);
    if (character === '"') return this.parseString();
    if (character === "t") return this.parseLiteral("true", true);
    if (character === "f") return this.parseLiteral("false", false);
    if (character === "n") return this.parseLiteral("null", null);
    if (character === "-" || isDigit(character)) return this.parseNumber();
    fail("json", `unexpected token at offset ${this.index}`);
  }

  parseObject(depth) {
    this.index += 1;
    const value = Object.create(null);
    const keys = new Set();
    this.skipWhitespace();
    if (this.text[this.index] === "}") {
      this.index += 1;
      return value;
    }
    for (;;) {
      this.skipWhitespace();
      if (this.text[this.index] !== '"') fail("json", "object key must be a string");
      const key = this.parseString();
      if (keys.has(key)) fail("duplicate-key", `duplicate object key: ${key}`);
      keys.add(key);
      this.skipWhitespace();
      if (this.text[this.index] !== ":") fail("json", "missing object colon");
      this.index += 1;
      value[key] = this.parseValue(depth + 1);
      this.skipWhitespace();
      const delimiter = this.text[this.index];
      this.index += 1;
      if (delimiter === "}") return value;
      if (delimiter !== ",") fail("json", "missing object delimiter");
    }
  }

  parseArray(depth) {
    this.index += 1;
    const value = [];
    this.skipWhitespace();
    if (this.text[this.index] === "]") {
      this.index += 1;
      return value;
    }
    for (;;) {
      value.push(this.parseValue(depth + 1));
      this.skipWhitespace();
      const delimiter = this.text[this.index];
      this.index += 1;
      if (delimiter === "]") return value;
      if (delimiter !== ",") fail("json", "missing array delimiter");
    }
  }

  parseString() {
    const start = this.index;
    this.index += 1;
    let escaped = false;
    while (this.index < this.text.length) {
      const code = this.text.charCodeAt(this.index);
      const character = this.text[this.index];
      if (!escaped && character === '"') {
        this.index += 1;
        const token = this.text.slice(start, this.index);
        let value;
        try {
          value = JSON.parse(token);
        } catch (error) {
          fail("json", `invalid JSON string: ${String(error)}`);
        }
        validateUnicode(value);
        const bytes = Buffer.byteLength(value, "utf8");
        if (bytes > this.limits.maxStringBytes) {
          fail("resource", `string has ${bytes} bytes`);
        }
        return value;
      }
      if (!escaped && code < 0x20) fail("json", "raw control character in string");
      if (!escaped && character === "\\") {
        escaped = true;
        this.index += 1;
        continue;
      }
      if (escaped) {
        if (character === "u") {
          const digits = this.text.slice(this.index + 1, this.index + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(digits)) fail("json", "invalid Unicode escape");
          this.index += 5;
        } else {
          if (!'"\\/bfnrt'.includes(character)) fail("json", "invalid string escape");
          this.index += 1;
        }
        escaped = false;
        continue;
      }
      this.index += 1;
    }
    fail("json", "unterminated JSON string");
  }

  parseNumber() {
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(
      this.text.slice(this.index),
    );
    if (!match) fail("json", "invalid JSON number");
    const token = match[0];
    this.index += token.length;
    if (token.includes(".") || token.includes("e") || token.includes("E") || token === "-0") {
      fail("json", "floating-point and negative-zero numbers are forbidden");
    }
    let integer;
    try {
      integer = BigInt(token);
    } catch {
      fail("json", "invalid JSON integer");
    }
    if (integer > MAX_SAFE_INTEGER || integer < -MAX_SAFE_INTEGER) {
      fail("unsafe-integer", `unsafe JCE1 integer: ${token}`);
    }
    return Number(integer);
  }

  parseLiteral(token, value) {
    if (this.text.slice(this.index, this.index + token.length) !== token) {
      fail("json", `invalid literal at offset ${this.index}`);
    }
    this.index += token.length;
    return value;
  }

  skipWhitespace() {
    while (/\s/u.test(this.text[this.index] ?? "") && this.index < this.text.length) {
      const character = this.text[this.index];
      if (!" \t\r\n".includes(character)) fail("json", "non-JSON whitespace");
      this.index += 1;
    }
  }
}

function isDigit(character) {
  return character !== undefined && character >= "0" && character <= "9";
}

function validateUnicode(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) fail("json", "lone high surrogate");
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      fail("json", "lone low surrogate");
    }
  }
}

function strictParse(text, limits = LIMITS) {
  return new StrictParser(text, limits).parse();
}

function decodeUtf8(bytes) {
  if (bytes.length > LIMITS.maxBytes) fail("resource", `input has ${bytes.length} bytes`);
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail("utf8", "input is not valid UTF-8");
  }
}

function strictParseBytes(bytes) {
  return strictParse(decodeUtf8(bytes));
}

function canonical(value) {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) fail("unsafe-integer", `unsafe JCE1 integer: ${value}`);
    return String(value);
  }
  if (typeof value === "string") {
    validateUnicode(value);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
      .join(",")}}`;
  }
  fail("json", `unsupported value type: ${typeof value}`);
}

function canonicalizeText(text) {
  return canonical(strictParse(text));
}

function lengthDelimited(bytes) {
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(bytes.length));
  return Buffer.concat([length, bytes]);
}

function requireDomain(domain) {
  if (!DOMAINS.has(domain)) fail("domain", `unregistered JCE1 digest domain: ${domain}`);
  return domain;
}

function digestV1(domain, payload) {
  requireDomain(domain);
  const bytes = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  if (bytes.length > LIMITS.maxBytes) fail("resource", `payload has ${bytes.length} bytes`);
  const preimage = Buffer.concat([
    HASH_PREFIX,
    lengthDelimited(Buffer.from(HASH_PROFILE, "ascii")),
    lengthDelimited(Buffer.from(domain, "ascii")),
    lengthDelimited(bytes),
  ]);
  return {
    algorithm: "sha256",
    profile: HASH_PROFILE,
    domain,
    value: createHash("sha256").update(preimage).digest("hex"),
  };
}

function verifyTypedDigest(domain, payload, supplied) {
  requireDomain(domain);
  if (
    supplied.algorithm !== "sha256" ||
    supplied.profile !== HASH_PROFILE ||
    supplied.domain !== domain ||
    !/^[0-9a-f]{64}$/.test(supplied.value)
  ) {
    fail("digest", "JCE1 digest tags or shape do not match");
  }
  const expected = digestV1(domain, payload);
  if (expected.value !== supplied.value) fail("digest", "JCE1 digest value does not match");
}

function canonicalSet(values) {
  const seen = new Set();
  const entries = values.map((value) => {
    const bytes = Buffer.from(canonical(value), "utf8");
    const key = bytes.toString("hex");
    if (seen.has(key)) fail("duplicate-set", "duplicate JCE1 canonical set element");
    seen.add(key);
    return {
      bytes,
      digest: digestV1("joan.canonical-set-element.v1", bytes).value,
      value,
    };
  });
  entries.sort((left, right) => {
    const digestOrder = left.digest < right.digest ? -1 : left.digest > right.digest ? 1 : 0;
    return digestOrder || Buffer.compare(left.bytes, right.bytes);
  });
  return entries.map((entry) => entry.value);
}

function classify(error) {
  if (!(error instanceof Jce1Error)) return "internal";
  if (error.code === "unsafe-integer") return "unsafe-integer";
  if (error.code === "resource") return "resource";
  if (error.code === "domain") return "domain";
  if (error.code === "digest") return "digest";
  if (error.code === "duplicate-set") return "duplicate-set";
  return "canonical-json";
}

function assert(condition, message) {
  if (!condition) fail("conformance", message);
}

function expectReject(input, expected) {
  try {
    canonicalizeText(input);
  } catch (error) {
    const observed = classify(error);
    assert(observed === expected, `expected ${expected}, observed ${observed}`);
    return observed;
  }
  fail("conformance", `input was accepted; expected ${expected}`);
}

function runCase(testCase) {
  switch (testCase.operation) {
    case "canonicalize": {
      const outputs = testCase.inputs.map(canonicalizeText);
      assert(outputs.every((output) => output === testCase.expected_output), `${testCase.id} output mismatch`);
      return { outputs };
    }
    case "canonicalize-distinct": {
      const outputs = testCase.inputs.map(canonicalizeText);
      assert(JSON.stringify(outputs) === JSON.stringify(testCase.expected_outputs), `${testCase.id} outputs mismatch`);
      assert(new Set(outputs).size === outputs.length, `${testCase.id} outputs were not distinct`);
      return { outputs };
    }
    case "reject":
      return { errors: testCase.inputs.map((input) => expectReject(input, testCase.expected_error)) };
    case "schema-reject": {
      const value = strictParse(testCase.input);
      const unknown = Object.keys(value).filter((key) => !testCase.allowed_fields.includes(key));
      assert(JSON.stringify(unknown.sort()) === JSON.stringify(testCase.expected_unknown.sort()), "unknown fields mismatch");
      return { unknown };
    }
    case "resource-bounds": {
      const inputs = [
        '"' + "x".repeat(LIMITS.maxBytes) + '"',
        "[".repeat(65) + "null" + "]".repeat(65),
        `[${Array.from({ length: LIMITS.maxNodes }, () => "null").join(",")}]`,
        '"' + "x".repeat(LIMITS.maxStringBytes + 1) + '"',
      ];
      return { errors: inputs.map((input) => expectReject(input, "resource")) };
    }
    case "domain-distinct": {
      const values = testCase.domains.map((domain) => digestV1(domain, testCase.payload).value);
      assert(new Set(values).size === values.length, "domain-separated digests collided");
      return { values };
    }
    case "fixed-digest": {
      const digest = digestV1(testCase.domain, Buffer.from(testCase.payload_hex, "hex"));
      assert(digest.value === testCase.expected_value, "fixed digest mismatch");
      return { digest };
    }
    case "typed-digest-reject": {
      const payload = Buffer.from(testCase.payload, "utf8");
      const valid = digestV1(testCase.domain, payload);
      const variants = [
        { ...valid, algorithm: "sha512" },
        { ...valid, profile: "joan-hash-v0" },
        { ...valid, domain: "joan.source.v1" },
        { ...valid, value: "0".repeat(64) },
      ];
      const errors = variants.map((variant) => {
        try {
          verifyTypedDigest(testCase.domain, payload, variant);
        } catch (error) {
          return classify(error);
        }
        fail("conformance", "typed digest mutation was accepted");
      });
      return { errors };
    }
    case "domain-reject": {
      const errors = testCase.domains.map((domain) => {
        try {
          requireDomain(domain);
        } catch (error) {
          return classify(error);
        }
        fail("conformance", `invalid domain was accepted: ${domain}`);
      });
      return { errors };
    }
    case "payload-bound": {
      digestV1(testCase.domain, Buffer.alloc(testCase.accepted_bytes));
      let rejected;
      try {
        digestV1(testCase.domain, Buffer.alloc(testCase.rejected_bytes));
      } catch (error) {
        rejected = classify(error);
      }
      assert(rejected === "resource", "oversized payload was accepted");
      return { accepted: testCase.accepted_bytes, rejected };
    }
    case "set-permutations": {
      const outputs = testCase.sets.map((values) => canonical(canonicalSet(values)));
      assert(outputs.every((output) => output === testCase.expected_output), "canonical set mismatch");
      return { outputs };
    }
    case "set-duplicate": {
      let observed;
      try {
        canonicalSet(testCase.values);
      } catch (error) {
        observed = classify(error);
      }
      assert(observed === "duplicate-set", "duplicate set element was accepted");
      return { error: observed };
    }
    case "synthetic-set-tie": {
      const records = testCase.records.slice().sort((left, right) => {
        const digestOrder = left.digest < right.digest ? -1 : left.digest > right.digest ? 1 : 0;
        return digestOrder || Buffer.compare(Buffer.from(left.bytes_hex, "hex"), Buffer.from(right.bytes_hex, "hex"));
      });
      const labels = records.map((record) => record.label);
      assert(JSON.stringify(labels) === JSON.stringify(testCase.expected_labels), "synthetic set tie-break mismatch");
      return { labels };
    }
    default:
      fail("conformance", `unsupported operation: ${testCase.operation}`);
  }
}

function runConformance(path) {
  const bytes = readFileSync(path);
  const suite = strictParseBytes(bytes);
  assert(suite.schema === "joan.jce1-conformance-suite.v1", "unsupported conformance suite");
  const specificationSha256 = createHash("sha256").update(readFileSync(SPEC_PATH)).digest("hex");
  assert(
    suite.spec_freeze_sha256 === specificationSha256,
    "spec_freeze_sha256 does not match spec/canonical-profile-jce1.md",
  );
  const results = [];
  for (const testCase of suite.cases) {
    try {
      const observation = runCase(testCase);
      results.push({ id: testCase.id, status: "passed", observation });
    } catch (error) {
      results.push({
        id: testCase.id,
        status: "failed",
        error_class: classify(error),
        message: String(error.message ?? error),
      });
    }
  }
  const failed = results.filter((result) => result.status === "failed").length;
  const report = {
    schema: "joan.jce1-conformance-report.v1",
    implementation: "node-independent-reference",
    suite_digest: digestV1("joan.conformance-vector.v1", bytes),
    total: results.length,
    passed: results.length - failed,
    failed,
    results,
  };
  process.stdout.write(`${canonical(report)}\n`);
  if (failed > 0) process.exitCode = 1;
}

function readInput(path) {
  return path === "-" ? readFileSync(0) : readFileSync(path);
}

function usage() {
  return [
    "usage:",
    "  node tools/jce1-reference.mjs canonicalize <file|->",
    "  node tools/jce1-reference.mjs digest <registered-domain> <file|->",
    "  node tools/jce1-reference.mjs canonical-set <array-file|->",
    "  node tools/jce1-reference.mjs conformance <suite.json>",
  ].join("\n");
}

const [, , command, ...argumentsList] = process.argv;
try {
  if (command === "canonicalize" && argumentsList.length === 1) {
    process.stdout.write(`${canonical(strictParseBytes(readInput(argumentsList[0])))}\n`);
  } else if (command === "digest" && argumentsList.length === 2) {
    process.stdout.write(`${canonical(digestV1(argumentsList[0], readInput(argumentsList[1])))}\n`);
  } else if (command === "canonical-set" && argumentsList.length === 1) {
    const value = strictParseBytes(readInput(argumentsList[0]));
    if (!Array.isArray(value)) fail("json", "canonical-set input must be a JSON array");
    process.stdout.write(`${canonical(canonicalSet(value))}\n`);
  } else if (command === "conformance" && argumentsList.length === 1) {
    runConformance(argumentsList[0]);
  } else {
    fail("usage", usage());
  }
} catch (error) {
  process.stderr.write(`jce1-reference: ${String(error.message ?? error)}\n`);
  process.exitCode = 2;
}
