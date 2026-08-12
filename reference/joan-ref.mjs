#!/usr/bin/env node

// Independent executable reference for the frozen JOAN v0 acceptance contract.
// It intentionally imports no JOAN implementation modules and has no host effects.

import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const MAX_SOURCE_BYTES = 1_048_576;
const MAX_TOKENS = 200_000;
const MAX_FUNCTIONS = 1_024;
const MAX_PARAMETERS = 64;
const MAX_STATEMENTS = 100_000;
const PUBLIC = Object.freeze({ class: "public" });

const KEYWORDS = new Set([
  "module",
  "fn",
  "effects",
  "let",
  "return",
  "request",
  "true",
  "false",
  "i64",
  "bool",
  "string",
  "unit",
]);

class ReferenceDiagnostic extends Error {
  constructor(phase, code) {
    super(`${phase}:${code}`);
    this.phase = phase;
    this.code = code;
  }
}

function fail(phase, code) {
  throw new ReferenceDiagnostic(phase, code);
}

function isIdentifierStart(value) {
  return value === "_" || /[A-Za-z]/.test(value);
}

function isIdentifierContinue(value) {
  return value === "_" || /[A-Za-z0-9]/.test(value);
}

function lex(source) {
  if (Buffer.byteLength(source, "utf8") > MAX_SOURCE_BYTES) {
    fail("lex", "J0001");
  }
  const tokens = [];
  let cursor = 0;
  const push = (type, value = null) => {
    if (tokens.length >= MAX_TOKENS) fail("lex", "J0003");
    tokens.push({ type, value });
  };
  while (cursor < source.length) {
    const value = source[cursor];
    const next = source[cursor + 1];
    if (/\s/u.test(value)) {
      cursor += 1;
      continue;
    }
    if (value === "/" && next === "/") {
      cursor += 2;
      while (cursor < source.length && source[cursor] !== "\n") cursor += 1;
      continue;
    }
    if (value === "/" && next === "*") {
      cursor += 2;
      let depth = 1;
      while (cursor < source.length && depth > 0) {
        if (source[cursor] === "/" && source[cursor + 1] === "*") {
          depth += 1;
          cursor += 2;
        } else if (source[cursor] === "*" && source[cursor + 1] === "/") {
          depth -= 1;
          cursor += 2;
        } else {
          cursor += 1;
        }
      }
      if (depth !== 0) fail("lex", "J0012");
      continue;
    }
    if (isIdentifierStart(value)) {
      const start = cursor;
      cursor += 1;
      while (cursor < source.length && isIdentifierContinue(source[cursor])) cursor += 1;
      const text = source.slice(start, cursor);
      push(KEYWORDS.has(text) ? text : "identifier", text);
      continue;
    }
    if (/[0-9]/.test(value)) {
      const start = cursor;
      cursor += 1;
      while (cursor < source.length && /[0-9]/.test(source[cursor])) cursor += 1;
      const text = source.slice(start, cursor);
      const integer = BigInt(text);
      if (integer > 9_223_372_036_854_775_807n) fail("lex", "J0005");
      push("integer", text);
      continue;
    }
    if (value === '"') {
      cursor += 1;
      let decoded = "";
      let closed = false;
      while (cursor < source.length) {
        const character = source[cursor];
        if (character === '"') {
          cursor += 1;
          closed = true;
          break;
        }
        if (character === "\n" || character === "\r") fail("lex", "J0007");
        if (character === "\\") {
          cursor += 1;
          if (cursor >= source.length) fail("lex", "J0008");
          const escaped = source[cursor];
          const escapes = { n: "\n", r: "\r", t: "\t", "\\": "\\", '"': '"' };
          if (!Object.hasOwn(escapes, escaped)) fail("lex", "J0009");
          decoded += escapes[escaped];
          cursor += 1;
          continue;
        }
        if (/\p{Cc}/u.test(character)) fail("lex", "J0010");
        decoded += character;
        cursor += 1;
      }
      if (!closed) fail("lex", "J0006");
      push("string-literal", decoded);
      continue;
    }
    const pair = source.slice(cursor, cursor + 2);
    const paired = new Set(["->", "==", "!=", "<=", ">=", "&&", "||"]);
    if (paired.has(pair)) {
      push(pair);
      cursor += 2;
      continue;
    }
    if ("(){}[],:;+-*/%=!<>".includes(value)) {
      push(value);
      cursor += 1;
      continue;
    }
    fail("lex", "J0011");
  }
  tokens.push({ type: "eof", value: null });
  return tokens;
}

class Parser {
  constructor(tokens) {
    this.tokens = tokens;
    this.cursor = 0;
  }

  current() {
    return this.tokens[this.cursor];
  }

  is(type) {
    return this.current().type === type;
  }

  advance() {
    const token = this.current();
    if (token.type !== "eof") this.cursor += 1;
    return token;
  }

  consume(type) {
    if (!this.is(type)) return null;
    return this.advance();
  }

  expect(type, code) {
    if (!this.is(type)) fail("parse", code);
    return this.advance();
  }

  identifier(code) {
    if (!this.is("identifier")) fail("parse", code);
    return this.advance().value;
  }

  contextual(value) {
    if (this.is("identifier") && this.current().value === value) {
      return this.advance();
    }
    return null;
  }

  program() {
    this.expect("module", "J1001");
    const module = this.identifier("J1002");
    const informationFlow = Boolean(this.contextual("flow"));
    this.expect(";", "J1003");
    const functions = [];
    while (!this.is("eof")) functions.push(this.function());
    if (functions.length === 0) fail("parse", "J1004");
    return { module, informationFlow, functions };
  }

  function() {
    this.expect("fn", "J1010");
    const name = this.identifier("J1011");
    this.expect("(", "J1012");
    const parameters = [];
    if (!this.is(")")) {
      do {
        const parameterName = this.identifier("J1013");
        this.expect(":", "J1014");
        const valueType = this.valueType();
        const information = this.informationLabel();
        parameters.push({ name: parameterName, valueType, information });
      } while (this.consume(","));
    }
    this.expect(")", "J1015");
    this.expect("->", "J1016");
    const returnType = this.valueType();
    const returnInformation = this.informationLabel();
    this.expect("effects", "J1017");
    this.expect("[", "J1018");
    const effects = [];
    if (!this.is("]")) {
      do effects.push(this.identifier("J1019")); while (this.consume(","));
    }
    this.expect("]", "J1020");
    const authorities = this.authorityParameters();
    const body = this.block();
    return {
      name,
      parameters,
      returnType,
      returnInformation,
      effects,
      authorities,
      body,
    };
  }

  valueType() {
    const token = this.advance();
    if (!["i64", "bool", "string", "unit"].includes(token.type)) fail("parse", "J1021");
    return token.type;
  }

  authorityParameters() {
    if (!this.contextual("authorities")) return null;
    this.expect("[", "J1022");
    const authorities = [];
    if (!this.is("]")) {
      do {
        const name = this.identifier("J1023");
        this.expect(":", "J1024");
        const effect = this.identifier("J1025");
        authorities.push({ name, effect });
      } while (this.consume(","));
    }
    this.expect("]", "J1026");
    return authorities;
  }

  informationLabel() {
    if (!this.contextual("flow")) return null;
    this.expect("[", "J1090");
    const classification = this.identifier("J1091");
    let label;
    if (classification === "public") {
      label = PUBLIC;
    } else if (classification === "secret") {
      this.expect(",", "J1092");
      if (!this.contextual("tenant")) fail("parse", "J1093");
      this.expect(":", "J1094");
      const tenant = this.identifier("J1095");
      this.expect(",", "J1096");
      if (!this.contextual("purpose")) fail("parse", "J1097");
      this.expect(":", "J1098");
      const purpose = this.identifier("J1099");
      label = { class: "secret", tenant, purpose };
    } else {
      fail("parse", "J1091");
    }
    this.expect("]", "J1100");
    return label;
  }

  block() {
    this.expect("{", "J1030");
    const body = [];
    while (!this.is("}")) {
      if (this.is("eof")) fail("parse", "J1031");
      body.push(this.statement());
    }
    this.advance();
    return body;
  }

  statement() {
    if (this.consume("let")) {
      const name = this.identifier("J1041");
      this.expect(":", "J1042");
      const valueType = this.valueType();
      const information = this.informationLabel();
      this.expect("=", "J1043");
      const value = this.expression();
      this.expect(";", "J1044");
      return { kind: "let", name, valueType, information, value };
    }
    if (this.consume("return")) {
      const value = this.is(";") ? null : this.expression();
      this.expect(";", "J1045");
      return { kind: "return", value };
    }
    if (this.consume("request")) {
      const effect = this.identifier("J1046");
      const argumentsList = this.arguments();
      const authority = this.contextual("using") ? this.identifier("J1048") : null;
      const information = this.informationLabel();
      this.expect(";", "J1047");
      return { kind: "request", effect, arguments: argumentsList, authority, information };
    }
    const expression = this.expression();
    this.expect(";", "J1040");
    return { kind: "expression", expression };
  }

  expression() {
    return this.binaryOr();
  }

  binaryOr() {
    return this.binary(() => this.binaryAnd(), ["||"]);
  }

  binaryAnd() {
    return this.binary(() => this.equality(), ["&&"]);
  }

  equality() {
    return this.binary(() => this.comparison(), ["==", "!="]);
  }

  comparison() {
    return this.binary(() => this.term(), ["<", "<=", ">", ">="]);
  }

  term() {
    return this.binary(() => this.factor(), ["+", "-"]);
  }

  factor() {
    return this.binary(() => this.unary(), ["*", "/", "%"]);
  }

  binary(next, operators) {
    let expression = next();
    while (operators.includes(this.current().type)) {
      const operator = this.advance().type;
      expression = { kind: "binary", operator, left: expression, right: next() };
    }
    return expression;
  }

  unary() {
    if (this.is("-") || this.is("!")) {
      const operator = this.advance().type;
      return { kind: "unary", operator, operand: this.unary() };
    }
    return this.primary();
  }

  primary() {
    const token = this.advance();
    if (token.type === "integer") return { kind: "integer" };
    if (token.type === "true" || token.type === "false") return { kind: "boolean" };
    if (token.type === "string-literal") return { kind: "string" };
    if (token.type === "identifier") {
      if (this.is("(")) {
        return { kind: "call", function: token.value, arguments: this.arguments() };
      }
      return { kind: "variable", name: token.value };
    }
    if (token.type === "(") {
      const expression = this.expression();
      this.expect(")", "J1050");
      return expression;
    }
    fail("parse", "J1051");
  }

  arguments() {
    this.expect("(", "J1060");
    const argumentsList = [];
    if (!this.is(")")) {
      do argumentsList.push(this.expression()); while (this.consume(","));
    }
    this.expect(")", "J1061");
    return argumentsList;
  }
}

function publicValue(valueType) {
  return { valueType, information: PUBLIC };
}

function sameLabel(left, right) {
  return left.class === right.class
    && (left.class === "public"
      || (left.tenant === right.tenant && left.purpose === right.purpose));
}

function canFlow(source, destination) {
  return source.class === "public" || sameLabel(source, destination);
}

function joinLabels(left, right) {
  if (sameLabel(left, right)) return left;
  if (left.class === "public") return right;
  if (right.class === "public") return left;
  return null;
}

class Checker {
  constructor(program) {
    this.program = program;
    this.diagnostics = [];
    this.signatures = new Map();
    this.calls = new Map();
    this.allEffects = new Set();
    this.linearProfile = program.informationFlow || program.functions.some(
      (fn) => fn.authorities !== null || fn.body.some((statement) => statement.kind === "request" && statement.authority !== null),
    );
  }

  add(code) {
    this.diagnostics.push(code);
  }

  run() {
    this.collectSignatures();
    this.checkEntrypoint();
    for (const fn of this.program.functions) this.checkFunction(fn);
    this.checkAcyclicCalls();
    if (this.diagnostics.length > 0) return null;
    const authoritySlotCount = this.program.functions.reduce(
      (count, fn) => count + (fn.authorities?.length ?? 0),
      0,
    );
    const receipt = {
      schema: this.program.informationFlow ? "joan.check-receipt.v1" : "joan.check-receipt.v0",
      status: "accepted",
      module: this.program.module,
      function_count: this.program.functions.length,
      statement_count: this.program.functions.reduce((count, fn) => count + fn.body.length, 0),
      declared_effects: [...this.allEffects].sort(),
      termination_profile: "no-loops-acyclic-call-graph-bounded-vm",
      effect_profile: "requests-recorded-never-executed",
      authority_profile: this.linearProfile
        ? "linear-one-shot-per-invocation"
        : "legacy-receipt-only",
      authority_slot_count: authoritySlotCount,
    };
    if (this.program.informationFlow) {
      receipt.information_flow_profile = "explicit-tenant-purpose-no-declassification";
      receipt.protected_boundary_count = this.protectedBoundaryCount();
    }
    return receipt;
  }

  collectSignatures() {
    if (this.program.functions.length > MAX_FUNCTIONS) this.add("J2001");
    let statements = 0;
    for (const fn of this.program.functions) {
      this.checkInformationShape(fn);
      statements += fn.body.length;
      if (fn.parameters.length > MAX_PARAMETERS) this.add("J2002");
      const effects = new Set();
      for (const effect of fn.effects) {
        if (effects.has(effect)) this.add("J2003");
        effects.add(effect);
        this.allEffects.add(effect);
      }
      const signature = {
        parameters: fn.parameters.map((parameter) => ({
          valueType: parameter.valueType,
          information: parameter.information ?? PUBLIC,
        })),
        returnValue: {
          valueType: fn.returnType,
          information: fn.returnInformation ?? PUBLIC,
        },
        effects,
      };
      if (this.signatures.has(fn.name)) this.add("J2004");
      this.signatures.set(fn.name, signature);
    }
    if (statements > MAX_STATEMENTS) this.add("J2005");
  }

  checkEntrypoint() {
    const main = this.signatures.get("main");
    if (!main) {
      this.add("J2010");
    } else if (main.parameters.length !== 0) {
      this.add("J2011");
    }
  }

  checkInformationShape(fn) {
    const boundary = (present) => {
      if (this.program.informationFlow && !present) this.add("J2060");
      if (!this.program.informationFlow && present) this.add("J2061");
    };
    boundary(fn.returnInformation !== null);
    for (const parameter of fn.parameters) boundary(parameter.information !== null);
    for (const statement of fn.body) {
      if (statement.kind === "let" || statement.kind === "request") {
        boundary(statement.information !== null);
      }
    }
  }

  checkFunction(fn) {
    const authorityState = this.authorityState(fn);
    if (authorityState === null) return;
    const [authoritySlots, availableAuthorities] = authorityState;
    const locals = new Map();
    for (const parameter of fn.parameters) {
      if (parameter.valueType === "unit") this.add("J2020");
      if (locals.has(parameter.name)) this.add("J2021");
      locals.set(parameter.name, {
        valueType: parameter.valueType,
        information: parameter.information ?? PUBLIC,
      });
    }
    if (fn.body.length === 0) {
      this.add("J2022");
      return;
    }
    let returned = false;
    for (const statement of fn.body) {
      if (returned) {
        this.add("J2023");
        continue;
      }
      returned = this.checkStatement(statement, locals, authoritySlots, availableAuthorities, fn);
    }
    if (!returned) this.add("J2029");
    if (this.linearProfile) {
      for (const _authority of [...availableAuthorities].sort()) this.add("J2057");
    }
  }

  authorityState(fn) {
    const slots = new Map();
    const available = new Set();
    if (!this.linearProfile) return [slots, available];
    if (fn.authorities === null) {
      this.add("J2050");
      return null;
    }
    for (const authority of fn.authorities) {
      if (slots.has(authority.name)) this.add("J2051");
      slots.set(authority.name, authority.effect);
      available.add(authority.name);
      if (!fn.effects.includes(authority.effect)) this.add("J2052");
    }
    return [slots, available];
  }

  checkStatement(statement, locals, authoritySlots, availableAuthorities, fn) {
    if (statement.kind === "let") {
      if (statement.valueType === "unit") this.add("J2024");
      const actual = this.expressionType(statement.value, locals, fn);
      this.requireType(statement.valueType, actual?.valueType);
      const destination = statement.information ?? PUBLIC;
      this.requireFlow(actual?.information, destination);
      if (locals.has(statement.name)) this.add("J2025");
      locals.set(statement.name, { valueType: statement.valueType, information: destination });
      return false;
    }
    if (statement.kind === "return") {
      this.checkReturn(statement.value, locals, fn);
      return true;
    }
    if (statement.kind === "request") {
      this.checkRequest(statement, locals, authoritySlots, availableAuthorities, fn);
      return false;
    }
    this.expressionType(statement.expression, locals, fn);
    return false;
  }

  checkReturn(expression, locals, fn) {
    if (expression === null && fn.returnType !== "unit") {
      this.add("J2026");
      return;
    }
    if (expression !== null && fn.returnType === "unit") {
      this.add("J2027");
      return;
    }
    if (expression !== null) {
      const actual = this.expressionType(expression, locals, fn);
      this.requireType(fn.returnType, actual?.valueType);
      this.requireFlow(actual?.information, fn.returnInformation ?? PUBLIC);
    }
  }

  checkRequest(statement, locals, authoritySlots, availableAuthorities, fn) {
    if (!fn.effects.includes(statement.effect)) this.add("J2028");
    const sink = statement.information ?? PUBLIC;
    for (const argument of statement.arguments) {
      const actual = this.expressionType(argument, locals, fn);
      this.requireFlow(actual?.information, sink);
    }
    if (!this.linearProfile) return;
    if (statement.authority === null) {
      this.add("J2053");
      return;
    }
    const allowedEffect = authoritySlots.get(statement.authority);
    if (allowedEffect === undefined) {
      this.add("J2054");
      return;
    }
    if (allowedEffect !== statement.effect) {
      this.add("J2055");
      return;
    }
    if (!availableAuthorities.delete(statement.authority)) this.add("J2056");
  }

  expressionType(expression, locals, caller) {
    if (expression.kind === "integer") return publicValue("i64");
    if (expression.kind === "boolean") return publicValue("bool");
    if (expression.kind === "string") return publicValue("string");
    if (expression.kind === "variable") {
      const value = locals.get(expression.name);
      if (!value) this.add("J2030");
      return value ?? null;
    }
    if (expression.kind === "unary") {
      const actual = this.expressionType(expression.operand, locals, caller);
      const expected = expression.operator === "-" ? "i64" : "bool";
      this.requireType(expected, actual?.valueType);
      return { valueType: expected, information: actual?.information ?? PUBLIC };
    }
    if (expression.kind === "binary") {
      return this.binaryType(expression, locals, caller);
    }
    return this.callType(expression, locals, caller);
  }

  binaryType(expression, locals, caller) {
    const left = this.expressionType(expression.left, locals, caller);
    const right = this.expressionType(expression.right, locals, caller);
    let valueType;
    if (["+", "-", "*", "/", "%"].includes(expression.operator)) {
      this.requireType("i64", left?.valueType);
      this.requireType("i64", right?.valueType);
      valueType = "i64";
    } else if (["<", "<=", ">", ">="].includes(expression.operator)) {
      this.requireType("i64", left?.valueType);
      this.requireType("i64", right?.valueType);
      valueType = "bool";
    } else if (["&&", "||"].includes(expression.operator)) {
      this.requireType("bool", left?.valueType);
      this.requireType("bool", right?.valueType);
      valueType = "bool";
    } else {
      if (left && right && left.valueType !== right.valueType) this.add("J2031");
      valueType = "bool";
    }
    let information = left?.information ?? right?.information ?? PUBLIC;
    if (left && right) {
      const joined = joinLabels(left.information, right.information);
      if (joined === null) {
        this.add("J2063");
        information = PUBLIC;
      } else {
        information = joined;
      }
    }
    return { valueType, information };
  }

  callType(expression, locals, caller) {
    const signature = this.signatures.get(expression.function);
    if (!signature) {
      this.add("J2032");
      for (const argument of expression.arguments) this.expressionType(argument, locals, caller);
      return null;
    }
    const calls = this.calls.get(caller.name) ?? [];
    calls.push(expression.function);
    this.calls.set(caller.name, calls);
    if (expression.arguments.length !== signature.parameters.length) this.add("J2033");
    for (let index = 0; index < expression.arguments.length; index += 1) {
      const actual = this.expressionType(expression.arguments[index], locals, caller);
      const expected = signature.parameters[index];
      if (expected) {
        this.requireType(expected.valueType, actual?.valueType);
        this.requireFlow(actual?.information, expected.information);
      }
    }
    const callerEffects = new Set(caller.effects);
    for (const effect of signature.effects) {
      if (!callerEffects.has(effect)) this.add("J2034");
    }
    return { ...signature.returnValue };
  }

  requireType(expected, actual) {
    if (actual !== undefined && expected !== actual) this.add("J2035");
  }

  requireFlow(source, destination) {
    if (this.program.informationFlow && source !== undefined && !canFlow(source, destination)) {
      this.add("J2062");
    }
  }

  checkAcyclicCalls() {
    const visiting = new Set();
    const visited = new Set();
    const visit = (name) => {
      if (visited.has(name)) return;
      if (visiting.has(name)) {
        this.add("J2040");
        return;
      }
      visiting.add(name);
      for (const callee of this.calls.get(name) ?? []) {
        if (visiting.has(callee)) this.add("J2040");
        else visit(callee);
      }
      visiting.delete(name);
      visited.add(name);
    };
    for (const name of this.signatures.keys()) visit(name);
  }

  protectedBoundaryCount() {
    let count = 0;
    for (const fn of this.program.functions) {
      if (fn.returnInformation?.class === "secret") count += 1;
      count += fn.parameters.filter((parameter) => parameter.information?.class === "secret").length;
      count += fn.body.filter(
        (statement) => (statement.kind === "let" || statement.kind === "request")
          && statement.information?.class === "secret",
      ).length;
    }
    return count;
  }
}

export function analyze(source) {
  try {
    const program = new Parser(lex(source)).program();
    const checker = new Checker(program);
    const receipt = checker.run();
    if (receipt !== null) return { phase: "check", status: "accepted", receipt };
    return { phase: "check", status: "rejected", diagnostic_codes: checker.diagnostics };
  } catch (error) {
    if (!(error instanceof ReferenceDiagnostic)) throw error;
    return { phase: error.phase, status: "rejected", diagnostic_codes: [error.code] };
  }
}

function main() {
  const [input, flag] = process.argv.slice(2);
  if (!input || (flag !== undefined && flag !== "--json")) {
    throw new Error("usage: node reference/joan-ref.mjs <program.joan> [--json]");
  }
  const result = analyze(readFileSync(input, "utf8"));
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (result.status === "rejected") process.exitCode = 2;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) main();
