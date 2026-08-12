#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { resolve } from "node:path";

const [sourceArgument] = process.argv.slice(2);
if (!sourceArgument) {
  throw new Error("usage: node --experimental-strip-types tools/typescript-strip-check.mjs <source.ts>");
}

const source = readFileSync(resolve(sourceArgument), "utf8");
const JavaScriptFunction = Function;
JavaScriptFunction(stripTypeScriptTypes(source, { mode: "strip" }));
