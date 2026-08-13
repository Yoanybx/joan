#!/usr/bin/env node

const U64_MASK = (1n << 64n) - 1n;
const FNV_OFFSET = 0xcbf29ce484222325n;
const FNV_PRIME = 0x00000100000001b3n;
const INSTRUCTIONS = {
  "cost-model": 6n,
  "deadline-slack": 6n,
  "dispatch-decision": 6n,
  "route-score": 11n,
  "split-budget": 8n,
};

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(2);
}

function u64(value) {
  return value & U64_MASK;
}

function splitmix64(state) {
  state.value = u64(state.value + 0x9e3779b97f4a7c15n);
  let value = state.value;
  value = u64((value ^ (value >> 30n)) * 0xbf58476d1ce4e5b9n);
  value = u64((value ^ (value >> 27n)) * 0x94d049bb133111ebn);
  return u64(value ^ (value >> 31n));
}

function bounded(state, modulus) {
  return splitmix64(state) % modulus;
}

function evaluate(workload, state) {
  if (workload === "cost-model") {
    const tokens = bounded(state, 1000n) + 1n;
    const price = bounded(state, 100n) + 1n;
    const storage = bounded(state, 1000n);
    return tokens * price + storage;
  }
  if (workload === "dispatch-decision") {
    const load = bounded(state, 1000n);
    const limit = bounded(state, 1000n);
    const authorized = splitmix64(state) & 1n;
    return load <= limit && authorized !== 0n ? 1n : 0n;
  }
  if (workload === "route-score") {
    const signal = bounded(state, 1000n);
    const confidence = bounded(state, 100n) + 1n;
    return (signal + 1n) * confidence - signal;
  }
  if (workload === "split-budget") {
    const total = bounded(state, 1000000n) + 1n;
    const workers = bounded(state, 64n) + 1n;
    return total / workers + total % workers;
  }
  if (workload === "deadline-slack") {
    const deadline = 1000000n + bounded(state, 500000n);
    const elapsed = bounded(state, 500000n);
    const reserve = bounded(state, 1000n);
    return deadline - elapsed - reserve;
  }
  fail(`unknown workload: ${workload}`);
}

const [workload, iterationsText, seedText] = process.argv.slice(2);
if (!(workload in INSTRUCTIONS)) fail("usage: native-benchmark-oracle.mjs <workload> <iterations> <seed>");
if (!/^[1-9][0-9]{0,7}$/.test(iterationsText ?? "")) fail("iterations are invalid");
if (!/^(0|[1-9][0-9]{0,19})$/.test(seedText ?? "")) fail("seed is invalid");
const iterations = BigInt(iterationsText);
if (iterations > 10000000n) fail("iterations exceed the oracle limit");
const seed = BigInt(seedText);
if (seed > U64_MASK) fail("seed exceeds u64");

const state = { value: seed };
let checksum = FNV_OFFSET;
for (let index = 0n; index < iterations; index += 1n) {
  checksum = u64((checksum ^ u64(evaluate(workload, state))) * FNV_PRIME);
}

process.stdout.write(`${JSON.stringify({
  schema: "joan.native-benchmark-oracle-observation.v0",
  status: "completed",
  workload,
  iterations: Number(iterations),
  seed: seed.toString(),
  checksum: checksum.toString(16).padStart(16, "0"),
  instructions_executed: Number(INSTRUCTIONS[workload] * iterations),
})}\n`);
