//! Bounded in-process runner for the JOAN native-backend comparison corpus.

use joan_compiler::compile_source;
use joan_native::compile_bytecode;
use serde::Serialize;
use std::env;
use std::fs;
use std::time::Instant;

const WARMUP_ITERATIONS: u64 = 256;
const INSTRUCTION_BUDGET: u64 = 128;
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

#[derive(Clone, Copy)]
enum Workload {
    CostModel,
    DispatchDecision,
    RouteScore,
    SplitBudget,
    DeadlineSlack,
}

impl Workload {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "cost-model" => Ok(Self::CostModel),
            "dispatch-decision" => Ok(Self::DispatchDecision),
            "route-score" => Ok(Self::RouteScore),
            "split-budget" => Ok(Self::SplitBudget),
            "deadline-slack" => Ok(Self::DeadlineSlack),
            _ => Err(format!("unknown native benchmark workload `{value}`")),
        }
    }

    const fn function(self) -> &'static str {
        match self {
            Self::CostModel => "cost_model",
            Self::DispatchDecision => "dispatch_decision",
            Self::RouteScore => "route_score",
            Self::SplitBudget => "split_budget",
            Self::DeadlineSlack => "deadline_slack",
        }
    }

    const fn id(self) -> &'static str {
        match self {
            Self::CostModel => "cost-model",
            Self::DispatchDecision => "dispatch-decision",
            Self::RouteScore => "route-score",
            Self::SplitBudget => "split-budget",
            Self::DeadlineSlack => "deadline-slack",
        }
    }

    fn arguments(self, state: &mut u64) -> ([i64; 3], usize) {
        match self {
            Self::CostModel => (
                [
                    bounded(state, 1_000) + 1,
                    bounded(state, 100) + 1,
                    bounded(state, 1_000),
                ],
                3,
            ),
            Self::DispatchDecision => (
                [
                    bounded(state, 1_000),
                    bounded(state, 1_000),
                    i64::from(splitmix64(state) & 1 == 1),
                ],
                3,
            ),
            Self::RouteScore => ([bounded(state, 1_000), bounded(state, 100) + 1, 0], 2),
            Self::SplitBudget => (
                [bounded(state, 1_000_000) + 1, bounded(state, 64) + 1, 0],
                2,
            ),
            Self::DeadlineSlack => (
                [
                    1_000_000 + bounded(state, 500_000),
                    bounded(state, 500_000),
                    bounded(state, 1_000),
                ],
                3,
            ),
        }
    }
}

#[derive(Serialize)]
struct BenchmarkOutput {
    schema: &'static str,
    status: &'static str,
    workload: &'static str,
    iterations: u64,
    seed: String,
    checksum: String,
    compile_ns: u64,
    runtime_ns: u64,
    instructions_executed: u64,
    artifact_digest: String,
    generated_code_bytes: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args().collect::<Vec<_>>();
    if arguments.len() != 5 {
        return Err(
            "usage: joan-native-bench <program.joan> <workload> <iterations> <seed>".into(),
        );
    }
    let source = fs::read_to_string(&arguments[1])?;
    let workload = Workload::parse(&arguments[2])?;
    let iterations = arguments[3].parse::<u64>()?;
    if iterations == 0 || iterations > 10_000_000 {
        return Err("iterations must be between 1 and 10000000".into());
    }
    let seed = arguments[4].parse::<u64>()?;

    let compile_started = Instant::now();
    let artifact = compile_source(&source)?;
    let native = compile_bytecode(&artifact.bytecode)?;
    let prepared = native.prepare(workload.function())?;
    let compile_ns = nanos(compile_started.elapsed().as_nanos())?;

    let mut warmup_state = seed ^ 0x4a4f_414e_4c31_3600;
    for _ in 0..WARMUP_ITERATIONS {
        let (values, count) = workload.arguments(&mut warmup_state);
        prepared.invoke_normalized(&values[..count], INSTRUCTION_BUDGET)?;
    }

    let mut state = seed;
    let mut checksum = FNV_OFFSET;
    let mut instructions_executed = 0_u64;
    let runtime_started = Instant::now();
    for _ in 0..iterations {
        let (values, count) = workload.arguments(&mut state);
        let receipt = prepared.invoke_normalized(&values[..count], INSTRUCTION_BUDGET)?;
        checksum = update_checksum(checksum, receipt.normalized_value);
        instructions_executed = instructions_executed
            .checked_add(receipt.instructions_executed)
            .ok_or("instruction counter overflow")?;
    }
    let runtime_ns = nanos(runtime_started.elapsed().as_nanos())?;
    let output = BenchmarkOutput {
        schema: "joan.native-kernel-observation.v0",
        status: "completed",
        workload: workload.id(),
        iterations,
        seed: seed.to_string(),
        checksum: format!("{checksum:016x}"),
        compile_ns,
        runtime_ns,
        instructions_executed,
        artifact_digest: native.receipt().artifact_digest.value.clone(),
        generated_code_bytes: native.receipt().code_bytes,
    };
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

fn bounded(state: &mut u64, modulus: u64) -> i64 {
    i64::try_from(splitmix64(state) % modulus).unwrap_or(0)
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn update_checksum(current: u64, value: i64) -> u64 {
    (current ^ u64::from_ne_bytes(value.to_ne_bytes())).wrapping_mul(FNV_PRIME)
}

fn nanos(value: u128) -> Result<u64, Box<dyn std::error::Error>> {
    Ok(u64::try_from(value).map_err(|_| "duration exceeds u64 nanoseconds")?)
}
