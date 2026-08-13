use std::env;
use std::time::Instant;

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
const WARMUP_ITERATIONS: u64 = 256;
const INSTRUCTION_BUDGET: u64 = 128;

#[derive(Clone, Copy)]
struct KernelResult {
    status: u8,
    value: i64,
    instructions: u64,
}

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
}

#[inline(always)]
fn charge(fuel: &mut u64) -> bool {
    let observed = *std::hint::black_box(&mut *fuel);
    if observed == 0 {
        return false;
    }
    *std::hint::black_box(&mut *fuel) = observed - 1;
    true
}

macro_rules! charge_or_return {
    ($fuel:expr, $instructions:expr) => {
        if !charge($fuel) {
            return KernelResult {
                status: 1,
                value: 0,
                instructions: $instructions,
            };
        }
        $instructions += 1;
    };
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn bounded(state: &mut u64, modulus: u64) -> i64 {
    i64::try_from(splitmix64(state) % modulus).unwrap_or(0)
}

#[inline(never)]
fn adjusted_signal(signal: i64, fuel: &mut u64) -> KernelResult {
    let mut instructions = 0;
    charge_or_return!(fuel, instructions);
    charge_or_return!(fuel, instructions);
    charge_or_return!(fuel, instructions);
    let Some(result) = signal.checked_add(1) else {
        return KernelResult {
            status: 2,
            value: 0,
            instructions,
        };
    };
    charge_or_return!(fuel, instructions);
    KernelResult {
        status: 0,
        value: result,
        instructions,
    }
}

#[inline(never)]
fn cost_model(tokens: i64, price: i64, storage: i64, fuel: &mut u64) -> KernelResult {
    let mut instructions = 0;
    charge_or_return!(fuel, instructions);
    charge_or_return!(fuel, instructions);
    charge_or_return!(fuel, instructions);
    let Some(product) = tokens.checked_mul(price) else {
        return KernelResult {
            status: 2,
            value: 0,
            instructions,
        };
    };
    charge_or_return!(fuel, instructions);
    charge_or_return!(fuel, instructions);
    let Some(result) = product.checked_add(storage) else {
        return KernelResult {
            status: 2,
            value: 0,
            instructions,
        };
    };
    charge_or_return!(fuel, instructions);
    KernelResult {
        status: 0,
        value: result,
        instructions,
    }
}

#[inline(never)]
fn deadline_slack(deadline: i64, elapsed: i64, reserve: i64, fuel: &mut u64) -> KernelResult {
    let mut instructions = 0;
    charge_or_return!(fuel, instructions);
    charge_or_return!(fuel, instructions);
    charge_or_return!(fuel, instructions);
    let Some(first) = deadline.checked_sub(elapsed) else {
        return KernelResult {
            status: 2,
            value: 0,
            instructions,
        };
    };
    charge_or_return!(fuel, instructions);
    charge_or_return!(fuel, instructions);
    let Some(result) = first.checked_sub(reserve) else {
        return KernelResult {
            status: 2,
            value: 0,
            instructions,
        };
    };
    charge_or_return!(fuel, instructions);
    KernelResult {
        status: 0,
        value: result,
        instructions,
    }
}

#[inline(never)]
fn dispatch_decision(load: i64, limit: i64, authorized: i64, fuel: &mut u64) -> KernelResult {
    let mut instructions = 0;
    charge_or_return!(fuel, instructions);
    charge_or_return!(fuel, instructions);
    charge_or_return!(fuel, instructions);
    let within_limit = load <= limit;
    charge_or_return!(fuel, instructions);
    charge_or_return!(fuel, instructions);
    let result = i64::from(within_limit && authorized != 0);
    charge_or_return!(fuel, instructions);
    KernelResult {
        status: 0,
        value: result,
        instructions,
    }
}

#[inline(never)]
fn route_score(signal: i64, confidence: i64, fuel: &mut u64) -> KernelResult {
    let mut instructions = 0;
    charge_or_return!(fuel, instructions);
    charge_or_return!(fuel, instructions);
    let adjusted = adjusted_signal(signal, fuel);
    instructions += adjusted.instructions;
    if adjusted.status != 0 {
        return KernelResult {
            status: adjusted.status,
            value: 0,
            instructions,
        };
    }
    charge_or_return!(fuel, instructions);
    charge_or_return!(fuel, instructions);
    let Some(product) = adjusted.value.checked_mul(confidence) else {
        return KernelResult {
            status: 2,
            value: 0,
            instructions,
        };
    };
    charge_or_return!(fuel, instructions);
    charge_or_return!(fuel, instructions);
    let Some(result) = product.checked_sub(signal) else {
        return KernelResult {
            status: 2,
            value: 0,
            instructions,
        };
    };
    charge_or_return!(fuel, instructions);
    KernelResult {
        status: 0,
        value: result,
        instructions,
    }
}

#[inline(never)]
fn split_budget(total: i64, workers: i64, fuel: &mut u64) -> KernelResult {
    let mut instructions = 0;
    charge_or_return!(fuel, instructions);
    charge_or_return!(fuel, instructions);
    charge_or_return!(fuel, instructions);
    let Some(quotient) = total.checked_div(workers) else {
        return KernelResult {
            status: 2,
            value: 0,
            instructions,
        };
    };
    charge_or_return!(fuel, instructions);
    charge_or_return!(fuel, instructions);
    charge_or_return!(fuel, instructions);
    let Some(remainder) = total.checked_rem(workers) else {
        return KernelResult {
            status: 2,
            value: 0,
            instructions,
        };
    };
    charge_or_return!(fuel, instructions);
    let Some(result) = quotient.checked_add(remainder) else {
        return KernelResult {
            status: 2,
            value: 0,
            instructions,
        };
    };
    charge_or_return!(fuel, instructions);
    KernelResult {
        status: 0,
        value: result,
        instructions,
    }
}

fn execute(workload: Workload, state: &mut u64) -> KernelResult {
    let mut fuel = INSTRUCTION_BUDGET;
    match workload {
        Workload::CostModel => {
            let tokens = bounded(state, 1_000) + 1;
            let price = bounded(state, 100) + 1;
            let storage = bounded(state, 1_000);
            cost_model(tokens, price, storage, &mut fuel)
        }
        Workload::DispatchDecision => {
            let load = bounded(state, 1_000);
            let limit = bounded(state, 1_000);
            let authorized = i64::try_from(splitmix64(state) & 1).unwrap_or(0);
            dispatch_decision(load, limit, authorized, &mut fuel)
        }
        Workload::RouteScore => {
            let signal = bounded(state, 1_000);
            let confidence = bounded(state, 100) + 1;
            route_score(signal, confidence, &mut fuel)
        }
        Workload::SplitBudget => {
            let total = bounded(state, 1_000_000) + 1;
            let workers = bounded(state, 64) + 1;
            split_budget(total, workers, &mut fuel)
        }
        Workload::DeadlineSlack => {
            let deadline = 1_000_000 + bounded(state, 500_000);
            let elapsed = bounded(state, 500_000);
            let reserve = bounded(state, 1_000);
            deadline_slack(deadline, elapsed, reserve, &mut fuel)
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args().collect::<Vec<_>>();
    if arguments.len() != 4 {
        return Err("usage: kernels <workload> <iterations> <seed>".into());
    }
    let workload_name = &arguments[1];
    let workload = Workload::parse(workload_name)?;
    let iterations = arguments[2].parse::<u64>()?;
    let seed = arguments[3].parse::<u64>()?;
    if iterations == 0 || iterations > 10_000_000 {
        return Err("iterations must be between 1 and 10000000".into());
    }
    let mut state = seed ^ 0x4a4f_414e_4c31_3600;
    for _ in 0..WARMUP_ITERATIONS {
        if execute(workload, &mut state).status != 0 {
            return Err("warmup failed".into());
        }
    }
    state = seed;
    let mut checksum = FNV_OFFSET;
    let mut instructions = 0_u64;
    let started = Instant::now();
    for _ in 0..iterations {
        let result = execute(workload, &mut state);
        if result.status != 0 {
            return Err("kernel execution failed".into());
        }
        checksum =
            (checksum ^ u64::from_ne_bytes(result.value.to_ne_bytes())).wrapping_mul(FNV_PRIME);
        instructions += result.instructions;
    }
    let runtime_ns = u64::try_from(started.elapsed().as_nanos())?;
    println!(
        "{{\"checksum\":\"{checksum:016x}\",\"instructions_executed\":{instructions},\"iterations\":{iterations},\"runtime_ns\":{runtime_ns},\"status\":\"completed\",\"workload\":\"{workload_name}\"}}"
    );
    Ok(())
}
