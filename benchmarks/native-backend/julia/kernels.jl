const FNV_OFFSET = UInt64(0xcbf29ce484222325)
const FNV_PRIME = UInt64(0x00000100000001b3)
const WARMUP_ITERATIONS = 256
const INSTRUCTION_BUDGET = UInt64(128)

function splitmix64(state::Base.RefValue{UInt64})::UInt64
    state[] += UInt64(0x9e3779b97f4a7c15)
    value = state[]
    value = (value ⊻ (value >> 30)) * UInt64(0xbf58476d1ce4e5b9)
    value = (value ⊻ (value >> 27)) * UInt64(0x94d049bb133111eb)
    value ⊻ (value >> 31)
end

bounded(state, modulus) = Int64(splitmix64(state) % UInt64(modulus))

function charge!(fuel)
    fuel[] == 0 && error("instruction budget exhausted")
    fuel[] -= UInt64(1)
end

function adjusted_signal(signal, fuel)
    charge!(fuel); charge!(fuel); charge!(fuel)
    result = Base.Checked.checked_add(signal, Int64(1))
    charge!(fuel)
    (result, UInt64(4))
end

function cost_model(tokens, price, storage, fuel)
    charge!(fuel); charge!(fuel); charge!(fuel)
    product = Base.Checked.checked_mul(tokens, price)
    charge!(fuel); charge!(fuel)
    result = Base.Checked.checked_add(product, storage)
    charge!(fuel)
    (result, UInt64(6))
end

function deadline_slack(deadline, elapsed, reserve, fuel)
    charge!(fuel); charge!(fuel); charge!(fuel)
    first = Base.Checked.checked_sub(deadline, elapsed)
    charge!(fuel); charge!(fuel)
    result = Base.Checked.checked_sub(first, reserve)
    charge!(fuel)
    (result, UInt64(6))
end

function dispatch_decision(load, limit, authorized, fuel)
    charge!(fuel); charge!(fuel); charge!(fuel)
    within_limit = load <= limit
    charge!(fuel); charge!(fuel)
    result = Int64(within_limit && authorized != 0)
    charge!(fuel)
    (result, UInt64(6))
end

function route_score(signal, confidence, fuel)
    charge!(fuel); charge!(fuel)
    adjusted, adjusted_instructions = adjusted_signal(signal, fuel)
    charge!(fuel); charge!(fuel)
    product = Base.Checked.checked_mul(adjusted, confidence)
    charge!(fuel); charge!(fuel)
    result = Base.Checked.checked_sub(product, signal)
    charge!(fuel)
    (result, UInt64(7) + adjusted_instructions)
end

function split_budget(total, workers, fuel)
    charge!(fuel); charge!(fuel); charge!(fuel)
    quotient = Base.Checked.checked_div(total, workers)
    charge!(fuel); charge!(fuel); charge!(fuel)
    remainder = Base.Checked.checked_rem(total, workers)
    charge!(fuel)
    result = Base.Checked.checked_add(quotient, remainder)
    charge!(fuel)
    (result, UInt64(8))
end

function execute(workload::Symbol, state)
    fuel = Ref(INSTRUCTION_BUDGET)
    if workload === :cost_model
        tokens = bounded(state, 1000) + 1
        price = bounded(state, 100) + 1
        storage = bounded(state, 1000)
        return cost_model(tokens, price, storage, fuel)
    end
    if workload === :dispatch_decision
        load = bounded(state, 1000)
        limit = bounded(state, 1000)
        authorized = Int64(splitmix64(state) & 1)
        return dispatch_decision(load, limit, authorized, fuel)
    end
    if workload === :route_score
        signal = bounded(state, 1000)
        confidence = bounded(state, 100) + 1
        return route_score(signal, confidence, fuel)
    end
    if workload === :split_budget
        total = bounded(state, 1000000) + 1
        workers = bounded(state, 64) + 1
        return split_budget(total, workers, fuel)
    end
    if workload === :deadline_slack
        deadline = 1000000 + bounded(state, 500000)
        elapsed = bounded(state, 500000)
        reserve = bounded(state, 1000)
        return deadline_slack(deadline, elapsed, reserve, fuel)
    end
    error("unknown native benchmark workload")
end

length(ARGS) == 3 || error("usage: kernels.jl <workload> <iterations> <seed>")
workload_name = ARGS[1]
workload = Symbol(replace(workload_name, "-" => "_"))
workload in (:cost_model, :dispatch_decision, :route_score, :split_budget, :deadline_slack) ||
    error("unknown native benchmark workload")
iterations = parse(UInt64, ARGS[2])
seed = parse(UInt64, ARGS[3])
state = Ref(seed ⊻ UInt64(0x4a4f414e4c313600))
for _ in 1:WARMUP_ITERATIONS
    execute(workload, state)
end
state[] = seed
checksum = FNV_OFFSET
instructions = UInt64(0)
started = time_ns()
for _ in UInt64(1):iterations
    value, observed_instructions = execute(workload, state)
    checksum = (checksum ⊻ reinterpret(UInt64, value)) * FNV_PRIME
    instructions += observed_instructions
end
runtime_ns = time_ns() - started
println("{\"checksum\":\"", string(checksum, base=16, pad=16),
        "\",\"instructions_executed\":", instructions,
        ",\"iterations\":", iterations,
        ",\"runtime_ns\":", runtime_ns,
        ",\"status\":\"completed\",\"workload\":\"", workload_name, "\"}")
