#include <chrono>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

#if defined(__clang__) || defined(__GNUC__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

constexpr std::uint64_t FNV_OFFSET = UINT64_C(0xcbf29ce484222325);
constexpr std::uint64_t FNV_PRIME = UINT64_C(0x00000100000001b3);
constexpr std::uint64_t WARMUP_ITERATIONS = UINT64_C(256);
constexpr std::uint64_t INSTRUCTION_BUDGET = UINT64_C(128);

struct KernelResult {
    int status;
    std::int64_t value;
    std::uint64_t instructions;
};

enum class Workload {
    CostModel,
    DispatchDecision,
    RouteScore,
    SplitBudget,
    DeadlineSlack,
};

Workload parse_workload(std::string_view name) {
    if (name == "cost-model") return Workload::CostModel;
    if (name == "dispatch-decision") return Workload::DispatchDecision;
    if (name == "route-score") return Workload::RouteScore;
    if (name == "split-budget") return Workload::SplitBudget;
    if (name == "deadline-slack") return Workload::DeadlineSlack;
    throw std::invalid_argument("unknown native benchmark workload");
}

bool charge(volatile std::uint64_t &fuel) {
    if (fuel == 0) return false;
    fuel = fuel - UINT64_C(1);
    return true;
}

#define CHARGE_OR_RETURN(fuel, instructions) \
    do { \
        if (!charge(fuel)) return KernelResult{1, INT64_C(0), instructions}; \
        instructions += UINT64_C(1); \
    } while (false)

std::uint64_t splitmix64(std::uint64_t &state) {
    state += UINT64_C(0x9e3779b97f4a7c15);
    auto value = state;
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

std::int64_t bounded(std::uint64_t &state, std::uint64_t modulus) {
    return static_cast<std::int64_t>(splitmix64(state) % modulus);
}

NOINLINE KernelResult adjusted_signal(std::int64_t signal, volatile std::uint64_t &fuel) {
    std::uint64_t instructions = 0;
    std::int64_t result;
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    if (__builtin_add_overflow(signal, INT64_C(1), &result)) return {2, 0, instructions};
    CHARGE_OR_RETURN(fuel, instructions);
    return {0, result, instructions};
}

NOINLINE KernelResult cost_model(std::int64_t tokens, std::int64_t price, std::int64_t storage, volatile std::uint64_t &fuel) {
    std::uint64_t instructions = 0;
    std::int64_t product;
    std::int64_t result;
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    if (__builtin_mul_overflow(tokens, price, &product)) return {2, 0, instructions};
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    if (__builtin_add_overflow(product, storage, &result)) return {2, 0, instructions};
    CHARGE_OR_RETURN(fuel, instructions);
    return {0, result, instructions};
}

NOINLINE KernelResult deadline_slack(std::int64_t deadline, std::int64_t elapsed, std::int64_t reserve, volatile std::uint64_t &fuel) {
    std::uint64_t instructions = 0;
    std::int64_t first;
    std::int64_t result;
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    if (__builtin_sub_overflow(deadline, elapsed, &first)) return {2, 0, instructions};
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    if (__builtin_sub_overflow(first, reserve, &result)) return {2, 0, instructions};
    CHARGE_OR_RETURN(fuel, instructions);
    return {0, result, instructions};
}

NOINLINE KernelResult dispatch_decision(std::int64_t load, std::int64_t limit, std::int64_t authorized, volatile std::uint64_t &fuel) {
    std::uint64_t instructions = 0;
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    const std::int64_t within_limit = load <= limit;
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    const std::int64_t result = within_limit && authorized != 0;
    CHARGE_OR_RETURN(fuel, instructions);
    return {0, result, instructions};
}

NOINLINE KernelResult route_score(std::int64_t signal, std::int64_t confidence, volatile std::uint64_t &fuel) {
    std::uint64_t instructions = 0;
    std::int64_t product;
    std::int64_t result;
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    auto adjusted = adjusted_signal(signal, fuel);
    if (adjusted.status != 0) return {adjusted.status, 0, instructions + adjusted.instructions};
    instructions += adjusted.instructions;
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    if (__builtin_mul_overflow(adjusted.value, confidence, &product)) return {2, 0, instructions};
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    if (__builtin_sub_overflow(product, signal, &result)) return {2, 0, instructions};
    CHARGE_OR_RETURN(fuel, instructions);
    return {0, result, instructions};
}

NOINLINE KernelResult split_budget(std::int64_t total, std::int64_t workers, volatile std::uint64_t &fuel) {
    std::uint64_t instructions = 0;
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    if (workers == 0 || (total == INT64_MIN && workers == -1)) return {2, 0, instructions};
    const auto quotient = total / workers;
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    if (workers == 0 || (total == INT64_MIN && workers == -1)) return {2, 0, instructions};
    const auto remainder = total % workers;
    CHARGE_OR_RETURN(fuel, instructions);
    std::int64_t result;
    if (__builtin_add_overflow(quotient, remainder, &result)) return {2, 0, instructions};
    CHARGE_OR_RETURN(fuel, instructions);
    return {0, result, instructions};
}

KernelResult execute(Workload workload, std::uint64_t &state) {
    volatile std::uint64_t fuel = INSTRUCTION_BUDGET;
    switch (workload) {
    case Workload::CostModel: {
        const auto tokens = bounded(state, 1000) + 1;
        const auto price = bounded(state, 100) + 1;
        const auto storage = bounded(state, 1000);
        return cost_model(tokens, price, storage, fuel);
    }
    case Workload::DispatchDecision: {
        const auto load = bounded(state, 1000);
        const auto limit = bounded(state, 1000);
        const auto authorized = static_cast<std::int64_t>(splitmix64(state) & 1);
        return dispatch_decision(load, limit, authorized, fuel);
    }
    case Workload::RouteScore: {
        const auto signal = bounded(state, 1000);
        const auto confidence = bounded(state, 100) + 1;
        return route_score(signal, confidence, fuel);
    }
    case Workload::SplitBudget: {
        const auto total = bounded(state, 1000000) + 1;
        const auto workers = bounded(state, 64) + 1;
        return split_budget(total, workers, fuel);
    }
    case Workload::DeadlineSlack: {
        const auto deadline = 1000000 + bounded(state, 500000);
        const auto elapsed = bounded(state, 500000);
        const auto reserve = bounded(state, 1000);
        return deadline_slack(deadline, elapsed, reserve, fuel);
    }
    }
    throw std::invalid_argument("invalid native benchmark workload");
}

int main(int argc, char **argv) {
    if (argc != 4) {
        std::cerr << "usage: kernels <workload> <iterations> <seed>\n";
        return 2;
    }
    try {
        const std::string_view workload_name(argv[1]);
        const auto workload = parse_workload(workload_name);
        const auto iterations = std::stoull(argv[2]);
        const auto seed = std::stoull(argv[3]);
        if (iterations == 0 || iterations > UINT64_C(10000000)) return 2;
        auto state = seed ^ UINT64_C(0x4a4f414e4c313600);
        for (std::uint64_t index = 0; index < WARMUP_ITERATIONS; ++index) {
            if (execute(workload, state).status != 0) return 4;
        }
        state = seed;
        auto checksum = FNV_OFFSET;
        std::uint64_t instructions = 0;
        const auto started = std::chrono::steady_clock::now();
        for (std::uint64_t index = 0; index < iterations; ++index) {
            const auto result = execute(workload, state);
            if (result.status != 0) return 4;
            checksum = (checksum ^ static_cast<std::uint64_t>(result.value)) * FNV_PRIME;
            instructions += result.instructions;
        }
        const auto runtime = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - started).count();
        std::cout << "{\"checksum\":\"" << std::hex << std::setw(16) << std::setfill('0') << checksum
                  << "\",\"instructions_executed\":" << std::dec << instructions
                  << ",\"iterations\":" << iterations << ",\"runtime_ns\":" << runtime
                  << ",\"status\":\"completed\",\"workload\":\"" << workload_name << "\"}\n";
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 2;
    }
    return 0;
}
