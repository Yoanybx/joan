#define _POSIX_C_SOURCE 200809L

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__clang__) || defined(__GNUC__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

static const uint64_t FNV_OFFSET = UINT64_C(0xcbf29ce484222325);
static const uint64_t FNV_PRIME = UINT64_C(0x00000100000001b3);
static const uint64_t WARMUP_ITERATIONS = UINT64_C(256);
static const uint64_t INSTRUCTION_BUDGET = UINT64_C(128);

struct kernel_result {
    int status;
    int64_t value;
    uint64_t instructions;
};

enum workload_kind {
    WORKLOAD_COST_MODEL,
    WORKLOAD_DISPATCH_DECISION,
    WORKLOAD_ROUTE_SCORE,
    WORKLOAD_SPLIT_BUDGET,
    WORKLOAD_DEADLINE_SLACK
};

static int parse_workload(const char *name, enum workload_kind *workload) {
    if (strcmp(name, "cost-model") == 0) *workload = WORKLOAD_COST_MODEL;
    else if (strcmp(name, "dispatch-decision") == 0) *workload = WORKLOAD_DISPATCH_DECISION;
    else if (strcmp(name, "route-score") == 0) *workload = WORKLOAD_ROUTE_SCORE;
    else if (strcmp(name, "split-budget") == 0) *workload = WORKLOAD_SPLIT_BUDGET;
    else if (strcmp(name, "deadline-slack") == 0) *workload = WORKLOAD_DEADLINE_SLACK;
    else return 0;
    return 1;
}

static int charge(volatile uint64_t *fuel) {
    if (*fuel == 0) return 0;
    *fuel -= UINT64_C(1);
    return 1;
}

#define CHARGE_OR_RETURN(fuel, instructions) \
    do { \
        if (!charge(fuel)) return (struct kernel_result){1, INT64_C(0), instructions}; \
        instructions += UINT64_C(1); \
    } while (0)

static uint64_t splitmix64(uint64_t *state) {
    uint64_t value;
    *state += UINT64_C(0x9e3779b97f4a7c15);
    value = *state;
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

static int64_t bounded(uint64_t *state, uint64_t modulus) {
    return (int64_t)(splitmix64(state) % modulus);
}

static NOINLINE struct kernel_result adjusted_signal(int64_t signal, volatile uint64_t *fuel) {
    uint64_t instructions = 0;
    int64_t result;
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    if (__builtin_add_overflow(signal, INT64_C(1), &result)) return (struct kernel_result){2, 0, instructions};
    CHARGE_OR_RETURN(fuel, instructions);
    return (struct kernel_result){0, result, instructions};
}

static NOINLINE struct kernel_result cost_model(int64_t tokens, int64_t price, int64_t storage, volatile uint64_t *fuel) {
    uint64_t instructions = 0;
    int64_t product;
    int64_t result;
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    if (__builtin_mul_overflow(tokens, price, &product)) return (struct kernel_result){2, 0, instructions};
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    if (__builtin_add_overflow(product, storage, &result)) return (struct kernel_result){2, 0, instructions};
    CHARGE_OR_RETURN(fuel, instructions);
    return (struct kernel_result){0, result, instructions};
}

static NOINLINE struct kernel_result deadline_slack(int64_t deadline, int64_t elapsed, int64_t reserve, volatile uint64_t *fuel) {
    uint64_t instructions = 0;
    int64_t first;
    int64_t result;
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    if (__builtin_sub_overflow(deadline, elapsed, &first)) return (struct kernel_result){2, 0, instructions};
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    if (__builtin_sub_overflow(first, reserve, &result)) return (struct kernel_result){2, 0, instructions};
    CHARGE_OR_RETURN(fuel, instructions);
    return (struct kernel_result){0, result, instructions};
}

static NOINLINE struct kernel_result dispatch_decision(int64_t load, int64_t limit, int64_t authorized, volatile uint64_t *fuel) {
    uint64_t instructions = 0;
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    int64_t within_limit = load <= limit;
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    int64_t result = within_limit && authorized != 0;
    CHARGE_OR_RETURN(fuel, instructions);
    return (struct kernel_result){0, result, instructions};
}

static NOINLINE struct kernel_result route_score(int64_t signal, int64_t confidence, volatile uint64_t *fuel) {
    uint64_t instructions = 0;
    int64_t product;
    int64_t result;
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    struct kernel_result adjusted = adjusted_signal(signal, fuel);
    if (adjusted.status != 0) return (struct kernel_result){adjusted.status, 0, instructions + adjusted.instructions};
    instructions += adjusted.instructions;
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    if (__builtin_mul_overflow(adjusted.value, confidence, &product)) return (struct kernel_result){2, 0, instructions};
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    if (__builtin_sub_overflow(product, signal, &result)) return (struct kernel_result){2, 0, instructions};
    CHARGE_OR_RETURN(fuel, instructions);
    return (struct kernel_result){0, result, instructions};
}

static NOINLINE struct kernel_result split_budget(int64_t total, int64_t workers, volatile uint64_t *fuel) {
    uint64_t instructions = 0;
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    if (workers == 0 || (total == INT64_MIN && workers == -1)) return (struct kernel_result){2, 0, instructions};
    int64_t quotient = total / workers;
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    CHARGE_OR_RETURN(fuel, instructions);
    if (workers == 0 || (total == INT64_MIN && workers == -1)) return (struct kernel_result){2, 0, instructions};
    int64_t remainder = total % workers;
    CHARGE_OR_RETURN(fuel, instructions);
    int64_t result;
    if (__builtin_add_overflow(quotient, remainder, &result)) return (struct kernel_result){2, 0, instructions};
    CHARGE_OR_RETURN(fuel, instructions);
    return (struct kernel_result){0, result, instructions};
}

static struct kernel_result execute(enum workload_kind workload, uint64_t *state) {
    volatile uint64_t fuel = INSTRUCTION_BUDGET;
    switch (workload) {
    case WORKLOAD_COST_MODEL: {
        int64_t tokens = bounded(state, 1000) + 1;
        int64_t price = bounded(state, 100) + 1;
        int64_t storage = bounded(state, 1000);
        return cost_model(tokens, price, storage, &fuel);
    }
    case WORKLOAD_DISPATCH_DECISION: {
        int64_t load = bounded(state, 1000);
        int64_t limit = bounded(state, 1000);
        int64_t authorized = (int64_t)(splitmix64(state) & 1);
        return dispatch_decision(load, limit, authorized, &fuel);
    }
    case WORKLOAD_ROUTE_SCORE: {
        int64_t signal = bounded(state, 1000);
        int64_t confidence = bounded(state, 100) + 1;
        return route_score(signal, confidence, &fuel);
    }
    case WORKLOAD_SPLIT_BUDGET: {
        int64_t total = bounded(state, 1000000) + 1;
        int64_t workers = bounded(state, 64) + 1;
        return split_budget(total, workers, &fuel);
    }
    case WORKLOAD_DEADLINE_SLACK: {
        int64_t deadline = INT64_C(1000000) + bounded(state, 500000);
        int64_t elapsed = bounded(state, 500000);
        int64_t reserve = bounded(state, 1000);
        return deadline_slack(deadline, elapsed, reserve, &fuel);
    }
    }
    return (struct kernel_result){2, 0, 0};
}

static uint64_t elapsed_ns(struct timespec start, struct timespec end) {
    uint64_t seconds = (uint64_t)(end.tv_sec - start.tv_sec);
    int64_t nanoseconds = (int64_t)end.tv_nsec - (int64_t)start.tv_nsec;
    if (nanoseconds < 0) {
        seconds -= UINT64_C(1);
        nanoseconds += INT64_C(1000000000);
    }
    return seconds * UINT64_C(1000000000) + (uint64_t)nanoseconds;
}

int main(int argc, char **argv) {
    char *end = NULL;
    uint64_t iterations;
    uint64_t seed;
    uint64_t state;
    uint64_t checksum = FNV_OFFSET;
    uint64_t instructions = 0;
    enum workload_kind workload;
    struct timespec start;
    struct timespec finish;
    if (argc != 4) {
        fprintf(stderr, "usage: kernels <workload> <iterations> <seed>\n");
        return 2;
    }
    if (!parse_workload(argv[1], &workload)) return 2;
    iterations = strtoull(argv[2], &end, 10);
    if (end == argv[2] || *end != '\0' || iterations == 0 || iterations > UINT64_C(10000000)) return 2;
    seed = strtoull(argv[3], &end, 10);
    if (end == argv[3] || *end != '\0') return 2;

    state = seed ^ UINT64_C(0x4a4f414e4c313600);
    for (uint64_t index = 0; index < WARMUP_ITERATIONS; ++index) {
        struct kernel_result result = execute(workload, &state);
        if (result.status != 0) return 4;
    }
    state = seed;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) return 3;
    for (uint64_t index = 0; index < iterations; ++index) {
        struct kernel_result result = execute(workload, &state);
        if (result.status != 0) return 4;
        checksum = (checksum ^ (uint64_t)result.value) * FNV_PRIME;
        instructions += result.instructions;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &finish) != 0) return 3;
    printf("{\"checksum\":\"%016" PRIx64 "\",\"instructions_executed\":%" PRIu64 ",\"iterations\":%" PRIu64 ",\"runtime_ns\":%" PRIu64 ",\"status\":\"completed\",\"workload\":\"%s\"}\n",
           checksum, instructions, iterations, elapsed_ns(start, finish), argv[1]);
    return 0;
}
