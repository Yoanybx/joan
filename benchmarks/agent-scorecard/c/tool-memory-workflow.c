#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    const char *effect;
    bool consumed;
} authority_slot;

static bool consume(authority_slot *slot, const char *effect) {
    if (slot->consumed || strcmp(slot->effect, effect) != 0) {
        return false;
    }
    slot->consumed = true;
    return true;
}

int main(void) {
    authority_slot api_once = {.effect = "api_call", .consumed = false};
    authority_slot memory_once = {.effect = "memory_write", .consumed = false};
    const long long result = 6LL * 7LL;
    if (!consume(&api_once, "api_call") || !consume(&memory_once, "memory_write")) {
        return 2;
    }
    printf("{\"effect_requests\":[{\"arguments\":[{\"type\":\"string\",\"value\":\"model\"},{\"type\":\"i64\",\"value\":\"%lld\"}],\"authority_slot\":\"api_once\",\"effect\":\"api_call\",\"information\":{\"class\":\"public\"}},{\"arguments\":[{\"type\":\"string\",\"value\":\"session\"},{\"type\":\"i64\",\"value\":\"%lld\"}],\"authority_slot\":\"memory_once\",\"effect\":\"memory_write\",\"information\":{\"class\":\"public\"}}],\"result\":{\"type\":\"i64\",\"value\":\"%lld\"}}\n", result, result, result);
    return 0;
}
