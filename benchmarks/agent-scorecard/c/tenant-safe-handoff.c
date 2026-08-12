#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    const char *classification;
    const char *tenant;
    const char *purpose;
} information_label;

static bool exact_label(information_label label) {
    return strcmp(label.classification, "secret") == 0 &&
           strcmp(label.tenant, "agent_a") == 0 &&
           strcmp(label.purpose, "handoff") == 0;
}

int main(void) {
    bool send_once = true;
    const information_label label = {
        .classification = "secret",
        .tenant = "agent_a",
        .purpose = "handoff",
    };
    if (!send_once || !exact_label(label)) {
        return 2;
    }
    send_once = false;
    if (send_once) {
        return 3;
    }
    fputs("{\"effect_requests\":[{\"arguments\":[{\"type\":\"string\",\"value\":\"bounded-agent-context\"}],\"authority_slot\":\"send_once\",\"effect\":\"network_send\",\"information\":{\"class\":\"secret\",\"purpose\":\"handoff\",\"tenant\":\"agent_a\"}}],\"result\":{\"type\":\"unit\"}}\n", stdout);
    return 0;
}
