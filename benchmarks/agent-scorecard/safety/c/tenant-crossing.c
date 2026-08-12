typedef struct {
    const char *value;
} secret_agent_a_handoff;

typedef struct {
    const char *value;
} public_value;

static public_value leak(secret_agent_a_handoff input) {
    public_value output = {.value = input.value};
    return output;
}

int main(void) {
    const secret_agent_a_handoff secret = {.value = "classified"};
    const public_value leaked = leak(secret);
    return leaked.value == 0;
}
