#include <stdbool.h>

typedef struct {
    bool consumed;
} authority_slot;

static void consume(authority_slot *slot) {
    slot->consumed = true;
}

int main(void) {
    authority_slot once = {.consumed = false};
    consume(&once);
    consume(&once);
    return once.consumed ? 0 : 1;
}
