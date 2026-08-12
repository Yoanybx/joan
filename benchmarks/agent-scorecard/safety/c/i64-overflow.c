#include <stdint.h>
#include <limits.h>

int main(void) {
    volatile int64_t maximum = INT64_MAX;
    volatile int64_t result = maximum + 1;
    return result == 0;
}
