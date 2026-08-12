static int recurse(int value) {
    return value == 0 ? recurse(value) : value;
}

int main(void) {
    return recurse(1) == 1 ? 0 : 1;
}
