struct Authority;

fn consume(_slot: Authority) {}

fn main() {
    let once = Authority;
    consume(once);
    consume(once);
}
