#[allow(unconditional_recursion)]
fn recurse() {
    recurse();
}

fn main() {
    let _ = std::hint::black_box(recurse as fn());
}
