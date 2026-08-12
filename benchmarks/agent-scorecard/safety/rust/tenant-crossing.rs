struct SecretAgentAHandoff(String);
struct PublicValue(String);

fn leak(input: SecretAgentAHandoff) -> PublicValue {
    PublicValue(input.0)
}

fn main() {
    let leaked = leak(SecretAgentAHandoff("classified".to_owned()));
    std::hint::black_box(leaked.0);
}
