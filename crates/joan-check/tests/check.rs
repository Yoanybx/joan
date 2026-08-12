//! Static type, effect, and termination contract tests.

use joan_check::check;
use joan_syntax::parse;

fn diagnostic_codes(source: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let program = parse(source)?;
    let Err(report) = check(&program) else {
        return Err("fixture unexpectedly passed static checking".into());
    };
    Ok(report
        .diagnostics
        .into_iter()
        .map(|diagnostic| diagnostic.code)
        .collect())
}

#[test]
fn undeclared_effect_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let codes = diagnostic_codes(
        r#"
module effect_test;
fn main() -> unit effects [] {
  request network_send("payload");
  return;
}
"#,
    )?;
    assert!(codes.iter().any(|code| code == "J2028"));
    Ok(())
}

#[test]
fn caller_must_propagate_callee_effects() -> Result<(), Box<dyn std::error::Error>> {
    let codes = diagnostic_codes(
        r#"
module attenuation;
fn send() -> unit effects [network_send] {
  request network_send("payload");
  return;
}
fn main() -> unit effects [] {
  send();
  return;
}
"#,
    )?;
    assert!(codes.iter().any(|code| code == "J2034"));
    Ok(())
}

#[test]
fn type_mismatch_fails_before_execution() -> Result<(), Box<dyn std::error::Error>> {
    let codes = diagnostic_codes(
        r"
module types;
fn main() -> i64 effects [] { return false; }
",
    )?;
    assert!(codes.iter().any(|code| code == "J2035"));
    Ok(())
}
