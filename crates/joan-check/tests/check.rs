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

#[test]
fn exact_linear_authority_is_accepted() -> Result<(), Box<dyn std::error::Error>> {
    let program = parse(
        r#"
module linear;
fn main() -> unit effects [network_send] authorities [send_once: network_send] {
  request network_send("payload") using send_once;
  return;
}
"#,
    )?;
    let receipt = check(&program)?;
    assert_eq!(receipt.authority_profile, "linear-one-shot-per-invocation");
    assert_eq!(receipt.authority_slot_count, 1);
    Ok(())
}

#[test]
fn linear_authority_reuse_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let codes = diagnostic_codes(
        r#"
module replay;
fn main() -> unit effects [network_send] authorities [send_once: network_send] {
  request network_send("first") using send_once;
  request network_send("second") using send_once;
  return;
}
"#,
    )?;
    assert!(codes.iter().any(|code| code == "J2056"));
    Ok(())
}

#[test]
fn missing_wrong_and_dropped_authority_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let missing = diagnostic_codes(
        r#"
module missing;
fn main() -> unit effects [network_send] authorities [send_once: network_send] {
  request network_send("payload");
  return;
}
"#,
    )?;
    assert!(missing.iter().any(|code| code == "J2053"));
    assert!(missing.iter().any(|code| code == "J2057"));

    let wrong = diagnostic_codes(
        r#"
module wrong;
fn main() -> unit effects [network_send, secret_read] authorities [read_once: secret_read] {
  request network_send("payload") using read_once;
  return;
}
"#,
    )?;
    assert!(wrong.iter().any(|code| code == "J2055"));
    Ok(())
}

#[test]
fn authority_profiles_cannot_mix_in_one_module() -> Result<(), Box<dyn std::error::Error>> {
    let codes = diagnostic_codes(
        r"
module mixed;
fn legacy() -> unit effects [] { return; }
fn main() -> unit effects [] authorities [] { legacy(); return; }
",
    )?;
    assert!(codes.iter().any(|code| code == "J2050"));
    Ok(())
}
