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

#[test]
fn tenant_purpose_information_flow_is_accepted() -> Result<(), Box<dyn std::error::Error>> {
    let program = parse(
        r#"
module secure flow;
fn relay(payload: string flow [secret, tenant:agent_a, purpose:handoff]) -> string flow [secret, tenant:agent_a, purpose:handoff] effects [] authorities [] {
  let copy: string flow [secret, tenant:agent_a, purpose:handoff] = payload;
  return copy;
}
fn main() -> unit flow [public] effects [network_send] authorities [send_once: network_send] {
  let payload: string flow [secret, tenant:agent_a, purpose:handoff] = "classified";
  request network_send(relay(payload)) using send_once flow [secret, tenant:agent_a, purpose:handoff];
  return;
}
"#,
    )?;
    let receipt = check(&program)?;
    assert_eq!(receipt.schema, "joan.check-receipt.v1");
    assert_eq!(
        receipt.information_flow_profile.as_deref(),
        Some("explicit-tenant-purpose-no-declassification")
    );
    assert_eq!(receipt.protected_boundary_count, Some(5));
    Ok(())
}

#[test]
fn secret_cannot_flow_to_public_or_cross_tenants() -> Result<(), Box<dyn std::error::Error>> {
    let public_leak = diagnostic_codes(
        r"
module leak flow;
fn leak(value: string flow [secret, tenant:agent_a, purpose:handoff]) -> string flow [public] effects [] authorities [] { return value; }
fn main() -> unit flow [public] effects [] authorities [] { return; }
",
    )?;
    assert!(public_leak.iter().any(|code| code == "J2062"));

    let tenant_crossing = diagnostic_codes(
        r"
module crossing flow;
fn cross(value: string flow [secret, tenant:agent_a, purpose:handoff]) -> string flow [secret, tenant:agent_b, purpose:handoff] effects [] authorities [] { return value; }
fn main() -> unit flow [public] effects [] authorities [] { return; }
",
    )?;
    assert!(tenant_crossing.iter().any(|code| code == "J2062"));
    Ok(())
}

#[test]
fn incompatible_protected_values_cannot_be_combined() -> Result<(), Box<dyn std::error::Error>> {
    let codes = diagnostic_codes(
        r"
module purpose_mix flow;
fn mix(left: i64 flow [secret, tenant:agent_a, purpose:handoff], right: i64 flow [secret, tenant:agent_a, purpose:billing]) -> i64 flow [secret, tenant:agent_a, purpose:handoff] effects [] authorities [] { return left + right; }
fn main() -> unit flow [public] effects [] authorities [] { return; }
",
    )?;
    assert!(codes.iter().any(|code| code == "J2063"));
    Ok(())
}

#[test]
fn flow_profile_requires_complete_annotations_and_explicit_module_marker()
-> Result<(), Box<dyn std::error::Error>> {
    let missing = diagnostic_codes(
        r"
module incomplete flow;
fn main() -> unit effects [] authorities [] { return; }
",
    )?;
    assert!(missing.iter().any(|code| code == "J2060"));

    let undeclared = diagnostic_codes(
        r"
module undeclared;
fn main() -> unit flow [public] effects [] { return; }
",
    )?;
    assert!(undeclared.iter().any(|code| code == "J2061"));
    Ok(())
}
