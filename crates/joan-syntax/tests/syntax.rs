//! Parser and canonical-formatter contract tests.

use joan_syntax::{format_source, parse};
use proptest::prelude::*;

const CANONICAL: &str = r#"module agent;

fn main() -> i64 effects [network_send] {
  let answer: i64 = 40 + 2;
  request network_send("agent-b", answer);
  return answer;
}
"#;

#[test]
fn formatter_is_idempotent() -> Result<(), Box<dyn std::error::Error>> {
    let dense = r#"module agent; fn main()->i64 effects[network_send]{let answer:i64=40+2;request network_send("agent-b",answer);return answer;}"#;
    let once = format_source(dense)?;
    let twice = format_source(&once)?;
    assert_eq!(once, CANONICAL);
    assert_eq!(once, twice);
    Ok(())
}

#[test]
fn linear_authority_syntax_formats_canonically() -> Result<(), Box<dyn std::error::Error>> {
    let dense = r#"module linear;fn main()->unit effects[network_send]authorities[send_once:network_send]{request network_send("peer")using send_once;return;}"#;
    let expected = r#"module linear;

fn main() -> unit effects [network_send] authorities [send_once: network_send] {
  request network_send("peer") using send_once;
  return;
}
"#;
    let formatted = format_source(dense)?;
    assert_eq!(formatted, expected);
    assert_eq!(format_source(&formatted)?, formatted);
    Ok(())
}

#[test]
fn linear_context_words_remain_valid_legacy_identifiers() -> Result<(), Box<dyn std::error::Error>>
{
    let source = r"module contextual;
fn echo(authorities: i64) -> i64 effects [] {
  let using: i64 = authorities;
  return using;
}
fn main() -> i64 effects [] { return echo(42); }
";
    let formatted = format_source(source)?;
    assert!(formatted.contains("echo(authorities: i64)"));
    assert!(formatted.contains("let using: i64 = authorities;"));
    Ok(())
}

#[test]
fn information_flow_syntax_formats_canonically() -> Result<(), Box<dyn std::error::Error>> {
    let dense = r#"module secure flow;fn relay(payload:string flow[secret,tenant:agent_a,purpose:handoff])->string flow[secret,tenant:agent_a,purpose:handoff]effects[]authorities[]{let copy:string flow[secret,tenant:agent_a,purpose:handoff]=payload;return copy;}fn main()->unit flow[public]effects[network_send]authorities[send_once:network_send]{let payload:string flow[secret,tenant:agent_a,purpose:handoff]="classified";request network_send(payload)using send_once flow[secret,tenant:agent_a,purpose:handoff];return;}"#;
    let expected = r#"module secure flow;

fn relay(payload: string flow [secret, tenant:agent_a, purpose:handoff]) -> string flow [secret, tenant:agent_a, purpose:handoff] effects [] authorities [] {
  let copy: string flow [secret, tenant:agent_a, purpose:handoff] = payload;
  return copy;
}

fn main() -> unit flow [public] effects [network_send] authorities [send_once: network_send] {
  let payload: string flow [secret, tenant:agent_a, purpose:handoff] = "classified";
  request network_send(payload) using send_once flow [secret, tenant:agent_a, purpose:handoff];
  return;
}
"#;
    let formatted = format_source(dense)?;
    assert_eq!(formatted, expected);
    assert_eq!(format_source(&formatted)?, formatted);
    Ok(())
}

#[test]
fn flow_context_word_remains_a_legacy_identifier() -> Result<(), Box<dyn std::error::Error>> {
    let source = r"module contextual;
fn echo(flow: i64) -> i64 effects [] { return flow; }
fn main() -> i64 effects [] { return echo(42); }
";
    let formatted = format_source(source)?;
    assert!(formatted.contains("echo(flow: i64)"));
    Ok(())
}

#[test]
fn malformed_source_has_a_stable_parse_diagnostic() -> Result<(), Box<dyn std::error::Error>> {
    let Err(report) = parse("module missing_semicolon") else {
        return Err("malformed source unexpectedly parsed".into());
    };
    assert_eq!(report.phase, "parse");
    assert_eq!(report.diagnostics[0].code, "J1003");
    Ok(())
}

#[test]
fn line_and_nested_block_comments_are_ignored() -> Result<(), Box<dyn std::error::Error>> {
    let commented = r"/* outer /* nested */ block */
module agent; // module declaration
fn main() -> i64 effects [] { return 42; }
";
    let program = parse(commented)?;
    assert_eq!(program.module, "agent");
    assert_eq!(program.functions.len(), 1);
    Ok(())
}

#[test]
fn unterminated_block_comment_has_a_stable_diagnostic() -> Result<(), Box<dyn std::error::Error>> {
    let Err(report) = parse("/* never closed") else {
        return Err("unterminated block comment unexpectedly parsed".into());
    };
    assert_eq!(report.phase, "lex");
    assert_eq!(report.diagnostics[0].code, "J0012");
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_utf8_never_panics(source in any::<String>()) {
        let _ = parse(&source);
    }
}
