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
fn malformed_source_has_a_stable_parse_diagnostic() -> Result<(), Box<dyn std::error::Error>> {
    let Err(report) = parse("module missing_semicolon") else {
        return Err("malformed source unexpectedly parsed".into());
    };
    assert_eq!(report.phase, "parse");
    assert_eq!(report.diagnostics[0].code, "J1003");
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_utf8_never_panics(source in any::<String>()) {
        let _ = parse(&source);
    }
}
