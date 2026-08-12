//! Bytecode compiler and bounded-VM contract tests.

use joan_compiler::{LanguageError, Value, compile_source, execute_bytecode, execute_source};

const ARITHMETIC: &str = r"
module arithmetic;

fn add(left: i64, right: i64) -> i64 effects [] {
  return left + right;
}

fn main() -> i64 effects [] {
  return add(40, 2);
}
";

#[test]
fn compiles_and_executes_real_source() -> Result<(), Box<dyn std::error::Error>> {
    let receipt = execute_source(ARITHMETIC)?;
    assert_eq!(receipt.result, Value::I64(42));
    assert!(receipt.effect_requests.is_empty());
    assert!(receipt.instructions_executed > 0);
    Ok(())
}

#[test]
fn semantic_digest_ignores_format_and_function_order() -> Result<(), Box<dyn std::error::Error>> {
    let reordered = r"module arithmetic;
fn main()->i64 effects[]{return add(40,2);}
fn add(left:i64,right:i64)->i64 effects[]{return left+right;}
";
    let first = compile_source(ARITHMETIC)?;
    let second = compile_source(reordered)?;
    assert_eq!(
        first.bytecode.semantic_digest,
        second.bytecode.semantic_digest
    );
    Ok(())
}

#[test]
fn effects_are_receipted_but_never_executed() -> Result<(), Box<dyn std::error::Error>> {
    let source = r#"
module dispatch;
fn main() -> i64 effects [network_send] {
  request network_send("agent-b", 7);
  return 7;
}
"#;
    let receipt = execute_source(source)?;
    assert_eq!(receipt.result, Value::I64(7));
    assert_eq!(receipt.effect_requests.len(), 1);
    assert_eq!(receipt.effect_requests[0].effect, "network_send");
    assert_eq!(
        receipt.effect_requests[0].arguments,
        vec![Value::String("agent-b".to_owned()), Value::I64(7)]
    );
    Ok(())
}

#[test]
fn recursive_program_is_rejected_before_codegen() -> Result<(), Box<dyn std::error::Error>> {
    let source = r"
module recursive;
fn main() -> i64 effects [] { return main(); }
";
    let Err(error) = compile_source(source) else {
        return Err("recursive program unexpectedly compiled".into());
    };
    let LanguageError::Diagnostics(report) = error else {
        return Err("expected static diagnostics".into());
    };
    assert!(
        report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "J2040")
    );
    Ok(())
}

#[test]
fn explicit_budget_stops_execution() -> Result<(), Box<dyn std::error::Error>> {
    let artifact = compile_source(ARITHMETIC)?;
    let Err(error) = execute_bytecode(&artifact.bytecode, 1) else {
        return Err("one-instruction budget unexpectedly completed".into());
    };
    assert!(error.to_string().contains("instruction budget exhausted"));
    Ok(())
}

#[test]
fn overflow_is_a_runtime_error_not_wraparound() -> Result<(), Box<dyn std::error::Error>> {
    let source = r"
module overflow;
fn main() -> i64 effects [] { return 9223372036854775807 + 1; }
";
    let Err(error) = execute_source(source) else {
        return Err("overflow unexpectedly completed".into());
    };
    assert!(error.to_string().contains("integer addition failed"));
    Ok(())
}
