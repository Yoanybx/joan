//! Bytecode compiler and bounded-VM contract tests.

use joan_canonical::canonicalize_str_v1;
use joan_compiler::{
    LanguageError, Value, canonicalize_source_ast, compile_source, execute_bytecode, execute_source,
};
use joan_identity::verify_canonical_ast_identity;

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
/* declaration order and layout are non-semantic */
fn main()->i64 effects[]{return add(40,2);} // entry
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
fn canonical_ast_ignores_effect_order_and_preserves_jce1_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let first = r#"
module dispatch;
fn helper(value: i64) -> i64 effects [network_send, memory_read] {
  request memory_read("key");
  request network_send("peer", value);
  return value;
}
fn main() -> i64 effects [network_send, memory_read] { return helper(42); }
"#;
    let reordered = r#"module dispatch;
fn main()->i64 effects[memory_read,network_send]{return helper(42);}
fn helper(value:i64)->i64 effects[memory_read,network_send]{
request memory_read("key"); request network_send("peer",value); return value;
}
"#;
    let first = canonicalize_source_ast(first)?;
    let second = canonicalize_source_ast(reordered)?;
    assert_eq!(first.bytes, second.bytes);
    assert_eq!(first.identity, second.identity);
    verify_canonical_ast_identity(&first.identity, &first.bytes)?;
    let text = std::str::from_utf8(&first.bytes)?;
    assert_eq!(canonicalize_str_v1(text)?, first.bytes);
    Ok(())
}

#[test]
fn canonical_ast_encodes_full_i64_as_exact_decimal_text() -> Result<(), Box<dyn std::error::Error>>
{
    let source = r"
module maximum;
fn main() -> i64 effects [] { return 9223372036854775807; }
";
    let encoded = canonicalize_source_ast(source)?;
    let text = std::str::from_utf8(&encoded.bytes)?;
    assert!(text.contains(r#""value":"9223372036854775807""#));
    assert_eq!(encoded.identity.encoding, "JCE1");
    assert_eq!(
        encoded.identity.digest.domain,
        "joan.language-canonical-ast.v1"
    );
    assert_eq!(encoded.identity.digest.profile, "joan-hash-v1");
    Ok(())
}

#[test]
fn semantic_changes_always_change_the_canonical_ast_digest()
-> Result<(), Box<dyn std::error::Error>> {
    let baseline = compile_source(ARITHMETIC)?.bytecode.semantic_digest;
    let mutations = [
        ARITHMETIC.replace("add(40, 2)", "add(41, 2)"),
        ARITHMETIC.replace("left + right", "left - right"),
        ARITHMETIC
            .replace("fn add", "fn sum")
            .replace("add(40, 2)", "sum(40, 2)"),
        ARITHMETIC.replace(
            "fn main() -> i64 effects []",
            "fn main() -> i64 effects [audit]",
        ),
    ];
    for mutation in mutations {
        assert_ne!(
            compile_source(&mutation)?.bytecode.semantic_digest,
            baseline
        );
    }
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
    assert_eq!(receipt.semantic_digest, receipt.semantic_identity.digest);
    Ok(())
}

#[test]
fn bytecode_with_inconsistent_semantic_identity_is_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let mut artifact = compile_source(ARITHMETIC)?;
    artifact.bytecode.semantic_digest.value = "0".repeat(64);
    let Err(error) = execute_bytecode(&artifact.bytecode, 100) else {
        return Err("bytecode with inconsistent semantic identity unexpectedly ran".into());
    };
    assert!(
        error
            .to_string()
            .contains("semantic digest does not match the canonical AST identity")
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
