//! Bytecode compiler and bounded-VM contract tests.

use joan_ast::InformationLabel;
use joan_bytecode::verify_bytecode;
use joan_canonical::canonicalize_str_v1;
use joan_compiler::{
    Instruction, LanguageError, Value, canonicalize_source_ast, compile_source, execute_bytecode,
    execute_source,
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

const INFORMATION_FLOW: &str = r#"
module secure flow;
fn relay(payload: string flow [secret, tenant:agent_a, purpose:handoff]) -> string flow [secret, tenant:agent_a, purpose:handoff] effects [] authorities [] {
  return payload;
}
fn main() -> unit flow [public] effects [api_call] authorities [call_once: api_call] {
  let payload: string flow [secret, tenant:agent_a, purpose:handoff] = "classified";
  request api_call(relay(payload)) using call_once flow [secret, tenant:agent_a, purpose:handoff];
  return;
}
"#;

#[test]
fn compiles_and_executes_real_source() -> Result<(), Box<dyn std::error::Error>> {
    let artifact = compile_source(ARITHMETIC)?;
    assert_eq!(artifact.verification, verify_bytecode(&artifact.bytecode)?);
    let receipt = execute_source(ARITHMETIC)?;
    assert_eq!(receipt.result, Value::I64(42));
    assert!(receipt.effect_requests.is_empty());
    assert!(receipt.instructions_executed > 0);
    assert_eq!(
        receipt.bytecode_digest,
        artifact.verification.bytecode_digest
    );
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
    assert_eq!(first.bytecode, second.bytecode);
    assert_eq!(
        first.verification.bytecode_digest,
        second.verification.bytecode_digest
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
fn linear_authority_is_bound_through_identity_bytecode_and_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    let source = r#"
module linear;
fn main() -> i64 effects [network_send] authorities [send_once: network_send] {
  request network_send("agent-b", 7) using send_once;
  return 7;
}
"#;
    let artifact = compile_source(source)?;
    assert_eq!(artifact.schema, "joan.compile-artifact.v2");
    assert_eq!(artifact.bytecode.schema, "joan.bytecode-program.v2");
    assert_eq!(
        artifact.bytecode.canonical_ast.schema,
        "joan.canonical-ast.v1"
    );
    assert_eq!(
        artifact.bytecode.semantic_identity.schema,
        "joan.canonical-ast-identity.v1"
    );
    assert_eq!(
        artifact.bytecode.semantic_digest.domain,
        "joan.language-canonical-ast.v2"
    );
    assert_eq!(
        artifact.verification.schema,
        "joan.bytecode-verification-receipt.v1"
    );
    assert_eq!(
        artifact.verification.bytecode_digest.domain,
        "joan.bytecode-program.v2"
    );

    let receipt = execute_source(source)?;
    assert_eq!(receipt.schema, "joan.execution-receipt.v2");
    assert_eq!(receipt.effect_requests[0].request_id.len(), 64);
    assert!(
        receipt.effect_requests[0]
            .request_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );
    assert_eq!(
        receipt.effect_requests[0].authority_slot.as_deref(),
        Some("send_once")
    );
    Ok(())
}

#[test]
fn information_labels_are_bound_through_identity_bytecode_and_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    let artifact = compile_source(INFORMATION_FLOW)?;
    assert_eq!(artifact.schema, "joan.compile-artifact.v3");
    assert_eq!(artifact.bytecode.schema, "joan.bytecode-program.v3");
    assert_eq!(
        artifact.bytecode.canonical_ast.schema,
        "joan.canonical-ast.v2"
    );
    assert_eq!(
        artifact.bytecode.semantic_identity.schema,
        "joan.canonical-ast-identity.v2"
    );
    assert_eq!(
        artifact.bytecode.semantic_digest.domain,
        "joan.language-canonical-ast.v3"
    );
    assert_eq!(
        artifact.verification.schema,
        "joan.bytecode-verification-receipt.v2"
    );
    assert_eq!(
        artifact.verification.bytecode_digest.domain,
        "joan.bytecode-program.v3"
    );

    let receipt = execute_source(INFORMATION_FLOW)?;
    assert_eq!(receipt.schema, "joan.execution-receipt.v3");
    assert_eq!(
        receipt.effect_requests[0].information,
        Some(InformationLabel::Secret {
            tenant: "agent_a".to_owned(),
            purpose: "handoff".to_owned(),
        })
    );
    assert_eq!(receipt.effect_requests[0].request_id.len(), 64);

    let changed_purpose = INFORMATION_FLOW.replace("purpose:handoff", "purpose:billing");
    assert_ne!(
        artifact.bytecode.semantic_digest,
        compile_source(&changed_purpose)?.bytecode.semantic_digest
    );
    Ok(())
}

#[test]
fn bytecode_verifier_rejects_information_table_downgrade() -> Result<(), Box<dyn std::error::Error>>
{
    let mut bytecode = compile_source(INFORMATION_FLOW)?.bytecode;
    let relay = bytecode
        .functions
        .iter_mut()
        .find(|function| function.name == "relay")
        .ok_or("missing relay function")?;
    relay.return_information = Some(InformationLabel::Public);
    let Err(error) = verify_bytecode(&bytecode) else {
        return Err("degraded information table unexpectedly verified".into());
    };
    assert!(error.to_string().contains("function return violates"));
    Ok(())
}

#[test]
fn legacy_source_keeps_legacy_identity_and_omits_authority_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let artifact = compile_source(
        r#"module legacy;
fn main() -> unit effects [audit] { request audit("event"); return; }
"#,
    )?;
    assert_eq!(artifact.bytecode.schema, "joan.bytecode-program.v1");
    assert_eq!(
        artifact.bytecode.canonical_ast.schema,
        "joan.canonical-ast.v0"
    );
    let encoded = serde_json::to_string(&artifact.bytecode)?;
    assert!(!encoded.contains("authority_slots"));
    assert!(!encoded.contains("\"authority\""));
    assert!(!encoded.contains("information"));
    Ok(())
}

#[test]
fn bytecode_verifier_rejects_linear_authority_reuse() -> Result<(), Box<dyn std::error::Error>> {
    let source = r#"
module linear_replay;
fn main() -> unit effects [network_send] authorities [first: network_send, second: network_send] {
  request network_send("first") using first;
  request network_send("second") using second;
  return;
}
"#;
    let mut bytecode = compile_source(source)?.bytecode;
    let mut requests = bytecode
        .functions
        .iter_mut()
        .flat_map(|function| function.instructions.iter_mut())
        .filter_map(|instruction| match instruction {
            Instruction::Request { authority, .. } => Some(authority),
            _ => None,
        });
    let first = requests
        .next()
        .and_then(|authority| authority.clone())
        .ok_or("missing first authority")?;
    *requests.next().ok_or("missing second authority")? = Some(first);
    let Err(error) = verify_bytecode(&bytecode) else {
        return Err("reused linear authority verified".into());
    };
    assert!(error.to_string().contains("reuses linear authority"));
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
fn modified_instructions_never_execute_under_a_valid_ast_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let mut artifact = compile_source(ARITHMETIC)?;
    let instruction = artifact
        .bytecode
        .functions
        .iter_mut()
        .flat_map(|function| function.instructions.iter_mut())
        .find(|instruction| matches!(instruction, Instruction::Push { .. }))
        .ok_or("compiled artifact has no push instruction")?;
    *instruction = Instruction::Push {
        value: Value::I64(999),
    };
    let Err(error) = verify_bytecode(&artifact.bytecode) else {
        return Err("modified bytecode verified".into());
    };
    assert!(error.to_string().contains("deterministic code generation"));
    let Err(error) = execute_bytecode(&artifact.bytecode, 100) else {
        return Err("modified bytecode ran".into());
    };
    assert!(error.to_string().contains("bytecode verification failed"));
    Ok(())
}

#[test]
fn invalid_stack_and_frame_shapes_fail_before_execution() -> Result<(), Box<dyn std::error::Error>>
{
    let mut stack_underflow = compile_source(ARITHMETIC)?.bytecode;
    stack_underflow.functions[0].instructions[0] = Instruction::Pop;
    let Err(error) = verify_bytecode(&stack_underflow) else {
        return Err("stack underflow verified".into());
    };
    assert!(error.to_string().contains("stack underflow"));

    let mut frame = compile_source(ARITHMETIC)?.bytecode;
    frame.functions[0].local_count += 1;
    let Err(error) = verify_bytecode(&frame) else {
        return Err("inconsistent frame verified".into());
    };
    assert!(error.to_string().contains("inconsistent frame"));

    let mut oversized_frame = compile_source(ARITHMETIC)?.bytecode;
    oversized_frame.functions[0].local_count = usize::MAX;
    let Err(error) = verify_bytecode(&oversized_frame) else {
        return Err("oversized frame verified".into());
    };
    assert!(error.to_string().contains("local count exceeds"));
    Ok(())
}

#[test]
fn embedded_ast_and_effect_substitution_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let mut ast = compile_source(ARITHMETIC)?.bytecode;
    ast.canonical_ast.module = "substituted".to_owned();
    let Err(error) = verify_bytecode(&ast) else {
        return Err("substituted AST verified".into());
    };
    assert!(error.to_string().contains("semantic identity"));

    let source = r#"
module dispatch;
fn main() -> i64 effects [audit] {
  request audit("event");
  return 7;
}
"#;
    let mut effect_program = compile_source(source)?.bytecode;
    let request = effect_program
        .functions
        .iter_mut()
        .flat_map(|function| function.instructions.iter_mut())
        .find(|instruction| matches!(instruction, Instruction::Request { .. }))
        .ok_or("compiled artifact has no request instruction")?;
    let Instruction::Request {
        effect: requested_effect,
        ..
    } = request
    else {
        return Err("selected instruction is not request".into());
    };
    *requested_effect = "network_send".to_owned();
    let Err(error) = verify_bytecode(&effect_program) else {
        return Err("undeclared effect verified".into());
    };
    assert!(error.to_string().contains("undeclared effect"));
    Ok(())
}

#[test]
fn bytecode_json_rejects_unknown_fields() -> Result<(), Box<dyn std::error::Error>> {
    let artifact = compile_source(ARITHMETIC)?;
    let mut value = serde_json::to_value(&artifact.bytecode)?;
    value
        .as_object_mut()
        .ok_or("bytecode is not an object")?
        .insert("ambient_authority".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<joan_compiler::BytecodeProgram>(value).is_err());
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
