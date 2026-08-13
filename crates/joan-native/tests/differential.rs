//! Differential VM/JIT execution and fail-closed native-subset tests.

use joan_bytecode::{Instruction, Value};
use joan_compiler::{compile_source, execute_bytecode_function};
use joan_native::{
    CRANELIFT_VERSION, MAX_NATIVE_INSTRUCTIONS_PER_FUNCTION, NativeError, compile_bytecode,
};

const PURE_PROGRAM: &str = r"
module native_differential;

fn arithmetic(a: i64, b: i64, c: i64) -> i64 effects [] {
  let sum: i64 = a + b;
  let scaled: i64 = sum * c;
  return scaled - b;
}

fn classify(a: i64, b: i64) -> bool effects [] {
  return (a < b) || (a == b);
}

fn conjunction(a: bool, b: bool) -> bool effects [] {
  return a && b;
}

fn discard(value: i64) -> i64 effects [] {
  value + 1;
  return value;
}

fn divide(a: i64, b: i64) -> i64 effects [] {
  return a / b;
}

fn greater(a: i64, b: i64) -> bool effects [] {
  return a > b;
}

fn greater_equal(a: i64, b: i64) -> bool effects [] {
  return a >= b;
}

fn increment(value: i64) -> i64 effects [] {
  return value + 1;
}

fn less_equal(a: i64, b: i64) -> bool effects [] {
  return a <= b;
}

fn logical_not(value: bool) -> bool effects [] {
  return !value;
}

fn make_unit() -> unit effects [] {
  return;
}

fn multiply(a: i64, b: i64) -> i64 effects [] {
  return a * b;
}

fn negate(value: i64) -> i64 effects [] {
  return -value;
}

fn not_equal(a: i64, b: i64) -> bool effects [] {
  return a != b;
}

fn pipeline(value: i64, scale: i64) -> i64 effects [] {
  return increment(value) * scale;
}

fn remainder(a: i64, b: i64) -> i64 effects [] {
  return a % b;
}

fn subtract(a: i64, b: i64) -> i64 effects [] {
  return a - b;
}

fn main() -> i64 effects [] {
  return 0;
}
";

fn expect_failure<T, E>(
    result: Result<T, E>,
    message: &'static str,
) -> Result<E, Box<dyn std::error::Error>>
where
    E: std::error::Error + 'static,
{
    match result {
        Ok(_) => Err(message.into()),
        Err(error) => Ok(error),
    }
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn bounded_signed(state: &mut u64, radius: i64) -> i64 {
    let width = u64::try_from(radius * 2 + 1).unwrap_or(1);
    i64::try_from(splitmix64(state) % width).unwrap_or(0) - radius
}

#[test]
fn jit_matches_vm_for_dynamic_values_calls_and_fuel() -> Result<(), Box<dyn std::error::Error>> {
    let artifact = compile_source(PURE_PROGRAM)?;
    let native = compile_bytecode(&artifact.bytecode)?;
    let cases = [
        (
            "arithmetic",
            vec![Value::I64(7), Value::I64(-2), Value::I64(5)],
        ),
        (
            "arithmetic",
            vec![Value::I64(-11), Value::I64(4), Value::I64(-3)],
        ),
        ("classify", vec![Value::I64(8), Value::I64(8)]),
        ("classify", vec![Value::I64(9), Value::I64(3)]),
        ("pipeline", vec![Value::I64(20), Value::I64(2)]),
        ("negate", vec![Value::I64(-17)]),
        ("logical_not", vec![Value::Bool(false)]),
        ("divide", vec![Value::I64(-19), Value::I64(4)]),
        ("remainder", vec![Value::I64(-19), Value::I64(4)]),
        ("not_equal", vec![Value::I64(8), Value::I64(9)]),
        ("less_equal", vec![Value::I64(8), Value::I64(8)]),
        ("greater", vec![Value::I64(9), Value::I64(8)]),
        ("greater_equal", vec![Value::I64(8), Value::I64(8)]),
        ("conjunction", vec![Value::Bool(true), Value::Bool(false)]),
        ("discard", vec![Value::I64(44)]),
        ("make_unit", vec![]),
    ];
    for (function, arguments) in cases {
        let vm =
            execute_bytecode_function(&artifact.bytecode, function, arguments.clone(), 10_000)?;
        let jit = native.invoke(function, &arguments, 10_000)?;
        assert_eq!(jit.result, vm.result);
        assert_eq!(jit.instructions_executed, vm.instructions_executed);
        assert_eq!(jit.bytecode_digest, vm.bytecode_digest);
        let exact = native.invoke(function, &arguments, vm.instructions_executed)?;
        assert_eq!(exact.result, vm.result);
        if vm.instructions_executed > 1 {
            let short = expect_failure(
                native.invoke(function, &arguments, vm.instructions_executed - 1),
                "one instruction below the exact budget must fail",
            )?;
            assert!(short.to_string().contains("instruction budget exhausted"));
        }
    }
    Ok(())
}

#[test]
fn jit_matches_vm_for_deterministic_dynamic_corpus() -> Result<(), Box<dyn std::error::Error>> {
    let artifact = compile_source(PURE_PROGRAM)?;
    let native = compile_bytecode(&artifact.bytecode)?;
    let mut state = 0x4a4f_414e_4c31_3600;
    for _ in 0..1_024 {
        let left = bounded_signed(&mut state, 10_000);
        let mut right = bounded_signed(&mut state, 10_000);
        if right == 0 {
            right = 1;
        }
        let scale = bounded_signed(&mut state, 100);
        for (function, arguments) in [
            (
                "arithmetic",
                vec![Value::I64(left), Value::I64(right), Value::I64(scale)],
            ),
            ("classify", vec![Value::I64(left), Value::I64(right)]),
            ("pipeline", vec![Value::I64(left), Value::I64(scale)]),
            ("divide", vec![Value::I64(left), Value::I64(right)]),
            ("remainder", vec![Value::I64(left), Value::I64(right)]),
        ] {
            let vm = execute_bytecode_function(
                &artifact.bytecode,
                function,
                arguments.clone(),
                u64::MAX,
            )?;
            let jit = native.invoke(function, &arguments, u64::MAX)?;
            assert_eq!(jit.result, vm.result);
            assert_eq!(jit.instructions_executed, vm.instructions_executed);
        }
    }
    Ok(())
}

#[test]
fn finalized_jit_memory_can_be_released_repeatedly() -> Result<(), Box<dyn std::error::Error>> {
    let artifact = compile_source(PURE_PROGRAM)?;
    for _ in 0..64 {
        let native = compile_bytecode(&artifact.bytecode)?;
        let result = native.invoke("pipeline", &[Value::I64(20), Value::I64(2)], 100)?;
        assert_eq!(result.result, Value::I64(42));
        drop(native);
    }
    Ok(())
}

#[test]
fn jit_matches_vm_failure_boundaries() -> Result<(), Box<dyn std::error::Error>> {
    let artifact = compile_source(PURE_PROGRAM)?;
    let native = compile_bytecode(&artifact.bytecode)?;

    let vm_budget = expect_failure(
        execute_bytecode_function(&artifact.bytecode, "increment", vec![Value::I64(1)], 3),
        "three instructions must not reach return",
    )?;
    let jit_budget = expect_failure(
        native.invoke("increment", &[Value::I64(1)], 3),
        "three instructions must not reach return",
    )?;
    assert!(
        vm_budget
            .to_string()
            .contains("instruction budget exhausted")
    );
    assert!(
        jit_budget
            .to_string()
            .contains("instruction budget exhausted")
    );

    let vm_overflow = expect_failure(
        execute_bytecode_function(
            &artifact.bytecode,
            "increment",
            vec![Value::I64(i64::MAX)],
            100,
        ),
        "checked addition must reject overflow",
    )?;
    let jit_overflow = expect_failure(
        native.invoke("increment", &[Value::I64(i64::MAX)], 100),
        "checked addition must reject overflow",
    )?;
    assert!(vm_overflow.to_string().contains("integer addition failed"));
    assert!(jit_overflow.to_string().contains("integer addition failed"));

    for (function, arguments, expected) in [
        (
            "negate",
            vec![Value::I64(i64::MIN)],
            "integer negation overflow",
        ),
        (
            "subtract",
            vec![Value::I64(i64::MIN), Value::I64(1)],
            "integer subtraction failed",
        ),
        (
            "multiply",
            vec![Value::I64(i64::MAX), Value::I64(2)],
            "integer multiplication failed",
        ),
        (
            "divide",
            vec![Value::I64(1), Value::I64(0)],
            "integer division failed",
        ),
        (
            "divide",
            vec![Value::I64(i64::MIN), Value::I64(-1)],
            "integer division failed",
        ),
        (
            "remainder",
            vec![Value::I64(1), Value::I64(0)],
            "integer remainder failed",
        ),
        (
            "remainder",
            vec![Value::I64(i64::MIN), Value::I64(-1)],
            "integer remainder failed",
        ),
    ] {
        let vm = expect_failure(
            execute_bytecode_function(&artifact.bytecode, function, arguments.clone(), 100),
            "VM must reject the arithmetic boundary",
        )?;
        let jit = expect_failure(
            native.invoke(function, &arguments, 100),
            "JIT must reject the arithmetic boundary",
        )?;
        assert!(vm.to_string().contains(expected));
        assert!(jit.to_string().contains(expected));
    }
    Ok(())
}

#[test]
fn artifact_is_stably_bound_and_invalid_inputs_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let artifact = compile_source(PURE_PROGRAM)?;
    let first = compile_bytecode(&artifact.bytecode)?;
    let second = compile_bytecode(&artifact.bytecode)?;
    assert_eq!(first.receipt(), second.receipt());
    assert_eq!(first.target(), first.receipt().target);
    assert_eq!(first.receipt().codegen_version, CRANELIFT_VERSION);
    assert_eq!(first.receipt().optimization_profile, "speed");
    assert!(first.receipt().relocation_count > 0);

    let type_error = expect_failure(
        first.invoke("increment", &[Value::Bool(true)], 100),
        "typed arguments must fail closed",
    )?;
    assert!(type_error.to_string().contains("expected i64"));
    assert!(first.invoke("increment", &[Value::I64(1)], 0).is_err());
    assert!(first.invoke("missing", &[], 100).is_err());
    assert!(first.invoke("increment", &[], 100).is_err());

    let prepared = first.prepare("classify")?;
    let prepared_result = prepared.invoke_normalized(&[8, 8], 100)?;
    assert_eq!(prepared_result.normalized_value, 1);
    assert_eq!(
        prepared_result.instructions_executed,
        execute_bytecode_function(
            &artifact.bytecode,
            "classify",
            vec![Value::I64(8), Value::I64(8)],
            100,
        )?
        .instructions_executed
    );
    assert!(prepared.invoke_normalized(&[8], 100).is_err());
    let prepared_bool = first.prepare("logical_not")?;
    assert!(prepared_bool.invoke_normalized(&[2], 100).is_err());

    let mut tampered = artifact.bytecode.clone();
    tampered.functions[0].instructions[0] = Instruction::Push {
        value: Value::I64(99),
    };
    assert!(matches!(
        compile_bytecode(&tampered),
        Err(NativeError::Bytecode(_))
    ));
    Ok(())
}

#[test]
fn oversized_verified_program_is_rejected_before_jit_codegen()
-> Result<(), Box<dyn std::error::Error>> {
    let mut source = String::from("module native_limit;\nfn main() -> i64 effects [] {\n");
    for _ in 0..=(MAX_NATIVE_INSTRUCTIONS_PER_FUNCTION / 2) {
        source.push_str("  1;\n");
    }
    source.push_str("  return 0;\n}\n");
    let artifact = compile_source(&source)?;
    let error = expect_failure(
        compile_bytecode(&artifact.bytecode),
        "native-specific instruction bound must reject before code generation",
    )?;
    assert!(matches!(error, NativeError::ResourceLimit(_)));
    assert!(error.to_string().contains("instructions; limit"));
    Ok(())
}

#[test]
fn strings_and_effects_are_not_silently_lowered() -> Result<(), Box<dyn std::error::Error>> {
    let string_program = compile_source(
        r#"
module native_string;
fn echo(value: string) -> string effects [] { return value; }
fn main() -> string effects [] { return echo("value"); }
"#,
    )?;
    assert!(matches!(
        compile_bytecode(&string_program.bytecode),
        Err(NativeError::Unsupported(_))
    ));

    let effect_program = compile_source(include_str!("../../../examples/agent-handoff.joan"))?;
    assert!(matches!(
        compile_bytecode(&effect_program.bytecode),
        Err(NativeError::Unsupported(_))
    ));
    Ok(())
}
