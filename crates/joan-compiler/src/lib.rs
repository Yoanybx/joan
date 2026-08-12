//! Deterministic bytecode compiler and bounded virtual machine for JOAN v0.

use joan_ast::{
    BinaryOperator, CanonicalExpression, CanonicalFunction, CanonicalStatement, DiagnosticReport,
    Program, UnaryOperator,
};
use joan_bytecode::{BYTECODE_PROGRAM_SCHEMA, BytecodeVerificationReceipt, verify_bytecode};
pub use joan_bytecode::{BytecodeFunction, BytecodeProgram, Instruction, Value};
use joan_canonical::{CanonicalError, Digest};
use joan_check::{CheckReceipt, check};
use joan_identity::{
    CanonicalAstIdentity, EncodedCanonicalAst, IdentityError, encode_canonical_ast,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

const DEFAULT_INSTRUCTION_BUDGET: u64 = 1_000_000;
const MAX_CALL_DEPTH: usize = 1_024;

/// Successful compilation receipt and artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompileArtifact {
    /// Artifact schema.
    pub schema: String,
    /// Always `compiled`.
    pub status: String,
    /// Static-check evidence.
    pub check: CheckReceipt,
    /// Standalone non-executing bytecode verification receipt.
    pub verification: BytecodeVerificationReceipt,
    /// Executable bytecode.
    pub bytecode: BytecodeProgram,
}

/// One requested host effect. The VM never performs it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRequest {
    /// Zero-based deterministic request sequence.
    pub request_index: u64,
    /// Program-bound one-use request identity.
    pub request_id: String,
    /// Function that requested the effect.
    pub function: String,
    /// Effect identifier.
    pub effect: String,
    /// Evaluated request arguments.
    pub arguments: Vec<Value>,
}

/// Deterministic execution receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReceipt {
    /// Receipt schema.
    pub schema: String,
    /// Always `completed`.
    pub status: String,
    /// Semantic program identity.
    pub semantic_digest: Digest,
    /// Versioned JCE1 AST identity accepted by the VM.
    pub semantic_identity: CanonicalAstIdentity,
    /// Typed identity of the exact verified bytecode artifact.
    pub bytecode_digest: Digest,
    /// Entrypoint result.
    pub result: Value,
    /// Host effects requested but not executed.
    pub effect_requests: Vec<EffectRequest>,
    /// Exact number of bytecode instructions evaluated.
    pub instructions_executed: u64,
}

/// Language pipeline failure.
#[derive(Debug, Error)]
pub enum LanguageError {
    /// Lexing, parsing, or static-check diagnostics.
    #[error("source rejected during {phase}", phase = .0.phase)]
    Diagnostics(DiagnosticReport),
    /// Canonical semantic identity failed.
    #[error("semantic identity failed: {0}")]
    Canonical(#[from] CanonicalError),
    /// Canonical AST identity construction failed.
    #[error("semantic identity failed: {0}")]
    Identity(#[from] IdentityError),
    /// Standalone bytecode verification failed before execution.
    #[error("bytecode verification failed: {0}")]
    Bytecode(#[from] joan_bytecode::BytecodeError),
    /// Internal compiler invariant failed.
    #[error("compiler invariant failed: {0}")]
    Compiler(String),
    /// Bounded VM rejected execution.
    #[error("runtime rejected execution: {0}")]
    Runtime(String),
}

impl From<DiagnosticReport> for LanguageError {
    fn from(value: DiagnosticReport) -> Self {
        Self::Diagnostics(value)
    }
}

/// Parse and statically check source without compiling it.
pub fn check_source(source: &str) -> Result<CheckReceipt, LanguageError> {
    let program = joan_syntax::parse(source)?;
    Ok(check(&program)?)
}

/// Parse, check, and encode the canonical semantic AST for one source module.
pub fn canonicalize_source_ast(source: &str) -> Result<EncodedCanonicalAst, LanguageError> {
    let program = joan_syntax::parse(source)?;
    check(&program)?;
    encode_program_ast(&program)
}

/// Parse, validate, and compile source to deterministic JOAN bytecode.
pub fn compile_source(source: &str) -> Result<CompileArtifact, LanguageError> {
    let program = joan_syntax::parse(source)?;
    let receipt = check(&program)?;
    let bytecode = compile_program(&program)?;
    let verification = verify_bytecode(&bytecode)?;
    Ok(CompileArtifact {
        schema: "joan.compile-artifact.v1".to_owned(),
        status: "compiled".to_owned(),
        check: receipt,
        verification,
        bytecode,
    })
}

/// Compile and run source under the default deterministic resource budget.
pub fn execute_source(source: &str) -> Result<ExecutionReceipt, LanguageError> {
    let artifact = compile_source(source)?;
    execute_bytecode(&artifact.bytecode, DEFAULT_INSTRUCTION_BUDGET)
}

/// Execute validated bytecode under an explicit instruction budget.
pub fn execute_bytecode(
    program: &BytecodeProgram,
    instruction_budget: u64,
) -> Result<ExecutionReceipt, LanguageError> {
    let verification = verify_bytecode(program)?;
    if instruction_budget == 0 {
        return Err(LanguageError::Runtime(
            "instruction budget must be greater than zero".to_owned(),
        ));
    }
    let mut machine = Machine {
        program,
        remaining: instruction_budget,
        executed: 0,
        requests: Vec::new(),
    };
    let result = machine.call(program.entry_function, Vec::new(), 0)?;
    Ok(ExecutionReceipt {
        schema: "joan.execution-receipt.v1".to_owned(),
        status: "completed".to_owned(),
        semantic_digest: program.semantic_digest.clone(),
        semantic_identity: program.semantic_identity.clone(),
        bytecode_digest: verification.bytecode_digest,
        result,
        effect_requests: machine.requests,
        instructions_executed: machine.executed,
    })
}

fn compile_program(program: &Program) -> Result<BytecodeProgram, LanguageError> {
    let canonical_ast = program.canonical();
    let function_indexes = canonical_ast
        .functions
        .iter()
        .enumerate()
        .map(|(index, function)| (function.name.clone(), index))
        .collect::<BTreeMap<_, _>>();
    let entry_function = function_indexes.get("main").copied().ok_or_else(|| {
        LanguageError::Compiler("checked program has no main function".to_owned())
    })?;
    let functions = canonical_ast
        .functions
        .iter()
        .map(|function| compile_function(function, &function_indexes))
        .collect::<Result<Vec<_>, _>>()?;
    let semantic_ast = encode_canonical_ast(&canonical_ast)?;
    Ok(BytecodeProgram {
        schema: BYTECODE_PROGRAM_SCHEMA.to_owned(),
        module: canonical_ast.module.clone(),
        semantic_digest: semantic_ast.identity.digest.clone(),
        semantic_identity: semantic_ast.identity,
        canonical_ast,
        entry_function,
        functions,
    })
}

fn encode_program_ast(program: &Program) -> Result<EncodedCanonicalAst, LanguageError> {
    Ok(encode_canonical_ast(&program.canonical())?)
}

fn compile_function(
    function: &CanonicalFunction,
    function_indexes: &BTreeMap<String, usize>,
) -> Result<BytecodeFunction, LanguageError> {
    let mut locals = function
        .parameters
        .iter()
        .enumerate()
        .map(|(index, parameter)| (parameter.name.clone(), index))
        .collect::<BTreeMap<_, _>>();
    let parameter_types = function
        .parameters
        .iter()
        .map(|parameter| parameter.value_type.clone())
        .collect::<Vec<_>>();
    let mut local_types = parameter_types.clone();
    let mut instructions = Vec::new();
    for statement in &function.body {
        match statement {
            CanonicalStatement::Let {
                name,
                value_type,
                value,
            } => {
                compile_expression(value, &locals, function_indexes, &mut instructions)?;
                let slot = locals.len();
                locals.insert(name.clone(), slot);
                local_types.push(value_type.clone());
                instructions.push(Instruction::StoreLocal { slot });
            }
            CanonicalStatement::Return { value } => {
                if let Some(value) = value {
                    compile_expression(value, &locals, function_indexes, &mut instructions)?;
                } else {
                    instructions.push(Instruction::Push { value: Value::Unit });
                }
                instructions.push(Instruction::Return);
            }
            CanonicalStatement::Request { effect, arguments } => {
                for argument in arguments {
                    compile_expression(argument, &locals, function_indexes, &mut instructions)?;
                }
                instructions.push(Instruction::Request {
                    effect: effect.clone(),
                    argument_count: arguments.len(),
                });
            }
            CanonicalStatement::Expression { expression } => {
                compile_expression(expression, &locals, function_indexes, &mut instructions)?;
                instructions.push(Instruction::Pop);
            }
        }
    }
    Ok(BytecodeFunction {
        name: function.name.clone(),
        parameter_count: parameter_types.len(),
        parameter_types,
        local_count: local_types.len(),
        local_types,
        return_type: function.return_type.clone(),
        effects: function.effects.clone(),
        instructions,
    })
}

fn compile_expression(
    expression: &CanonicalExpression,
    locals: &BTreeMap<String, usize>,
    function_indexes: &BTreeMap<String, usize>,
    instructions: &mut Vec<Instruction>,
) -> Result<(), LanguageError> {
    match expression {
        CanonicalExpression::Integer { value } => instructions.push(Instruction::Push {
            value: Value::I64(value.parse::<i64>().map_err(|_| {
                LanguageError::Compiler("canonical integer is outside i64".to_owned())
            })?),
        }),
        CanonicalExpression::Boolean { value } => instructions.push(Instruction::Push {
            value: Value::Bool(*value),
        }),
        CanonicalExpression::String { value } => instructions.push(Instruction::Push {
            value: Value::String(value.clone()),
        }),
        CanonicalExpression::Variable { name } => {
            let slot = locals.get(name).copied().ok_or_else(|| {
                LanguageError::Compiler(format!("checked local `{name}` is missing"))
            })?;
            instructions.push(Instruction::LoadLocal { slot });
        }
        CanonicalExpression::Unary { operator, operand } => {
            compile_expression(operand, locals, function_indexes, instructions)?;
            instructions.push(match operator {
                UnaryOperator::Negate => Instruction::Negate,
                UnaryOperator::Not => Instruction::Not,
            });
        }
        CanonicalExpression::Binary {
            operator,
            left,
            right,
        } => {
            compile_expression(left, locals, function_indexes, instructions)?;
            compile_expression(right, locals, function_indexes, instructions)?;
            instructions.push(binary_instruction(operator));
        }
        CanonicalExpression::Call {
            function,
            arguments,
        } => {
            for argument in arguments {
                compile_expression(argument, locals, function_indexes, instructions)?;
            }
            let index = function_indexes.get(function).copied().ok_or_else(|| {
                LanguageError::Compiler(format!("checked function `{function}` is missing"))
            })?;
            instructions.push(Instruction::Call {
                function: index,
                argument_count: arguments.len(),
            });
        }
    }
    Ok(())
}

const fn binary_instruction(operator: &BinaryOperator) -> Instruction {
    match operator {
        BinaryOperator::Add => Instruction::Add,
        BinaryOperator::Subtract => Instruction::Subtract,
        BinaryOperator::Multiply => Instruction::Multiply,
        BinaryOperator::Divide => Instruction::Divide,
        BinaryOperator::Remainder => Instruction::Remainder,
        BinaryOperator::Equal => Instruction::Equal,
        BinaryOperator::NotEqual => Instruction::NotEqual,
        BinaryOperator::Less => Instruction::Less,
        BinaryOperator::LessEqual => Instruction::LessEqual,
        BinaryOperator::Greater => Instruction::Greater,
        BinaryOperator::GreaterEqual => Instruction::GreaterEqual,
        BinaryOperator::And => Instruction::And,
        BinaryOperator::Or => Instruction::Or,
    }
}

struct Machine<'a> {
    program: &'a BytecodeProgram,
    remaining: u64,
    executed: u64,
    requests: Vec<EffectRequest>,
}

impl Machine<'_> {
    #[allow(
        clippy::too_many_lines,
        reason = "a flat opcode dispatcher keeps all VM semantics visible at one boundary"
    )]
    fn call(
        &mut self,
        function_index: usize,
        arguments: Vec<Value>,
        depth: usize,
    ) -> Result<Value, LanguageError> {
        if depth >= MAX_CALL_DEPTH {
            return Err(LanguageError::Runtime(
                "call-depth limit exceeded".to_owned(),
            ));
        }
        let function = self.program.functions.get(function_index).ok_or_else(|| {
            LanguageError::Runtime("call target is outside the function table".to_owned())
        })?;
        if arguments.len() != function.parameter_count {
            return Err(LanguageError::Runtime(format!(
                "function `{}` expected {} arguments but received {}",
                function.name,
                function.parameter_count,
                arguments.len()
            )));
        }
        let mut locals = vec![Value::Unit; function.local_count];
        for (slot, value) in arguments.into_iter().enumerate() {
            locals[slot] = value;
        }
        let mut stack = Vec::new();
        for instruction in &function.instructions {
            self.consume_instruction()?;
            match instruction {
                Instruction::Push { value } => stack.push(value.clone()),
                Instruction::LoadLocal { slot } => {
                    let value = locals.get(*slot).cloned().ok_or_else(|| {
                        LanguageError::Runtime("local load is outside the frame".to_owned())
                    })?;
                    stack.push(value);
                }
                Instruction::StoreLocal { slot } => {
                    let value = pop(&mut stack)?;
                    let target = locals.get_mut(*slot).ok_or_else(|| {
                        LanguageError::Runtime("local store is outside the frame".to_owned())
                    })?;
                    *target = value;
                }
                Instruction::Pop => {
                    pop(&mut stack)?;
                }
                Instruction::Negate => {
                    let value = pop_i64(&mut stack)?;
                    stack.push(Value::I64(value.checked_neg().ok_or_else(|| {
                        LanguageError::Runtime("integer negation overflow".to_owned())
                    })?));
                }
                Instruction::Not => {
                    let value = pop_bool(&mut stack)?;
                    stack.push(Value::Bool(!value));
                }
                Instruction::Add => integer_binary(&mut stack, i64::checked_add, "addition")?,
                Instruction::Subtract => {
                    integer_binary(&mut stack, i64::checked_sub, "subtraction")?;
                }
                Instruction::Multiply => {
                    integer_binary(&mut stack, i64::checked_mul, "multiplication")?;
                }
                Instruction::Divide => {
                    integer_binary(&mut stack, i64::checked_div, "division")?;
                }
                Instruction::Remainder => {
                    integer_binary(&mut stack, i64::checked_rem, "remainder")?;
                }
                Instruction::Equal => compare_equal(&mut stack, false)?,
                Instruction::NotEqual => compare_equal(&mut stack, true)?,
                Instruction::Less => compare_i64(&mut stack, |left, right| left < right)?,
                Instruction::LessEqual => compare_i64(&mut stack, |left, right| left <= right)?,
                Instruction::Greater => compare_i64(&mut stack, |left, right| left > right)?,
                Instruction::GreaterEqual => {
                    compare_i64(&mut stack, |left, right| left >= right)?;
                }
                Instruction::And => boolean_binary(&mut stack, |left, right| left && right)?,
                Instruction::Or => boolean_binary(&mut stack, |left, right| left || right)?,
                Instruction::Call {
                    function,
                    argument_count,
                } => {
                    let arguments = pop_arguments(&mut stack, *argument_count)?;
                    let result = self.call(*function, arguments, depth + 1)?;
                    stack.push(result);
                }
                Instruction::Request {
                    effect,
                    argument_count,
                } => {
                    let arguments = pop_arguments(&mut stack, *argument_count)?;
                    let request_index = u64::try_from(self.requests.len()).map_err(|_| {
                        LanguageError::Runtime("effect request count exceeds u64".to_owned())
                    })?;
                    self.requests.push(EffectRequest {
                        request_index,
                        request_id: format!(
                            "{}:{request_index:016x}",
                            self.program.semantic_digest.value
                        ),
                        function: function.name.clone(),
                        effect: effect.clone(),
                        arguments,
                    });
                }
                Instruction::Return => return pop(&mut stack),
            }
        }
        Err(LanguageError::Runtime(format!(
            "function `{}` ended without return bytecode",
            function.name
        )))
    }

    fn consume_instruction(&mut self) -> Result<(), LanguageError> {
        if self.remaining == 0 {
            return Err(LanguageError::Runtime(
                "instruction budget exhausted".to_owned(),
            ));
        }
        self.remaining -= 1;
        self.executed += 1;
        Ok(())
    }
}

fn pop(stack: &mut Vec<Value>) -> Result<Value, LanguageError> {
    stack
        .pop()
        .ok_or_else(|| LanguageError::Runtime("value stack underflow".to_owned()))
}

fn pop_i64(stack: &mut Vec<Value>) -> Result<i64, LanguageError> {
    match pop(stack)? {
        Value::I64(value) => Ok(value),
        _ => Err(LanguageError::Runtime(
            "bytecode expected an i64 value".to_owned(),
        )),
    }
}

fn pop_bool(stack: &mut Vec<Value>) -> Result<bool, LanguageError> {
    match pop(stack)? {
        Value::Bool(value) => Ok(value),
        _ => Err(LanguageError::Runtime(
            "bytecode expected a bool value".to_owned(),
        )),
    }
}

fn pop_arguments(stack: &mut Vec<Value>, count: usize) -> Result<Vec<Value>, LanguageError> {
    if stack.len() < count {
        return Err(LanguageError::Runtime(
            "argument stack underflow".to_owned(),
        ));
    }
    Ok(stack.split_off(stack.len() - count))
}

fn integer_binary(
    stack: &mut Vec<Value>,
    operation: fn(i64, i64) -> Option<i64>,
    name: &'static str,
) -> Result<(), LanguageError> {
    let right = pop_i64(stack)?;
    let left = pop_i64(stack)?;
    let value = operation(left, right)
        .ok_or_else(|| LanguageError::Runtime(format!("integer {name} failed")))?;
    stack.push(Value::I64(value));
    Ok(())
}

fn boolean_binary(
    stack: &mut Vec<Value>,
    operation: fn(bool, bool) -> bool,
) -> Result<(), LanguageError> {
    let right = pop_bool(stack)?;
    let left = pop_bool(stack)?;
    stack.push(Value::Bool(operation(left, right)));
    Ok(())
}

fn compare_i64(
    stack: &mut Vec<Value>,
    operation: fn(i64, i64) -> bool,
) -> Result<(), LanguageError> {
    let right = pop_i64(stack)?;
    let left = pop_i64(stack)?;
    stack.push(Value::Bool(operation(left, right)));
    Ok(())
}

fn compare_equal(stack: &mut Vec<Value>, invert: bool) -> Result<(), LanguageError> {
    let right = pop(stack)?;
    let left = pop(stack)?;
    stack.push(Value::Bool((left == right) != invert));
    Ok(())
}
