//! Standalone, non-executing verification for JOAN bytecode artifacts.

use joan_ast::{
    AuthorityParameter, BinaryOperator, CanonicalExpression, CanonicalFunction, CanonicalProgram,
    CanonicalStatement, Expression, Function, InformationLabel, Parameter, Program, Span,
    Statement, Type, UnaryOperator,
};
use joan_canonical::{Digest, Jce1Error, RegisteredDomainV1, digest_serializable_v1};
use joan_check::{CheckReceipt, check};
use joan_identity::{CanonicalAstIdentity, IdentityError, encode_canonical_ast};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Exact bytecode program schema accepted by this verifier.
pub const BYTECODE_PROGRAM_SCHEMA: &str = "joan.bytecode-program.v1";
/// Bytecode schema with linear authority slots.
pub const BYTECODE_PROGRAM_LINEAR_SCHEMA: &str = "joan.bytecode-program.v2";
/// Bytecode schema with tenant-purpose information-flow labels.
pub const BYTECODE_PROGRAM_INFORMATION_SCHEMA: &str = "joan.bytecode-program.v3";
/// Exact receipt schema emitted by this verifier.
pub const BYTECODE_VERIFICATION_RECEIPT_SCHEMA: &str = "joan.bytecode-verification-receipt.v0";
/// Verification receipt for linear bytecode.
pub const BYTECODE_VERIFICATION_LINEAR_RECEIPT_SCHEMA: &str =
    "joan.bytecode-verification-receipt.v1";
/// Verification receipt for information-flow bytecode.
pub const BYTECODE_VERIFICATION_INFORMATION_RECEIPT_SCHEMA: &str =
    "joan.bytecode-verification-receipt.v2";

const MAX_FUNCTIONS: usize = 1_024;
const MAX_PARAMETERS: usize = 64;
const MAX_LOCALS_PER_FUNCTION: usize = 100_064;
const MAX_STATEMENTS: usize = 100_000;
const MAX_EXPRESSION_NODES: usize = 200_000;
const MAX_EXPRESSION_DEPTH: usize = 256;
const MAX_INSTRUCTIONS_PER_FUNCTION: usize = 100_000;
const MAX_TOTAL_INSTRUCTIONS: u64 = 1_000_000;
const MAX_STACK_DEPTH: usize = 65_536;

/// One runtime value supported by the JOAN v0 VM.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    tag = "type",
    content = "value",
    rename_all = "lowercase"
)]
pub enum Value {
    /// Signed 64-bit integer.
    I64(#[serde(with = "i64_decimal")] i64),
    /// Boolean.
    Bool(bool),
    /// UTF-8 string.
    String(String),
    /// Unit value.
    Unit,
}

mod i64_decimal {
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(
        clippy::trivially_copy_pass_by_ref,
        reason = "serde with modules require the serializer hook to borrow the field"
    )]
    pub fn serialize<S>(value: &i64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<i64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let parsed = value.parse::<i64>().map_err(serde::de::Error::custom)?;
        if parsed.to_string() != value {
            return Err(serde::de::Error::custom(
                "i64 bytecode value is not canonical decimal text",
            ));
        }
        Ok(parsed)
    }
}

impl Value {
    const fn value_type(&self) -> Type {
        match self {
            Self::I64(_) => Type::I64,
            Self::Bool(_) => Type::Bool,
            Self::String(_) => Type::String,
            Self::Unit => Type::Unit,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AbstractValue {
    value_type: Type,
    information: InformationLabel,
}

impl AbstractValue {
    fn public(value_type: Type) -> Self {
        Self {
            value_type,
            information: InformationLabel::Public,
        }
    }
}

/// One deterministic bytecode instruction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "op", rename_all = "kebab-case")]
pub enum Instruction {
    /// Push a constant.
    Push {
        /// Constant value.
        value: Value,
    },
    /// Copy an initialized local onto the value stack.
    LoadLocal {
        /// Zero-based frame slot.
        slot: usize,
    },
    /// Move a value into an uninitialized immutable local.
    StoreLocal {
        /// Zero-based frame slot.
        slot: usize,
    },
    /// Drop the top stack value.
    Pop,
    /// Negate an integer.
    Negate,
    /// Negate a boolean.
    Not,
    /// Add two integers.
    Add,
    /// Subtract two integers.
    Subtract,
    /// Multiply two integers.
    Multiply,
    /// Divide two integers.
    Divide,
    /// Compute integer remainder.
    Remainder,
    /// Compare equal primitive values.
    Equal,
    /// Compare unequal primitive values.
    NotEqual,
    /// Compare integers.
    Less,
    /// Compare integers.
    LessEqual,
    /// Compare integers.
    Greater,
    /// Compare integers.
    GreaterEqual,
    /// Boolean conjunction.
    And,
    /// Boolean disjunction.
    Or,
    /// Invoke one statically resolved function.
    Call {
        /// Function table index.
        function: usize,
        /// Number of arguments already on the value stack.
        argument_count: usize,
    },
    /// Record, but do not execute, a host-effect request.
    Request {
        /// Effect identifier.
        effect: String,
        /// Linear authority slot moved into this request.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        authority: Option<String>,
        /// Exact request sink label in information-flow bytecode.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        information: Option<InformationLabel>,
        /// Number of arguments already on the value stack.
        argument_count: usize,
    },
    /// Return the only value on the frame stack.
    Return,
}

/// One effect-specific authority slot required for each function invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BytecodeAuthoritySlot {
    /// Slot name.
    pub name: String,
    /// Only effect this slot can authorize.
    pub effect: String,
}

/// One typed compiled function.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BytecodeFunction {
    /// Function name.
    pub name: String,
    /// Number of parameter slots.
    pub parameter_count: usize,
    /// Ordered parameter types.
    pub parameter_types: Vec<Type>,
    /// Ordered parameter labels, present only in information-flow bytecode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameter_information: Option<Vec<InformationLabel>>,
    /// Total local slots, including parameters.
    pub local_count: usize,
    /// Ordered frame slot types, including parameters.
    pub local_types: Vec<Type>,
    /// Ordered frame-slot labels, present only in information-flow bytecode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_information: Option<Vec<InformationLabel>>,
    /// Declared return type.
    pub return_type: Type,
    /// Return label, present only in information-flow bytecode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_information: Option<InformationLabel>,
    /// Explicit sorted effect row.
    pub effects: Vec<String>,
    /// Sorted linear authority slots; absent only in legacy bytecode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_slots: Option<Vec<BytecodeAuthoritySlot>>,
    /// Ordered bytecode.
    pub instructions: Vec<Instruction>,
}

/// Complete deterministic bytecode artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BytecodeProgram {
    /// Artifact schema.
    pub schema: String,
    /// Module name.
    pub module: String,
    /// Canonical AST digest retained for compatibility and indexing.
    pub semantic_digest: Digest,
    /// Versioned JCE1 AST identity.
    pub semantic_identity: CanonicalAstIdentity,
    /// Exact span-free AST from which bytecode must be derived.
    pub canonical_ast: CanonicalProgram,
    /// Entrypoint function table index.
    pub entry_function: usize,
    /// Functions sorted by function name.
    pub functions: Vec<BytecodeFunction>,
}

/// Deterministic proof that an exact bytecode program passed without execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BytecodeVerificationReceipt {
    /// Receipt schema.
    pub schema: String,
    /// Always `verified`.
    pub status: String,
    /// Exact verifier profile.
    pub verifier: String,
    /// Typed identity of the complete bytecode payload.
    pub bytecode_digest: Digest,
    /// Canonical AST identity bound to the bytecode.
    pub semantic_digest: Digest,
    /// Number of verified functions.
    pub function_count: u64,
    /// Number of verified instructions.
    pub instruction_count: u64,
    /// Largest abstract operand-stack depth.
    pub max_stack_depth: u64,
    /// Exact code-generation binding rule.
    pub codegen_binding: String,
    /// Verifier effect policy.
    pub effect_profile: String,
}

/// Bytecode identity, structure, typing or code-generation failure.
#[derive(Debug, Error)]
pub enum BytecodeError {
    /// JCE1 canonicalization or typed hashing failed.
    #[error(transparent)]
    Jce1(#[from] Jce1Error),
    /// Canonical AST identity construction failed.
    #[error(transparent)]
    Identity(#[from] IdentityError),
    /// Canonical AST failed the existing static checker.
    #[error("canonical AST failed static checks: {0}")]
    Static(String),
    /// Artifact contract or abstract bytecode validation failed.
    #[error("invalid bytecode: {0}")]
    Invalid(String),
    /// Supplied instructions differ from independently emitted instructions.
    #[error("bytecode does not match deterministic code generation from its canonical AST")]
    CodegenMismatch,
}

/// Verify a complete artifact without executing instructions or host effects.
pub fn verify_bytecode(
    program: &BytecodeProgram,
) -> Result<BytecodeVerificationReceipt, BytecodeError> {
    let (digest_domain, receipt_schema, effect_profile, codegen_binding) =
        bytecode_profile(&program.schema, &program.canonical_ast.schema)?;
    validate_canonical_shape(&program.canonical_ast)?;
    let check_receipt = check_canonical_ast(&program.canonical_ast)?;
    let encoded = encode_canonical_ast(&program.canonical_ast)?;
    if program.semantic_identity != encoded.identity {
        return Err(BytecodeError::Invalid(
            "semantic identity does not match the embedded canonical AST".to_owned(),
        ));
    }
    if program.semantic_digest != program.semantic_identity.digest {
        return Err(BytecodeError::Invalid(
            "semantic digest does not match the canonical AST identity".to_owned(),
        ));
    }
    if program.module != program.canonical_ast.module || program.module != check_receipt.module {
        return Err(BytecodeError::Invalid(
            "module does not match the embedded canonical AST".to_owned(),
        ));
    }

    let observation = verify_structure(program)?;
    let expected = independently_emit(&program.canonical_ast, encoded.identity)?;
    if program != &expected {
        return Err(BytecodeError::CodegenMismatch);
    }
    let bytecode_digest = digest_serializable_v1(digest_domain, program)?;
    Ok(BytecodeVerificationReceipt {
        schema: receipt_schema.to_owned(),
        status: "verified".to_owned(),
        verifier: "joan-standalone-bytecode-verifier-v0".to_owned(),
        bytecode_digest,
        semantic_digest: program.semantic_digest.clone(),
        function_count: u64::try_from(program.functions.len())
            .map_err(|_| BytecodeError::Invalid("function count exceeds u64".to_owned()))?,
        instruction_count: observation.instruction_count,
        max_stack_depth: u64::try_from(observation.max_stack_depth)
            .map_err(|_| BytecodeError::Invalid("stack depth exceeds u64".to_owned()))?,
        codegen_binding: codegen_binding.to_owned(),
        effect_profile: effect_profile.to_owned(),
    })
}

fn bytecode_profile(
    program_schema: &str,
    ast_schema: &str,
) -> Result<(RegisteredDomainV1, &'static str, &'static str, &'static str), BytecodeError> {
    match (program_schema, ast_schema) {
        (BYTECODE_PROGRAM_SCHEMA, CanonicalProgram::LEGACY_SCHEMA) => Ok((
            RegisteredDomainV1::BytecodeProgram,
            BYTECODE_VERIFICATION_RECEIPT_SCHEMA,
            "requests-validated-never-executed",
            "canonical-ast-v0-independent-emitter-exact-match",
        )),
        (BYTECODE_PROGRAM_LINEAR_SCHEMA, CanonicalProgram::LINEAR_SCHEMA) => Ok((
            RegisteredDomainV1::BytecodeProgramLinear,
            BYTECODE_VERIFICATION_LINEAR_RECEIPT_SCHEMA,
            "linear-authority-validated-never-executed",
            "canonical-ast-v1-independent-emitter-exact-match",
        )),
        (BYTECODE_PROGRAM_INFORMATION_SCHEMA, CanonicalProgram::INFORMATION_SCHEMA) => Ok((
            RegisteredDomainV1::BytecodeProgramInformation,
            BYTECODE_VERIFICATION_INFORMATION_RECEIPT_SCHEMA,
            "tenant-purpose-flow-and-linear-authority-validated-never-executed",
            "canonical-ast-v2-independent-emitter-exact-match",
        )),
        _ => Err(BytecodeError::Invalid(format!(
            "unsupported bytecode/canonical AST schema pair {program_schema} / {ast_schema}"
        ))),
    }
}

/// Reconstruct and statically check the source-equivalent canonical AST.
pub fn check_canonical_ast(ast: &CanonicalProgram) -> Result<CheckReceipt, BytecodeError> {
    validate_canonical_shape(ast)?;
    let program = program_from_canonical(ast)?;
    check(&program).map_err(|report| {
        let reason = report.diagnostics.first().map_or_else(
            || "checker rejected without diagnostics".to_owned(),
            |item| format!("{} {}", item.code, item.message),
        );
        BytecodeError::Static(reason)
    })
}

fn validate_canonical_shape(ast: &CanonicalProgram) -> Result<(), BytecodeError> {
    if !CanonicalProgram::supports_schema(&ast.schema) {
        return Err(BytecodeError::Invalid(format!(
            "unsupported canonical AST schema {}",
            ast.schema
        )));
    }
    validate_identifier("module", &ast.module)?;
    if ast.functions.is_empty() || ast.functions.len() > MAX_FUNCTIONS {
        return Err(BytecodeError::Invalid(format!(
            "function count must be 1..={MAX_FUNCTIONS}"
        )));
    }
    let mut previous_name: Option<&str> = None;
    let mut statement_count = 0usize;
    let mut expression_count = 0usize;
    for function in &ast.functions {
        validate_identifier("function", &function.name)?;
        if previous_name.is_some_and(|previous| previous >= function.name.as_str()) {
            return Err(BytecodeError::Invalid(
                "canonical functions must be strictly sorted by name".to_owned(),
            ));
        }
        previous_name = Some(&function.name);
        if function.parameters.len() > MAX_PARAMETERS {
            return Err(BytecodeError::Invalid(format!(
                "parameter count exceeds {MAX_PARAMETERS}"
            )));
        }
        for parameter in &function.parameters {
            validate_identifier("parameter", &parameter.name)?;
            validate_optional_information(parameter.information.as_ref())?;
        }
        validate_optional_information(function.return_information.as_ref())?;
        validate_sorted_effects(&function.effects)?;
        validate_canonical_authorities(ast.is_linear(), function)?;
        validate_canonical_information(ast.is_information_flow(), function)?;
        statement_count = statement_count
            .checked_add(function.body.len())
            .ok_or_else(|| BytecodeError::Invalid("statement count overflow".to_owned()))?;
        if statement_count > MAX_STATEMENTS {
            return Err(BytecodeError::Invalid(format!(
                "statement count exceeds {MAX_STATEMENTS}"
            )));
        }
        for statement in &function.body {
            validate_statement(
                statement,
                ast.is_linear(),
                ast.is_information_flow(),
                &mut expression_count,
            )?;
        }
    }
    Ok(())
}

fn validate_bytecode_authorities(
    linear: bool,
    function: &BytecodeFunction,
) -> Result<(), BytecodeError> {
    match (linear, &function.authority_slots) {
        (false, None) => Ok(()),
        (false, Some(_)) => Err(BytecodeError::Invalid(format!(
            "legacy function {} contains authority slots",
            function.name
        ))),
        (true, None) => Err(BytecodeError::Invalid(format!(
            "linear function {} has no authority slot table",
            function.name
        ))),
        (true, Some(slots)) => {
            let mut previous: Option<&str> = None;
            for slot in slots {
                validate_identifier("bytecode authority slot", &slot.name)?;
                validate_identifier("bytecode authority effect", &slot.effect)?;
                if previous.is_some_and(|item| item >= slot.name.as_str()) {
                    return Err(BytecodeError::Invalid(format!(
                        "function {} authority slots are not strictly sorted",
                        function.name
                    )));
                }
                if function.effects.binary_search(&slot.effect).is_err() {
                    return Err(BytecodeError::Invalid(format!(
                        "function {} authority slot {} widens undeclared effect {}",
                        function.name, slot.name, slot.effect
                    )));
                }
                previous = Some(&slot.name);
            }
            Ok(())
        }
    }
}

fn validate_bytecode_information(
    information_flow: bool,
    function: &BytecodeFunction,
) -> Result<(), BytecodeError> {
    match (
        information_flow,
        &function.parameter_information,
        &function.local_information,
        &function.return_information,
    ) {
        (false, None, None, None) => Ok(()),
        (false, _, _, _) => Err(BytecodeError::Invalid(format!(
            "non-flow function {} contains information tables",
            function.name
        ))),
        (true, Some(parameters), Some(locals), Some(return_label)) => {
            if parameters.len() != function.parameter_count
                || locals.len() != function.local_count
                || parameters != &locals[..function.parameter_count]
            {
                return Err(BytecodeError::Invalid(format!(
                    "flow function {} has inconsistent information tables",
                    function.name
                )));
            }
            for label in parameters.iter().chain(locals).chain([return_label]) {
                validate_optional_information(Some(label))?;
            }
            Ok(())
        }
        (true, _, _, _) => Err(BytecodeError::Invalid(format!(
            "flow function {} has incomplete information tables",
            function.name
        ))),
    }
}

fn validate_canonical_authorities(
    linear: bool,
    function: &CanonicalFunction,
) -> Result<(), BytecodeError> {
    match (linear, &function.authorities) {
        (false, None) => Ok(()),
        (false, Some(_)) => Err(BytecodeError::Invalid(
            "legacy canonical AST cannot contain authority slots".to_owned(),
        )),
        (true, None) => Err(BytecodeError::Invalid(format!(
            "linear function {} has no authority slot declaration",
            function.name
        ))),
        (true, Some(authorities)) => {
            let mut previous: Option<&str> = None;
            for authority in authorities {
                validate_identifier("authority slot", &authority.name)?;
                validate_identifier("authority effect", &authority.effect)?;
                if previous.is_some_and(|item| item >= authority.name.as_str()) {
                    return Err(BytecodeError::Invalid(
                        "authority slots must be strictly sorted by name".to_owned(),
                    ));
                }
                previous = Some(&authority.name);
            }
            Ok(())
        }
    }
}

fn validate_canonical_information(
    information_flow: bool,
    function: &CanonicalFunction,
) -> Result<(), BytecodeError> {
    validate_information_presence(
        information_flow,
        function.return_information.as_ref(),
        "return",
    )?;
    for parameter in &function.parameters {
        validate_information_presence(
            information_flow,
            parameter.information.as_ref(),
            "parameter",
        )?;
    }
    Ok(())
}

fn validate_information_presence(
    information_flow: bool,
    label: Option<&InformationLabel>,
    boundary: &str,
) -> Result<(), BytecodeError> {
    match (information_flow, label) {
        (true, Some(label)) => validate_optional_information(Some(label)),
        (true, None) => Err(BytecodeError::Invalid(format!(
            "flow {boundary} has no information label"
        ))),
        (false, None) => Ok(()),
        (false, Some(_)) => Err(BytecodeError::Invalid(format!(
            "non-flow {boundary} contains an information label"
        ))),
    }
}

fn validate_optional_information(label: Option<&InformationLabel>) -> Result<(), BytecodeError> {
    if let Some(InformationLabel::Secret { tenant, purpose }) = label {
        validate_identifier("information tenant", tenant)?;
        validate_identifier("information purpose", purpose)?;
    }
    Ok(())
}

fn validate_sorted_effects(effects: &[String]) -> Result<(), BytecodeError> {
    let mut previous: Option<&str> = None;
    for effect in effects {
        validate_identifier("effect", effect)?;
        if previous.is_some_and(|item| item >= effect.as_str()) {
            return Err(BytecodeError::Invalid(
                "effect rows must be strictly sorted".to_owned(),
            ));
        }
        previous = Some(effect);
    }
    Ok(())
}

fn validate_statement(
    statement: &CanonicalStatement,
    linear: bool,
    information_flow: bool,
    expression_count: &mut usize,
) -> Result<(), BytecodeError> {
    match statement {
        CanonicalStatement::Let {
            name,
            information,
            value,
            ..
        } => {
            validate_identifier("local", name)?;
            validate_information_presence(information_flow, information.as_ref(), "local")?;
            validate_expression(value, 0, expression_count)
        }
        CanonicalStatement::Return { value } => value.as_ref().map_or(Ok(()), |expression| {
            validate_expression(expression, 0, expression_count)
        }),
        CanonicalStatement::Request {
            effect,
            authority,
            information,
            arguments,
        } => {
            validate_identifier("requested effect", effect)?;
            validate_information_presence(information_flow, information.as_ref(), "request")?;
            match (linear, authority) {
                (false, None) => {}
                (true, Some(authority)) => validate_identifier("request authority", authority)?,
                (false, Some(_)) => {
                    return Err(BytecodeError::Invalid(
                        "legacy request cannot name an authority slot".to_owned(),
                    ));
                }
                (true, None) => {
                    return Err(BytecodeError::Invalid(
                        "linear request must name an authority slot".to_owned(),
                    ));
                }
            }
            for argument in arguments {
                validate_expression(argument, 0, expression_count)?;
            }
            Ok(())
        }
        CanonicalStatement::Expression { expression } => {
            validate_expression(expression, 0, expression_count)
        }
    }
}

fn validate_expression(
    expression: &CanonicalExpression,
    depth: usize,
    count: &mut usize,
) -> Result<(), BytecodeError> {
    if depth > MAX_EXPRESSION_DEPTH {
        return Err(BytecodeError::Invalid(format!(
            "expression depth exceeds {MAX_EXPRESSION_DEPTH}"
        )));
    }
    *count = count
        .checked_add(1)
        .ok_or_else(|| BytecodeError::Invalid("expression count overflow".to_owned()))?;
    if *count > MAX_EXPRESSION_NODES {
        return Err(BytecodeError::Invalid(format!(
            "expression node count exceeds {MAX_EXPRESSION_NODES}"
        )));
    }
    match expression {
        CanonicalExpression::Integer { value } => {
            let parsed = value
                .parse::<i64>()
                .map_err(|_| BytecodeError::Invalid("integer literal is outside i64".to_owned()))?;
            if parsed.to_string() != *value {
                return Err(BytecodeError::Invalid(
                    "integer literal is not canonical decimal i64".to_owned(),
                ));
            }
        }
        CanonicalExpression::Variable { name } => validate_identifier("variable", name)?,
        CanonicalExpression::Unary { operand, .. } => {
            validate_expression(operand, depth + 1, count)?;
        }
        CanonicalExpression::Binary { left, right, .. } => {
            validate_expression(left, depth + 1, count)?;
            validate_expression(right, depth + 1, count)?;
        }
        CanonicalExpression::Call {
            function,
            arguments,
        } => {
            validate_identifier("callee", function)?;
            for argument in arguments {
                validate_expression(argument, depth + 1, count)?;
            }
        }
        CanonicalExpression::Boolean { .. } | CanonicalExpression::String { .. } => {}
    }
    Ok(())
}

fn validate_identifier(field: &str, value: &str) -> Result<(), BytecodeError> {
    let mut bytes = value.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(BytecodeError::Invalid(format!(
            "{field} must use JOAN ASCII identifier syntax"
        )));
    }
    Ok(())
}

fn program_from_canonical(ast: &CanonicalProgram) -> Result<Program, BytecodeError> {
    Ok(Program {
        schema: "joan.ast.v0".to_owned(),
        module: ast.module.clone(),
        information_flow: ast.is_information_flow(),
        functions: ast
            .functions
            .iter()
            .map(function_from_canonical)
            .collect::<Result<Vec<_>, _>>()?,
        span: Span::default(),
    })
}

fn function_from_canonical(function: &CanonicalFunction) -> Result<Function, BytecodeError> {
    Ok(Function {
        name: function.name.clone(),
        parameters: function
            .parameters
            .iter()
            .map(|parameter| Parameter {
                name: parameter.name.clone(),
                value_type: parameter.value_type.clone(),
                information: parameter.information.clone(),
                span: Span::default(),
            })
            .collect(),
        return_type: function.return_type.clone(),
        return_information: function.return_information.clone(),
        effects: function.effects.clone(),
        authorities: function.authorities.as_ref().map(|authorities| {
            authorities
                .iter()
                .map(|authority| AuthorityParameter {
                    name: authority.name.clone(),
                    effect: authority.effect.clone(),
                    span: Span::default(),
                })
                .collect()
        }),
        body: function
            .body
            .iter()
            .map(statement_from_canonical)
            .collect::<Result<Vec<_>, _>>()?,
        span: Span::default(),
    })
}

fn statement_from_canonical(statement: &CanonicalStatement) -> Result<Statement, BytecodeError> {
    let span = Span::default();
    Ok(match statement {
        CanonicalStatement::Let {
            name,
            value_type,
            information,
            value,
        } => Statement::Let {
            name: name.clone(),
            value_type: value_type.clone(),
            information: information.clone(),
            value: expression_from_canonical(value)?,
            span,
        },
        CanonicalStatement::Return { value } => Statement::Return {
            value: value.as_ref().map(expression_from_canonical).transpose()?,
            span,
        },
        CanonicalStatement::Request {
            effect,
            authority,
            information,
            arguments,
        } => Statement::Request {
            effect: effect.clone(),
            authority: authority.clone(),
            information: information.clone(),
            arguments: arguments
                .iter()
                .map(expression_from_canonical)
                .collect::<Result<Vec<_>, _>>()?,
            span,
        },
        CanonicalStatement::Expression { expression } => Statement::Expression {
            expression: expression_from_canonical(expression)?,
            span,
        },
    })
}

fn expression_from_canonical(
    expression: &CanonicalExpression,
) -> Result<Expression, BytecodeError> {
    let span = Span::default();
    Ok(match expression {
        CanonicalExpression::Integer { value } => Expression::Integer {
            value: value
                .parse::<i64>()
                .map_err(|_| BytecodeError::Invalid("integer literal is outside i64".to_owned()))?,
            span,
        },
        CanonicalExpression::Boolean { value } => Expression::Boolean {
            value: *value,
            span,
        },
        CanonicalExpression::String { value } => Expression::String {
            value: value.clone(),
            span,
        },
        CanonicalExpression::Variable { name } => Expression::Variable {
            name: name.clone(),
            span,
        },
        CanonicalExpression::Unary { operator, operand } => Expression::Unary {
            operator: operator.clone(),
            operand: Box::new(expression_from_canonical(operand)?),
            span,
        },
        CanonicalExpression::Binary {
            operator,
            left,
            right,
        } => Expression::Binary {
            operator: operator.clone(),
            left: Box::new(expression_from_canonical(left)?),
            right: Box::new(expression_from_canonical(right)?),
            span,
        },
        CanonicalExpression::Call {
            function,
            arguments,
        } => Expression::Call {
            function: function.clone(),
            arguments: arguments
                .iter()
                .map(expression_from_canonical)
                .collect::<Result<Vec<_>, _>>()?,
            span,
        },
    })
}

struct VerificationObservation {
    instruction_count: u64,
    max_stack_depth: usize,
}

fn verify_structure(program: &BytecodeProgram) -> Result<VerificationObservation, BytecodeError> {
    if program.functions.is_empty() || program.functions.len() > MAX_FUNCTIONS {
        return Err(BytecodeError::Invalid(format!(
            "function table count must be 1..={MAX_FUNCTIONS}"
        )));
    }
    let entry = program
        .functions
        .get(program.entry_function)
        .ok_or_else(|| {
            BytecodeError::Invalid("entry function is outside the function table".to_owned())
        })?;
    if entry.name != "main" || entry.parameter_count != 0 {
        return Err(BytecodeError::Invalid(
            "entry function must be zero-argument main".to_owned(),
        ));
    }

    let mut names = BTreeSet::new();
    let mut graph = vec![Vec::new(); program.functions.len()];
    let mut instruction_count = 0u64;
    let mut max_stack_depth = 0usize;
    for (function_index, function) in program.functions.iter().enumerate() {
        validate_identifier("bytecode function", &function.name)?;
        if !names.insert(function.name.as_str()) {
            return Err(BytecodeError::Invalid(
                "bytecode function names must be unique".to_owned(),
            ));
        }
        validate_sorted_effects(&function.effects)?;
        validate_bytecode_authorities(program.canonical_ast.is_linear(), function)?;
        validate_bytecode_information(program.canonical_ast.is_information_flow(), function)?;
        if function.local_count > MAX_LOCALS_PER_FUNCTION {
            return Err(BytecodeError::Invalid(format!(
                "function {} local count exceeds {MAX_LOCALS_PER_FUNCTION}",
                function.name
            )));
        }
        if function.parameter_count != function.parameter_types.len()
            || function.local_count != function.local_types.len()
            || function.parameter_count > function.local_count
        {
            return Err(BytecodeError::Invalid(format!(
                "function {} has inconsistent frame counts",
                function.name
            )));
        }
        if function.parameter_count > MAX_PARAMETERS {
            return Err(BytecodeError::Invalid(format!(
                "function {} parameter count exceeds {MAX_PARAMETERS}",
                function.name
            )));
        }
        if function.parameter_types != function.local_types[..function.parameter_count] {
            return Err(BytecodeError::Invalid(format!(
                "function {} parameter types do not match frame prefix",
                function.name
            )));
        }
        if function.local_types.contains(&Type::Unit) {
            return Err(BytecodeError::Invalid(format!(
                "function {} contains a unit parameter or local",
                function.name
            )));
        }
        if function.instructions.is_empty()
            || function.instructions.len() > MAX_INSTRUCTIONS_PER_FUNCTION
        {
            return Err(BytecodeError::Invalid(format!(
                "function {} instruction count must be 1..={MAX_INSTRUCTIONS_PER_FUNCTION}",
                function.name
            )));
        }
        let count = u64::try_from(function.instructions.len())
            .map_err(|_| BytecodeError::Invalid("instruction count exceeds u64".to_owned()))?;
        instruction_count = instruction_count
            .checked_add(count)
            .ok_or_else(|| BytecodeError::Invalid("instruction count overflow".to_owned()))?;
        if instruction_count > MAX_TOTAL_INSTRUCTIONS {
            return Err(BytecodeError::Invalid(format!(
                "total instruction count exceeds {MAX_TOTAL_INSTRUCTIONS}"
            )));
        }
        let depth = verify_function(program, function_index, &mut graph[function_index])?;
        max_stack_depth = max_stack_depth.max(depth);
    }
    verify_acyclic(&graph)?;
    Ok(VerificationObservation {
        instruction_count,
        max_stack_depth,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "one flat abstract opcode dispatcher makes every stack transition reviewable"
)]
fn verify_function(
    program: &BytecodeProgram,
    function_index: usize,
    calls: &mut Vec<usize>,
) -> Result<usize, BytecodeError> {
    let function = &program.functions[function_index];
    let mut initialized = vec![false; function.local_count];
    initialized[..function.parameter_count].fill(true);
    let mut stack = Vec::new();
    let mut max_depth = 0usize;
    let authority_slots = function
        .authority_slots
        .as_ref()
        .map(|slots| {
            slots
                .iter()
                .map(|slot| (slot.name.as_str(), slot.effect.as_str()))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let mut consumed_authorities = BTreeSet::new();
    for (instruction_index, instruction) in function.instructions.iter().enumerate() {
        if matches!(instruction, Instruction::Return)
            && instruction_index + 1 != function.instructions.len()
        {
            return Err(BytecodeError::Invalid(format!(
                "function {} has instructions after return",
                function.name
            )));
        }
        match instruction {
            Instruction::Push { value } => stack.push(AbstractValue::public(value.value_type())),
            Instruction::LoadLocal { slot } => {
                let value_type = function.local_types.get(*slot).ok_or_else(|| {
                    BytecodeError::Invalid(format!(
                        "function {} loads outside its frame",
                        function.name
                    ))
                })?;
                if !initialized[*slot] {
                    return Err(BytecodeError::Invalid(format!(
                        "function {} loads an uninitialized local",
                        function.name
                    )));
                }
                let information = function
                    .local_information
                    .as_ref()
                    .map_or(InformationLabel::Public, |labels| labels[*slot].clone());
                stack.push(AbstractValue {
                    value_type: value_type.clone(),
                    information,
                });
            }
            Instruction::StoreLocal { slot } => {
                let expected = function.local_types.get(*slot).ok_or_else(|| {
                    BytecodeError::Invalid(format!(
                        "function {} stores outside its frame",
                        function.name
                    ))
                })?;
                if initialized[*slot] {
                    return Err(BytecodeError::Invalid(format!(
                        "function {} overwrites an immutable local",
                        function.name
                    )));
                }
                let actual = require_pop(&mut stack, expected, "local store")?;
                let destination = function
                    .local_information
                    .as_ref()
                    .map_or(&InformationLabel::Public, |labels| &labels[*slot]);
                require_information_flow(&actual.information, destination, "local store")?;
                initialized[*slot] = true;
            }
            Instruction::Pop => {
                pop_type(&mut stack, "pop")?;
            }
            Instruction::Negate => unary_type(&mut stack, &Type::I64, &Type::I64, "negate")?,
            Instruction::Not => unary_type(&mut stack, &Type::Bool, &Type::Bool, "not")?,
            Instruction::Add
            | Instruction::Subtract
            | Instruction::Multiply
            | Instruction::Divide
            | Instruction::Remainder => {
                binary_type(&mut stack, &Type::I64, &Type::I64, "integer binary")?;
            }
            Instruction::Less
            | Instruction::LessEqual
            | Instruction::Greater
            | Instruction::GreaterEqual => {
                binary_type(&mut stack, &Type::I64, &Type::Bool, "integer comparison")?;
            }
            Instruction::And | Instruction::Or => {
                binary_type(&mut stack, &Type::Bool, &Type::Bool, "boolean binary")?;
            }
            Instruction::Equal | Instruction::NotEqual => {
                let right = pop_type(&mut stack, "equality")?;
                let left = pop_type(&mut stack, "equality")?;
                if left.value_type != right.value_type {
                    return Err(BytecodeError::Invalid(
                        "equality operands have different types".to_owned(),
                    ));
                }
                let information =
                    join_information(&left.information, &right.information, "equality")?;
                stack.push(AbstractValue {
                    value_type: Type::Bool,
                    information,
                });
            }
            Instruction::Call {
                function: target_index,
                argument_count,
            } => {
                let target = program.functions.get(*target_index).ok_or_else(|| {
                    BytecodeError::Invalid("call target is outside the function table".to_owned())
                })?;
                if *argument_count != target.parameter_count {
                    return Err(BytecodeError::Invalid(format!(
                        "call to {} has inconsistent argument count",
                        target.name
                    )));
                }
                require_arguments(
                    &mut stack,
                    &target.parameter_types,
                    target.parameter_information.as_deref(),
                    "call",
                )?;
                if !target
                    .effects
                    .iter()
                    .all(|effect| function.effects.binary_search(effect).is_ok())
                {
                    return Err(BytecodeError::Invalid(format!(
                        "function {} does not propagate callee effects",
                        function.name
                    )));
                }
                calls.push(*target_index);
                stack.push(AbstractValue {
                    value_type: target.return_type.clone(),
                    information: target.return_information.clone().unwrap_or_default(),
                });
            }
            Instruction::Request {
                effect,
                authority,
                information,
                argument_count,
            } => {
                validate_identifier("bytecode requested effect", effect)?;
                if function.effects.binary_search(effect).is_err() {
                    return Err(BytecodeError::Invalid(format!(
                        "function {} requests undeclared effect {}",
                        function.name, effect
                    )));
                }
                if stack.len() < *argument_count {
                    return Err(BytecodeError::Invalid(
                        "effect argument stack underflow".to_owned(),
                    ));
                }
                validate_information_presence(
                    program.canonical_ast.is_information_flow(),
                    information.as_ref(),
                    "bytecode request",
                )?;
                let sink = information.as_ref().unwrap_or(&InformationLabel::Public);
                for argument in &stack[stack.len() - argument_count..] {
                    require_information_flow(&argument.information, sink, "effect request")?;
                }
                match (program.canonical_ast.is_linear(), authority) {
                    (false, None) => {}
                    (true, Some(authority)) => {
                        let allowed_effect =
                            authority_slots.get(authority.as_str()).ok_or_else(|| {
                                BytecodeError::Invalid(format!(
                                    "function {} requests unknown authority slot {}",
                                    function.name, authority
                                ))
                            })?;
                        if *allowed_effect != effect {
                            return Err(BytecodeError::Invalid(format!(
                                "function {} authority slot {} permits {}, not {}",
                                function.name, authority, allowed_effect, effect
                            )));
                        }
                        if !consumed_authorities.insert(authority.as_str()) {
                            return Err(BytecodeError::Invalid(format!(
                                "function {} reuses linear authority slot {}",
                                function.name, authority
                            )));
                        }
                    }
                    (false, Some(_)) => {
                        return Err(BytecodeError::Invalid(
                            "legacy bytecode request contains authority".to_owned(),
                        ));
                    }
                    (true, None) => {
                        return Err(BytecodeError::Invalid(
                            "linear bytecode request has no authority".to_owned(),
                        ));
                    }
                }
                stack.truncate(stack.len() - argument_count);
            }
            Instruction::Return => {
                let expected_information = function
                    .return_information
                    .as_ref()
                    .unwrap_or(&InformationLabel::Public);
                if stack.len() != 1 || stack[0].value_type != function.return_type {
                    return Err(BytecodeError::Invalid(format!(
                        "function {} returns the wrong stack shape or type",
                        function.name
                    )));
                }
                require_information_flow(
                    &stack[0].information,
                    expected_information,
                    "function return",
                )?;
                stack.clear();
            }
        }
        if stack.len() > MAX_STACK_DEPTH {
            return Err(BytecodeError::Invalid(format!(
                "abstract stack depth exceeds {MAX_STACK_DEPTH}"
            )));
        }
        max_depth = max_depth.max(stack.len());
    }
    if !matches!(function.instructions.last(), Some(Instruction::Return)) {
        return Err(BytecodeError::Invalid(format!(
            "function {} does not end in return",
            function.name
        )));
    }
    if consumed_authorities.len() != authority_slots.len() {
        return Err(BytecodeError::Invalid(format!(
            "function {} does not consume every linear authority slot",
            function.name
        )));
    }
    Ok(max_depth)
}

fn pop_type(stack: &mut Vec<AbstractValue>, context: &str) -> Result<AbstractValue, BytecodeError> {
    stack
        .pop()
        .ok_or_else(|| BytecodeError::Invalid(format!("{context} stack underflow")))
}

fn require_pop(
    stack: &mut Vec<AbstractValue>,
    expected: &Type,
    context: &str,
) -> Result<AbstractValue, BytecodeError> {
    let actual = pop_type(stack, context)?;
    if actual.value_type != *expected {
        return Err(BytecodeError::Invalid(format!(
            "{context} expected {} but found {}",
            expected.as_str(),
            actual.value_type.as_str()
        )));
    }
    Ok(actual)
}

fn unary_type(
    stack: &mut Vec<AbstractValue>,
    input: &Type,
    output: &Type,
    context: &str,
) -> Result<(), BytecodeError> {
    let value = require_pop(stack, input, context)?;
    stack.push(AbstractValue {
        value_type: output.clone(),
        information: value.information,
    });
    Ok(())
}

fn binary_type(
    stack: &mut Vec<AbstractValue>,
    input: &Type,
    output: &Type,
    context: &str,
) -> Result<(), BytecodeError> {
    let right = require_pop(stack, input, context)?;
    let left = require_pop(stack, input, context)?;
    stack.push(AbstractValue {
        value_type: output.clone(),
        information: join_information(&left.information, &right.information, context)?,
    });
    Ok(())
}

fn require_arguments(
    stack: &mut Vec<AbstractValue>,
    expected: &[Type],
    expected_information: Option<&[InformationLabel]>,
    context: &str,
) -> Result<(), BytecodeError> {
    if stack.len() < expected.len() {
        return Err(BytecodeError::Invalid(format!(
            "{context} argument stack underflow"
        )));
    }
    let start = stack.len() - expected.len();
    if stack[start..]
        .iter()
        .map(|value| &value.value_type)
        .ne(expected.iter())
    {
        return Err(BytecodeError::Invalid(format!(
            "{context} argument types do not match target signature"
        )));
    }
    if let Some(labels) = expected_information {
        for (actual, destination) in stack[start..].iter().zip(labels) {
            require_information_flow(&actual.information, destination, context)?;
        }
    }
    stack.truncate(start);
    Ok(())
}

fn require_information_flow(
    source: &InformationLabel,
    destination: &InformationLabel,
    context: &str,
) -> Result<(), BytecodeError> {
    if source.can_flow_to(destination) {
        Ok(())
    } else {
        Err(BytecodeError::Invalid(format!(
            "{context} violates tenant-purpose information flow"
        )))
    }
}

fn join_information(
    left: &InformationLabel,
    right: &InformationLabel,
    context: &str,
) -> Result<InformationLabel, BytecodeError> {
    left.join(right).ok_or_else(|| {
        BytecodeError::Invalid(format!(
            "{context} combines incompatible tenant-purpose labels"
        ))
    })
}

fn verify_acyclic(graph: &[Vec<usize>]) -> Result<(), BytecodeError> {
    let mut state = vec![0u8; graph.len()];
    for index in 0..graph.len() {
        visit_graph(index, graph, &mut state)?;
    }
    Ok(())
}

fn visit_graph(index: usize, graph: &[Vec<usize>], state: &mut [u8]) -> Result<(), BytecodeError> {
    match state[index] {
        1 => {
            return Err(BytecodeError::Invalid(
                "bytecode call graph contains a cycle".to_owned(),
            ));
        }
        2 => return Ok(()),
        _ => {}
    }
    state[index] = 1;
    for target in &graph[index] {
        visit_graph(*target, graph, state)?;
    }
    state[index] = 2;
    Ok(())
}

fn independently_emit(
    ast: &CanonicalProgram,
    identity: CanonicalAstIdentity,
) -> Result<BytecodeProgram, BytecodeError> {
    let indexes = ast
        .functions
        .iter()
        .enumerate()
        .map(|(index, function)| (function.name.clone(), index))
        .collect::<BTreeMap<_, _>>();
    let entry_function = indexes
        .get("main")
        .copied()
        .ok_or_else(|| BytecodeError::Invalid("canonical AST has no main".to_owned()))?;
    let functions = ast
        .functions
        .iter()
        .map(|function| independently_emit_function(function, &indexes))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BytecodeProgram {
        schema: if ast.is_information_flow() {
            BYTECODE_PROGRAM_INFORMATION_SCHEMA
        } else if ast.is_linear() {
            BYTECODE_PROGRAM_LINEAR_SCHEMA
        } else {
            BYTECODE_PROGRAM_SCHEMA
        }
        .to_owned(),
        module: ast.module.clone(),
        semantic_digest: identity.digest.clone(),
        semantic_identity: identity,
        canonical_ast: ast.clone(),
        entry_function,
        functions,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "one flat independent emitter keeps exact AST-to-bytecode binding reviewable"
)]
fn independently_emit_function(
    function: &CanonicalFunction,
    function_indexes: &BTreeMap<String, usize>,
) -> Result<BytecodeFunction, BytecodeError> {
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
    let parameter_information = function
        .return_information
        .as_ref()
        .map(|_| {
            function
                .parameters
                .iter()
                .map(|parameter| {
                    parameter.information.clone().ok_or_else(|| {
                        BytecodeError::Invalid("flow parameter has no information label".to_owned())
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;
    let mut local_types = parameter_types.clone();
    let mut local_information = parameter_information.clone();
    let mut instructions = Vec::new();
    for statement in &function.body {
        match statement {
            CanonicalStatement::Let {
                name,
                value_type,
                information,
                value,
            } => {
                independently_emit_expression(value, &locals, function_indexes, &mut instructions)?;
                let slot = locals.len();
                locals.insert(name.clone(), slot);
                local_types.push(value_type.clone());
                if let Some(labels) = &mut local_information {
                    labels.push(information.clone().ok_or_else(|| {
                        BytecodeError::Invalid("flow local has no information label".to_owned())
                    })?);
                }
                instructions.push(Instruction::StoreLocal { slot });
            }
            CanonicalStatement::Return { value } => {
                if let Some(value) = value {
                    independently_emit_expression(
                        value,
                        &locals,
                        function_indexes,
                        &mut instructions,
                    )?;
                } else {
                    instructions.push(Instruction::Push { value: Value::Unit });
                }
                instructions.push(Instruction::Return);
            }
            CanonicalStatement::Request {
                effect,
                authority,
                information,
                arguments,
            } => {
                for argument in arguments {
                    independently_emit_expression(
                        argument,
                        &locals,
                        function_indexes,
                        &mut instructions,
                    )?;
                }
                instructions.push(Instruction::Request {
                    effect: effect.clone(),
                    authority: authority.clone(),
                    information: information.clone(),
                    argument_count: arguments.len(),
                });
            }
            CanonicalStatement::Expression { expression } => {
                independently_emit_expression(
                    expression,
                    &locals,
                    function_indexes,
                    &mut instructions,
                )?;
                instructions.push(Instruction::Pop);
            }
        }
    }
    Ok(BytecodeFunction {
        name: function.name.clone(),
        parameter_count: parameter_types.len(),
        parameter_types,
        parameter_information,
        local_count: local_types.len(),
        local_types,
        local_information,
        return_type: function.return_type.clone(),
        return_information: function.return_information.clone(),
        effects: function.effects.clone(),
        authority_slots: function.authorities.as_ref().map(|authorities| {
            authorities
                .iter()
                .map(|authority| BytecodeAuthoritySlot {
                    name: authority.name.clone(),
                    effect: authority.effect.clone(),
                })
                .collect()
        }),
        instructions,
    })
}

fn independently_emit_expression(
    expression: &CanonicalExpression,
    locals: &BTreeMap<String, usize>,
    function_indexes: &BTreeMap<String, usize>,
    instructions: &mut Vec<Instruction>,
) -> Result<(), BytecodeError> {
    match expression {
        CanonicalExpression::Integer { value } => instructions.push(Instruction::Push {
            value: Value::I64(value.parse::<i64>().map_err(|_| {
                BytecodeError::Invalid("integer literal is outside i64".to_owned())
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
                BytecodeError::Invalid(format!("canonical local {name} is missing"))
            })?;
            instructions.push(Instruction::LoadLocal { slot });
        }
        CanonicalExpression::Unary { operator, operand } => {
            independently_emit_expression(operand, locals, function_indexes, instructions)?;
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
            independently_emit_expression(left, locals, function_indexes, instructions)?;
            independently_emit_expression(right, locals, function_indexes, instructions)?;
            instructions.push(binary_instruction(operator));
        }
        CanonicalExpression::Call {
            function,
            arguments,
        } => {
            for argument in arguments {
                independently_emit_expression(argument, locals, function_indexes, instructions)?;
            }
            let target = function_indexes.get(function).copied().ok_or_else(|| {
                BytecodeError::Invalid(format!("canonical function {function} is missing"))
            })?;
            instructions.push(Instruction::Call {
                function: target,
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
