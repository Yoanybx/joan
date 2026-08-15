//! Experimental Cranelift JIT backend for the pure JOAN native subset.

#![deny(unsafe_code)]

#[allow(unsafe_code)]
mod unsafe_boundary;

use cranelift_codegen::FinalizedRelocTarget;
use cranelift_codegen::ir::{
    AbiParam, ExternalName, InstBuilder, MemFlagsData, UserFuncName, Value as ClValue,
    condcodes::IntCC, types,
};
use cranelift_codegen::settings::{self, Configurable};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{FuncId, Linkage, Module, default_libcall_names};
use joan_ast::Type;
use joan_bytecode::{
    BYTECODE_PROGRAM_SCHEMA, BytecodeFunction, BytecodeProgram, Instruction, Value, verify_bytecode,
};
use joan_canonical::{
    Digest, Jce1Error, RegisteredDomainV1, digest_bytes_v1, digest_serializable_v1,
};
pub use joan_host::{
    NATIVE_COMPILE_RECEIPT_V0, NATIVE_EXECUTION_RECEIPT_V0, NativeCompileReceipt,
    NativeExecutionReceipt,
};
use serde::Serialize;
use std::collections::BTreeMap;
use thiserror::Error;

use unsafe_boundary::{NativeEntrypoint, OwnedJitModule, finalized_entrypoint, invoke_entrypoint};

/// First executable native subset. It intentionally excludes strings and effects.
pub const NATIVE_SUBSET_V0: &str = "joan.native-subset.v0";
/// Backend implementation and configuration identifier.
pub const NATIVE_BACKEND_V0: &str = "joan.cranelift-jit.v0";
/// Frozen Cranelift optimization profile for the native backend.
pub const NATIVE_OPTIMIZATION_PROFILE_V0: &str = "speed";
/// Exact Cranelift crate version frozen into this backend implementation.
pub const CRANELIFT_VERSION: &str = "0.134.3";

/// Maximum JOAN functions accepted before allocating JIT state.
pub const MAX_NATIVE_FUNCTIONS: usize = 256;
/// Maximum instructions in one native-subset function.
pub const MAX_NATIVE_INSTRUCTIONS_PER_FUNCTION: usize = 10_000;
/// Maximum instructions across one compiled native-subset program.
pub const MAX_NATIVE_TOTAL_INSTRUCTIONS: usize = 50_000;
/// Maximum frame slots in one native-subset function.
pub const MAX_NATIVE_LOCALS_PER_FUNCTION: usize = 10_000;
const MAX_NATIVE_CODE_BYTES_PER_FUNCTION: usize = 1_048_576;
const MAX_NATIVE_TOTAL_CODE_BYTES: u64 = 16 * 1_048_576;
const MAX_NATIVE_RELOCATIONS_PER_FUNCTION: usize = 10_000;
const MAX_NATIVE_TOTAL_RELOCATIONS: u64 = 5_120_000;

const STATUS_OK: u32 = 0;
const STATUS_BUDGET_EXHAUSTED: u32 = 1;
const STATUS_NEGATION_OVERFLOW: u32 = 2;
const STATUS_ADDITION_FAILED: u32 = 3;
const STATUS_SUBTRACTION_FAILED: u32 = 4;
const STATUS_MULTIPLICATION_FAILED: u32 = 5;
const STATUS_DIVISION_FAILED: u32 = 6;
const STATUS_REMAINDER_FAILED: u32 = 7;

/// Raw result from one prepared native invocation.
///
/// This intentionally contains no trust receipt. A caller that batches work must bind its final
/// result to [`NativeCompileReceipt`] before crossing a trust boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeKernelResult {
    /// Normalized result: integer unchanged, boolean as 0/1, and unit as 0.
    pub normalized_value: i64,
    /// Exact JOAN bytecode instructions consumed by this invocation.
    pub instructions_executed: u64,
}

#[derive(Clone, Debug, Serialize)]
struct NativeArtifactCore<'a> {
    subset: &'a str,
    backend: &'a str,
    codegen_version: &'a str,
    optimization_profile: &'a str,
    target: &'a str,
    flags: &'a [String],
    semantic_digest: &'a Digest,
    bytecode_digest: &'a Digest,
    functions: &'a [NativeCodeIdentity],
}

#[derive(Clone, Debug, Serialize)]
struct NativeCodeIdentity {
    name: String,
    code_digest: Digest,
    code_bytes: u64,
    relocations: Vec<NativeRelocationIdentity>,
}

#[derive(Clone, Debug, Serialize)]
struct NativeRelocationIdentity {
    offset: u32,
    kind: String,
    target: String,
    addend: String,
}

#[derive(Clone)]
struct NativeFunction {
    entrypoint: NativeEntrypoint,
    parameter_types: Vec<Type>,
    return_type: Type,
}

/// Compiled native program. Generated function pointers remain valid while this value is alive.
pub struct NativeProgram {
    module: OwnedJitModule,
    functions: BTreeMap<String, NativeFunction>,
    receipt: NativeCompileReceipt,
}

/// Function resolved once for allocation-free repeated native invocation.
pub struct PreparedNativeInvocation<'a> {
    function: &'a NativeFunction,
}

impl std::fmt::Debug for PreparedNativeInvocation<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedNativeInvocation")
            .field("parameter_types", &self.function.parameter_types)
            .field("return_type", &self.function.return_type)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for NativeProgram {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeProgram")
            .field("functions", &self.functions.keys().collect::<Vec<_>>())
            .field("receipt", &self.receipt)
            .finish_non_exhaustive()
    }
}

/// Native compilation or execution failure.
#[derive(Debug, Error)]
pub enum NativeError {
    /// Verified bytecode contract was rejected.
    #[error("bytecode verification failed: {0}")]
    Bytecode(#[from] joan_bytecode::BytecodeError),
    /// Program uses a feature outside the frozen native subset.
    #[error("native subset rejected program: {0}")]
    Unsupported(String),
    /// Program or generated code exceeds the experimental JIT resource envelope.
    #[error("native resource limit rejected program: {0}")]
    ResourceLimit(String),
    /// Cranelift could not construct or link native code.
    #[error("native code generation failed: {0}")]
    Codegen(String),
    /// Canonical artifact identity construction failed.
    #[error("native artifact identity failed: {0}")]
    Identity(#[from] Jce1Error),
    /// Invocation input or bounded execution failed.
    #[error("native execution failed: {0}")]
    Runtime(String),
}

impl NativeProgram {
    /// Compilation receipt for this exact native artifact.
    #[must_use]
    pub const fn receipt(&self) -> &NativeCompileReceipt {
        &self.receipt
    }

    /// Resolve one function once for bounded repeated invocation.
    pub fn prepare(
        &self,
        function_name: &str,
    ) -> Result<PreparedNativeInvocation<'_>, NativeError> {
        let function = self.functions.get(function_name).ok_or_else(|| {
            NativeError::Runtime(format!("function `{function_name}` was not found"))
        })?;
        Ok(PreparedNativeInvocation { function })
    }

    /// Invoke one compiled function with dynamic typed arguments and a strict instruction budget.
    pub fn invoke(
        &self,
        function_name: &str,
        arguments: &[Value],
        instruction_budget: u64,
    ) -> Result<NativeExecutionReceipt, NativeError> {
        if instruction_budget == 0 {
            return Err(NativeError::Runtime(
                "instruction budget must be greater than zero".to_owned(),
            ));
        }
        let function = self.functions.get(function_name).ok_or_else(|| {
            NativeError::Runtime(format!("function `{function_name}` was not found"))
        })?;
        validate_arguments(function_name, &function.parameter_types, arguments)?;
        let normalized = arguments
            .iter()
            .map(normalize_value)
            .collect::<Result<Vec<_>, _>>()?;
        let mut remaining = instruction_budget;
        let mut output = 0_i64;
        let status = invoke_entrypoint(
            function.entrypoint,
            &normalized,
            &mut remaining,
            &mut output,
        );
        if status != STATUS_OK {
            return Err(NativeError::Runtime(status_message(status).to_owned()));
        }
        let result = denormalize_value(output, &function.return_type)?;
        Ok(NativeExecutionReceipt {
            schema: NATIVE_EXECUTION_RECEIPT_V0.to_owned(),
            status: "completed".to_owned(),
            artifact_digest: self.receipt.artifact_digest.clone(),
            bytecode_digest: self.receipt.bytecode_digest.clone(),
            function: function_name.to_owned(),
            result,
            instructions_executed: instruction_budget - remaining,
        })
    }

    /// Keep the JIT module observably owned by this artifact.
    #[must_use]
    pub fn target(&self) -> String {
        self.module.isa().triple().to_string()
    }
}

impl PreparedNativeInvocation<'_> {
    /// Invoke through the normalized scalar ABI without a per-call allocation or trust receipt.
    ///
    /// Argument count and canonical boolean/unit encodings remain checked. Fuel and checked
    /// arithmetic have the same semantics as [`NativeProgram::invoke`].
    pub fn invoke_normalized(
        &self,
        arguments: &[i64],
        instruction_budget: u64,
    ) -> Result<NativeKernelResult, NativeError> {
        if instruction_budget == 0 {
            return Err(NativeError::Runtime(
                "instruction budget must be greater than zero".to_owned(),
            ));
        }
        validate_normalized_arguments(&self.function.parameter_types, arguments)?;
        let mut remaining = instruction_budget;
        let mut output = 0_i64;
        let status = invoke_entrypoint(
            self.function.entrypoint,
            arguments,
            &mut remaining,
            &mut output,
        );
        if status != STATUS_OK {
            return Err(NativeError::Runtime(status_message(status).to_owned()));
        }
        validate_normalized_result(output, &self.function.return_type)?;
        Ok(NativeKernelResult {
            normalized_value: output,
            instructions_executed: instruction_budget - remaining,
        })
    }
}

/// Verify and compile one program into host-native code for the frozen pure subset.
pub fn compile_bytecode(program: &BytecodeProgram) -> Result<NativeProgram, NativeError> {
    let verification = verify_bytecode(program)?;
    validate_subset(program)?;
    let (mut module, target, flags) = new_jit_module()?;

    let internal_ids = declare_internal_functions(&mut module, program)?;
    let wrapper_ids = declare_wrappers(&mut module, program)?;
    let mut code_identities = Vec::with_capacity(program.functions.len() * 2);
    for (index, function) in program.functions.iter().enumerate() {
        code_identities.push(define_internal_function(
            &mut module,
            function,
            internal_ids[index],
            &internal_ids,
            format!("internal:{}", function.name),
        )?);
    }
    for (index, function) in program.functions.iter().enumerate() {
        code_identities.push(define_wrapper(
            &mut module,
            function,
            wrapper_ids[index],
            internal_ids[index],
            format!("wrapper:{}", function.name),
        )?);
    }
    let (code_bytes, relocation_count) = summarize_code_identities(&code_identities)?;
    module
        .finalize_definitions()
        .map_err(|error| NativeError::Codegen(error.to_string()))?;

    let mut functions = BTreeMap::new();
    for (index, function) in program.functions.iter().enumerate() {
        let entrypoint = finalized_entrypoint(&module, wrapper_ids[index]);
        functions.insert(
            function.name.clone(),
            NativeFunction {
                entrypoint,
                parameter_types: function.parameter_types.clone(),
                return_type: function.return_type.clone(),
            },
        );
    }

    let artifact_digest = digest_serializable_v1(
        RegisteredDomainV1::NativeArtifact,
        &NativeArtifactCore {
            subset: NATIVE_SUBSET_V0,
            backend: NATIVE_BACKEND_V0,
            codegen_version: CRANELIFT_VERSION,
            optimization_profile: NATIVE_OPTIMIZATION_PROFILE_V0,
            target: &target,
            flags: &flags,
            semantic_digest: &program.semantic_digest,
            bytecode_digest: &verification.bytecode_digest,
            functions: &code_identities,
        },
    )?;
    let function_count = u64::try_from(program.functions.len())
        .map_err(|_| NativeError::Codegen("function count exceeds u64".to_owned()))?;
    let receipt = NativeCompileReceipt {
        schema: NATIVE_COMPILE_RECEIPT_V0.to_owned(),
        status: "compiled".to_owned(),
        subset: NATIVE_SUBSET_V0.to_owned(),
        backend: NATIVE_BACKEND_V0.to_owned(),
        codegen_version: CRANELIFT_VERSION.to_owned(),
        optimization_profile: NATIVE_OPTIMIZATION_PROFILE_V0.to_owned(),
        target,
        flags,
        semantic_digest: program.semantic_digest.clone(),
        bytecode_digest: verification.bytecode_digest,
        artifact_digest,
        function_count,
        code_bytes,
        relocation_count,
    };
    Ok(NativeProgram {
        module,
        functions,
        receipt,
    })
}

fn new_jit_module() -> Result<(OwnedJitModule, String, Vec<String>), NativeError> {
    let mut flag_builder = settings::builder();
    for (name, value) in [
        ("use_colocated_libcalls", "false"),
        ("is_pic", "false"),
        ("opt_level", NATIVE_OPTIMIZATION_PROFILE_V0),
    ] {
        flag_builder
            .set(name, value)
            .map_err(|error| NativeError::Codegen(error.to_string()))?;
    }
    let isa = cranelift_native::builder()
        .map_err(|error| NativeError::Codegen(error.to_owned()))?
        .finish(settings::Flags::new(flag_builder))
        .map_err(|error| NativeError::Codegen(error.to_string()))?;
    let module = OwnedJitModule::new(JITModule::new(JITBuilder::with_isa(
        isa,
        default_libcall_names(),
    )));
    let target = module.isa().triple().to_string();
    let mut flags = module
        .isa()
        .flags()
        .iter()
        .map(|flag| flag.to_string())
        .collect::<Vec<_>>();
    flags.extend(module.isa().isa_flags().iter().map(ToString::to_string));
    flags.sort();
    flags.dedup();
    Ok((module, target, flags))
}

fn summarize_code_identities(functions: &[NativeCodeIdentity]) -> Result<(u64, u64), NativeError> {
    let code_bytes = functions.iter().try_fold(0_u64, |total, function| {
        total
            .checked_add(function.code_bytes)
            .ok_or_else(|| NativeError::Codegen("generated code size exceeds u64".to_owned()))
    })?;
    if code_bytes > MAX_NATIVE_TOTAL_CODE_BYTES {
        return Err(NativeError::ResourceLimit(format!(
            "generated code has {code_bytes} bytes; limit is {MAX_NATIVE_TOTAL_CODE_BYTES}"
        )));
    }
    let relocations = functions.iter().try_fold(0_u64, |total, function| {
        u64::try_from(function.relocations.len())
            .ok()
            .and_then(|count| total.checked_add(count))
            .ok_or_else(|| NativeError::Codegen("relocation count exceeds u64".to_owned()))
    })?;
    if relocations > MAX_NATIVE_TOTAL_RELOCATIONS {
        return Err(NativeError::ResourceLimit(format!(
            "generated code has {relocations} relocations; limit is {MAX_NATIVE_TOTAL_RELOCATIONS}"
        )));
    }
    Ok((code_bytes, relocations))
}

fn validate_subset(program: &BytecodeProgram) -> Result<(), NativeError> {
    if program.schema != BYTECODE_PROGRAM_SCHEMA {
        return Err(NativeError::Unsupported(format!(
            "schema `{}` is not `{BYTECODE_PROGRAM_SCHEMA}`",
            program.schema
        )));
    }
    if program.functions.len() > MAX_NATIVE_FUNCTIONS {
        return Err(NativeError::ResourceLimit(format!(
            "program has {} functions; limit is {MAX_NATIVE_FUNCTIONS}",
            program.functions.len()
        )));
    }
    let mut total_instructions = 0_usize;
    for function in &program.functions {
        if function.instructions.len() > MAX_NATIVE_INSTRUCTIONS_PER_FUNCTION {
            return Err(NativeError::ResourceLimit(format!(
                "function `{}` has {} instructions; limit is {MAX_NATIVE_INSTRUCTIONS_PER_FUNCTION}",
                function.name,
                function.instructions.len()
            )));
        }
        total_instructions = total_instructions
            .checked_add(function.instructions.len())
            .ok_or_else(|| NativeError::ResourceLimit("instruction count overflow".to_owned()))?;
        if total_instructions > MAX_NATIVE_TOTAL_INSTRUCTIONS {
            return Err(NativeError::ResourceLimit(format!(
                "program has {total_instructions} instructions; limit is {MAX_NATIVE_TOTAL_INSTRUCTIONS}"
            )));
        }
        if function.local_count > MAX_NATIVE_LOCALS_PER_FUNCTION {
            return Err(NativeError::ResourceLimit(format!(
                "function `{}` has {} locals; limit is {MAX_NATIVE_LOCALS_PER_FUNCTION}",
                function.name, function.local_count
            )));
        }
        if !function.effects.is_empty() || function.authority_slots.is_some() {
            return Err(NativeError::Unsupported(format!(
                "function `{}` is not pure legacy bytecode",
                function.name
            )));
        }
        for value_type in function
            .parameter_types
            .iter()
            .chain(&function.local_types)
            .chain(std::iter::once(&function.return_type))
        {
            if matches!(value_type, Type::String) {
                return Err(NativeError::Unsupported(format!(
                    "function `{}` uses string values",
                    function.name
                )));
            }
        }
        for instruction in &function.instructions {
            match instruction {
                Instruction::Push {
                    value: Value::String(_),
                }
                | Instruction::Request { .. } => {
                    return Err(NativeError::Unsupported(format!(
                        "function `{}` contains an unsupported instruction",
                        function.name
                    )));
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn declare_internal_functions(
    module: &mut JITModule,
    program: &BytecodeProgram,
) -> Result<Vec<FuncId>, NativeError> {
    program
        .functions
        .iter()
        .map(|function| {
            let mut signature = module.make_signature();
            for _ in &function.parameter_types {
                signature.params.push(AbiParam::new(types::I64));
            }
            signature
                .params
                .push(AbiParam::new(module.target_config().pointer_type()));
            signature.returns.push(AbiParam::new(types::I32));
            signature.returns.push(AbiParam::new(types::I64));
            module
                .declare_function(
                    &format!("joan_native_internal_{}", function.name),
                    Linkage::Local,
                    &signature,
                )
                .map_err(|error| NativeError::Codegen(error.to_string()))
        })
        .collect()
}

fn declare_wrappers(
    module: &mut JITModule,
    program: &BytecodeProgram,
) -> Result<Vec<FuncId>, NativeError> {
    let pointer_type = module.target_config().pointer_type();
    program
        .functions
        .iter()
        .map(|function| {
            let mut signature = module.make_signature();
            signature.params.push(AbiParam::new(pointer_type));
            signature.params.push(AbiParam::new(pointer_type));
            signature.params.push(AbiParam::new(pointer_type));
            signature.returns.push(AbiParam::new(types::I32));
            module
                .declare_function(
                    &format!("joan_native_wrapper_{}", function.name),
                    Linkage::Local,
                    &signature,
                )
                .map_err(|error| NativeError::Codegen(error.to_string()))
        })
        .collect()
}

#[allow(
    clippy::too_many_lines,
    reason = "the straight-line lowering keeps each frozen bytecode opcode auditable"
)]
fn define_internal_function(
    module: &mut JITModule,
    function: &BytecodeFunction,
    function_id: FuncId,
    function_ids: &[FuncId],
    identity_name: String,
) -> Result<NativeCodeIdentity, NativeError> {
    let mut context = module.make_context();
    let mut signature = module.make_signature();
    for _ in &function.parameter_types {
        signature.params.push(AbiParam::new(types::I64));
    }
    signature
        .params
        .push(AbiParam::new(module.target_config().pointer_type()));
    signature.returns.push(AbiParam::new(types::I32));
    signature.returns.push(AbiParam::new(types::I64));
    context.func.signature = signature;
    context.func.name = UserFuncName::user(0, function_id.as_u32());
    let mut function_builder_context = FunctionBuilderContext::new();
    {
        let target_config = module.target_config();
        let mut builder = FunctionBuilder::new(&mut context.func, &mut function_builder_context);
        let mem_flags = MemFlagsData::trusted();
        let entry = builder.create_block();
        builder.append_block_params_for_function_params(entry);
        builder.switch_to_block(entry);
        let parameters = builder.block_params(entry).to_vec();
        let fuel = parameters[function.parameter_count];
        let mut locals = vec![None; function.local_count];
        for (index, value) in parameters[..function.parameter_count]
            .iter()
            .copied()
            .enumerate()
        {
            locals[index] = Some(value);
        }
        let mut stack = Vec::new();
        for instruction in &function.instructions {
            emit_fuel_charge(&mut builder, fuel, mem_flags);
            match instruction {
                Instruction::Push { value } => {
                    stack.push(builder.ins().iconst(types::I64, normalize_value(value)?));
                }
                Instruction::LoadLocal { slot } => stack.push(locals[*slot].ok_or_else(|| {
                    NativeError::Codegen("verified local was not initialized".to_owned())
                })?),
                Instruction::StoreLocal { slot } => {
                    locals[*slot] = Some(pop_stack(&mut stack)?);
                }
                Instruction::Pop => {
                    pop_stack(&mut stack)?;
                }
                Instruction::Negate => {
                    let value = pop_stack(&mut stack)?;
                    let zero = builder.ins().iconst(types::I64, 0);
                    let (result, overflow) = builder.ins().ssub_overflow(zero, value);
                    emit_error_if(&mut builder, overflow, STATUS_NEGATION_OVERFLOW);
                    stack.push(result);
                }
                Instruction::Not => {
                    let value = pop_stack(&mut stack)?;
                    stack.push(builder.ins().bxor_imm_s(value, 1));
                }
                Instruction::Add | Instruction::Subtract | Instruction::Multiply => {
                    let right = pop_stack(&mut stack)?;
                    let left = pop_stack(&mut stack)?;
                    let (result, overflow, status) = match instruction {
                        Instruction::Add => {
                            let (result, overflow) = builder.ins().sadd_overflow(left, right);
                            (result, overflow, STATUS_ADDITION_FAILED)
                        }
                        Instruction::Subtract => {
                            let (result, overflow) = builder.ins().ssub_overflow(left, right);
                            (result, overflow, STATUS_SUBTRACTION_FAILED)
                        }
                        Instruction::Multiply => {
                            let (result, overflow) = builder.ins().smul_overflow(left, right);
                            (result, overflow, STATUS_MULTIPLICATION_FAILED)
                        }
                        _ => unreachable!(),
                    };
                    emit_error_if(&mut builder, overflow, status);
                    stack.push(result);
                }
                Instruction::Divide | Instruction::Remainder => {
                    let right = pop_stack(&mut stack)?;
                    let left = pop_stack(&mut stack)?;
                    let zero = builder.ins().icmp_imm_s(IntCC::Equal, right, 0);
                    let minimum = builder.ins().icmp_imm_s(IntCC::Equal, left, i64::MIN);
                    let negative_one = builder.ins().icmp_imm_s(IntCC::Equal, right, -1);
                    let overflow = builder.ins().band(minimum, negative_one);
                    let invalid = builder.ins().bor(zero, overflow);
                    let status = if matches!(instruction, Instruction::Divide) {
                        STATUS_DIVISION_FAILED
                    } else {
                        STATUS_REMAINDER_FAILED
                    };
                    emit_error_if(&mut builder, invalid, status);
                    stack.push(if matches!(instruction, Instruction::Divide) {
                        builder.ins().sdiv(left, right)
                    } else {
                        builder.ins().srem(left, right)
                    });
                }
                Instruction::Equal | Instruction::NotEqual => {
                    let right = pop_stack(&mut stack)?;
                    let left = pop_stack(&mut stack)?;
                    let condition = if matches!(instruction, Instruction::Equal) {
                        IntCC::Equal
                    } else {
                        IntCC::NotEqual
                    };
                    let value = builder.ins().icmp(condition, left, right);
                    stack.push(builder.ins().uextend(types::I64, value));
                }
                Instruction::Less
                | Instruction::LessEqual
                | Instruction::Greater
                | Instruction::GreaterEqual => {
                    let right = pop_stack(&mut stack)?;
                    let left = pop_stack(&mut stack)?;
                    let condition = match instruction {
                        Instruction::Less => IntCC::SignedLessThan,
                        Instruction::LessEqual => IntCC::SignedLessThanOrEqual,
                        Instruction::Greater => IntCC::SignedGreaterThan,
                        Instruction::GreaterEqual => IntCC::SignedGreaterThanOrEqual,
                        _ => unreachable!(),
                    };
                    let value = builder.ins().icmp(condition, left, right);
                    stack.push(builder.ins().uextend(types::I64, value));
                }
                Instruction::And | Instruction::Or => {
                    let right = pop_stack(&mut stack)?;
                    let left = pop_stack(&mut stack)?;
                    stack.push(if matches!(instruction, Instruction::And) {
                        builder.ins().band(left, right)
                    } else {
                        builder.ins().bor(left, right)
                    });
                }
                Instruction::Call {
                    function: target,
                    argument_count,
                } => {
                    let arguments = pop_arguments(&mut stack, *argument_count)?;
                    let target_ref =
                        module.declare_func_in_func(function_ids[*target], builder.func);
                    let mut call_arguments = arguments;
                    call_arguments.push(fuel);
                    let call = builder.ins().call(target_ref, &call_arguments);
                    let results = builder.inst_results(call);
                    let status = results[0];
                    let result = results[1];
                    emit_status_propagation(&mut builder, status);
                    stack.push(result);
                }
                Instruction::Request { .. } => {
                    return Err(NativeError::Unsupported(format!(
                        "function `{}` contains a request",
                        function.name
                    )));
                }
                Instruction::Return => {
                    let value = pop_stack(&mut stack)?;
                    let ok = builder.ins().iconst(types::I32, i64::from(STATUS_OK));
                    builder.ins().return_(&[ok, value]);
                }
            }
        }
        builder.seal_all_blocks();
        builder.finalize(target_config);
    }
    module
        .define_function(function_id, &mut context)
        .map_err(|error| NativeError::Codegen(error.to_string()))?;
    let identity = capture_code_identity(&context, identity_name)?;
    module.clear_context(&mut context);
    Ok(identity)
}

fn define_wrapper(
    module: &mut JITModule,
    function: &BytecodeFunction,
    wrapper_id: FuncId,
    internal_id: FuncId,
    identity_name: String,
) -> Result<NativeCodeIdentity, NativeError> {
    let mut context = module.make_context();
    let pointer_type = module.target_config().pointer_type();
    let mut signature = module.make_signature();
    signature.params.push(AbiParam::new(pointer_type));
    signature.params.push(AbiParam::new(pointer_type));
    signature.params.push(AbiParam::new(pointer_type));
    signature.returns.push(AbiParam::new(types::I32));
    context.func.signature = signature;
    context.func.name = UserFuncName::user(0, wrapper_id.as_u32());
    let mut function_builder_context = FunctionBuilderContext::new();
    {
        let target_config = module.target_config();
        let mut builder = FunctionBuilder::new(&mut context.func, &mut function_builder_context);
        let mem_flags = MemFlagsData::trusted();
        let entry = builder.create_block();
        builder.append_block_params_for_function_params(entry);
        builder.switch_to_block(entry);
        let parameters = builder.block_params(entry).to_vec();
        let arguments_pointer = parameters[0];
        let fuel = parameters[1];
        let output = parameters[2];
        let mut arguments = Vec::with_capacity(function.parameter_count + 1);
        for index in 0..function.parameter_count {
            let offset = i32::try_from(index.checked_mul(8).ok_or_else(|| {
                NativeError::Codegen("wrapper argument offset overflow".to_owned())
            })?)
            .map_err(|_| NativeError::Codegen("wrapper argument offset exceeds i32".to_owned()))?;
            arguments.push(
                builder
                    .ins()
                    .load(types::I64, mem_flags, arguments_pointer, offset),
            );
        }
        arguments.push(fuel);
        let internal_ref = module.declare_func_in_func(internal_id, builder.func);
        let call = builder.ins().call(internal_ref, &arguments);
        let results = builder.inst_results(call);
        let status = results[0];
        let value = results[1];
        let failed = builder.ins().icmp_imm_s(IntCC::NotEqual, status, 0);
        let error_block = builder.create_block();
        let success_block = builder.create_block();
        builder
            .ins()
            .brif(failed, error_block, &[], success_block, &[]);
        builder.switch_to_block(error_block);
        builder.ins().return_(&[status]);
        builder.switch_to_block(success_block);
        builder.ins().store(mem_flags, value, output, 0);
        builder.ins().return_(&[status]);
        builder.seal_all_blocks();
        builder.finalize(target_config);
    }
    module
        .define_function(wrapper_id, &mut context)
        .map_err(|error| NativeError::Codegen(error.to_string()))?;
    let identity = capture_code_identity(&context, identity_name)?;
    module.clear_context(&mut context);
    Ok(identity)
}

fn capture_code_identity(
    context: &cranelift_codegen::Context,
    name: String,
) -> Result<NativeCodeIdentity, NativeError> {
    let compiled = context
        .compiled_code()
        .ok_or_else(|| NativeError::Codegen("Cranelift returned no compiled code".to_owned()))?;
    let code = compiled.code_buffer();
    if code.len() > MAX_NATIVE_CODE_BYTES_PER_FUNCTION {
        return Err(NativeError::ResourceLimit(format!(
            "generated function `{name}` has {} bytes; limit is {MAX_NATIVE_CODE_BYTES_PER_FUNCTION}",
            code.len()
        )));
    }
    let raw_relocations = compiled.buffer.relocs();
    if raw_relocations.len() > MAX_NATIVE_RELOCATIONS_PER_FUNCTION {
        return Err(NativeError::ResourceLimit(format!(
            "generated function `{name}` has {} relocations; limit is {MAX_NATIVE_RELOCATIONS_PER_FUNCTION}",
            raw_relocations.len()
        )));
    }
    let mut relocations = Vec::with_capacity(raw_relocations.len());
    for relocation in raw_relocations {
        if !matches!(
            relocation.target,
            FinalizedRelocTarget::ExternalName(ExternalName::User(_))
                | FinalizedRelocTarget::Func(_)
        ) {
            return Err(NativeError::Unsupported(format!(
                "generated function `{name}` requested non-internal relocation `{}`",
                relocation.target.display(None)
            )));
        }
        relocations.push(NativeRelocationIdentity {
            offset: relocation.offset,
            kind: format!("{:?}", relocation.kind),
            target: relocation.target.display(None),
            addend: relocation.addend.to_string(),
        });
    }
    Ok(NativeCodeIdentity {
        name,
        code_digest: digest_bytes_v1(RegisteredDomainV1::NativeCode, code)?,
        code_bytes: u64::try_from(code.len())
            .map_err(|_| NativeError::Codegen("generated code size exceeds u64".to_owned()))?,
        relocations,
    })
}

fn emit_fuel_charge(builder: &mut FunctionBuilder<'_>, fuel: ClValue, mem_flags: MemFlagsData) {
    let remaining = builder.ins().load(types::I64, mem_flags, fuel, 0);
    let exhausted = builder.ins().icmp_imm_s(IntCC::Equal, remaining, 0);
    emit_error_if(builder, exhausted, STATUS_BUDGET_EXHAUSTED);
    let updated = builder.ins().iadd_imm_s(remaining, -1);
    builder.ins().store(mem_flags, updated, fuel, 0);
}

fn emit_error_if(builder: &mut FunctionBuilder<'_>, condition: ClValue, status: u32) {
    let error_block = builder.create_block();
    let continue_block = builder.create_block();
    builder
        .ins()
        .brif(condition, error_block, &[], continue_block, &[]);
    builder.switch_to_block(error_block);
    let status = builder.ins().iconst(types::I32, i64::from(status));
    let zero = builder.ins().iconst(types::I64, 0);
    builder.ins().return_(&[status, zero]);
    builder.switch_to_block(continue_block);
}

fn emit_status_propagation(builder: &mut FunctionBuilder<'_>, status: ClValue) {
    let failed = builder.ins().icmp_imm_s(IntCC::NotEqual, status, 0);
    let error_block = builder.create_block();
    let continue_block = builder.create_block();
    builder
        .ins()
        .brif(failed, error_block, &[], continue_block, &[]);
    builder.switch_to_block(error_block);
    let zero = builder.ins().iconst(types::I64, 0);
    builder.ins().return_(&[status, zero]);
    builder.switch_to_block(continue_block);
}

fn pop_stack(stack: &mut Vec<ClValue>) -> Result<ClValue, NativeError> {
    stack
        .pop()
        .ok_or_else(|| NativeError::Codegen("verified stack underflow during lowering".to_owned()))
}

fn pop_arguments(stack: &mut Vec<ClValue>, count: usize) -> Result<Vec<ClValue>, NativeError> {
    if stack.len() < count {
        return Err(NativeError::Codegen(
            "verified argument stack underflow during lowering".to_owned(),
        ));
    }
    Ok(stack.split_off(stack.len() - count))
}

fn validate_arguments(
    function_name: &str,
    expected: &[Type],
    arguments: &[Value],
) -> Result<(), NativeError> {
    if expected.len() != arguments.len() {
        return Err(NativeError::Runtime(format!(
            "function `{function_name}` expected {} arguments but received {}",
            expected.len(),
            arguments.len()
        )));
    }
    for (index, (value_type, value)) in expected.iter().zip(arguments).enumerate() {
        if !matches_type(value, value_type) {
            return Err(NativeError::Runtime(format!(
                "function `{function_name}` argument {index} expected {}",
                value_type.as_str()
            )));
        }
    }
    Ok(())
}

fn validate_normalized_arguments(expected: &[Type], arguments: &[i64]) -> Result<(), NativeError> {
    if expected.len() != arguments.len() {
        return Err(NativeError::Runtime(format!(
            "prepared function expected {} arguments but received {}",
            expected.len(),
            arguments.len()
        )));
    }
    for (index, (value_type, value)) in expected.iter().zip(arguments).enumerate() {
        match value_type {
            Type::I64 => {}
            Type::Bool if *value == 0 || *value == 1 => {}
            Type::Unit if *value == 0 => {}
            Type::Bool | Type::Unit => {
                return Err(NativeError::Runtime(format!(
                    "prepared argument {index} is not canonical {}",
                    value_type.as_str()
                )));
            }
            Type::String => {
                return Err(NativeError::Unsupported(
                    "string values are outside the native subset".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_normalized_result(value: i64, value_type: &Type) -> Result<(), NativeError> {
    match value_type {
        Type::I64 => Ok(()),
        Type::Bool if value == 0 || value == 1 => Ok(()),
        Type::Unit if value == 0 => Ok(()),
        Type::Bool => Err(NativeError::Runtime(
            "native backend produced a non-canonical bool".to_owned(),
        )),
        Type::Unit => Err(NativeError::Runtime(
            "native backend produced a non-canonical unit".to_owned(),
        )),
        Type::String => Err(NativeError::Unsupported(
            "string values are outside the native subset".to_owned(),
        )),
    }
}

const fn matches_type(value: &Value, value_type: &Type) -> bool {
    matches!(
        (value, value_type),
        (Value::I64(_), Type::I64) | (Value::Bool(_), Type::Bool) | (Value::Unit, Type::Unit)
    )
}

fn normalize_value(value: &Value) -> Result<i64, NativeError> {
    match value {
        Value::I64(value) => Ok(*value),
        Value::Bool(value) => Ok(i64::from(*value)),
        Value::Unit => Ok(0),
        Value::String(_) => Err(NativeError::Unsupported(
            "string values are outside the native subset".to_owned(),
        )),
    }
}

fn denormalize_value(value: i64, value_type: &Type) -> Result<Value, NativeError> {
    match value_type {
        Type::I64 => Ok(Value::I64(value)),
        Type::Bool if value == 0 || value == 1 => Ok(Value::Bool(value == 1)),
        Type::Bool => Err(NativeError::Runtime(
            "native backend produced a non-canonical bool".to_owned(),
        )),
        Type::Unit if value == 0 => Ok(Value::Unit),
        Type::Unit => Err(NativeError::Runtime(
            "native backend produced a non-canonical unit".to_owned(),
        )),
        Type::String => Err(NativeError::Unsupported(
            "string values are outside the native subset".to_owned(),
        )),
    }
}

const fn status_message(status: u32) -> &'static str {
    match status {
        STATUS_BUDGET_EXHAUSTED => "instruction budget exhausted",
        STATUS_NEGATION_OVERFLOW => "integer negation overflow",
        STATUS_ADDITION_FAILED => "integer addition failed",
        STATUS_SUBTRACTION_FAILED => "integer subtraction failed",
        STATUS_MULTIPLICATION_FAILED => "integer multiplication failed",
        STATUS_DIVISION_FAILED => "integer division failed",
        STATUS_REMAINDER_FAILED => "integer remainder failed",
        _ => "native backend returned an unknown status",
    }
}
