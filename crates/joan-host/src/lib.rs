//! Bounded protocol and controller for isolated JOAN native execution.

mod controller;

pub use controller::{ensure_sibling_executor, execute_sibling, execute_with_path};

use joan_bytecode::{BytecodeProgram, Value, verify_bytecode};
use joan_canonical::{
    Digest, Jce1Error, RegisteredDomainV1, digest_serializable_v1, from_serializable_v1,
    parse_strict_v1, to_canonical_bytes_v1,
};
use joan_lattice::{
    FLAG_RECEIPT_REQUIRED, FrameError, FrameParts, LEVEL_COUNT, Level, decode, encode,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::io::{self, Read};
use thiserror::Error;

/// Request control schema carried by the process-isolation protocol.
pub const HOST_EXECUTION_REQUEST_V0: &str = "joan.host-execution-request.v0";
/// Current request control schema with bound operating-system limits.
pub const HOST_EXECUTION_REQUEST_V1: &str = "joan.host-execution-request.v1";
/// Child response schema carried by the process-isolation protocol.
pub const HOST_EXECUTOR_RESPONSE_V0: &str = "joan.host-executor-response.v0";
/// Current child response schema bound to a resource-limited request.
pub const HOST_EXECUTOR_RESPONSE_V1: &str = "joan.host-executor-response.v1";
/// Parent receipt schema for one process-isolated attempt.
pub const HOST_EXECUTION_RECEIPT_V0: &str = "joan.host-execution-receipt.v0";
/// Current parent receipt schema with limit and Unix-signal observability.
pub const HOST_EXECUTION_RECEIPT_V1: &str = "joan.host-execution-receipt.v1";
/// Receipt emitted after native compilation.
pub const NATIVE_COMPILE_RECEIPT_V0: &str = "joan.native-compile-receipt.v0";
/// Receipt emitted after one native invocation.
pub const NATIVE_EXECUTION_RECEIPT_V0: &str = "joan.native-execution-receipt.v0";

/// Maximum accepted request frame, including the Lattice header.
pub const MAX_HOST_REQUEST_FRAME_BYTES: usize = 2 * 1_048_576;
/// Maximum accepted response frame, including the Lattice header.
pub const MAX_HOST_RESPONSE_FRAME_BYTES: usize = 256 * 1_024;
/// Maximum function arguments accepted by the isolated native subset.
pub const MAX_HOST_ARGUMENTS: usize = 64;
/// Maximum wall-time limit accepted by the controller.
pub const MAX_HOST_WALL_TIME_MS: u64 = 60_000;
/// Default wall-time limit for one child attempt.
pub const DEFAULT_HOST_WALL_TIME_MS: u64 = 30_000;
/// Maximum accepted operating-system CPU-time limit.
pub const MAX_HOST_CPU_TIME_SECONDS: u64 = 30;
/// Default operating-system CPU-time limit.
pub const DEFAULT_HOST_CPU_TIME_SECONDS: u64 = 10;
/// Minimum accepted process-memory limit.
pub const MIN_HOST_MEMORY_LIMIT_BYTES: u64 = 256 * 1_048_576;
/// Maximum accepted process-memory limit.
pub const MAX_HOST_MEMORY_LIMIT_BYTES: u64 = 16 * 1_073_741_824;
/// Default process-memory limit.
pub const DEFAULT_HOST_MEMORY_LIMIT_BYTES: u64 = MAX_HOST_MEMORY_LIMIT_BYTES;
/// Minimum accepted open-file descriptor limit.
pub const MIN_HOST_OPEN_FILES: u64 = 16;
/// Maximum accepted open-file descriptor limit.
pub const MAX_HOST_OPEN_FILES: u64 = 256;
/// Default open-file descriptor limit.
pub const DEFAULT_HOST_OPEN_FILES: u64 = 64;
/// Maximum file-size limit accepted by the pure executor.
pub const MAX_HOST_FILE_SIZE_BYTES: u64 = 1_048_576;
/// Default file-size limit. Zero prevents regular-file output.
pub const DEFAULT_HOST_FILE_SIZE_BYTES: u64 = 0;

const MAX_FUNCTION_NAME_BYTES: usize = 128;
const MAX_FAILURE_MESSAGE_BYTES: usize = 1_024;
const MAX_INSTRUCTION_BUDGET: u64 = 1_000_000_000;

/// Native compilation metadata bound to verified bytecode and generated code bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCompileReceipt {
    /// Receipt schema.
    pub schema: String,
    /// Always `compiled`.
    pub status: String,
    /// Exact accepted native subset.
    pub subset: String,
    /// Exact backend implementation.
    pub backend: String,
    /// Exact code-generator version.
    pub codegen_version: String,
    /// Frozen backend optimization profile.
    pub optimization_profile: String,
    /// Selected native target triple.
    pub target: String,
    /// Frozen backend flags affecting generated code.
    pub flags: Vec<String>,
    /// Semantic identity of the source program.
    pub semantic_digest: Digest,
    /// Identity of the exact verified bytecode.
    pub bytecode_digest: Digest,
    /// Identity of generated code and backend configuration.
    pub artifact_digest: Digest,
    /// Number of compiled JOAN functions.
    pub function_count: u64,
    /// Sum of generated function and wrapper code bytes.
    pub code_bytes: u64,
    /// Number of address-independent relocation records.
    pub relocation_count: u64,
}

/// Result of invoking one native function under an instruction budget.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExecutionReceipt {
    /// Receipt schema.
    pub schema: String,
    /// Always `completed`.
    pub status: String,
    /// Native artifact identity used by the invocation.
    pub artifact_digest: Digest,
    /// Verified bytecode identity used by the invocation.
    pub bytecode_digest: Digest,
    /// Exact invoked function.
    pub function: String,
    /// Typed invocation result.
    pub result: Value,
    /// Exact number of JOAN bytecode instructions consumed.
    pub instructions_executed: u64,
}

/// Operation accepted by the pure native executor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum HostOperation {
    /// Compile verified bytecode and return its native artifact receipt.
    Compile,
    /// Compile and invoke one pure function.
    Run {
        /// Exact function name.
        function: String,
        /// Typed arguments.
        arguments: Vec<Value>,
        /// Maximum JOAN instructions consumed by the invocation.
        instruction_budget: u64,
    },
}

/// Operating-system primitive used for one process-memory limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostMemoryLimitKind {
    /// No kernel memory primitive is available; the receipt records this explicitly.
    Unavailable,
    /// Bound the complete virtual address space where the operating system supports it.
    AddressSpace,
    /// Bound the data segment where address-space limits are unusable.
    DataSegment,
}

/// Controller-enforced bounds for one child attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostLimits {
    wall_time_ms: u64,
    cpu_time_seconds: u64,
    memory_limit_kind: HostMemoryLimitKind,
    memory_limit_bytes: u64,
    open_files: u64,
    file_size_bytes: u64,
    core_size_bytes: u64,
}

impl HostLimits {
    /// Construct limits with a bounded nonzero wall-time.
    pub fn new(wall_time_ms: u64) -> Result<Self, HostError> {
        Self::with_resource_bounds(
            wall_time_ms,
            DEFAULT_HOST_CPU_TIME_SECONDS,
            default_memory_limit_bytes(),
            DEFAULT_HOST_OPEN_FILES,
            DEFAULT_HOST_FILE_SIZE_BYTES,
        )
    }

    /// Construct a complete bounded resource profile for one attempt.
    pub fn with_resource_bounds(
        wall_time_ms: u64,
        cpu_time_seconds: u64,
        memory_limit_bytes: u64,
        open_files: u64,
        file_size_bytes: u64,
    ) -> Result<Self, HostError> {
        Self::with_memory_limit_kind(
            wall_time_ms,
            cpu_time_seconds,
            default_memory_limit_kind(),
            memory_limit_bytes,
            open_files,
            file_size_bytes,
        )
    }

    /// Construct a complete profile with an explicit memory-limit primitive.
    pub fn with_memory_limit_kind(
        wall_time_ms: u64,
        cpu_time_seconds: u64,
        memory_limit_kind: HostMemoryLimitKind,
        memory_limit_bytes: u64,
        open_files: u64,
        file_size_bytes: u64,
    ) -> Result<Self, HostError> {
        let limits = Self {
            wall_time_ms,
            cpu_time_seconds,
            memory_limit_kind,
            memory_limit_bytes,
            open_files,
            file_size_bytes,
            core_size_bytes: 0,
        };
        validate_limits(&limits)?;
        Ok(limits)
    }

    /// Wall-time limit in milliseconds.
    #[must_use]
    pub const fn wall_time_ms(self) -> u64 {
        self.wall_time_ms
    }

    /// Operating-system CPU-time limit in seconds.
    #[must_use]
    pub const fn cpu_time_seconds(self) -> u64 {
        self.cpu_time_seconds
    }

    /// Operating-system primitive used for the process-memory limit.
    #[must_use]
    pub const fn memory_limit_kind(self) -> HostMemoryLimitKind {
        self.memory_limit_kind
    }

    /// Process-memory limit in bytes.
    #[must_use]
    pub const fn memory_limit_bytes(self) -> u64 {
        self.memory_limit_bytes
    }

    /// Open-file descriptor limit.
    #[must_use]
    pub const fn open_files(self) -> u64 {
        self.open_files
    }

    /// Regular-file output limit in bytes.
    #[must_use]
    pub const fn file_size_bytes(self) -> u64 {
        self.file_size_bytes
    }

    /// Core-dump limit in bytes. The pure profile always returns zero.
    #[must_use]
    pub const fn core_size_bytes(self) -> u64 {
        self.core_size_bytes
    }
}

fn validate_limits(limits: &HostLimits) -> Result<(), HostError> {
    if limits.wall_time_ms == 0 || limits.wall_time_ms > MAX_HOST_WALL_TIME_MS {
        return Err(HostError::InvalidRequest(format!(
            "wall time must be between 1 and {MAX_HOST_WALL_TIME_MS} milliseconds"
        )));
    }
    if limits.cpu_time_seconds == 0 || limits.cpu_time_seconds > MAX_HOST_CPU_TIME_SECONDS {
        return Err(HostError::InvalidRequest(format!(
            "CPU time must be between 1 and {MAX_HOST_CPU_TIME_SECONDS} seconds"
        )));
    }
    #[cfg(not(target_vendor = "apple"))]
    if limits.memory_limit_kind == HostMemoryLimitKind::Unavailable {
        return Err(HostError::InvalidRequest(
            "unavailable memory limits are restricted to Apple hosts".to_owned(),
        ));
    }
    match limits.memory_limit_kind {
        HostMemoryLimitKind::Unavailable if limits.memory_limit_bytes != 0 => {
            return Err(HostError::InvalidRequest(
                "unavailable memory limit must use zero bytes".to_owned(),
            ));
        }
        HostMemoryLimitKind::AddressSpace | HostMemoryLimitKind::DataSegment
            if !(MIN_HOST_MEMORY_LIMIT_BYTES..=MAX_HOST_MEMORY_LIMIT_BYTES)
                .contains(&limits.memory_limit_bytes) =>
        {
            return Err(HostError::InvalidRequest(format!(
                "memory limit must be between {MIN_HOST_MEMORY_LIMIT_BYTES} and {MAX_HOST_MEMORY_LIMIT_BYTES} bytes"
            )));
        }
        _ => {}
    }
    if !(MIN_HOST_OPEN_FILES..=MAX_HOST_OPEN_FILES).contains(&limits.open_files) {
        return Err(HostError::InvalidRequest(format!(
            "open files must be between {MIN_HOST_OPEN_FILES} and {MAX_HOST_OPEN_FILES}"
        )));
    }
    if limits.file_size_bytes > MAX_HOST_FILE_SIZE_BYTES {
        return Err(HostError::InvalidRequest(format!(
            "file size must not exceed {MAX_HOST_FILE_SIZE_BYTES} bytes"
        )));
    }
    if limits.core_size_bytes != 0 {
        return Err(HostError::InvalidRequest(
            "core dump size must remain zero".to_owned(),
        ));
    }
    Ok(())
}

impl Default for HostLimits {
    fn default() -> Self {
        Self {
            wall_time_ms: DEFAULT_HOST_WALL_TIME_MS,
            cpu_time_seconds: DEFAULT_HOST_CPU_TIME_SECONDS,
            memory_limit_kind: default_memory_limit_kind(),
            memory_limit_bytes: default_memory_limit_bytes(),
            open_files: DEFAULT_HOST_OPEN_FILES,
            file_size_bytes: DEFAULT_HOST_FILE_SIZE_BYTES,
            core_size_bytes: 0,
        }
    }
}

#[cfg(target_vendor = "apple")]
const fn default_memory_limit_kind() -> HostMemoryLimitKind {
    HostMemoryLimitKind::Unavailable
}

#[cfg(not(target_vendor = "apple"))]
const fn default_memory_limit_kind() -> HostMemoryLimitKind {
    HostMemoryLimitKind::AddressSpace
}

#[cfg(target_vendor = "apple")]
const fn default_memory_limit_bytes() -> u64 {
    0
}

#[cfg(not(target_vendor = "apple"))]
const fn default_memory_limit_bytes() -> u64 {
    DEFAULT_HOST_MEMORY_LIMIT_BYTES
}

/// Canonical request metadata placed in the Lattice shape level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostExecutionRequest {
    /// Request schema.
    pub schema: String,
    /// Pure operation requested from the child.
    pub operation: HostOperation,
    /// Exact operating-system resource profile the child must apply.
    pub limits: HostLimits,
    /// Semantic program identity.
    pub semantic_digest: Digest,
    /// Exact verified-bytecode identity.
    pub bytecode_digest: Digest,
    /// Typed identity of this request excluding this field.
    pub request_digest: Digest,
}

/// Fully decoded executor input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutorRequest {
    /// Canonical request control.
    pub control: HostExecutionRequest,
    /// Independently verified bytecode bound by the control.
    pub bytecode: BytecodeProgram,
}

/// Deterministic child outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorResponseStatus {
    /// Native compilation or invocation completed.
    Completed,
    /// A deterministic validation, compilation or invocation error occurred.
    Failed,
}

/// Bounded child failure classification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorFailureCode {
    /// Verified bytecode was rejected by the backend.
    BytecodeRejected,
    /// The program is outside the frozen pure native subset.
    UnsupportedNativeSubset,
    /// A native backend resource limit was exceeded.
    ResourceLimit,
    /// Native code generation failed.
    CodegenFailed,
    /// Native artifact identity construction failed.
    IdentityFailed,
    /// The exact instruction budget was exhausted.
    InstructionBudgetExhausted,
    /// Native invocation failed deterministically.
    RuntimeFailed,
}

/// Canonical child response before the parent interprets process state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorResponse {
    /// Response schema.
    pub schema: String,
    /// Deterministic child outcome.
    pub status: ExecutorResponseStatus,
    /// Bound request identity.
    pub request_digest: Digest,
    /// Bound semantic identity.
    pub semantic_digest: Digest,
    /// Bound verified-bytecode identity.
    pub bytecode_digest: Digest,
    /// Native compilation receipt, when compilation succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compile_receipt: Option<NativeCompileReceipt>,
    /// Native execution receipt, when invocation succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_receipt: Option<NativeExecutionReceipt>,
    /// Stable failure classification for a failed response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<ExecutorFailureCode>,
    /// Bounded diagnostic for a failed response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_message: Option<String>,
    /// Typed response identity excluding this field.
    pub response_digest: Digest,
}

/// Parent-side attempt status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostExecutionStatus {
    /// Child exited successfully and every binding was verified.
    Completed,
    /// Child returned a canonical deterministic rejection.
    Failed,
    /// Process or protocol state cannot prove completion.
    Unknown,
}

/// Stable parent-side reason for an attempt status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostExecutionReason {
    /// A canonical child result passed every binding check.
    ExecutorCompleted,
    /// The child returned a deterministic canonical rejection.
    ExecutorRejected,
    /// The executor could not be started.
    SpawnFailed,
    /// Request delivery could not be proven complete.
    RequestWriteFailed,
    /// The wall-time limit expired and the child was killed.
    Timeout,
    /// The child exited unsuccessfully or by signal.
    ChildExitUnknown,
    /// Child output exceeded its byte limit.
    OutputLimitExceeded,
    /// Child output could not be read completely.
    OutputReadFailed,
    /// The process-group leader exited while a descendant remained alive.
    DescendantDetected,
    /// Child output was malformed or noncanonical.
    MalformedResponse,
    /// A response identity or request binding did not match.
    BindingMismatch,
    /// Waiting for process state failed.
    ProcessWaitFailed,
}

/// Idempotent parent receipt for one isolated execution attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostExecutionReceipt {
    /// Receipt schema.
    pub schema: String,
    /// Proven attempt status.
    pub status: HostExecutionStatus,
    /// Stable status reason.
    pub reason: HostExecutionReason,
    /// Exact resource profile bound to the attempted request.
    pub limits: HostLimits,
    /// Bound request identity.
    pub request_digest: Digest,
    /// Bound semantic identity.
    pub semantic_digest: Digest,
    /// Bound verified-bytecode identity.
    pub bytecode_digest: Digest,
    /// Child exit code when one was available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_exit_code: Option<i32>,
    /// Unix signal that terminated the child, mutually exclusive with exit code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_unix_signal: Option<i32>,
    /// Verified child response identity, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executor_response_digest: Option<Digest>,
    /// Native compilation receipt, when verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compile_receipt: Option<NativeCompileReceipt>,
    /// Native execution receipt, when verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_receipt: Option<NativeExecutionReceipt>,
    /// Bounded deterministic diagnostic, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Typed receipt identity excluding this field.
    pub receipt_digest: Digest,
}

/// Isolated host protocol failure before an attempt receipt can be formed.
#[derive(Debug, Error)]
pub enum HostError {
    /// Request limits or shape are invalid.
    #[error("invalid host request: {0}")]
    InvalidRequest(String),
    /// Canonical JCE1 encoding or identity failed.
    #[error(transparent)]
    Canonical(#[from] Jce1Error),
    /// Strict JSON decoding failed.
    #[error("host protocol JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    /// Lattice framing failed.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// Bytecode verification failed.
    #[error(transparent)]
    Bytecode(#[from] joan_bytecode::BytecodeError),
    /// Process or pipe I/O failed before a receipt was available.
    #[error("host process I/O failed: {0}")]
    Io(#[from] io::Error),
    /// The child could not establish its requested operating-system limits.
    #[error("host resource limit setup failed: {0}")]
    ResourceLimit(String),
    /// A protocol invariant failed.
    #[error("host protocol rejected message: {0}")]
    Protocol(String),
}

#[derive(Serialize)]
struct RequestCore<'a> {
    schema: &'a str,
    operation: &'a HostOperation,
    limits: &'a HostLimits,
    semantic_digest: &'a Digest,
    bytecode_digest: &'a Digest,
}

#[derive(Serialize)]
struct ResponseCore<'a> {
    schema: &'a str,
    status: &'a ExecutorResponseStatus,
    request_digest: &'a Digest,
    semantic_digest: &'a Digest,
    bytecode_digest: &'a Digest,
    compile_receipt: &'a Option<NativeCompileReceipt>,
    execution_receipt: &'a Option<NativeExecutionReceipt>,
    failure_code: &'a Option<ExecutorFailureCode>,
    failure_message: &'a Option<String>,
}

#[derive(Serialize)]
struct ReceiptCore<'a> {
    schema: &'a str,
    status: &'a HostExecutionStatus,
    reason: &'a HostExecutionReason,
    limits: &'a HostLimits,
    request_digest: &'a Digest,
    semantic_digest: &'a Digest,
    bytecode_digest: &'a Digest,
    child_exit_code: Option<i32>,
    child_unix_signal: Option<i32>,
    executor_response_digest: &'a Option<Digest>,
    compile_receipt: &'a Option<NativeCompileReceipt>,
    execution_receipt: &'a Option<NativeExecutionReceipt>,
    detail: &'a Option<String>,
}

/// Build and encode one verified request frame.
pub fn encode_request_frame(
    bytecode: &BytecodeProgram,
    operation: HostOperation,
) -> Result<(HostExecutionRequest, Vec<u8>), HostError> {
    encode_request_frame_with_limits(bytecode, operation, HostLimits::default())
}

/// Build and encode one verified request frame with explicit resource limits.
pub fn encode_request_frame_with_limits(
    bytecode: &BytecodeProgram,
    operation: HostOperation,
    limits: HostLimits,
) -> Result<(HostExecutionRequest, Vec<u8>), HostError> {
    validate_operation(&operation)?;
    validate_limits(&limits)?;
    let verification = verify_bytecode(bytecode)?;
    let request_digest = digest_serializable_v1(
        RegisteredDomainV1::HostExecutionRequestV2,
        &RequestCore {
            schema: HOST_EXECUTION_REQUEST_V1,
            operation: &operation,
            limits: &limits,
            semantic_digest: &verification.semantic_digest,
            bytecode_digest: &verification.bytecode_digest,
        },
    )?;
    let control = HostExecutionRequest {
        schema: HOST_EXECUTION_REQUEST_V1.to_owned(),
        operation,
        limits,
        semantic_digest: verification.semantic_digest,
        bytecode_digest: verification.bytecode_digest,
        request_digest,
    };
    let control_bytes = encode_jce1(&control)?;
    let bytecode_bytes = encode_jce1(bytecode)?;
    let schema_digest = transport_digest(HOST_EXECUTION_REQUEST_V1.as_bytes());
    let intent_digest = transport_digest(&control_bytes);
    let mut levels: [&[u8]; LEVEL_COUNT] = [&[]; LEVEL_COUNT];
    levels[Level::Shape as usize] = &control_bytes;
    levels[Level::Evidence as usize] = &bytecode_bytes;
    let frame = encode(&FrameParts {
        schema_digest: &schema_digest,
        intent_digest: &intent_digest,
        flags: FLAG_RECEIPT_REQUIRED,
        levels,
    })?;
    if frame.len() > MAX_HOST_REQUEST_FRAME_BYTES {
        return Err(HostError::InvalidRequest(format!(
            "request frame exceeds {MAX_HOST_REQUEST_FRAME_BYTES} bytes"
        )));
    }
    Ok((control, frame))
}

/// Decode, verify and bind one complete request frame.
pub fn decode_request_frame(frame: &[u8]) -> Result<ExecutorRequest, HostError> {
    if frame.len() > MAX_HOST_REQUEST_FRAME_BYTES {
        return Err(HostError::InvalidRequest(format!(
            "request frame exceeds {MAX_HOST_REQUEST_FRAME_BYTES} bytes"
        )));
    }
    let decoded = decode(frame)?;
    require_request_levels(&decoded)?;
    if decoded.flags() != FLAG_RECEIPT_REQUIRED {
        return Err(HostError::Protocol(
            "request must require an explicit receipt".to_owned(),
        ));
    }
    let expected_schema = transport_digest(HOST_EXECUTION_REQUEST_V1.as_bytes());
    if decoded.schema_digest() != expected_schema {
        return Err(HostError::Protocol(
            "request schema digest does not match".to_owned(),
        ));
    }
    let control_bytes = decoded.level(Level::Shape);
    if decoded.intent_digest() != transport_digest(control_bytes) {
        return Err(HostError::Protocol(
            "request intent digest does not match".to_owned(),
        ));
    }
    let control: HostExecutionRequest = decode_jce1(control_bytes)?;
    let bytecode: BytecodeProgram = decode_jce1(decoded.level(Level::Evidence))?;
    validate_operation(&control.operation)?;
    validate_limits(&control.limits)?;
    if control.schema != HOST_EXECUTION_REQUEST_V1 {
        return Err(HostError::Protocol(
            "unsupported host request schema".to_owned(),
        ));
    }
    let verification = verify_bytecode(&bytecode)?;
    if control.semantic_digest != verification.semantic_digest
        || control.bytecode_digest != verification.bytecode_digest
    {
        return Err(HostError::Protocol(
            "request is not bound to the supplied bytecode".to_owned(),
        ));
    }
    let expected_request = digest_serializable_v1(
        RegisteredDomainV1::HostExecutionRequestV2,
        &RequestCore {
            schema: HOST_EXECUTION_REQUEST_V1,
            operation: &control.operation,
            limits: &control.limits,
            semantic_digest: &control.semantic_digest,
            bytecode_digest: &control.bytecode_digest,
        },
    )?;
    if control.request_digest != expected_request {
        return Err(HostError::Protocol(
            "request identity does not match".to_owned(),
        ));
    }
    Ok(ExecutorRequest { control, bytecode })
}

/// Construct a successful compile-only child response.
pub fn completed_compile_response(
    request: &HostExecutionRequest,
    compile_receipt: NativeCompileReceipt,
) -> Result<ExecutorResponse, HostError> {
    build_response(
        request,
        ExecutorResponseStatus::Completed,
        Some(compile_receipt),
        None,
        None,
        None,
    )
}

/// Construct a successful native-invocation child response.
pub fn completed_run_response(
    request: &HostExecutionRequest,
    compile_receipt: NativeCompileReceipt,
    execution_receipt: NativeExecutionReceipt,
) -> Result<ExecutorResponse, HostError> {
    build_response(
        request,
        ExecutorResponseStatus::Completed,
        Some(compile_receipt),
        Some(execution_receipt),
        None,
        None,
    )
}

/// Construct a deterministic failed child response.
pub fn failed_executor_response(
    request: &HostExecutionRequest,
    compile_receipt: Option<NativeCompileReceipt>,
    code: ExecutorFailureCode,
    message: &str,
) -> Result<ExecutorResponse, HostError> {
    let message = bounded_detail(message);
    build_response(
        request,
        ExecutorResponseStatus::Failed,
        compile_receipt,
        None,
        Some(code),
        Some(message),
    )
}

/// Encode one child response as a bounded Lattice frame.
pub fn encode_response_frame(response: &ExecutorResponse) -> Result<Vec<u8>, HostError> {
    validate_response_shape(response)?;
    let bytes = encode_jce1(response)?;
    let schema_digest = transport_digest(HOST_EXECUTOR_RESPONSE_V1.as_bytes());
    let intent_digest = transport_digest(&bytes);
    let mut levels: [&[u8]; LEVEL_COUNT] = [&[]; LEVEL_COUNT];
    levels[Level::Result as usize] = &bytes;
    let frame = encode(&FrameParts {
        schema_digest: &schema_digest,
        intent_digest: &intent_digest,
        flags: 0,
        levels,
    })?;
    if frame.len() > MAX_HOST_RESPONSE_FRAME_BYTES {
        return Err(HostError::Protocol(format!(
            "response frame exceeds {MAX_HOST_RESPONSE_FRAME_BYTES} bytes"
        )));
    }
    Ok(frame)
}

/// Decode and validate one complete child response frame.
pub fn decode_response_frame(frame: &[u8]) -> Result<ExecutorResponse, HostError> {
    if frame.len() > MAX_HOST_RESPONSE_FRAME_BYTES {
        return Err(HostError::Protocol(format!(
            "response frame exceeds {MAX_HOST_RESPONSE_FRAME_BYTES} bytes"
        )));
    }
    let decoded = decode(frame)?;
    for level in [
        Level::Frame,
        Level::Shape,
        Level::Intent,
        Level::Authority,
        Level::Evidence,
    ] {
        if !decoded.level(level).is_empty() {
            return Err(HostError::Protocol(
                "response contains an unexpected Lattice level".to_owned(),
            ));
        }
    }
    if decoded.flags() != 0 {
        return Err(HostError::Protocol(
            "response contains unsupported flags".to_owned(),
        ));
    }
    let expected_schema = transport_digest(HOST_EXECUTOR_RESPONSE_V1.as_bytes());
    if decoded.schema_digest() != expected_schema {
        return Err(HostError::Protocol(
            "response schema digest does not match".to_owned(),
        ));
    }
    let bytes = decoded.level(Level::Result);
    if decoded.intent_digest() != transport_digest(bytes) {
        return Err(HostError::Protocol(
            "response intent digest does not match".to_owned(),
        ));
    }
    let response: ExecutorResponse = decode_jce1(bytes)?;
    validate_response_shape(&response)?;
    Ok(response)
}

/// Read at most `limit` bytes and report whether one extra byte was present.
pub fn read_bounded<R: Read>(reader: &mut R, limit: usize) -> io::Result<(Vec<u8>, bool)> {
    let read_limit = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    reader.take(read_limit).read_to_end(&mut bytes)?;
    let oversized = bytes.len() > limit;
    if oversized {
        bytes.truncate(limit);
    }
    Ok((bytes, oversized))
}

/// Apply the request-bound POSIX resource profile inside the executor process.
#[cfg(unix)]
pub fn apply_executor_resource_limits(limits: HostLimits) -> Result<(), HostError> {
    use rustix::process::{Resource, Rlimit, setrlimit};

    validate_limits(&limits)?;
    for (resource, value, name) in [
        (Resource::Core, limits.core_size_bytes(), "core"),
        (Resource::Fsize, limits.file_size_bytes(), "file_size"),
        (Resource::Nofile, limits.open_files(), "open_files"),
    ] {
        setrlimit(
            resource,
            Rlimit {
                current: Some(value),
                maximum: Some(value),
            },
        )
        .map_err(|error| HostError::ResourceLimit(format!("{name}: {error}")))?;
    }
    setrlimit(
        Resource::Cpu,
        Rlimit {
            current: Some(limits.cpu_time_seconds()),
            maximum: Some(limits.cpu_time_seconds().saturating_add(1)),
        },
    )
    .map_err(|error| HostError::ResourceLimit(format!("cpu_time: {error}")))?;
    match limits.memory_limit_kind() {
        HostMemoryLimitKind::Unavailable => {}
        HostMemoryLimitKind::AddressSpace => set_address_space_limit(limits.memory_limit_bytes())?,
        HostMemoryLimitKind::DataSegment => setrlimit(
            Resource::Data,
            Rlimit {
                current: Some(limits.memory_limit_bytes()),
                maximum: Some(limits.memory_limit_bytes()),
            },
        )
        .map_err(|error| HostError::ResourceLimit(format!("data_segment: {error}")))?,
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "openbsd")))]
fn set_address_space_limit(bytes: u64) -> Result<(), HostError> {
    use rustix::process::{Resource, Rlimit, setrlimit};

    setrlimit(
        Resource::As,
        Rlimit {
            current: Some(bytes),
            maximum: Some(bytes),
        },
    )
    .map_err(|error| HostError::ResourceLimit(format!("address_space: {error}")))
}

#[cfg(all(unix, target_os = "openbsd"))]
fn set_address_space_limit(_bytes: u64) -> Result<(), HostError> {
    Err(HostError::ResourceLimit(
        "address-space limits are unavailable on OpenBSD".to_owned(),
    ))
}

/// Reject native execution where the POSIX limit profile cannot be established.
#[cfg(not(unix))]
pub fn apply_executor_resource_limits(_limits: HostLimits) -> Result<(), HostError> {
    Err(HostError::ResourceLimit(
        "POSIX resource limits are unavailable on this platform".to_owned(),
    ))
}

pub(crate) fn make_host_receipt(
    request: &HostExecutionRequest,
    status: HostExecutionStatus,
    reason: HostExecutionReason,
    child_exit_code: Option<i32>,
    child_unix_signal: Option<i32>,
    response: Option<&ExecutorResponse>,
    detail: Option<String>,
) -> Result<HostExecutionReceipt, HostError> {
    if child_exit_code.is_some() && child_unix_signal.is_some() {
        return Err(HostError::Protocol(
            "child exit code and Unix signal are mutually exclusive".to_owned(),
        ));
    }
    let executor_response_digest = response.as_ref().map(|value| value.response_digest.clone());
    let compile_receipt = response
        .as_ref()
        .and_then(|value| value.compile_receipt.clone());
    let execution_receipt = response
        .as_ref()
        .and_then(|value| value.execution_receipt.clone());
    let detail = detail.map(|value| bounded_detail(&value));
    let receipt_digest = digest_serializable_v1(
        RegisteredDomainV1::HostExecutionReceiptV2,
        &ReceiptCore {
            schema: HOST_EXECUTION_RECEIPT_V1,
            status: &status,
            reason: &reason,
            limits: &request.limits,
            request_digest: &request.request_digest,
            semantic_digest: &request.semantic_digest,
            bytecode_digest: &request.bytecode_digest,
            child_exit_code,
            child_unix_signal,
            executor_response_digest: &executor_response_digest,
            compile_receipt: &compile_receipt,
            execution_receipt: &execution_receipt,
            detail: &detail,
        },
    )?;
    Ok(HostExecutionReceipt {
        schema: HOST_EXECUTION_RECEIPT_V1.to_owned(),
        status,
        reason,
        limits: request.limits,
        request_digest: request.request_digest.clone(),
        semantic_digest: request.semantic_digest.clone(),
        bytecode_digest: request.bytecode_digest.clone(),
        child_exit_code,
        child_unix_signal,
        executor_response_digest,
        compile_receipt,
        execution_receipt,
        detail,
        receipt_digest,
    })
}

pub(crate) fn validate_bound_response(
    request: &HostExecutionRequest,
    response: &ExecutorResponse,
) -> Result<(), HostError> {
    if response.request_digest != request.request_digest
        || response.semantic_digest != request.semantic_digest
        || response.bytecode_digest != request.bytecode_digest
    {
        return Err(HostError::Protocol(
            "executor response request binding does not match".to_owned(),
        ));
    }
    match (&request.operation, &response.status) {
        (HostOperation::Compile, ExecutorResponseStatus::Completed) => {
            if response.compile_receipt.is_none() || response.execution_receipt.is_some() {
                return Err(HostError::Protocol(
                    "compile response has invalid receipts".to_owned(),
                ));
            }
        }
        (HostOperation::Run { function, .. }, ExecutorResponseStatus::Completed) => {
            let Some(compile) = &response.compile_receipt else {
                return Err(HostError::Protocol(
                    "run response omits compile receipt".to_owned(),
                ));
            };
            let Some(execution) = &response.execution_receipt else {
                return Err(HostError::Protocol(
                    "run response omits execution receipt".to_owned(),
                ));
            };
            if execution.function != *function
                || execution.artifact_digest != compile.artifact_digest
            {
                return Err(HostError::Protocol(
                    "run response native binding does not match".to_owned(),
                ));
            }
        }
        (_, ExecutorResponseStatus::Failed) => {}
    }
    if let Some(compile) = &response.compile_receipt
        && (compile.semantic_digest != request.semantic_digest
            || compile.bytecode_digest != request.bytecode_digest)
    {
        return Err(HostError::Protocol(
            "compile receipt binding does not match request".to_owned(),
        ));
    }
    if let Some(execution) = &response.execution_receipt
        && execution.bytecode_digest != request.bytecode_digest
    {
        return Err(HostError::Protocol(
            "execution receipt bytecode binding does not match".to_owned(),
        ));
    }
    Ok(())
}

fn build_response(
    request: &HostExecutionRequest,
    status: ExecutorResponseStatus,
    compile_receipt: Option<NativeCompileReceipt>,
    execution_receipt: Option<NativeExecutionReceipt>,
    failure_code: Option<ExecutorFailureCode>,
    failure_message: Option<String>,
) -> Result<ExecutorResponse, HostError> {
    let response_digest = digest_serializable_v1(
        RegisteredDomainV1::HostExecutorResponseV2,
        &ResponseCore {
            schema: HOST_EXECUTOR_RESPONSE_V1,
            status: &status,
            request_digest: &request.request_digest,
            semantic_digest: &request.semantic_digest,
            bytecode_digest: &request.bytecode_digest,
            compile_receipt: &compile_receipt,
            execution_receipt: &execution_receipt,
            failure_code: &failure_code,
            failure_message: &failure_message,
        },
    )?;
    let response = ExecutorResponse {
        schema: HOST_EXECUTOR_RESPONSE_V1.to_owned(),
        status,
        request_digest: request.request_digest.clone(),
        semantic_digest: request.semantic_digest.clone(),
        bytecode_digest: request.bytecode_digest.clone(),
        compile_receipt,
        execution_receipt,
        failure_code,
        failure_message,
        response_digest,
    };
    validate_response_shape(&response)?;
    Ok(response)
}

fn validate_response_shape(response: &ExecutorResponse) -> Result<(), HostError> {
    if response.schema != HOST_EXECUTOR_RESPONSE_V1 {
        return Err(HostError::Protocol(
            "unsupported executor response schema".to_owned(),
        ));
    }
    match response.status {
        ExecutorResponseStatus::Completed => {
            if response.failure_code.is_some() || response.failure_message.is_some() {
                return Err(HostError::Protocol(
                    "completed response contains failure fields".to_owned(),
                ));
            }
        }
        ExecutorResponseStatus::Failed => {
            if response.failure_code.is_none()
                || response
                    .failure_message
                    .as_ref()
                    .is_none_or(String::is_empty)
                || response.execution_receipt.is_some()
            {
                return Err(HostError::Protocol(
                    "failed response has invalid fields".to_owned(),
                ));
            }
        }
    }
    if response
        .failure_message
        .as_ref()
        .is_some_and(|message| message.len() > MAX_FAILURE_MESSAGE_BYTES)
    {
        return Err(HostError::Protocol(
            "executor failure message exceeds its bound".to_owned(),
        ));
    }
    let expected = digest_serializable_v1(
        RegisteredDomainV1::HostExecutorResponseV2,
        &ResponseCore {
            schema: HOST_EXECUTOR_RESPONSE_V1,
            status: &response.status,
            request_digest: &response.request_digest,
            semantic_digest: &response.semantic_digest,
            bytecode_digest: &response.bytecode_digest,
            compile_receipt: &response.compile_receipt,
            execution_receipt: &response.execution_receipt,
            failure_code: &response.failure_code,
            failure_message: &response.failure_message,
        },
    )?;
    if response.response_digest != expected {
        return Err(HostError::Protocol(
            "executor response identity does not match".to_owned(),
        ));
    }
    Ok(())
}

fn validate_operation(operation: &HostOperation) -> Result<(), HostError> {
    if let HostOperation::Run {
        function,
        arguments,
        instruction_budget,
    } = operation
    {
        if function.is_empty() || function.len() > MAX_FUNCTION_NAME_BYTES || !function.is_ascii() {
            return Err(HostError::InvalidRequest(
                "function name is empty, non-ASCII or too long".to_owned(),
            ));
        }
        if arguments.len() > MAX_HOST_ARGUMENTS {
            return Err(HostError::InvalidRequest(format!(
                "argument count exceeds {MAX_HOST_ARGUMENTS}"
            )));
        }
        if *instruction_budget == 0 || *instruction_budget > MAX_INSTRUCTION_BUDGET {
            return Err(HostError::InvalidRequest(format!(
                "instruction budget must be between 1 and {MAX_INSTRUCTION_BUDGET}"
            )));
        }
    }
    Ok(())
}

fn require_request_levels(frame: &joan_lattice::BorrowedFrame<'_>) -> Result<(), HostError> {
    if frame.level(Level::Shape).is_empty() || frame.level(Level::Evidence).is_empty() {
        return Err(HostError::Protocol(
            "request omits control or bytecode evidence".to_owned(),
        ));
    }
    for level in [Level::Frame, Level::Intent, Level::Authority, Level::Result] {
        if !frame.level(level).is_empty() {
            return Err(HostError::Protocol(
                "request contains an unexpected Lattice level".to_owned(),
            ));
        }
    }
    Ok(())
}

fn encode_jce1<T: Serialize>(value: &T) -> Result<Vec<u8>, HostError> {
    let canonical = from_serializable_v1(value)?;
    Ok(to_canonical_bytes_v1(&canonical)?)
}

fn decode_jce1<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, HostError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| HostError::Protocol(format!("protocol payload is not UTF-8: {error}")))?;
    let canonical = parse_strict_v1(text)?;
    if to_canonical_bytes_v1(&canonical)? != bytes {
        return Err(HostError::Protocol(
            "protocol payload is not exact canonical JCE1".to_owned(),
        ));
    }
    Ok(serde_json::from_value(canonical.to_serde_value())?)
}

fn transport_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn bounded_detail(message: &str) -> String {
    if message.len() <= MAX_FAILURE_MESSAGE_BYTES {
        return message.to_owned();
    }
    let mut end = MAX_FAILURE_MESSAGE_BYTES;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    message[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use joan_compiler::compile_source;

    const PURE: &str = r"module host_protocol;
fn score(left: i64, right: i64) -> i64 effects [] {
  return left * right;
}
fn main() -> i64 effects [] {
  return 0;
}
";

    #[test]
    fn request_frame_round_trips_and_binds_bytecode() -> Result<(), Box<dyn std::error::Error>> {
        let artifact = compile_source(PURE)?;
        let operation = HostOperation::Run {
            function: "score".to_owned(),
            arguments: vec![Value::I64(6), Value::I64(7)],
            instruction_budget: 100,
        };
        let (control, frame) = encode_request_frame(&artifact.bytecode, operation.clone())?;
        let decoded = decode_request_frame(&frame)?;
        assert_eq!(decoded.control, control);
        assert_eq!(decoded.control.operation, operation);
        assert_eq!(decoded.bytecode, artifact.bytecode);
        Ok(())
    }

    #[test]
    fn malformed_duplicate_and_oversized_frames_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifact = compile_source(PURE)?;
        let (_, frame) = encode_request_frame(&artifact.bytecode, HostOperation::Compile)?;

        let mut malformed = frame.clone();
        malformed[0] ^= 0xff;
        assert!(decode_request_frame(&malformed).is_err());
        assert!(decode_request_frame(&frame[..frame.len() - 1]).is_err());

        let mut duplicate = frame.clone();
        duplicate.extend_from_slice(&frame);
        assert!(decode_request_frame(&duplicate).is_err());

        let oversized = vec![0_u8; MAX_HOST_REQUEST_FRAME_BYTES + 1];
        assert!(decode_request_frame(&oversized).is_err());
        Ok(())
    }

    #[test]
    fn operation_and_limit_bounds_fail_before_spawn() -> Result<(), Box<dyn std::error::Error>> {
        let artifact = compile_source(PURE)?;
        assert!(HostLimits::new(0).is_err());
        assert!(HostLimits::new(MAX_HOST_WALL_TIME_MS + 1).is_err());
        assert!(
            encode_request_frame(
                &artifact.bytecode,
                HostOperation::Run {
                    function: "score".to_owned(),
                    arguments: Vec::new(),
                    instruction_budget: 0,
                }
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn resource_policy_is_part_of_request_identity() -> Result<(), Box<dyn std::error::Error>> {
        let artifact = compile_source(PURE)?;
        let (short, _) = encode_request_frame_with_limits(
            &artifact.bytecode,
            HostOperation::Compile,
            HostLimits::new(100)?,
        )?;
        let (long, _) = encode_request_frame_with_limits(
            &artifact.bytecode,
            HostOperation::Compile,
            HostLimits::new(200)?,
        )?;
        assert_ne!(short.request_digest, long.request_digest);
        assert_ne!(short.limits, long.limits);
        Ok(())
    }

    #[test]
    fn receipt_rejects_simultaneous_exit_code_and_signal() -> Result<(), Box<dyn std::error::Error>>
    {
        let artifact = compile_source(PURE)?;
        let (request, _) = encode_request_frame(&artifact.bytecode, HostOperation::Compile)?;
        let result = make_host_receipt(
            &request,
            HostExecutionStatus::Unknown,
            HostExecutionReason::ChildExitUnknown,
            Some(1),
            Some(9),
            None,
            None,
        );
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn default_memory_limit_matches_host_capability() {
        let limits = HostLimits::default();
        if cfg!(target_vendor = "apple") {
            assert_eq!(limits.memory_limit_kind(), HostMemoryLimitKind::Unavailable);
            assert_eq!(limits.memory_limit_bytes(), 0);
        } else {
            assert_eq!(
                limits.memory_limit_kind(),
                HostMemoryLimitKind::AddressSpace
            );
            assert_eq!(limits.memory_limit_bytes(), DEFAULT_HOST_MEMORY_LIMIT_BYTES);
        }
    }

    #[test]
    fn response_binding_cannot_be_replayed_for_another_request()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifact = compile_source(PURE)?;
        let (compile_request, _) =
            encode_request_frame(&artifact.bytecode, HostOperation::Compile)?;
        let (run_request, _) = encode_request_frame(
            &artifact.bytecode,
            HostOperation::Run {
                function: "score".to_owned(),
                arguments: vec![Value::I64(6), Value::I64(7)],
                instruction_budget: 100,
            },
        )?;
        let response = failed_executor_response(
            &compile_request,
            None,
            ExecutorFailureCode::CodegenFailed,
            "deterministic rejection",
        )?;
        assert!(validate_bound_response(&compile_request, &response).is_ok());
        assert!(validate_bound_response(&run_request, &response).is_err());

        let frame = encode_response_frame(&response)?;
        assert!(decode_response_frame(&frame[..frame.len() - 1]).is_err());
        let mut duplicate = frame.clone();
        duplicate.extend_from_slice(&frame);
        assert!(decode_response_frame(&duplicate).is_err());
        Ok(())
    }
}
