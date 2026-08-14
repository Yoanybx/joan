//! Deterministic generation and independent verification of bounded JOAN tools.
//!
//! TF-V0 is pure-only. It has no network, filesystem, process, secret, payment,
//! device, telemetry, deployment or host-effect adapter.

#![forbid(unsafe_code)]

use joan_bytecode::{BytecodeProgram, Instruction, verify_bytecode};
use joan_canonical::{
    Digest, Jce1Error, RegisteredDomainV1, digest_bytes_v1, digest_serializable_v1,
    from_serializable_v1, to_canonical_bytes_v1,
};
use joan_compiler::{compile_source, execute_bytecode_function};
use joan_guardian::{
    GuardianCandidate, GuardianDecisionReceipt, GuardianOutcome, GuardianRole, evaluate_candidate,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use joan_bytecode::Value;

/// Exact TF-V0 specification schema.
pub const TOOL_SPEC_SCHEMA: &str = "joan.tool-spec.v0";
/// Exact TF-V0 specification-verification receipt schema.
pub const TOOL_SPEC_VERIFICATION_SCHEMA: &str = "joan.tool-spec-verification-receipt.v0";
/// Exact TF-V0 bundle schema.
pub const TOOL_BUNDLE_SCHEMA: &str = "joan.tool-bundle.v0";
/// Exact TF-V0 independent verification receipt schema.
pub const TOOL_VERIFICATION_SCHEMA: &str = "joan.tool-verification-receipt.v0";
/// Exact TF-V0 finalization receipt schema.
pub const TOOL_FINALIZATION_SCHEMA: &str = "joan.tool-finalization-receipt.v0";
/// Exact TF-V0 promotion decision schema.
pub const TOOL_PROMOTION_SCHEMA: &str = "joan.tool-promotion-decision.v0";
/// Number of deterministic generation passes required by TF-V0.
pub const GENERATION_PASSES: u64 = 3;
/// Maximum accepted instruction budget.
pub const MAX_INSTRUCTION_BUDGET: u64 = 1_000_000;
/// Maximum number of declared tests.
pub const MAX_TEST_CASES: usize = 64;

const MAX_IDENTIFIER_BYTES: usize = 64;
const TOOL_GENERATOR_ID: &str = "tool-generator";

/// Pure operation templates supported by TF-V0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ToolOperation {
    /// Return one integer argument unchanged.
    IdentityI64,
    /// Add two integers with JOAN checked arithmetic.
    AddI64,
    /// Subtract two integers with JOAN checked arithmetic.
    SubtractI64,
    /// Multiply two integers with JOAN checked arithmetic.
    MultiplyI64,
    /// Compare two integers for equality.
    EqualI64,
    /// Compute boolean conjunction.
    AndBool,
}

/// One mandatory deterministic behavior test.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolTestCase {
    /// Stable lowercase test identifier.
    pub name: String,
    /// Typed arguments supplied to generated function `run`.
    pub arguments: Vec<Value>,
    /// Exact expected result.
    pub expected: Value,
}

/// Declarative input accepted by the deterministic generator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSpec {
    /// Must equal [`TOOL_SPEC_SCHEMA`].
    pub schema: String,
    /// Lowercase JOAN module identifier.
    pub name: String,
    /// Tenant label bound into the specification identity.
    pub tenant: String,
    /// Purpose label bound into the specification identity.
    pub purpose: String,
    /// Maximum instructions allowed for each declared test.
    pub instruction_budget: u64,
    /// Pure generated operation.
    pub operation: ToolOperation,
    /// Required independent behavior tests.
    pub tests: Vec<ToolTestCase>,
}

/// Stable machine-readable verification finding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolFinding {
    /// Stable TF-V0 code.
    pub code: String,
    /// Deterministic explanation.
    pub message: String,
}

/// Verification status used by specification and bundle receipts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    /// Every required gate passed.
    Verified,
    /// At least one required gate failed.
    Rejected,
}

/// Receipt proving that one exact `ToolSpec` passed or failed static policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSpecVerificationReceipt {
    /// Exact receipt schema.
    pub schema: String,
    /// Typed JCE1 identity of the specification.
    pub spec_digest: Digest,
    /// Static verification result.
    pub status: VerificationStatus,
    /// Ordered findings; empty only when verified.
    pub findings: Vec<ToolFinding>,
    /// Typed JCE1 identity of all preceding fields.
    pub receipt_digest: Digest,
}

/// Complete portable output of the deterministic generator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolBundle {
    /// Exact bundle schema.
    pub schema: String,
    /// `ToolSpec` identity used to generate the bundle.
    pub spec_digest: Digest,
    /// Generated auditable JOAN Source.
    pub source: String,
    /// Typed identity of exact source bytes.
    pub source_digest: Digest,
    /// Complete independently verifiable bytecode.
    pub bytecode: BytecodeProgram,
    /// Typed identity emitted by the standalone bytecode verifier.
    pub bytecode_digest: Digest,
    /// Number of byte-identical generation passes.
    pub generation_passes: u64,
    /// Typed identity of all preceding bundle fields.
    pub bundle_digest: Digest,
}

/// Independent verification result for one exact bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolVerificationReceipt {
    /// Exact receipt schema.
    pub schema: String,
    /// Exact `ToolSpec` identity.
    pub spec_digest: Digest,
    /// Exact generated bundle identity.
    pub bundle_digest: Digest,
    /// Verification result.
    pub status: VerificationStatus,
    /// Number of declared tests executed successfully.
    pub tests_passed: u64,
    /// True only when three independent generations were byte-identical.
    pub generations_byte_identical: bool,
    /// Always false in TF-V0.
    pub external_effects_executed: bool,
    /// Ordered findings; empty only when verified.
    pub findings: Vec<ToolFinding>,
    /// Typed JCE1 identity of all preceding fields.
    pub receipt_digest: Digest,
}

/// Finalization result after an externally supplied guardian candidate is evaluated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalizationStatus {
    /// Independent verification and guardian approval passed.
    Finalized,
    /// The bundle remains quarantined.
    Quarantined,
}

/// Guardian-bound finalization receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolFinalizationReceipt {
    /// Exact receipt schema.
    pub schema: String,
    /// Exact bundle identity.
    pub bundle_digest: Digest,
    /// Exact independent verification receipt identity.
    pub verification_digest: Digest,
    /// Finalization result.
    pub status: FinalizationStatus,
    /// Guardian result, when the candidate itself was structurally valid.
    pub guardian: Option<GuardianDecisionReceipt>,
    /// Ordered findings.
    pub findings: Vec<ToolFinding>,
    /// Typed JCE1 identity of all preceding fields.
    pub receipt_digest: Digest,
}

/// Final promotion state. Eligibility never authorizes deployment or host effects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionStatus {
    /// Eligible for a later, separately authorized packaging step.
    Eligible,
    /// Not eligible and retained in quarantine.
    Quarantined,
}

/// Deterministic promotion decision derived from finalization only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPromotionDecision {
    /// Exact decision schema.
    pub schema: String,
    /// Exact finalization receipt identity.
    pub finalization_digest: Digest,
    /// Promotion state.
    pub status: PromotionStatus,
    /// Stable reason codes; empty only when eligible.
    pub reasons: Vec<String>,
    /// Typed JCE1 identity of all preceding fields.
    pub decision_digest: Digest,
}

/// Unexpected encoding or generation failure.
#[derive(Debug, Error)]
pub enum ToolForgeError {
    /// Registered JCE1 encoding failed.
    #[error(transparent)]
    Jce1(#[from] Jce1Error),
    /// A specification cannot be forged until its static receipt is verified.
    #[error("tool specification rejected: {0}")]
    SpecRejected(String),
    /// JOAN compilation failed for generator-owned source.
    #[error("generated source failed compilation: {0}")]
    Compilation(String),
    /// Three generation passes disagreed.
    #[error("generated bundles were not byte-identical")]
    NondeterministicGeneration,
}

#[derive(Serialize)]
struct SpecReceiptCore<'a> {
    schema: &'a str,
    spec_digest: &'a Digest,
    status: VerificationStatus,
    findings: &'a [ToolFinding],
}

#[derive(Serialize)]
struct BundleCore<'a> {
    schema: &'a str,
    spec_digest: &'a Digest,
    source: &'a str,
    source_digest: &'a Digest,
    bytecode: &'a BytecodeProgram,
    bytecode_digest: &'a Digest,
    generation_passes: u64,
}

#[derive(Serialize)]
struct VerificationCore<'a> {
    schema: &'a str,
    spec_digest: &'a Digest,
    bundle_digest: &'a Digest,
    status: VerificationStatus,
    tests_passed: u64,
    generations_byte_identical: bool,
    external_effects_executed: bool,
    findings: &'a [ToolFinding],
}

#[derive(Serialize)]
struct FinalizationCore<'a> {
    schema: &'a str,
    bundle_digest: &'a Digest,
    verification_digest: &'a Digest,
    status: FinalizationStatus,
    guardian: &'a Option<GuardianDecisionReceipt>,
    findings: &'a [ToolFinding],
}

#[derive(Serialize)]
struct PromotionCore<'a> {
    schema: &'a str,
    finalization_digest: &'a Digest,
    status: PromotionStatus,
    reasons: &'a [String],
}

/// Statically verify an exact `ToolSpec` without generating code.
pub fn verify_spec(spec: &ToolSpec) -> Result<ToolSpecVerificationReceipt, ToolForgeError> {
    let spec_digest = digest_serializable_v1(RegisteredDomainV1::ToolSpec, spec)?;
    let findings = validate_spec(spec);
    let status = if findings.is_empty() {
        VerificationStatus::Verified
    } else {
        VerificationStatus::Rejected
    };
    let receipt_digest = digest_serializable_v1(
        RegisteredDomainV1::ToolSpecVerification,
        &SpecReceiptCore {
            schema: TOOL_SPEC_VERIFICATION_SCHEMA,
            spec_digest: &spec_digest,
            status,
            findings: &findings,
        },
    )?;
    Ok(ToolSpecVerificationReceipt {
        schema: TOOL_SPEC_VERIFICATION_SCHEMA.to_owned(),
        spec_digest,
        status,
        findings,
        receipt_digest,
    })
}

/// Generate one portable bundle after three byte-identical in-memory passes.
pub fn forge_tool(spec: &ToolSpec) -> Result<ToolBundle, ToolForgeError> {
    let static_receipt = verify_spec(spec)?;
    if static_receipt.status != VerificationStatus::Verified {
        let codes = static_receipt
            .findings
            .iter()
            .map(|item| item.code.as_str())
            .collect::<Vec<_>>()
            .join(",");
        return Err(ToolForgeError::SpecRejected(codes));
    }
    let generated = [
        generate_once(spec)?,
        generate_once(spec)?,
        generate_once(spec)?,
    ];
    let bytes = generated
        .iter()
        .map(encode_jce1)
        .collect::<Result<Vec<_>, _>>()?;
    if bytes.windows(2).any(|pair| pair[0] != pair[1]) {
        return Err(ToolForgeError::NondeterministicGeneration);
    }
    generated
        .into_iter()
        .next()
        .ok_or(ToolForgeError::NondeterministicGeneration)
}

/// Independently regenerate, verify and execute all declared tests for a bundle.
pub fn verify_tool(
    spec: &ToolSpec,
    bundle: &ToolBundle,
) -> Result<ToolVerificationReceipt, ToolForgeError> {
    let spec_receipt = verify_spec(spec)?;
    let mut findings = spec_receipt.findings;
    if bundle.schema != TOOL_BUNDLE_SCHEMA {
        findings.push(finding("TF1001", "unsupported tool bundle schema"));
    }
    if bundle.spec_digest != spec_receipt.spec_digest {
        findings.push(finding("TF1002", "bundle is bound to another ToolSpec"));
    }
    let source_digest = digest_bytes_v1(RegisteredDomainV1::Source, bundle.source.as_bytes())?;
    if source_digest != bundle.source_digest {
        findings.push(finding("TF1003", "source digest mismatch"));
    }
    let expected_bundle_digest = digest_bundle(bundle)?;
    if expected_bundle_digest != bundle.bundle_digest {
        findings.push(finding("TF1004", "bundle digest mismatch"));
    }
    if bundle.generation_passes != GENERATION_PASSES {
        findings.push(finding("TF1005", "bundle lacks three generation passes"));
    }

    let bytecode_verified = verify_bundle_bytecode(bundle, &mut findings);

    let regenerated = if let Ok(value) = forge_tool(spec) {
        Some(value)
    } else {
        findings.push(finding("TF1009", "independent regeneration failed"));
        None
    };
    let generations_byte_identical = regenerated.as_ref().is_some_and(|value| value == bundle);
    if !generations_byte_identical {
        findings.push(finding(
            "TF1010",
            "independent regeneration disagreed with bundle",
        ));
    }

    let mut tests_passed = 0_u64;
    if bytecode_verified && findings.is_empty() {
        for test in &spec.tests {
            match execute_bytecode_function(
                &bundle.bytecode,
                "run",
                test.arguments.clone(),
                spec.instruction_budget,
            ) {
                Ok(receipt)
                    if receipt.result == test.expected && receipt.effect_requests.is_empty() =>
                {
                    tests_passed = tests_passed.saturating_add(1);
                }
                Ok(_) => findings.push(finding(
                    "TF1011",
                    &format!("behavior test {} failed", test.name),
                )),
                Err(_) => findings.push(finding(
                    "TF1012",
                    &format!("behavior test {} could not execute", test.name),
                )),
            }
        }
    }

    let status = if findings.is_empty()
        && tests_passed == u64::try_from(spec.tests.len()).unwrap_or(u64::MAX)
    {
        VerificationStatus::Verified
    } else {
        VerificationStatus::Rejected
    };
    let receipt_digest = digest_serializable_v1(
        RegisteredDomainV1::ToolVerification,
        &VerificationCore {
            schema: TOOL_VERIFICATION_SCHEMA,
            spec_digest: &spec_receipt.spec_digest,
            bundle_digest: &bundle.bundle_digest,
            status,
            tests_passed,
            generations_byte_identical,
            external_effects_executed: false,
            findings: &findings,
        },
    )?;
    Ok(ToolVerificationReceipt {
        schema: TOOL_VERIFICATION_SCHEMA.to_owned(),
        spec_digest: spec_receipt.spec_digest,
        bundle_digest: bundle.bundle_digest.clone(),
        status,
        tests_passed,
        generations_byte_identical,
        external_effects_executed: false,
        findings,
        receipt_digest,
    })
}

/// Evaluate an externally supplied guardian candidate and finalize fail-closed.
pub fn finalize_tool(
    spec: &ToolSpec,
    bundle: &ToolBundle,
    verification: &ToolVerificationReceipt,
    candidate: &GuardianCandidate,
) -> Result<ToolFinalizationReceipt, ToolForgeError> {
    let mut findings = Vec::new();
    if digest_bundle(bundle)? != bundle.bundle_digest {
        findings.push(finding("TF2001", "bundle identity is invalid"));
    }
    let expected_verification = verify_tool(spec, bundle)?;
    if verification != &expected_verification
        || expected_verification.status != VerificationStatus::Verified
    {
        findings.push(finding(
            "TF2002",
            "independent verification is absent, rejected or not reproducible",
        ));
    }
    if candidate.candidate_root != bundle.bundle_digest {
        findings.push(finding(
            "TF2003",
            "guardian candidate targets another bundle",
        ));
    }
    if !matches_tool_guardian_policy(bundle, candidate) {
        findings.push(finding(
            "TF2006",
            "guardian candidate violates TF-V0 policy",
        ));
    }
    let guardian = if findings.is_empty() {
        if let Ok(receipt) = evaluate_candidate(candidate) {
            if receipt.outcome != GuardianOutcome::Approved {
                findings.push(finding("TF2004", "guardian outcome is not approved"));
            }
            Some(receipt)
        } else {
            findings.push(finding("TF2005", "guardian candidate is invalid"));
            None
        }
    } else {
        None
    };
    let status = if findings.is_empty() {
        FinalizationStatus::Finalized
    } else {
        FinalizationStatus::Quarantined
    };
    let receipt_digest = digest_serializable_v1(
        RegisteredDomainV1::ToolFinalization,
        &FinalizationCore {
            schema: TOOL_FINALIZATION_SCHEMA,
            bundle_digest: &bundle.bundle_digest,
            verification_digest: &verification.receipt_digest,
            status,
            guardian: &guardian,
            findings: &findings,
        },
    )?;
    Ok(ToolFinalizationReceipt {
        schema: TOOL_FINALIZATION_SCHEMA.to_owned(),
        bundle_digest: bundle.bundle_digest.clone(),
        verification_digest: verification.receipt_digest.clone(),
        status,
        guardian,
        findings,
        receipt_digest,
    })
}

/// Rederive the complete chain and decide eligibility without applying the tool.
pub fn evaluate_promotion(
    spec: &ToolSpec,
    bundle: &ToolBundle,
    verification: &ToolVerificationReceipt,
    candidate: &GuardianCandidate,
    finalization: &ToolFinalizationReceipt,
) -> Result<ToolPromotionDecision, ToolForgeError> {
    let expected_finalization = finalize_tool(spec, bundle, verification, candidate)?;
    let (status, reasons) = if finalization == &expected_finalization
        && expected_finalization.status == FinalizationStatus::Finalized
        && expected_finalization.findings.is_empty()
        && expected_finalization
            .guardian
            .as_ref()
            .is_some_and(|receipt| receipt.outcome == GuardianOutcome::Approved)
    {
        (PromotionStatus::Eligible, Vec::new())
    } else {
        (
            PromotionStatus::Quarantined,
            vec!["finalization-chain-not-approved".to_owned()],
        )
    };
    let decision_digest = digest_serializable_v1(
        RegisteredDomainV1::ToolPromotion,
        &PromotionCore {
            schema: TOOL_PROMOTION_SCHEMA,
            finalization_digest: &finalization.receipt_digest,
            status,
            reasons: &reasons,
        },
    )?;
    Ok(ToolPromotionDecision {
        schema: TOOL_PROMOTION_SCHEMA.to_owned(),
        finalization_digest: finalization.receipt_digest.clone(),
        status,
        reasons,
        decision_digest,
    })
}

fn validate_spec(spec: &ToolSpec) -> Vec<ToolFinding> {
    let mut findings = Vec::new();
    if spec.schema != TOOL_SPEC_SCHEMA {
        findings.push(finding("TF0001", "unsupported ToolSpec schema"));
    }
    validate_identifier("TF0002", "tool name", &spec.name, &mut findings);
    validate_identifier("TF0003", "tenant", &spec.tenant, &mut findings);
    validate_identifier("TF0004", "purpose", &spec.purpose, &mut findings);
    if !(1..=MAX_INSTRUCTION_BUDGET).contains(&spec.instruction_budget) {
        findings.push(finding(
            "TF0005",
            "instruction budget is outside TF-V0 bounds",
        ));
    }
    if spec.tests.is_empty() || spec.tests.len() > MAX_TEST_CASES {
        findings.push(finding("TF0006", "ToolSpec requires 1..=64 behavior tests"));
    }
    let mut names = std::collections::BTreeSet::new();
    for test in spec.tests.iter().take(MAX_TEST_CASES) {
        validate_identifier("TF0007", "test name", &test.name, &mut findings);
        if !names.insert(test.name.as_str()) {
            findings.push(finding("TF0008", "test names must be unique"));
        }
        let (argument_types, result_type, _) = operation_contract(spec.operation);
        if test.arguments.len() != argument_types.len()
            || test
                .arguments
                .iter()
                .zip(argument_types)
                .any(|(value, expected)| value_kind(value) != *expected)
            || value_kind(&test.expected) != result_type
        {
            findings.push(finding(
                "TF0009",
                "test values do not match operation types",
            ));
        }
    }
    findings
}

fn validate_identifier(code: &str, label: &str, value: &str, findings: &mut Vec<ToolFinding>) {
    let mut bytes = value.bytes();
    let valid = !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && !matches!(
            value,
            "fn" | "module" | "return" | "true" | "false" | "effects"
        );
    if !valid {
        findings.push(finding(
            code,
            &format!("{label} must be a non-reserved lowercase ASCII identifier"),
        ));
    }
}

fn generate_once(spec: &ToolSpec) -> Result<ToolBundle, ToolForgeError> {
    let spec_digest = digest_serializable_v1(RegisteredDomainV1::ToolSpec, spec)?;
    let source = generated_source(spec);
    let source_digest = digest_bytes_v1(RegisteredDomainV1::Source, source.as_bytes())?;
    let artifact =
        compile_source(&source).map_err(|error| ToolForgeError::Compilation(error.to_string()))?;
    let core = BundleCore {
        schema: TOOL_BUNDLE_SCHEMA,
        spec_digest: &spec_digest,
        source: &source,
        source_digest: &source_digest,
        bytecode: &artifact.bytecode,
        bytecode_digest: &artifact.verification.bytecode_digest,
        generation_passes: GENERATION_PASSES,
    };
    let bundle_digest = digest_serializable_v1(RegisteredDomainV1::ToolBundle, &core)?;
    Ok(ToolBundle {
        schema: TOOL_BUNDLE_SCHEMA.to_owned(),
        spec_digest,
        source,
        source_digest,
        bytecode: artifact.bytecode,
        bytecode_digest: artifact.verification.bytecode_digest,
        generation_passes: GENERATION_PASSES,
        bundle_digest,
    })
}

fn generated_source(spec: &ToolSpec) -> String {
    let (arguments, result, expression) = operation_contract(spec.operation);
    let parameters = arguments
        .iter()
        .enumerate()
        .map(|(index, kind)| format!("{}: {}", parameter_name(index), kind.source_name()))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "module {};\n\nfn run({parameters}) -> {} effects [] authorities [] {{\n  return {expression};\n}}\n\nfn main() -> i64 effects [] authorities [] {{\n  return 0;\n}}\n",
        spec.name,
        result.source_name(),
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ValueKind {
    I64,
    Bool,
    Unsupported,
}

impl ValueKind {
    const fn source_name(self) -> &'static str {
        match self {
            Self::I64 => "i64",
            Self::Bool => "bool",
            Self::Unsupported => "unit",
        }
    }
}

fn operation_contract(operation: ToolOperation) -> (&'static [ValueKind], ValueKind, &'static str) {
    const ONE_I64: &[ValueKind] = &[ValueKind::I64];
    const TWO_I64: &[ValueKind] = &[ValueKind::I64, ValueKind::I64];
    const TWO_BOOL: &[ValueKind] = &[ValueKind::Bool, ValueKind::Bool];
    match operation {
        ToolOperation::IdentityI64 => (ONE_I64, ValueKind::I64, "left"),
        ToolOperation::AddI64 => (TWO_I64, ValueKind::I64, "left + right"),
        ToolOperation::SubtractI64 => (TWO_I64, ValueKind::I64, "left - right"),
        ToolOperation::MultiplyI64 => (TWO_I64, ValueKind::I64, "left * right"),
        ToolOperation::EqualI64 => (TWO_I64, ValueKind::Bool, "left == right"),
        ToolOperation::AndBool => (TWO_BOOL, ValueKind::Bool, "left && right"),
    }
}

fn parameter_name(index: usize) -> &'static str {
    match index {
        0 => "left",
        1 => "right",
        _ => "value",
    }
}

fn value_kind(value: &Value) -> ValueKind {
    match value {
        Value::I64(_) => ValueKind::I64,
        Value::Bool(_) => ValueKind::Bool,
        Value::String(_) | Value::Unit => ValueKind::Unsupported,
    }
}

fn is_pure_bytecode(bytecode: &BytecodeProgram) -> bool {
    bytecode.functions.iter().all(|function| {
        function.effects.is_empty()
            && function
                .instructions
                .iter()
                .all(|instruction| !matches!(instruction, Instruction::Request { .. }))
    })
}

fn matches_tool_guardian_policy(bundle: &ToolBundle, candidate: &GuardianCandidate) -> bool {
    let required_roles = std::collections::BTreeSet::from([
        GuardianRole::SemanticVerifier,
        GuardianRole::TestGuardian,
        GuardianRole::PolicyGatekeeper,
    ]);
    let expected_guardians = std::collections::BTreeMap::from([
        ("semantic-verifier", GuardianRole::SemanticVerifier),
        ("test-verifier", GuardianRole::TestGuardian),
        ("policy-verifier", GuardianRole::PolicyGatekeeper),
    ]);
    if candidate.schema != "joan.guardian-candidate.v0"
        || candidate.candidate_root != bundle.bundle_digest
        || candidate.proposer_id != TOOL_GENERATOR_ID
        || candidate.required_roles != required_roles
        || candidate.approval_threshold != 3
        || candidate.votes.len() != expected_guardians.len()
    {
        return false;
    }

    let actual_guardians = candidate
        .votes
        .iter()
        .map(|vote| (vote.guardian_id.as_str(), vote.role.clone()))
        .collect::<std::collections::BTreeMap<_, _>>();
    actual_guardians == expected_guardians
        && candidate.votes.iter().all(|vote| {
            vote.candidate_root == bundle.bundle_digest
                && vote.evidence.len() == 2
                && vote.evidence.contains(&bundle.source_digest)
                && vote.evidence.contains(&bundle.bytecode_digest)
        })
}

fn verify_bundle_bytecode(bundle: &ToolBundle, findings: &mut Vec<ToolFinding>) -> bool {
    let bytecode_verified = if let Ok(receipt) = verify_bytecode(&bundle.bytecode) {
        if receipt.bytecode_digest != bundle.bytecode_digest {
            findings.push(finding("TF1006", "bytecode digest mismatch"));
        }
        true
    } else {
        findings.push(finding("TF1007", "standalone bytecode verification failed"));
        false
    };
    if !is_pure_bytecode(&bundle.bytecode) {
        findings.push(finding(
            "TF1008",
            "bundle contains an effect-capable instruction or row",
        ));
    }
    bytecode_verified
}

fn digest_bundle(bundle: &ToolBundle) -> Result<Digest, ToolForgeError> {
    Ok(digest_serializable_v1(
        RegisteredDomainV1::ToolBundle,
        &BundleCore {
            schema: &bundle.schema,
            spec_digest: &bundle.spec_digest,
            source: &bundle.source,
            source_digest: &bundle.source_digest,
            bytecode: &bundle.bytecode,
            bytecode_digest: &bundle.bytecode_digest,
            generation_passes: bundle.generation_passes,
        },
    )?)
}

fn encode_jce1<T: Serialize>(value: &T) -> Result<Vec<u8>, ToolForgeError> {
    let canonical = from_serializable_v1(value)?;
    Ok(to_canonical_bytes_v1(&canonical)?)
}

fn finding(code: &str, message: &str) -> ToolFinding {
    ToolFinding {
        code: code.to_owned(),
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use joan_guardian::{GuardianVote, VoteDecision};
    use std::collections::BTreeSet;

    fn add_spec() -> ToolSpec {
        ToolSpec {
            schema: TOOL_SPEC_SCHEMA.to_owned(),
            name: "add_cost".to_owned(),
            tenant: "agent_alpha".to_owned(),
            purpose: "costing".to_owned(),
            instruction_budget: 64,
            operation: ToolOperation::AddI64,
            tests: vec![
                ToolTestCase {
                    name: "positive".to_owned(),
                    arguments: vec![Value::I64(20), Value::I64(22)],
                    expected: Value::I64(42),
                },
                ToolTestCase {
                    name: "negative".to_owned(),
                    arguments: vec![Value::I64(-5), Value::I64(2)],
                    expected: Value::I64(-3),
                },
            ],
        }
    }

    fn guardian_candidate(bundle: &ToolBundle) -> GuardianCandidate {
        let evidence = vec![bundle.source_digest.clone(), bundle.bytecode_digest.clone()];
        let vote = |id: &str, role: GuardianRole| GuardianVote {
            guardian_id: id.to_owned(),
            role,
            candidate_root: bundle.bundle_digest.clone(),
            decision: VoteDecision::Approve,
            evidence: evidence.clone(),
        };
        GuardianCandidate {
            schema: "joan.guardian-candidate.v0".to_owned(),
            candidate_root: bundle.bundle_digest.clone(),
            proposer_id: "tool-generator".to_owned(),
            required_roles: BTreeSet::from([
                GuardianRole::SemanticVerifier,
                GuardianRole::TestGuardian,
                GuardianRole::PolicyGatekeeper,
            ]),
            approval_threshold: 3,
            votes: vec![
                vote("semantic-verifier", GuardianRole::SemanticVerifier),
                vote("test-verifier", GuardianRole::TestGuardian),
                vote("policy-verifier", GuardianRole::PolicyGatekeeper),
            ],
        }
    }

    #[test]
    fn full_pure_pipeline_is_deterministic_and_eligible() -> Result<(), Box<dyn std::error::Error>>
    {
        let spec = add_spec();
        assert_eq!(verify_spec(&spec)?.status, VerificationStatus::Verified);
        let first = forge_tool(&spec)?;
        let second = forge_tool(&spec)?;
        assert_eq!(encode_jce1(&first)?, encode_jce1(&second)?);
        assert!(first.source.contains("effects [] authorities []"));
        assert!(is_pure_bytecode(&first.bytecode));
        let verification = verify_tool(&spec, &first)?;
        assert_eq!(verification.status, VerificationStatus::Verified);
        assert_eq!(verification.tests_passed, 2);
        assert!(!verification.external_effects_executed);
        let candidate = guardian_candidate(&first);
        let finalization = finalize_tool(&spec, &first, &verification, &candidate)?;
        assert_eq!(finalization.status, FinalizationStatus::Finalized);
        let promotion =
            evaluate_promotion(&spec, &first, &verification, &candidate, &finalization)?;
        assert_eq!(promotion.status, PromotionStatus::Eligible);
        Ok(())
    }

    #[test]
    fn missing_tests_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let mut spec = add_spec();
        spec.tests.clear();
        let receipt = verify_spec(&spec)?;
        assert_eq!(receipt.status, VerificationStatus::Rejected);
        assert!(receipt.findings.iter().any(|item| item.code == "TF0006"));
        assert!(forge_tool(&spec).is_err());
        Ok(())
    }

    #[test]
    fn altered_bundle_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let spec = add_spec();
        let mut bundle = forge_tool(&spec)?;
        bundle.source.push(' ');
        let receipt = verify_tool(&spec, &bundle)?;
        assert_eq!(receipt.status, VerificationStatus::Rejected);
        assert!(!receipt.findings.is_empty());
        Ok(())
    }

    #[test]
    fn forged_verification_cannot_finalize() -> Result<(), Box<dyn std::error::Error>> {
        let spec = add_spec();
        let bundle = forge_tool(&spec)?;
        let mut forged = verify_tool(&spec, &bundle)?;
        forged.tests_passed = 0;
        let candidate = guardian_candidate(&bundle);
        let finalization = finalize_tool(&spec, &bundle, &forged, &candidate)?;
        assert_eq!(finalization.status, FinalizationStatus::Quarantined);
        assert!(
            finalization
                .findings
                .iter()
                .any(|item| item.code == "TF2002")
        );
        Ok(())
    }

    #[test]
    fn fabricated_finalization_cannot_promote() -> Result<(), Box<dyn std::error::Error>> {
        let spec = add_spec();
        let bundle = forge_tool(&spec)?;
        let verification = verify_tool(&spec, &bundle)?;
        let candidate = guardian_candidate(&bundle);
        let mut fabricated = finalize_tool(&spec, &bundle, &verification, &candidate)?;
        fabricated.receipt_digest = verification.receipt_digest.clone();
        let promotion = evaluate_promotion(&spec, &bundle, &verification, &candidate, &fabricated)?;
        assert_eq!(promotion.status, PromotionStatus::Quarantined);
        Ok(())
    }

    #[test]
    fn oversized_spec_does_not_execute_tests() -> Result<(), Box<dyn std::error::Error>> {
        let valid_spec = add_spec();
        let bundle = forge_tool(&valid_spec)?;
        let mut oversized = valid_spec;
        let template = oversized.tests.first().cloned().ok_or("missing test")?;
        while oversized.tests.len() <= MAX_TEST_CASES {
            let mut next = template.clone();
            next.name = format!("case_{}", oversized.tests.len());
            oversized.tests.push(next);
        }
        let receipt = verify_tool(&oversized, &bundle)?;
        assert_eq!(receipt.status, VerificationStatus::Rejected);
        assert_eq!(receipt.tests_passed, 0);
        assert!(receipt.findings.iter().any(|item| item.code == "TF0006"));
        Ok(())
    }

    #[test]
    fn caller_cannot_lower_guardian_quorum() -> Result<(), Box<dyn std::error::Error>> {
        let spec = add_spec();
        let bundle = forge_tool(&spec)?;
        let verification = verify_tool(&spec, &bundle)?;
        let mut candidate = guardian_candidate(&bundle);
        candidate.approval_threshold = 1;
        candidate.required_roles = BTreeSet::from([GuardianRole::SemanticVerifier]);
        candidate.votes.truncate(1);
        let finalization = finalize_tool(&spec, &bundle, &verification, &candidate)?;
        assert_eq!(finalization.status, FinalizationStatus::Quarantined);
        assert!(
            finalization
                .findings
                .iter()
                .any(|item| item.code == "TF2006")
        );
        Ok(())
    }

    #[test]
    fn false_test_expectation_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let mut spec = add_spec();
        let test = spec.tests.get_mut(0).ok_or("missing test")?;
        test.expected = Value::I64(41);
        let bundle = forge_tool(&spec)?;
        let receipt = verify_tool(&spec, &bundle)?;
        assert_eq!(receipt.status, VerificationStatus::Rejected);
        assert!(receipt.findings.iter().any(|item| item.code == "TF1011"));
        Ok(())
    }

    #[test]
    fn generator_cannot_self_approve() -> Result<(), Box<dyn std::error::Error>> {
        let spec = add_spec();
        let bundle = forge_tool(&spec)?;
        let verification = verify_tool(&spec, &bundle)?;
        let mut candidate = guardian_candidate(&bundle);
        candidate.proposer_id = "semantic-verifier".to_owned();
        let finalization = finalize_tool(&spec, &bundle, &verification, &candidate)?;
        assert_eq!(finalization.status, FinalizationStatus::Quarantined);
        assert!(
            finalization
                .findings
                .iter()
                .any(|item| item.code == "TF2006")
        );
        assert_eq!(
            evaluate_promotion(&spec, &bundle, &verification, &candidate, &finalization)?.status,
            PromotionStatus::Quarantined
        );
        Ok(())
    }

    #[test]
    fn pending_guardian_keeps_bundle_quarantined() -> Result<(), Box<dyn std::error::Error>> {
        let spec = add_spec();
        let bundle = forge_tool(&spec)?;
        let verification = verify_tool(&spec, &bundle)?;
        let mut candidate = guardian_candidate(&bundle);
        candidate.votes.truncate(1);
        let finalization = finalize_tool(&spec, &bundle, &verification, &candidate)?;
        assert_eq!(finalization.status, FinalizationStatus::Quarantined);
        Ok(())
    }
}
