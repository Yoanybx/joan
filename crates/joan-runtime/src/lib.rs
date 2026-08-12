//! Effect planning with external authority and atomic one-use approval consumption.

use joan_canonical::{
    CanonicalError, Digest, Jce1Error, RegisteredDomainV1, digest_serializable,
    digest_serializable_v1,
};
use joan_compiler::{ExecutionReceipt, Value};
use joan_identity::{IdentityError, verify_canonical_ast_identity_descriptor};
use joan_instruction::{
    AuthorityEnvelope, InstructionDecision, InstructionError, InstructionRequest,
    resolve_instructions,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

/// In-process one-use approval ledger.
///
/// The caller is responsible for durable, transactional persistence before any
/// real effect executor is enabled.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapabilityLedger {
    consumed_nonces: BTreeSet<String>,
}

impl CapabilityLedger {
    /// Test whether one approval nonce has already been consumed.
    #[must_use]
    pub fn is_consumed(&self, nonce: &str) -> bool {
        self.consumed_nonces.contains(nonce)
    }

    /// Number of consumed approvals.
    #[must_use]
    pub fn len(&self) -> usize {
        self.consumed_nonces.len()
    }

    /// Whether no approval has been consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.consumed_nonces.is_empty()
    }
}

/// One authorized effect plan. This is still data and performs no I/O.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedEffect {
    /// Program-bound one-use request identity.
    pub request_id: String,
    /// Zero-based request sequence.
    pub request_index: u64,
    /// Function that emitted the request.
    pub function: String,
    /// Atomic capability/effect name.
    pub effect: String,
    /// Source authority slot moved into this request, when linear.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_slot: Option<String>,
    /// Deterministically evaluated arguments.
    pub arguments: Vec<Value>,
    /// Exact consumed approval nonce.
    pub approval_nonce: String,
}

/// Atomic plan receipt produced before any external executor is invoked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectPlanReceipt {
    /// Receipt schema.
    pub schema: String,
    /// `pure` or `authorized`.
    pub status: String,
    /// Program semantic identity.
    pub semantic_digest: Digest,
    /// External authority identity, absent for pure programs.
    pub authority_envelope_digest: Option<Digest>,
    /// Fully authorized effects in execution order.
    pub effects: Vec<PlannedEffect>,
    /// Digest binding all preceding plan fields.
    pub plan_digest: Digest,
}

/// Effect-plan rejection.
#[derive(Debug, Error)]
pub enum RuntimePlanError {
    /// Canonical identity failed.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    /// Typed JCE1 request identity failed.
    #[error(transparent)]
    Jce1(#[from] Jce1Error),
    /// Semantic identity descriptor failed validation.
    #[error(transparent)]
    Identity(#[from] IdentityError),
    /// Authority attenuation failed.
    #[error(transparent)]
    Instruction(#[from] InstructionError),
    /// Authority task identity is not the exact program identity.
    #[error("authority task_id must equal the program semantic digest")]
    TaskMismatch,
    /// Execution receipt mixes or degrades legacy and linear authority profiles.
    #[error("execution receipt has an inconsistent authority profile")]
    ProfileMismatch,
    /// Authority resolver did not authorize the requested effect set.
    #[error("authority decision did not allow every requested effect")]
    AuthorityDenied,
    /// Effect request identities are malformed or repeated.
    #[error("invalid or duplicate effect request identity: {0}")]
    InvalidRequest(String),
    /// No exact one-use approval exists for one request.
    #[error("missing exact one-use approval for request {0}")]
    MissingApproval(String),
    /// An approval was already consumed.
    #[error("approval nonce was already consumed: {0}")]
    Replay(String),
}

#[derive(Serialize)]
struct EffectPlanCore<'a> {
    status: &'a str,
    semantic_digest: &'a Digest,
    authority_envelope_digest: &'a Option<Digest>,
    effects: &'a [PlannedEffect],
}

#[derive(Serialize)]
struct LinearEffectRequestCore<'a> {
    semantic_digest: &'a Digest,
    request_index: u64,
    function: &'a str,
    effect: &'a str,
    authority_slot: &'a str,
    arguments: &'a [Value],
}

/// Validate all effect authority and atomically consume exact one-use approvals.
///
/// This function performs no host effect. On any error, `ledger` is unchanged.
pub fn plan_effects(
    execution: &ExecutionReceipt,
    authority: Option<&AuthorityEnvelope>,
    ledger: &mut CapabilityLedger,
) -> Result<EffectPlanReceipt, RuntimePlanError> {
    validate_execution_profile(execution)?;
    if execution.effect_requests.is_empty() {
        return build_receipt(execution, None, Vec::new());
    }
    let authority = authority.ok_or(RuntimePlanError::AuthorityDenied)?;
    if authority.task_id != execution.semantic_digest.value {
        return Err(RuntimePlanError::TaskMismatch);
    }

    let requested_effects = execution
        .effect_requests
        .iter()
        .map(|request| request.effect.clone())
        .collect::<BTreeSet<_>>();
    let decision = resolve_instructions(&InstructionRequest {
        schema: "joan.instruction-request.v0".to_owned(),
        authority: authority.clone(),
        instructions: Vec::new(),
        requested_effects,
    })?;
    if decision.decision != InstructionDecision::Allow {
        return Err(RuntimePlanError::AuthorityDenied);
    }

    let mut pending_nonces = BTreeSet::new();
    let mut planned = Vec::with_capacity(execution.effect_requests.len());
    for (position, request) in execution.effect_requests.iter().enumerate() {
        let expected_index = u64::try_from(position)
            .map_err(|_| RuntimePlanError::InvalidRequest(request.request_id.clone()))?;
        let expected_id = derive_request_id(execution, request)?;
        if request.request_index != expected_index
            || request.request_id != expected_id
            || !pending_nonces.insert(request.request_id.clone())
        {
            return Err(RuntimePlanError::InvalidRequest(request.request_id.clone()));
        }
        if ledger.is_consumed(&request.request_id) {
            return Err(RuntimePlanError::Replay(request.request_id.clone()));
        }
        let exact_count = authority
            .approvals
            .iter()
            .filter(|approval| {
                approval.nonce == request.request_id
                    && approval.task_id == authority.task_id
                    && approval.capabilities.len() == 1
                    && approval.capabilities.contains(&request.effect)
                    && approval.authority_slot == request.authority_slot
            })
            .count();
        if exact_count != 1 {
            return Err(RuntimePlanError::MissingApproval(
                request.request_id.clone(),
            ));
        }
        planned.push(PlannedEffect {
            request_id: request.request_id.clone(),
            request_index: request.request_index,
            function: request.function.clone(),
            effect: request.effect.clone(),
            authority_slot: request.authority_slot.clone(),
            arguments: request.arguments.clone(),
            approval_nonce: request.request_id.clone(),
        });
    }

    let authority_digest = Some(digest_serializable(
        "joan.authority-envelope.v0",
        authority,
    )?);
    let receipt = build_receipt(execution, authority_digest, planned)?;
    ledger.consumed_nonces.extend(pending_nonces);
    Ok(receipt)
}

fn derive_request_id(
    execution: &ExecutionReceipt,
    request: &joan_compiler::EffectRequest,
) -> Result<String, RuntimePlanError> {
    if execution.schema == "joan.execution-receipt.v2" {
        let authority_slot = request
            .authority_slot
            .as_deref()
            .ok_or(RuntimePlanError::ProfileMismatch)?;
        Ok(digest_serializable_v1(
            RegisteredDomainV1::EffectApplication,
            &LinearEffectRequestCore {
                semantic_digest: &execution.semantic_digest,
                request_index: request.request_index,
                function: &request.function,
                effect: &request.effect,
                authority_slot,
                arguments: &request.arguments,
            },
        )?
        .value)
    } else {
        Ok(format!(
            "{}:{:016x}",
            execution.semantic_digest.value, request.request_index
        ))
    }
}

fn validate_execution_profile(execution: &ExecutionReceipt) -> Result<(), RuntimePlanError> {
    verify_canonical_ast_identity_descriptor(&execution.semantic_identity)?;
    if execution.semantic_digest != execution.semantic_identity.digest {
        return Err(RuntimePlanError::ProfileMismatch);
    }
    let legacy = execution.status == "completed"
        && execution.schema == "joan.execution-receipt.v1"
        && execution.semantic_identity.schema == "joan.canonical-ast-identity.v0"
        && execution.semantic_identity.ast_schema == "joan.canonical-ast.v0"
        && execution.semantic_digest.domain == "joan.language-canonical-ast.v1"
        && valid_bytecode_digest(&execution.bytecode_digest, "joan.bytecode-program.v1")
        && execution
            .effect_requests
            .iter()
            .all(|request| request.authority_slot.is_none());
    let linear = execution.status == "completed"
        && execution.schema == "joan.execution-receipt.v2"
        && execution.semantic_identity.schema == "joan.canonical-ast-identity.v1"
        && execution.semantic_identity.ast_schema == "joan.canonical-ast.v1"
        && execution.semantic_digest.domain == "joan.language-canonical-ast.v2"
        && valid_bytecode_digest(&execution.bytecode_digest, "joan.bytecode-program.v2")
        && execution
            .effect_requests
            .iter()
            .all(|request| request.authority_slot.is_some());
    if legacy || linear {
        Ok(())
    } else {
        Err(RuntimePlanError::ProfileMismatch)
    }
}

fn valid_bytecode_digest(digest: &Digest, domain: &str) -> bool {
    digest.algorithm == "sha256"
        && digest.profile == "joan-hash-v1"
        && digest.domain == domain
        && digest.value.len() == 64
        && digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn build_receipt(
    execution: &ExecutionReceipt,
    authority_envelope_digest: Option<Digest>,
    effects: Vec<PlannedEffect>,
) -> Result<EffectPlanReceipt, RuntimePlanError> {
    let status = if effects.is_empty() {
        "pure".to_owned()
    } else {
        "authorized".to_owned()
    };
    let plan_digest = digest_serializable(
        "joan.effect-plan-receipt.v0",
        &EffectPlanCore {
            status: &status,
            semantic_digest: &execution.semantic_digest,
            authority_envelope_digest: &authority_envelope_digest,
            effects: &effects,
        },
    )?;
    Ok(EffectPlanReceipt {
        schema: "joan.effect-plan-receipt.v0".to_owned(),
        status,
        semantic_digest: execution.semantic_digest.clone(),
        authority_envelope_digest,
        effects,
        plan_digest,
    })
}
