//! Effect planning with external authority and atomic one-use approval consumption.

use joan_canonical::{CanonicalError, Digest, digest_serializable};
use joan_compiler::{ExecutionReceipt, Value};
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
    /// Authority attenuation failed.
    #[error(transparent)]
    Instruction(#[from] InstructionError),
    /// Authority task identity is not the exact program identity.
    #[error("authority task_id must equal the program semantic digest")]
    TaskMismatch,
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

/// Validate all effect authority and atomically consume exact one-use approvals.
///
/// This function performs no host effect. On any error, `ledger` is unchanged.
pub fn plan_effects(
    execution: &ExecutionReceipt,
    authority: Option<&AuthorityEnvelope>,
    ledger: &mut CapabilityLedger,
) -> Result<EffectPlanReceipt, RuntimePlanError> {
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
    for request in &execution.effect_requests {
        let expected_id = format!(
            "{}:{:016x}",
            execution.semantic_digest.value, request.request_index
        );
        if request.request_id != expected_id || !pending_nonces.insert(request.request_id.clone()) {
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
