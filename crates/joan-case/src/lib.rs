//! Atomic, content-addressed dispute-case state transitions.

use joan_canonical::{CanonicalError, Digest, digest_serializable};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

const MAX_IDEMPOTENCY_KEYS: usize = 10_000;

/// States in the autonomous dispute lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaseState {
    /// A party submitted a claim.
    Submitted,
    /// The machine intake gate is validating eligibility.
    IntakeValidation,
    /// The case is not eligible for this policy.
    RejectedOutOfScope,
    /// Deterministic validation requires a bounded correction.
    AwaitingCure,
    /// The case passed intake.
    Accepted,
    /// Evidence and economic state are under preservation hold.
    PreservationHold,
    /// Machine-readable notice was emitted.
    NoticeServed,
    /// The response deadline is active.
    ResponseWindow,
    /// Evidence can be submitted.
    EvidenceCollection,
    /// The evidence graph is immutable for this decision round.
    EvidenceLocked,
    /// Deterministic predicates are being evaluated.
    DeterministicEvaluation,
    /// A bounded automatic settlement was offered.
    AutomatedSettlementOffered,
    /// Both agents accepted the automatic settlement.
    SettledByAgreement,
    /// A machine-adjudicator quorum was assigned.
    ReviewAssigned,
    /// The primary machine quorum emitted a proposal.
    ProposedDecision,
    /// A bounded challenge window is active.
    ChallengeWindow,
    /// A primary decision is final subject to the selected profile.
    FinalDecision,
    /// A machine appeal can still be filed.
    AppealWindow,
    /// A disjoint appeal quorum is evaluating the case.
    Appealed,
    /// The automatic appeal decision is final.
    AppealDecision,
    /// A repair must be performed before settlement.
    RepairPending,
    /// Repair evidence is being checked.
    Reverification,
    /// A remedy instruction is being applied to a mock or external adapter.
    RemedyExecution,
    /// Local intent is being reconciled with adapter truth.
    ExecutionReconciliation,
    /// Policy froze the case under its precommitted fallback.
    Quarantined,
    /// A deadline expired according to policy.
    Expired,
    /// The case reached a terminal portable state.
    Closed,
}

/// Inputs required to create one submitted dispute case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewCase {
    /// Schema identifier.
    pub schema: String,
    /// Stable case identifier.
    pub case_id: String,
    /// Exact service-contract digest.
    pub contract_digest: Digest,
    /// Exact transaction-cylinder digest.
    pub transaction_digest: Digest,
    /// Claiming machine or principal identity.
    pub claimant_id: String,
    /// Responding machine or principal identity.
    pub respondent_id: String,
    /// Exact automatic-finality policy digest.
    pub policy_digest: Digest,
    /// Maximum value controlled by this case.
    pub value_microunits: u64,
}

/// Immutable-at-each-revision dispute case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisputeCase {
    /// Schema identifier.
    pub schema: String,
    /// Stable case identifier.
    pub case_id: String,
    /// Exact service-contract digest.
    pub contract_digest: Digest,
    /// Exact transaction-cylinder digest.
    pub transaction_digest: Digest,
    /// Claiming machine or principal identity.
    pub claimant_id: String,
    /// Responding machine or principal identity.
    pub respondent_id: String,
    /// Exact automatic-finality policy digest.
    pub policy_digest: Digest,
    /// Maximum value controlled by this case.
    pub value_microunits: u64,
    /// Current deterministic state.
    pub state: CaseState,
    /// Monotonic transition revision.
    pub revision: u64,
    /// Consumed transition keys preventing replay.
    pub consumed_idempotency_keys: BTreeSet<String>,
    /// Digest of every field above.
    pub case_digest: Digest,
}

/// One requested atomic case transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseTransition {
    /// Schema identifier.
    pub schema: String,
    /// Exact case digest expected by the caller.
    pub expected_case_digest: Digest,
    /// Exact revision expected by the caller.
    pub expected_revision: u64,
    /// Expected current state.
    pub from: CaseState,
    /// Requested next state.
    pub to: CaseState,
    /// Authorized logical actor performing the transition.
    pub actor_id: String,
    /// Reference to the external authority/policy decision.
    pub authority_ref: Digest,
    /// Consume-once transition key.
    pub idempotency_key: String,
    /// Stable reason code, not free-form model reasoning.
    pub reason_code: String,
    /// Evidence roots supporting the transition.
    pub evidence_refs: Vec<Digest>,
}

/// Receipt proving one committed case transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseTransitionReceipt {
    /// Schema identifier.
    pub schema: String,
    /// Stable case identifier.
    pub case_id: String,
    /// Prior exact case digest.
    pub prior_case_digest: Digest,
    /// New exact case digest.
    pub new_case_digest: Digest,
    /// New monotonic revision.
    pub revision: u64,
    /// Prior state.
    pub from: CaseState,
    /// New state.
    pub to: CaseState,
    /// Transition actor.
    pub actor_id: String,
    /// Stable reason code.
    pub reason_code: String,
    /// Digest of the complete transition request.
    pub transition_digest: Digest,
    /// True only after the isolated copy passed every gate.
    pub committed: bool,
}

/// Case validation or transition failure.
#[derive(Debug, Error)]
pub enum CaseError {
    /// Canonical encoding or hashing failed.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    /// An unsupported schema was supplied.
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(String),
    /// A required string identity or code was empty.
    #[error("required field is empty: {0}")]
    EmptyField(&'static str),
    /// Claimant and respondent cannot be the same identity.
    #[error("claimant and respondent identities must differ")]
    SameParty,
    /// Value must be non-zero for this Genesis profile.
    #[error("case value must be greater than zero")]
    ZeroValue,
    /// Stored case digest does not match its fields.
    #[error("stored case digest is invalid")]
    InvalidStoredDigest,
    /// Caller precondition did not match the current case digest.
    #[error("expected case digest does not match")]
    StaleCaseDigest,
    /// Caller precondition did not match the current revision.
    #[error("expected revision does not match")]
    StaleRevision,
    /// Caller precondition did not match the current state.
    #[error("expected state does not match")]
    StaleState,
    /// The lifecycle does not permit this transition.
    #[error("illegal case transition")]
    IllegalTransition,
    /// The transition idempotency key was already consumed.
    #[error("transition idempotency key was already consumed")]
    Replay,
    /// The bounded consume-once set is exhausted.
    #[error("case idempotency capacity exhausted")]
    IdempotencyCapacity,
    /// Monotonic revision overflowed.
    #[error("case revision overflow")]
    RevisionOverflow,
}

#[derive(Serialize)]
struct CaseCore<'a> {
    schema: &'a str,
    case_id: &'a str,
    contract_digest: &'a Digest,
    transaction_digest: &'a Digest,
    claimant_id: &'a str,
    respondent_id: &'a str,
    policy_digest: &'a Digest,
    value_microunits: u64,
    state: CaseState,
    revision: u64,
    consumed_idempotency_keys: &'a BTreeSet<String>,
}

/// Create a content-addressed case in `submitted` state.
pub fn create_case(input: &NewCase) -> Result<DisputeCase, CaseError> {
    if input.schema != "joan.new-dispute-case.v0" {
        return Err(CaseError::UnsupportedSchema(input.schema.clone()));
    }
    require_nonempty(&input.case_id, "case_id")?;
    require_nonempty(&input.claimant_id, "claimant_id")?;
    require_nonempty(&input.respondent_id, "respondent_id")?;
    if input.claimant_id == input.respondent_id {
        return Err(CaseError::SameParty);
    }
    if input.value_microunits == 0 {
        return Err(CaseError::ZeroValue);
    }
    let mut case = DisputeCase {
        schema: "joan.dispute-case.v0".to_owned(),
        case_id: input.case_id.clone(),
        contract_digest: input.contract_digest.clone(),
        transaction_digest: input.transaction_digest.clone(),
        claimant_id: input.claimant_id.clone(),
        respondent_id: input.respondent_id.clone(),
        policy_digest: input.policy_digest.clone(),
        value_microunits: input.value_microunits,
        state: CaseState::Submitted,
        revision: 0,
        consumed_idempotency_keys: BTreeSet::new(),
        case_digest: placeholder_digest(),
    };
    case.case_digest = compute_case_digest(&case)?;
    Ok(case)
}

/// Verify that the stored case digest matches every protected field.
pub fn verify_case(case: &DisputeCase) -> Result<(), CaseError> {
    if case.schema != "joan.dispute-case.v0" {
        return Err(CaseError::UnsupportedSchema(case.schema.clone()));
    }
    if compute_case_digest(case)? != case.case_digest {
        return Err(CaseError::InvalidStoredDigest);
    }
    Ok(())
}

/// Apply one legal transition to an isolated clone and emit a receipt.
pub fn transition_case(
    case: &DisputeCase,
    transition: &CaseTransition,
) -> Result<(DisputeCase, CaseTransitionReceipt), CaseError> {
    verify_case(case)?;
    if transition.schema != "joan.case-transition.v0" {
        return Err(CaseError::UnsupportedSchema(transition.schema.clone()));
    }
    require_nonempty(&transition.actor_id, "actor_id")?;
    require_nonempty(&transition.idempotency_key, "idempotency_key")?;
    require_nonempty(&transition.reason_code, "reason_code")?;
    if transition.expected_case_digest != case.case_digest {
        return Err(CaseError::StaleCaseDigest);
    }
    if transition.expected_revision != case.revision {
        return Err(CaseError::StaleRevision);
    }
    if transition.from != case.state {
        return Err(CaseError::StaleState);
    }
    if !is_allowed(transition.from, transition.to) {
        return Err(CaseError::IllegalTransition);
    }
    if case
        .consumed_idempotency_keys
        .contains(&transition.idempotency_key)
    {
        return Err(CaseError::Replay);
    }
    if case.consumed_idempotency_keys.len() >= MAX_IDEMPOTENCY_KEYS {
        return Err(CaseError::IdempotencyCapacity);
    }

    let prior_case_digest = case.case_digest.clone();
    let mut candidate = case.clone();
    candidate
        .consumed_idempotency_keys
        .insert(transition.idempotency_key.clone());
    candidate.state = transition.to;
    candidate.revision = candidate
        .revision
        .checked_add(1)
        .ok_or(CaseError::RevisionOverflow)?;
    candidate.case_digest = compute_case_digest(&candidate)?;
    let receipt = CaseTransitionReceipt {
        schema: "joan.case-transition-receipt.v0".to_owned(),
        case_id: case.case_id.clone(),
        prior_case_digest,
        new_case_digest: candidate.case_digest.clone(),
        revision: candidate.revision,
        from: transition.from,
        to: transition.to,
        actor_id: transition.actor_id.clone(),
        reason_code: transition.reason_code.clone(),
        transition_digest: digest_serializable("joan.case-transition.v0", transition)?,
        committed: true,
    };
    Ok((candidate, receipt))
}

fn compute_case_digest(case: &DisputeCase) -> Result<Digest, CanonicalError> {
    digest_serializable(
        "joan.dispute-case.v0",
        &CaseCore {
            schema: &case.schema,
            case_id: &case.case_id,
            contract_digest: &case.contract_digest,
            transaction_digest: &case.transaction_digest,
            claimant_id: &case.claimant_id,
            respondent_id: &case.respondent_id,
            policy_digest: &case.policy_digest,
            value_microunits: case.value_microunits,
            state: case.state,
            revision: case.revision,
            consumed_idempotency_keys: &case.consumed_idempotency_keys,
        },
    )
}

fn require_nonempty(value: &str, field: &'static str) -> Result<(), CaseError> {
    if value.trim().is_empty() {
        Err(CaseError::EmptyField(field))
    } else {
        Ok(())
    }
}

fn placeholder_digest() -> Digest {
    Digest {
        algorithm: String::new(),
        profile: String::new(),
        domain: String::new(),
        value: String::new(),
    }
}

fn is_allowed(from: CaseState, to: CaseState) -> bool {
    use CaseState::{
        Accepted, AppealDecision, AppealWindow, Appealed, AutomatedSettlementOffered, AwaitingCure,
        ChallengeWindow, Closed, DeterministicEvaluation, EvidenceCollection, EvidenceLocked,
        ExecutionReconciliation, Expired, FinalDecision, IntakeValidation, NoticeServed,
        PreservationHold, ProposedDecision, Quarantined, RejectedOutOfScope, RemedyExecution,
        RepairPending, ResponseWindow, Reverification, ReviewAssigned, SettledByAgreement,
        Submitted,
    };
    matches!(
        (from, to),
        (Submitted, IntakeValidation)
            | (
                IntakeValidation,
                RejectedOutOfScope | AwaitingCure | Accepted
            )
            | (AwaitingCure, IntakeValidation | Expired)
            | (Accepted, PreservationHold)
            | (PreservationHold, NoticeServed)
            | (NoticeServed, ResponseWindow)
            | (ResponseWindow, EvidenceCollection | Expired)
            | (EvidenceCollection | Reverification, EvidenceLocked)
            | (EvidenceLocked, DeterministicEvaluation)
            | (
                DeterministicEvaluation,
                AutomatedSettlementOffered | ReviewAssigned | FinalDecision | Quarantined
            )
            | (
                AutomatedSettlementOffered,
                SettledByAgreement | ReviewAssigned
            )
            | (SettledByAgreement | Quarantined, RemedyExecution)
            | (ReviewAssigned, ProposedDecision | Quarantined)
            | (ProposedDecision, ChallengeWindow | FinalDecision)
            | (ChallengeWindow, FinalDecision | Appealed)
            | (
                FinalDecision,
                AppealWindow | RemedyExecution | RepairPending
            )
            | (AppealWindow, Appealed | RemedyExecution)
            | (Appealed, AppealDecision)
            | (
                AppealDecision,
                RemedyExecution | RepairPending | Quarantined
            )
            | (RepairPending, Reverification)
            | (RemedyExecution, ExecutionReconciliation)
            | (ExecutionReconciliation, RemedyExecution | Closed)
    )
}
