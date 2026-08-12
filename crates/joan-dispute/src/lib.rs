//! Deterministic, machine-only dispute adjudication with precommitted fallbacks.

use joan_canonical::{CanonicalError, Digest, digest_serializable};
use joan_case::{CaseState, DisputeCase, verify_case};
use joan_evidence::{EvidenceGraph, EvidenceVerification, verify_evidence_graph};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

/// Objective claim classes supported by JDR1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimCode {
    /// Provider did not deliver the contracted artifact/result.
    NonDelivery,
    /// Delivered result failed precommitted acceptance criteria.
    AcceptanceFailure,
    /// The same economic instruction was charged more than once.
    DuplicateCharge,
    /// Measured charge exceeded the authorized budget or quote.
    BudgetExceeded,
    /// Execution exceeded the granted scope.
    UnauthorizedScope,
    /// Local and settlement-adapter truth disagree.
    SettlementMismatch,
    /// A required repair failed re-verification.
    RepairFailure,
}

/// Remedy classes that can be authorized before execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RemedyKind {
    /// Return the full held value to the buyer.
    FullRefund,
    /// Release the full held value to the provider.
    ReleaseProvider,
    /// Split value using the profile's exact basis points.
    Split,
    /// Keep value held while a bounded repair executes.
    Repair,
    /// Freeze value under the policy's safety fallback.
    Quarantine,
}

/// Automatic result used only when the machine quorum cannot resolve a claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum AmbiguityFallback {
    /// Refund all held value.
    FullRefund,
    /// Release all held value to the provider.
    ReleaseProvider,
    /// Split held value by exact buyer-refund basis points.
    Split {
        /// Buyer refund from 0 through 10,000 basis points.
        buyer_refund_bps: u16,
    },
    /// Require repair while retaining held value.
    Repair,
    /// Freeze value and close this automatic profile as out of scope.
    Quarantine,
}

/// Precommitted machine-only finality profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomaticResolutionProfile {
    /// Schema identifier.
    pub schema: String,
    /// Exact policy digest bound into the case.
    pub policy_digest: Digest,
    /// Claim codes eligible for automatic resolution.
    pub eligible_claim_codes: BTreeSet<ClaimCode>,
    /// Remedies that can be emitted.
    pub allowed_remedies: BTreeSet<RemedyKind>,
    /// Maximum case value for this profile.
    pub max_value_microunits: u64,
    /// Primary machine-adjudicator identities.
    pub primary_adjudicators: BTreeSet<String>,
    /// Independent appeal machine-adjudicator identities.
    pub appeal_adjudicators: BTreeSet<String>,
    /// Primary votes required for one side to prevail.
    pub primary_threshold: u64,
    /// Appeal votes required for one side to prevail.
    pub appeal_threshold: u64,
    /// Automatic outcome for ties, insufficient votes or contradictory quorums.
    pub ambiguity_fallback: AmbiguityFallback,
    /// Must be true; JDR1 has no runtime human-escalation path.
    pub automatic_finality: bool,
}

/// One exact claim against one case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    /// Schema identifier.
    pub schema: String,
    /// Stable claim identifier.
    pub claim_id: String,
    /// Associated case identifier.
    pub case_id: String,
    /// Claimant identity; must match the case.
    pub claimant_id: String,
    /// Objective claim code.
    pub claim_code: ClaimCode,
    /// Requested remedy when the claim is upheld.
    pub requested_remedy: RemedyKind,
    /// Evidence identifiers supporting the claim.
    pub evidence_refs: Vec<String>,
}

/// Primary or appeal adjudication phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionPhase {
    /// Initial machine-adjudicator quorum.
    Primary,
    /// Disjoint automatic appeal quorum.
    Appeal,
}

/// One machine adjudicator's bounded finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingDisposition {
    /// Verified evidence supports the claim.
    SupportsClaim,
    /// Verified evidence rejects the claim.
    RejectsClaim,
    /// Evidence is insufficient or contradictory for this adjudicator.
    Abstain,
}

/// Finding bound to exact case, evidence and policy roots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineFinding {
    /// Schema identifier.
    pub schema: String,
    /// Stable machine-adjudicator identity.
    pub adjudicator_id: String,
    /// Primary or appeal phase.
    pub phase: DecisionPhase,
    /// Exact case digest.
    pub case_digest: Digest,
    /// Exact locked evidence root.
    pub evidence_root: Digest,
    /// Exact policy digest.
    pub policy_digest: Digest,
    /// Bounded finding.
    pub disposition: FindingDisposition,
    /// Verified evidence identifiers used by this finding.
    pub evidence_refs: Vec<String>,
}

/// High-level decision result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionStatus {
    /// The claim reached the required support threshold.
    ClaimUpheld,
    /// The claim reached the required rejection threshold.
    ClaimRejected,
    /// No side prevailed and the contractual fallback was applied.
    FallbackApplied,
}

/// Exact allocation generated by the selected remedy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemedyAllocation {
    /// Remedy kind.
    pub kind: RemedyKind,
    /// Value returned to the buyer.
    pub buyer_refund_microunits: u64,
    /// Value released to the provider.
    pub provider_release_microunits: u64,
    /// Value kept locked for repair/quarantine.
    pub retained_microunits: u64,
}

/// Reproducible automatic decision receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomaticDecisionReceipt {
    /// Schema identifier.
    pub schema: String,
    /// Primary or appeal phase.
    pub phase: DecisionPhase,
    /// Exact case digest.
    pub case_digest: Digest,
    /// Exact locked evidence root.
    pub evidence_root: Digest,
    /// Exact claim digest.
    pub claim_digest: Digest,
    /// Exact profile digest.
    pub profile_digest: Digest,
    /// Prior decision replaced by an appeal, if any.
    pub supersedes: Option<Digest>,
    /// Decision result.
    pub status: DecisionStatus,
    /// Supporting vote count.
    pub support_count: u64,
    /// Rejecting vote count.
    pub reject_count: u64,
    /// Abstaining vote count.
    pub abstain_count: u64,
    /// Sorted distinct adjudicator identities.
    pub participating_adjudicators: Vec<String>,
    /// Exact remedy allocation.
    pub remedy: RemedyAllocation,
    /// Stable machine-readable reasons.
    pub reason_codes: Vec<String>,
    /// Explicit automatic finality class.
    pub finality_class: String,
    /// Digest of every receipt field above.
    pub decision_digest: Digest,
}

/// Complete offline input for primary resolution or automatic appeal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisputeEvaluationBundle {
    /// Schema identifier.
    pub schema: String,
    /// Exact case snapshot.
    pub case: DisputeCase,
    /// Exact locked evidence graph.
    pub evidence: EvidenceGraph,
    /// Claim under review.
    pub claim: Claim,
    /// Automatic-finality profile.
    pub profile: AutomaticResolutionProfile,
    /// Machine findings for the selected phase.
    pub findings: Vec<MachineFinding>,
    /// Prior primary decision when this is an appeal.
    pub prior_decision: Option<AutomaticDecisionReceipt>,
}

/// Automatic dispute evaluation failure.
#[derive(Debug, Error)]
pub enum DisputeError {
    /// Canonical encoding or hashing failed.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    /// Case validation failed.
    #[error(transparent)]
    Case(#[from] joan_case::CaseError),
    /// Evidence graph validation failed.
    #[error(transparent)]
    Evidence(#[from] joan_evidence::EvidenceError),
    /// Unsupported schema.
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(String),
    /// Required field was empty.
    #[error("required field is empty: {0}")]
    EmptyField(&'static str),
    /// The case is not in an adjudicable state.
    #[error("case state is not eligible for adjudication")]
    InvalidCaseState,
    /// Evidence must be locked before adjudication.
    #[error("evidence graph is not locked")]
    EvidenceNotLocked,
    /// Case/evidence/claim identifiers disagree.
    #[error("case, claim and evidence bindings do not match")]
    BindingMismatch,
    /// Profile policy digest does not match the case.
    #[error("resolution profile policy digest does not match")]
    PolicyMismatch,
    /// Runtime-human or non-final profile is forbidden.
    #[error("automatic finality must be enabled")]
    AutomaticFinalityRequired,
    /// Primary and appeal adjudicator identities overlap.
    #[error("primary and appeal adjudicator sets must be disjoint")]
    AdjudicatorOverlap,
    /// Quorum threshold is invalid.
    #[error("invalid adjudicator threshold")]
    InvalidThreshold,
    /// Case value exceeds profile.
    #[error("case value exceeds automatic profile maximum")]
    ValueOutOfRange,
    /// Claim code is not eligible.
    #[error("claim code is not eligible for automatic resolution")]
    IneligibleClaim,
    /// Requested or fallback remedy is not allowed.
    #[error("remedy is not allowed by the profile")]
    RemedyNotAllowed,
    /// Evidence reference is missing or not verified.
    #[error("missing or unverified evidence reference: {0}")]
    InvalidEvidenceReference(String),
    /// Finding is bound to another phase/case/evidence/policy.
    #[error("machine finding binding does not match")]
    FindingBindingMismatch,
    /// Adjudicator is not assigned to this phase.
    #[error("adjudicator is not assigned to this phase: {0}")]
    UnauthorizedAdjudicator(String),
    /// An adjudicator submitted more than one finding.
    #[error("duplicate adjudicator finding: {0}")]
    DuplicateFinding(String),
    /// Non-abstaining finding omitted verified evidence.
    #[error("decisive finding requires verified evidence")]
    FindingWithoutEvidence,
    /// Appeal input or prior-decision digest is invalid.
    #[error("invalid prior decision for automatic appeal")]
    InvalidPriorDecision,
    /// Integer arithmetic exceeded supported range.
    #[error("remedy amount overflow")]
    AmountOverflow,
}

#[derive(Serialize)]
struct DecisionCore<'a> {
    schema: &'a str,
    phase: DecisionPhase,
    case_digest: &'a Digest,
    evidence_root: &'a Digest,
    claim_digest: &'a Digest,
    profile_digest: &'a Digest,
    supersedes: &'a Option<Digest>,
    status: DecisionStatus,
    support_count: u64,
    reject_count: u64,
    abstain_count: u64,
    participating_adjudicators: &'a [String],
    remedy: &'a RemedyAllocation,
    reason_codes: &'a [String],
    finality_class: &'a str,
}

/// Evaluate a complete primary or appeal bundle without external effects.
pub fn evaluate_bundle(
    bundle: &DisputeEvaluationBundle,
) -> Result<AutomaticDecisionReceipt, DisputeError> {
    if bundle.schema != "joan.dispute-evaluation-bundle.v0" {
        return Err(DisputeError::UnsupportedSchema(bundle.schema.clone()));
    }
    match &bundle.prior_decision {
        Some(prior) => evaluate(
            &bundle.case,
            &bundle.evidence,
            &bundle.claim,
            &bundle.profile,
            &bundle.findings,
            DecisionPhase::Appeal,
            Some(prior),
        ),
        None => evaluate(
            &bundle.case,
            &bundle.evidence,
            &bundle.claim,
            &bundle.profile,
            &bundle.findings,
            DecisionPhase::Primary,
            None,
        ),
    }
}

/// Verify the digest of a previously emitted decision receipt.
pub fn verify_decision(decision: &AutomaticDecisionReceipt) -> Result<(), DisputeError> {
    if decision.schema != "joan.automatic-decision-receipt.v0" {
        return Err(DisputeError::UnsupportedSchema(decision.schema.clone()));
    }
    if decision_content_digest(decision)? != decision.decision_digest {
        return Err(DisputeError::InvalidPriorDecision);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn evaluate(
    case: &DisputeCase,
    evidence: &EvidenceGraph,
    claim: &Claim,
    profile: &AutomaticResolutionProfile,
    findings: &[MachineFinding],
    phase: DecisionPhase,
    prior: Option<&AutomaticDecisionReceipt>,
) -> Result<AutomaticDecisionReceipt, DisputeError> {
    validate_inputs(case, evidence, claim, profile, phase, prior)?;
    let allowed_adjudicators = match phase {
        DecisionPhase::Primary => &profile.primary_adjudicators,
        DecisionPhase::Appeal => &profile.appeal_adjudicators,
    };
    let threshold = match phase {
        DecisionPhase::Primary => profile.primary_threshold,
        DecisionPhase::Appeal => profile.appeal_threshold,
    };
    let (support_count, reject_count, abstain_count, participating_adjudicators) =
        evaluate_findings(
            case,
            evidence,
            profile,
            findings,
            phase,
            allowed_adjudicators,
        )?;

    let (status, remedy_kind, reason) = if support_count >= threshold && reject_count < threshold {
        (
            DecisionStatus::ClaimUpheld,
            claim.requested_remedy,
            "claim-threshold-satisfied",
        )
    } else if reject_count >= threshold && support_count < threshold {
        (
            DecisionStatus::ClaimRejected,
            RemedyKind::ReleaseProvider,
            "rejection-threshold-satisfied",
        )
    } else {
        (
            DecisionStatus::FallbackApplied,
            fallback_kind(&profile.ambiguity_fallback),
            "precommitted-ambiguity-fallback",
        )
    };
    if !profile.allowed_remedies.contains(&remedy_kind) {
        return Err(DisputeError::RemedyNotAllowed);
    }
    let remedy = allocation_for(
        remedy_kind,
        &profile.ambiguity_fallback,
        case.value_microunits,
    )?;
    let claim_digest = digest_serializable("joan.dispute-claim.v0", claim)?;
    let profile_digest = digest_serializable("joan.automatic-resolution-profile.v0", profile)?;
    let supersedes = prior.map(|decision| decision.decision_digest.clone());
    let finality_class = match phase {
        DecisionPhase::Primary => "automatic-primary-appealable",
        DecisionPhase::Appeal => "automatic-appeal-final",
    };
    let mut decision = AutomaticDecisionReceipt {
        schema: "joan.automatic-decision-receipt.v0".to_owned(),
        phase,
        case_digest: case.case_digest.clone(),
        evidence_root: evidence.graph_root.clone(),
        claim_digest,
        profile_digest,
        supersedes,
        status,
        support_count,
        reject_count,
        abstain_count,
        participating_adjudicators,
        remedy,
        reason_codes: vec![reason.to_owned()],
        finality_class: finality_class.to_owned(),
        decision_digest: placeholder_digest(),
    };
    decision.decision_digest = decision_content_digest(&decision)?;
    Ok(decision)
}

fn validate_inputs(
    case: &DisputeCase,
    evidence: &EvidenceGraph,
    claim: &Claim,
    profile: &AutomaticResolutionProfile,
    phase: DecisionPhase,
    prior: Option<&AutomaticDecisionReceipt>,
) -> Result<(), DisputeError> {
    verify_case(case)?;
    verify_evidence_graph(evidence)?;
    if !matches!(
        case.state,
        CaseState::DeterministicEvaluation
            | CaseState::ReviewAssigned
            | CaseState::ProposedDecision
            | CaseState::ChallengeWindow
            | CaseState::Appealed
    ) {
        return Err(DisputeError::InvalidCaseState);
    }
    if !evidence.locked {
        return Err(DisputeError::EvidenceNotLocked);
    }
    if claim.schema != "joan.dispute-claim.v0" {
        return Err(DisputeError::UnsupportedSchema(claim.schema.clone()));
    }
    require_nonempty(&claim.claim_id, "claim_id")?;
    if evidence.case_id != case.case_id
        || claim.case_id != case.case_id
        || claim.claimant_id != case.claimant_id
    {
        return Err(DisputeError::BindingMismatch);
    }
    validate_profile(profile)?;
    if profile.policy_digest != case.policy_digest {
        return Err(DisputeError::PolicyMismatch);
    }
    if case.value_microunits > profile.max_value_microunits {
        return Err(DisputeError::ValueOutOfRange);
    }
    if !profile.eligible_claim_codes.contains(&claim.claim_code) {
        return Err(DisputeError::IneligibleClaim);
    }
    if !profile.allowed_remedies.contains(&claim.requested_remedy) {
        return Err(DisputeError::RemedyNotAllowed);
    }
    verify_evidence_refs(evidence, &claim.evidence_refs)?;
    match (phase, prior) {
        (DecisionPhase::Primary, None) => Ok(()),
        (DecisionPhase::Appeal, Some(decision)) => {
            verify_decision(decision)?;
            if decision.phase != DecisionPhase::Primary
                || decision.case_digest != case.case_digest
                || decision.evidence_root != evidence.graph_root
            {
                return Err(DisputeError::InvalidPriorDecision);
            }
            Ok(())
        }
        _ => Err(DisputeError::InvalidPriorDecision),
    }
}

fn validate_profile(profile: &AutomaticResolutionProfile) -> Result<(), DisputeError> {
    if profile.schema != "joan.automatic-resolution-profile.v0" {
        return Err(DisputeError::UnsupportedSchema(profile.schema.clone()));
    }
    if !profile.automatic_finality {
        return Err(DisputeError::AutomaticFinalityRequired);
    }
    if !profile
        .primary_adjudicators
        .is_disjoint(&profile.appeal_adjudicators)
    {
        return Err(DisputeError::AdjudicatorOverlap);
    }
    let primary_len = u64::try_from(profile.primary_adjudicators.len())
        .map_err(|_| DisputeError::InvalidThreshold)?;
    let appeal_len = u64::try_from(profile.appeal_adjudicators.len())
        .map_err(|_| DisputeError::InvalidThreshold)?;
    if profile.primary_threshold == 0
        || profile.appeal_threshold == 0
        || profile.primary_threshold > primary_len
        || profile.appeal_threshold > appeal_len
    {
        return Err(DisputeError::InvalidThreshold);
    }
    let fallback = fallback_kind(&profile.ambiguity_fallback);
    if !profile.allowed_remedies.contains(&fallback)
        || !profile
            .allowed_remedies
            .contains(&RemedyKind::ReleaseProvider)
    {
        return Err(DisputeError::RemedyNotAllowed);
    }
    if let AmbiguityFallback::Split { buyer_refund_bps } = profile.ambiguity_fallback
        && buyer_refund_bps > 10_000
    {
        return Err(DisputeError::RemedyNotAllowed);
    }
    Ok(())
}

fn evaluate_findings(
    case: &DisputeCase,
    evidence: &EvidenceGraph,
    profile: &AutomaticResolutionProfile,
    findings: &[MachineFinding],
    phase: DecisionPhase,
    allowed: &BTreeSet<String>,
) -> Result<(u64, u64, u64, Vec<String>), DisputeError> {
    let mut seen = BTreeSet::new();
    let mut support = 0_u64;
    let mut reject = 0_u64;
    let mut abstain = 0_u64;
    for finding in findings {
        if finding.schema != "joan.machine-finding.v0" {
            return Err(DisputeError::UnsupportedSchema(finding.schema.clone()));
        }
        require_nonempty(&finding.adjudicator_id, "adjudicator_id")?;
        if finding.phase != phase
            || finding.case_digest != case.case_digest
            || finding.evidence_root != evidence.graph_root
            || finding.policy_digest != profile.policy_digest
        {
            return Err(DisputeError::FindingBindingMismatch);
        }
        if !allowed.contains(&finding.adjudicator_id) {
            return Err(DisputeError::UnauthorizedAdjudicator(
                finding.adjudicator_id.clone(),
            ));
        }
        if !seen.insert(finding.adjudicator_id.clone()) {
            return Err(DisputeError::DuplicateFinding(
                finding.adjudicator_id.clone(),
            ));
        }
        if finding.disposition != FindingDisposition::Abstain && finding.evidence_refs.is_empty() {
            return Err(DisputeError::FindingWithoutEvidence);
        }
        verify_evidence_refs(evidence, &finding.evidence_refs)?;
        match finding.disposition {
            FindingDisposition::SupportsClaim => support += 1,
            FindingDisposition::RejectsClaim => reject += 1,
            FindingDisposition::Abstain => abstain += 1,
        }
    }
    Ok((support, reject, abstain, seen.into_iter().collect()))
}

fn verify_evidence_refs(graph: &EvidenceGraph, references: &[String]) -> Result<(), DisputeError> {
    for reference in references {
        let item = graph
            .items
            .get(reference)
            .ok_or_else(|| DisputeError::InvalidEvidenceReference(reference.clone()))?;
        if item.verification != EvidenceVerification::Verified {
            return Err(DisputeError::InvalidEvidenceReference(reference.clone()));
        }
    }
    Ok(())
}

fn fallback_kind(fallback: &AmbiguityFallback) -> RemedyKind {
    match fallback {
        AmbiguityFallback::FullRefund => RemedyKind::FullRefund,
        AmbiguityFallback::ReleaseProvider => RemedyKind::ReleaseProvider,
        AmbiguityFallback::Split { .. } => RemedyKind::Split,
        AmbiguityFallback::Repair => RemedyKind::Repair,
        AmbiguityFallback::Quarantine => RemedyKind::Quarantine,
    }
}

fn allocation_for(
    remedy: RemedyKind,
    fallback: &AmbiguityFallback,
    value: u64,
) -> Result<RemedyAllocation, DisputeError> {
    let allocation = match remedy {
        RemedyKind::FullRefund => RemedyAllocation {
            kind: remedy,
            buyer_refund_microunits: value,
            provider_release_microunits: 0,
            retained_microunits: 0,
        },
        RemedyKind::ReleaseProvider => RemedyAllocation {
            kind: remedy,
            buyer_refund_microunits: 0,
            provider_release_microunits: value,
            retained_microunits: 0,
        },
        RemedyKind::Split => {
            let AmbiguityFallback::Split { buyer_refund_bps } = fallback else {
                return Err(DisputeError::RemedyNotAllowed);
            };
            let refund =
                u64::try_from((u128::from(value) * u128::from(*buyer_refund_bps)) / 10_000_u128)
                    .map_err(|_| DisputeError::AmountOverflow)?;
            let release = value
                .checked_sub(refund)
                .ok_or(DisputeError::AmountOverflow)?;
            RemedyAllocation {
                kind: remedy,
                buyer_refund_microunits: refund,
                provider_release_microunits: release,
                retained_microunits: 0,
            }
        }
        RemedyKind::Repair | RemedyKind::Quarantine => RemedyAllocation {
            kind: remedy,
            buyer_refund_microunits: 0,
            provider_release_microunits: 0,
            retained_microunits: value,
        },
    };
    Ok(allocation)
}

/// Compute the protected content digest for a decision receipt.
///
/// This function does not authorize or validate a decision. Use [`verify_decision`]
/// before applying a receipt received from another component.
pub fn decision_content_digest(
    decision: &AutomaticDecisionReceipt,
) -> Result<Digest, CanonicalError> {
    digest_serializable(
        "joan.automatic-decision-receipt.v0",
        &DecisionCore {
            schema: &decision.schema,
            phase: decision.phase,
            case_digest: &decision.case_digest,
            evidence_root: &decision.evidence_root,
            claim_digest: &decision.claim_digest,
            profile_digest: &decision.profile_digest,
            supersedes: &decision.supersedes,
            status: decision.status,
            support_count: decision.support_count,
            reject_count: decision.reject_count,
            abstain_count: decision.abstain_count,
            participating_adjudicators: &decision.participating_adjudicators,
            remedy: &decision.remedy,
            reason_codes: &decision.reason_codes,
            finality_class: &decision.finality_class,
        },
    )
}

fn require_nonempty(value: &str, field: &'static str) -> Result<(), DisputeError> {
    if value.trim().is_empty() {
        Err(DisputeError::EmptyField(field))
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
