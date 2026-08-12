//! Deterministic local guardian decisions with explicit one-host limitations.

use joan_canonical::{CanonicalError, Digest, digest_serializable};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Guardian roles implemented by the Genesis logical mesh.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuardianRole {
    /// Verifies semantic identity and patch preconditions.
    SemanticVerifier,
    /// Verifies required test evidence.
    TestGuardian,
    /// Applies deterministic policy constraints.
    PolicyGatekeeper,
    /// Preserves immutable candidate evidence.
    Archivist,
    /// May propose a repair but cannot approve its own proposal.
    RepairProposer,
}

/// One guardian's vote on one exact candidate root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoteDecision {
    /// Guardian approves the candidate under its role.
    Approve,
    /// Guardian rejects the candidate.
    Deny,
    /// Guardian produced no approval or denial.
    Abstain,
}

/// Signed-vote payload before an external signature profile is added.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianVote {
    /// Stable logical guardian identity.
    pub guardian_id: String,
    /// Guardian role.
    pub role: GuardianRole,
    /// Exact candidate root under review.
    pub candidate_root: Digest,
    /// Vote decision.
    pub decision: VoteDecision,
    /// Digests of findings/evidence supporting the vote.
    pub evidence: Vec<Digest>,
}

/// Candidate and threshold policy submitted to the guardian evaluator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianCandidate {
    /// Schema identifier.
    pub schema: String,
    /// Exact protected transition candidate root.
    pub candidate_root: Digest,
    /// Agent or guardian that proposed the change.
    pub proposer_id: String,
    /// Required approving roles.
    pub required_roles: BTreeSet<GuardianRole>,
    /// Minimum distinct approving guardian identities.
    pub approval_threshold: u64,
    /// Votes presented for deterministic evaluation.
    pub votes: Vec<GuardianVote>,
}

/// Deterministic guardian gate result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardianOutcome {
    /// Every required role and threshold passed with no deny vote.
    Approved,
    /// At least one valid deny vote was present.
    Denied,
    /// Evidence or approvals remain insufficient.
    Pending,
}

/// Reproducible guardian decision receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianDecisionReceipt {
    /// Schema identifier.
    pub schema: String,
    /// Exact candidate root.
    pub candidate_root: Digest,
    /// Final deterministic result.
    pub outcome: GuardianOutcome,
    /// Distinct count of valid approval votes.
    pub approvals: u64,
    /// Distinct approving roles.
    pub approved_roles: BTreeSet<GuardianRole>,
    /// Roles still required when pending.
    pub missing_roles: BTreeSet<GuardianRole>,
    /// Guardian IDs that denied the candidate.
    pub denying_guardians: Vec<String>,
    /// Explicit limitation of the Genesis implementation.
    pub independence_profile: String,
    /// Digest of all receipt fields except this digest.
    pub receipt_digest: Digest,
}

/// Guardian evaluation error.
#[derive(Debug, Error)]
pub enum GuardianError {
    /// Canonical encoding or hashing failed.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    /// Candidate schema is unsupported.
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(String),
    /// Threshold is zero or cannot be represented safely.
    #[error("invalid approval threshold")]
    InvalidThreshold,
    /// Required role set is empty.
    #[error("at least one guardian role is required")]
    NoRequiredRoles,
    /// Guardian ID is empty.
    #[error("guardian identity is empty")]
    EmptyGuardianId,
    /// The same guardian identity voted more than once.
    #[error("duplicate guardian vote: {0}")]
    DuplicateGuardian(String),
    /// Vote is bound to another candidate root.
    #[error("guardian vote candidate root mismatch: {0}")]
    CandidateMismatch(String),
    /// Proposer attempted to approve its own candidate.
    #[error("proposer cannot approve its own candidate")]
    SelfApproval,
}

#[derive(Serialize)]
struct ReceiptCore<'a> {
    schema: &'a str,
    candidate_root: &'a Digest,
    outcome: &'a GuardianOutcome,
    approvals: u64,
    approved_roles: &'a BTreeSet<GuardianRole>,
    missing_roles: &'a BTreeSet<GuardianRole>,
    denying_guardians: &'a [String],
    independence_profile: &'a str,
}

/// Evaluate a candidate without executing or applying it.
pub fn evaluate_candidate(
    candidate: &GuardianCandidate,
) -> Result<GuardianDecisionReceipt, GuardianError> {
    if candidate.schema != "joan.guardian-candidate.v0" {
        return Err(GuardianError::UnsupportedSchema(candidate.schema.clone()));
    }
    if candidate.approval_threshold == 0 {
        return Err(GuardianError::InvalidThreshold);
    }
    if candidate.required_roles.is_empty() {
        return Err(GuardianError::NoRequiredRoles);
    }

    let mut voters = BTreeSet::new();
    let mut approved_roles = BTreeSet::new();
    let mut denying_guardians = Vec::new();
    let mut approvals_by_id = BTreeMap::new();

    for vote in &candidate.votes {
        if vote.guardian_id.is_empty() {
            return Err(GuardianError::EmptyGuardianId);
        }
        if vote.candidate_root != candidate.candidate_root {
            return Err(GuardianError::CandidateMismatch(vote.guardian_id.clone()));
        }
        if !voters.insert(vote.guardian_id.clone()) {
            return Err(GuardianError::DuplicateGuardian(vote.guardian_id.clone()));
        }
        match vote.decision {
            VoteDecision::Approve => {
                if vote.guardian_id == candidate.proposer_id {
                    return Err(GuardianError::SelfApproval);
                }
                approved_roles.insert(vote.role.clone());
                approvals_by_id.insert(vote.guardian_id.clone(), vote.role.clone());
            }
            VoteDecision::Deny => denying_guardians.push(vote.guardian_id.clone()),
            VoteDecision::Abstain => {}
        }
    }

    denying_guardians.sort();
    let missing_roles = candidate
        .required_roles
        .difference(&approved_roles)
        .cloned()
        .collect::<BTreeSet<_>>();
    let approvals =
        u64::try_from(approvals_by_id.len()).map_err(|_| GuardianError::InvalidThreshold)?;
    let outcome = if !denying_guardians.is_empty() {
        GuardianOutcome::Denied
    } else if missing_roles.is_empty() && approvals >= candidate.approval_threshold {
        GuardianOutcome::Approved
    } else {
        GuardianOutcome::Pending
    };
    let schema = "joan.guardian-decision-receipt.v0";
    let independence_profile = "one-host-logical-only";
    let receipt_digest = digest_serializable(
        "joan.guardian-decision-receipt.v0",
        &ReceiptCore {
            schema,
            candidate_root: &candidate.candidate_root,
            outcome: &outcome,
            approvals,
            approved_roles: &approved_roles,
            missing_roles: &missing_roles,
            denying_guardians: &denying_guardians,
            independence_profile,
        },
    )?;
    Ok(GuardianDecisionReceipt {
        schema: schema.to_owned(),
        candidate_root: candidate.candidate_root.clone(),
        outcome,
        approvals,
        approved_roles,
        missing_roles,
        denying_guardians,
        independence_profile: independence_profile.to_owned(),
        receipt_digest,
    })
}
