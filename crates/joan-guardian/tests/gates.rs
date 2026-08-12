//! Guardian threshold and separation-of-duty tests.

use joan_canonical::digest_bytes;
use joan_guardian::{
    GuardianCandidate, GuardianError, GuardianOutcome, GuardianRole, GuardianVote, VoteDecision,
    evaluate_candidate,
};
use std::collections::BTreeSet;

fn candidate_root() -> Result<joan_canonical::Digest, Box<dyn std::error::Error>> {
    Ok(digest_bytes("joan.candidate.v0", b"candidate")?)
}

fn vote(
    id: &str,
    role: GuardianRole,
    decision: VoteDecision,
) -> Result<GuardianVote, Box<dyn std::error::Error>> {
    Ok(GuardianVote {
        guardian_id: id.to_owned(),
        role,
        candidate_root: candidate_root()?,
        decision,
        evidence: Vec::new(),
    })
}

fn base_candidate(
    votes: Vec<GuardianVote>,
) -> Result<GuardianCandidate, Box<dyn std::error::Error>> {
    Ok(GuardianCandidate {
        schema: "joan.guardian-candidate.v0".to_owned(),
        candidate_root: candidate_root()?,
        proposer_id: "repair-proposer".to_owned(),
        required_roles: BTreeSet::from([
            GuardianRole::SemanticVerifier,
            GuardianRole::PolicyGatekeeper,
        ]),
        approval_threshold: 2,
        votes,
    })
}

#[test]
fn required_roles_and_threshold_approve() -> Result<(), Box<dyn std::error::Error>> {
    let candidate = base_candidate(vec![
        vote(
            "semantic",
            GuardianRole::SemanticVerifier,
            VoteDecision::Approve,
        )?,
        vote(
            "policy",
            GuardianRole::PolicyGatekeeper,
            VoteDecision::Approve,
        )?,
    ])?;
    let receipt = evaluate_candidate(&candidate)?;
    assert_eq!(receipt.outcome, GuardianOutcome::Approved);
    assert_eq!(receipt.independence_profile, "one-host-logical-only");
    Ok(())
}

#[test]
fn deny_vote_dominates() -> Result<(), Box<dyn std::error::Error>> {
    let candidate = base_candidate(vec![
        vote(
            "semantic",
            GuardianRole::SemanticVerifier,
            VoteDecision::Approve,
        )?,
        vote(
            "policy",
            GuardianRole::PolicyGatekeeper,
            VoteDecision::Approve,
        )?,
        vote("security", GuardianRole::TestGuardian, VoteDecision::Deny)?,
    ])?;
    assert_eq!(
        evaluate_candidate(&candidate)?.outcome,
        GuardianOutcome::Denied
    );
    Ok(())
}

#[test]
fn missing_role_is_pending() -> Result<(), Box<dyn std::error::Error>> {
    let candidate = base_candidate(vec![
        vote(
            "semantic-a",
            GuardianRole::SemanticVerifier,
            VoteDecision::Approve,
        )?,
        vote(
            "semantic-b",
            GuardianRole::SemanticVerifier,
            VoteDecision::Approve,
        )?,
    ])?;
    let receipt = evaluate_candidate(&candidate)?;
    assert_eq!(receipt.outcome, GuardianOutcome::Pending);
    assert!(
        receipt
            .missing_roles
            .contains(&GuardianRole::PolicyGatekeeper)
    );
    Ok(())
}

#[test]
fn proposer_cannot_approve_own_candidate() -> Result<(), Box<dyn std::error::Error>> {
    let candidate = base_candidate(vec![vote(
        "repair-proposer",
        GuardianRole::SemanticVerifier,
        VoteDecision::Approve,
    )?])?;
    assert!(matches!(
        evaluate_candidate(&candidate),
        Err(GuardianError::SelfApproval)
    ));
    Ok(())
}

#[test]
fn duplicate_guardian_identity_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let candidate = base_candidate(vec![
        vote(
            "same",
            GuardianRole::SemanticVerifier,
            VoteDecision::Approve,
        )?,
        vote(
            "same",
            GuardianRole::PolicyGatekeeper,
            VoteDecision::Approve,
        )?,
    ])?;
    assert!(matches!(
        evaluate_candidate(&candidate),
        Err(GuardianError::DuplicateGuardian(id)) if id == "same"
    ));
    Ok(())
}
