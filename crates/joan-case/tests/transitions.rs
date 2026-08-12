//! Atomic dispute-case transition tests.

use joan_canonical::digest_bytes;
use joan_case::{
    CaseError, CaseState, CaseTransition, NewCase, create_case, transition_case, verify_case,
};

fn sample_case() -> Result<joan_case::DisputeCase, Box<dyn std::error::Error>> {
    Ok(create_case(&NewCase {
        schema: "joan.new-dispute-case.v0".to_owned(),
        case_id: "case-001".to_owned(),
        contract_digest: digest_bytes("test.contract", b"contract")?,
        transaction_digest: digest_bytes("test.transaction", b"transaction")?,
        claimant_id: "buyer-agent".to_owned(),
        respondent_id: "provider-agent".to_owned(),
        policy_digest: digest_bytes("test.policy", b"policy")?,
        value_microunits: 1_000_000,
    })?)
}

fn transition(
    case: &joan_case::DisputeCase,
    to: CaseState,
    key: &str,
) -> Result<CaseTransition, Box<dyn std::error::Error>> {
    Ok(CaseTransition {
        schema: "joan.case-transition.v0".to_owned(),
        expected_case_digest: case.case_digest.clone(),
        expected_revision: case.revision,
        from: case.state,
        to,
        actor_id: "intake-engine".to_owned(),
        authority_ref: digest_bytes("test.authority", b"authority")?,
        idempotency_key: key.to_owned(),
        reason_code: "eligible".to_owned(),
        evidence_refs: Vec::new(),
    })
}

#[test]
fn legal_transition_is_atomic_and_verifiable() -> Result<(), Box<dyn std::error::Error>> {
    let case = sample_case()?;
    let request = transition(&case, CaseState::IntakeValidation, "step-1")?;
    let (next, receipt) = transition_case(&case, &request)?;
    assert_eq!(case.state, CaseState::Submitted);
    assert_eq!(next.state, CaseState::IntakeValidation);
    assert_eq!(next.revision, 1);
    assert!(receipt.committed);
    verify_case(&next)?;
    Ok(())
}

#[test]
fn stale_digest_fails_without_mutation() -> Result<(), Box<dyn std::error::Error>> {
    let case = sample_case()?;
    let mut request = transition(&case, CaseState::IntakeValidation, "step-1")?;
    request.expected_case_digest = digest_bytes("test.case", b"stale")?;
    let before = case.clone();
    assert!(matches!(
        transition_case(&case, &request),
        Err(CaseError::StaleCaseDigest)
    ));
    assert_eq!(case, before);
    Ok(())
}

#[test]
fn illegal_transition_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let case = sample_case()?;
    let request = transition(&case, CaseState::Closed, "skip-all-gates")?;
    assert!(matches!(
        transition_case(&case, &request),
        Err(CaseError::IllegalTransition)
    ));
    Ok(())
}

#[test]
fn idempotency_key_cannot_be_replayed() -> Result<(), Box<dyn std::error::Error>> {
    let case = sample_case()?;
    let first = transition(&case, CaseState::IntakeValidation, "same-key")?;
    let (next, _) = transition_case(&case, &first)?;
    let replay = transition(&next, CaseState::Accepted, "same-key")?;
    assert!(matches!(
        transition_case(&next, &replay),
        Err(CaseError::Replay)
    ));
    Ok(())
}

#[test]
fn protected_field_tampering_breaks_digest() -> Result<(), Box<dyn std::error::Error>> {
    let mut case = sample_case()?;
    case.value_microunits = 9_999_999;
    assert!(matches!(
        verify_case(&case),
        Err(CaseError::InvalidStoredDigest)
    ));
    Ok(())
}

#[test]
fn same_input_produces_same_case_and_receipt() -> Result<(), Box<dyn std::error::Error>> {
    let left = sample_case()?;
    let right = sample_case()?;
    assert_eq!(left, right);
    let left_request = transition(&left, CaseState::IntakeValidation, "step-1")?;
    let right_request = transition(&right, CaseState::IntakeValidation, "step-1")?;
    assert_eq!(
        transition_case(&left, &left_request)?,
        transition_case(&right, &right_request)?
    );
    Ok(())
}
