//! Mock-ledger conservation and replay tests.

use joan_canonical::digest_bytes;
use joan_dispute::{
    AutomaticDecisionReceipt, DecisionPhase, DecisionStatus, RemedyAllocation, RemedyKind,
    decision_content_digest,
};
use joan_mock_ledger::{
    ApplyDecisionRequest, HoldStatus, LedgerError, MockLedger, ReserveRequest, apply_decision,
    create_ledger, reserve, verify_ledger,
};
use std::collections::BTreeMap;

fn ledger() -> Result<MockLedger, Box<dyn std::error::Error>> {
    Ok(create_ledger(BTreeMap::from([
        ("buyer".to_owned(), 2_000_000),
        ("provider".to_owned(), 100_000),
    ]))?)
}

fn reserve_request(ledger: &MockLedger) -> Result<ReserveRequest, Box<dyn std::error::Error>> {
    Ok(ReserveRequest {
        schema: "joan.mock-reserve-request.v0".to_owned(),
        expected_ledger_root: ledger.ledger_root.clone(),
        expected_revision: ledger.revision,
        hold_id: "hold-001".to_owned(),
        buyer_id: "buyer".to_owned(),
        provider_id: "provider".to_owned(),
        contract_digest: digest_bytes("test.contract", b"contract")?,
        amount_microunits: 1_000_000,
        idempotency_key: "reserve-001".to_owned(),
    })
}

fn decision(
    kind: RemedyKind,
    buyer: u64,
    provider: u64,
    retained: u64,
) -> Result<AutomaticDecisionReceipt, Box<dyn std::error::Error>> {
    let mut receipt = AutomaticDecisionReceipt {
        schema: "joan.automatic-decision-receipt.v0".to_owned(),
        phase: DecisionPhase::Primary,
        case_digest: digest_bytes("test.case", b"case")?,
        evidence_root: digest_bytes("test.evidence", b"evidence")?,
        claim_digest: digest_bytes("test.claim", b"claim")?,
        profile_digest: digest_bytes("test.profile", b"profile")?,
        supersedes: None,
        status: DecisionStatus::ClaimUpheld,
        support_count: 2,
        reject_count: 0,
        abstain_count: 0,
        participating_adjudicators: vec!["a".to_owned(), "b".to_owned()],
        remedy: RemedyAllocation {
            kind,
            buyer_refund_microunits: buyer,
            provider_release_microunits: provider,
            retained_microunits: retained,
        },
        reason_codes: vec!["test".to_owned()],
        finality_class: "automatic-primary-appealable".to_owned(),
        decision_digest: digest_bytes("placeholder", b"placeholder")?,
    };
    receipt.decision_digest = decision_content_digest(&receipt)?;
    Ok(receipt)
}

fn apply_request(ledger: &MockLedger, receipt: AutomaticDecisionReceipt) -> ApplyDecisionRequest {
    ApplyDecisionRequest {
        schema: "joan.mock-apply-decision-request.v0".to_owned(),
        expected_ledger_root: ledger.ledger_root.clone(),
        expected_revision: ledger.revision,
        hold_id: "hold-001".to_owned(),
        idempotency_key: "decision-001".to_owned(),
        decision: receipt,
    }
}

#[test]
fn reserve_and_refund_conserve_total_value() -> Result<(), Box<dyn std::error::Error>> {
    let ledger = ledger()?;
    let (reserved, _) = reserve(&ledger, &reserve_request(&ledger)?)?;
    let request = apply_request(
        &reserved,
        decision(RemedyKind::FullRefund, 1_000_000, 0, 0)?,
    );
    let (resolved, receipt) = apply_decision(&reserved, &request)?;
    assert_eq!(resolved.balances["buyer"], 2_000_000);
    assert_eq!(resolved.holds["hold-001"].status, HoldStatus::Refunded);
    assert_eq!(receipt.conserved_total_microunits, 2_100_000);
    verify_ledger(&resolved)?;
    Ok(())
}

#[test]
fn split_conserves_rounding_exactly() -> Result<(), Box<dyn std::error::Error>> {
    let ledger = ledger()?;
    let (reserved, _) = reserve(&ledger, &reserve_request(&ledger)?)?;
    let request = apply_request(&reserved, decision(RemedyKind::Split, 600_000, 400_000, 0)?);
    let (resolved, _) = apply_decision(&reserved, &request)?;
    assert_eq!(resolved.balances["buyer"], 1_600_000);
    assert_eq!(resolved.balances["provider"], 500_000);
    assert_eq!(resolved.holds["hold-001"].status, HoldStatus::Split);
    verify_ledger(&resolved)?;
    Ok(())
}

#[test]
fn repair_keeps_value_locked() -> Result<(), Box<dyn std::error::Error>> {
    let ledger = ledger()?;
    let (reserved, _) = reserve(&ledger, &reserve_request(&ledger)?)?;
    let request = apply_request(&reserved, decision(RemedyKind::Repair, 0, 0, 1_000_000)?);
    let (resolved, _) = apply_decision(&reserved, &request)?;
    assert_eq!(resolved.holds["hold-001"].status, HoldStatus::RepairPending);
    assert_eq!(
        resolved.holds["hold-001"].locked_amount_microunits,
        1_000_000
    );
    verify_ledger(&resolved)?;
    Ok(())
}

#[test]
fn decision_cannot_be_applied_twice() -> Result<(), Box<dyn std::error::Error>> {
    let ledger = ledger()?;
    let (reserved, _) = reserve(&ledger, &reserve_request(&ledger)?)?;
    let request = apply_request(
        &reserved,
        decision(RemedyKind::ReleaseProvider, 0, 1_000_000, 0)?,
    );
    let (resolved, _) = apply_decision(&reserved, &request)?;
    let replay = ApplyDecisionRequest {
        expected_ledger_root: resolved.ledger_root.clone(),
        expected_revision: resolved.revision,
        idempotency_key: "decision-002".to_owned(),
        ..request
    };
    assert!(matches!(
        apply_decision(&resolved, &replay),
        Err(LedgerError::HoldNotReserved)
    ));
    Ok(())
}

#[test]
fn invalid_allocation_fails_without_mutation() -> Result<(), Box<dyn std::error::Error>> {
    let ledger = ledger()?;
    let (reserved, _) = reserve(&ledger, &reserve_request(&ledger)?)?;
    let before = reserved.clone();
    let request = apply_request(&reserved, decision(RemedyKind::Split, 500_000, 400_000, 0)?);
    assert!(matches!(
        apply_decision(&reserved, &request),
        Err(LedgerError::AllocationMismatch)
    ));
    assert_eq!(reserved, before);
    Ok(())
}
