//! Machine-only primary and appeal adjudication tests.

use joan_canonical::digest_bytes;
use joan_case::{CaseState, CaseTransition, DisputeCase, NewCase, create_case, transition_case};
use joan_dispute::{
    AmbiguityFallback, AutomaticDecisionReceipt, AutomaticResolutionProfile, Claim, ClaimCode,
    DecisionPhase, DecisionStatus, DisputeError, DisputeEvaluationBundle, FindingDisposition,
    MachineFinding, RemedyKind, evaluate_bundle, verify_decision,
};
use joan_evidence::{
    Confidentiality, EvidenceGraph, EvidenceItem, EvidenceMutation, EvidenceMutationRequest,
    EvidenceVerification, create_evidence_graph, mutate_evidence,
};
use std::collections::BTreeSet;

struct Fixture {
    case: DisputeCase,
    evidence: EvidenceGraph,
    profile: AutomaticResolutionProfile,
    claim: Claim,
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let policy_digest = digest_bytes("test.policy", b"automatic-profile")?;
    let case = create_case(&NewCase {
        schema: "joan.new-dispute-case.v0".to_owned(),
        case_id: "case-001".to_owned(),
        contract_digest: digest_bytes("test.contract", b"contract")?,
        transaction_digest: digest_bytes("test.transaction", b"transaction")?,
        claimant_id: "buyer".to_owned(),
        respondent_id: "provider".to_owned(),
        policy_digest: policy_digest.clone(),
        value_microunits: 1_000_000,
    })?;
    let case = advance_to_evaluation(case)?;
    let evidence = locked_evidence()?;
    let profile = AutomaticResolutionProfile {
        schema: "joan.automatic-resolution-profile.v0".to_owned(),
        policy_digest,
        eligible_claim_codes: BTreeSet::from([
            ClaimCode::NonDelivery,
            ClaimCode::AcceptanceFailure,
        ]),
        allowed_remedies: BTreeSet::from([
            RemedyKind::FullRefund,
            RemedyKind::ReleaseProvider,
            RemedyKind::Split,
            RemedyKind::Repair,
            RemedyKind::Quarantine,
        ]),
        max_value_microunits: 2_000_000,
        primary_adjudicators: BTreeSet::from([
            "primary-a".to_owned(),
            "primary-b".to_owned(),
            "primary-c".to_owned(),
        ]),
        appeal_adjudicators: BTreeSet::from([
            "appeal-a".to_owned(),
            "appeal-b".to_owned(),
            "appeal-c".to_owned(),
        ]),
        primary_threshold: 2,
        appeal_threshold: 2,
        ambiguity_fallback: AmbiguityFallback::Split {
            buyer_refund_bps: 6_000,
        },
        automatic_finality: true,
    };
    let claim = Claim {
        schema: "joan.dispute-claim.v0".to_owned(),
        claim_id: "claim-001".to_owned(),
        case_id: "case-001".to_owned(),
        claimant_id: "buyer".to_owned(),
        claim_code: ClaimCode::AcceptanceFailure,
        requested_remedy: RemedyKind::FullRefund,
        evidence_refs: vec!["test-result".to_owned()],
    };
    Ok(Fixture {
        case,
        evidence,
        profile,
        claim,
    })
}

fn advance_to_evaluation(mut case: DisputeCase) -> Result<DisputeCase, Box<dyn std::error::Error>> {
    for (index, state) in [
        CaseState::IntakeValidation,
        CaseState::Accepted,
        CaseState::PreservationHold,
        CaseState::NoticeServed,
        CaseState::ResponseWindow,
        CaseState::EvidenceCollection,
        CaseState::EvidenceLocked,
        CaseState::DeterministicEvaluation,
    ]
    .into_iter()
    .enumerate()
    {
        let transition = CaseTransition {
            schema: "joan.case-transition.v0".to_owned(),
            expected_case_digest: case.case_digest.clone(),
            expected_revision: case.revision,
            from: case.state,
            to: state,
            actor_id: "case-engine".to_owned(),
            authority_ref: digest_bytes("test.authority", b"case-engine")?,
            idempotency_key: format!("case-step-{index}"),
            reason_code: "automatic-procedure".to_owned(),
            evidence_refs: Vec::new(),
        };
        case = transition_case(&case, &transition)?.0;
    }
    Ok(case)
}

fn locked_evidence() -> Result<EvidenceGraph, Box<dyn std::error::Error>> {
    let graph = create_evidence_graph("case-001")?;
    let item = EvidenceItem {
        evidence_id: "test-result".to_owned(),
        issuer_id: "test-runner".to_owned(),
        content_digest: digest_bytes("test.evidence", b"failed acceptance")?,
        source: "acceptance-suite".to_owned(),
        acquired_at_epoch_seconds: 1_786_406_400,
        content_type: "application/json".to_owned(),
        relevance_code: "acceptance-failure".to_owned(),
        confidentiality: Confidentiality::Restricted,
        verification: EvidenceVerification::Verified,
    };
    let add = evidence_request(&graph, "add", EvidenceMutation::AddItem { item })?;
    let graph = mutate_evidence(&graph, &add)?.0;
    let lock = evidence_request(&graph, "lock", EvidenceMutation::Lock)?;
    Ok(mutate_evidence(&graph, &lock)?.0)
}

fn evidence_request(
    graph: &EvidenceGraph,
    key: &str,
    mutation: EvidenceMutation,
) -> Result<EvidenceMutationRequest, Box<dyn std::error::Error>> {
    Ok(EvidenceMutationRequest {
        schema: "joan.evidence-mutation-request.v0".to_owned(),
        expected_graph_root: graph.graph_root.clone(),
        expected_revision: graph.revision,
        actor_id: "evidence-engine".to_owned(),
        authority_ref: digest_bytes("test.authority", b"evidence")?,
        idempotency_key: key.to_owned(),
        mutation,
    })
}

fn finding(
    fixture: &Fixture,
    adjudicator: &str,
    phase: DecisionPhase,
    disposition: FindingDisposition,
) -> MachineFinding {
    MachineFinding {
        schema: "joan.machine-finding.v0".to_owned(),
        adjudicator_id: adjudicator.to_owned(),
        phase,
        case_digest: fixture.case.case_digest.clone(),
        evidence_root: fixture.evidence.graph_root.clone(),
        policy_digest: fixture.profile.policy_digest.clone(),
        disposition,
        evidence_refs: if disposition == FindingDisposition::Abstain {
            Vec::new()
        } else {
            vec!["test-result".to_owned()]
        },
    }
}

fn bundle(
    fixture: &Fixture,
    findings: Vec<MachineFinding>,
    prior_decision: Option<AutomaticDecisionReceipt>,
) -> DisputeEvaluationBundle {
    DisputeEvaluationBundle {
        schema: "joan.dispute-evaluation-bundle.v0".to_owned(),
        case: fixture.case.clone(),
        evidence: fixture.evidence.clone(),
        claim: fixture.claim.clone(),
        profile: fixture.profile.clone(),
        findings,
        prior_decision,
    }
}

#[test]
fn support_quorum_upholds_claim() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let decision = evaluate_bundle(&bundle(
        &fixture,
        vec![
            finding(
                &fixture,
                "primary-a",
                DecisionPhase::Primary,
                FindingDisposition::SupportsClaim,
            ),
            finding(
                &fixture,
                "primary-b",
                DecisionPhase::Primary,
                FindingDisposition::SupportsClaim,
            ),
        ],
        None,
    ))?;
    assert_eq!(decision.status, DecisionStatus::ClaimUpheld);
    assert_eq!(decision.remedy.kind, RemedyKind::FullRefund);
    assert_eq!(decision.remedy.buyer_refund_microunits, 1_000_000);
    verify_decision(&decision)?;
    Ok(())
}

#[test]
fn rejection_quorum_releases_provider() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let decision = evaluate_bundle(&bundle(
        &fixture,
        vec![
            finding(
                &fixture,
                "primary-a",
                DecisionPhase::Primary,
                FindingDisposition::RejectsClaim,
            ),
            finding(
                &fixture,
                "primary-b",
                DecisionPhase::Primary,
                FindingDisposition::RejectsClaim,
            ),
        ],
        None,
    ))?;
    assert_eq!(decision.status, DecisionStatus::ClaimRejected);
    assert_eq!(decision.remedy.provider_release_microunits, 1_000_000);
    Ok(())
}

#[test]
fn tie_uses_precommitted_split_without_human_path() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let decision = evaluate_bundle(&bundle(
        &fixture,
        vec![
            finding(
                &fixture,
                "primary-a",
                DecisionPhase::Primary,
                FindingDisposition::SupportsClaim,
            ),
            finding(
                &fixture,
                "primary-b",
                DecisionPhase::Primary,
                FindingDisposition::RejectsClaim,
            ),
        ],
        None,
    ))?;
    assert_eq!(decision.status, DecisionStatus::FallbackApplied);
    assert_eq!(decision.remedy.buyer_refund_microunits, 600_000);
    assert_eq!(decision.remedy.provider_release_microunits, 400_000);
    Ok(())
}

#[test]
fn finding_order_does_not_change_decision() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let a = finding(
        &fixture,
        "primary-a",
        DecisionPhase::Primary,
        FindingDisposition::SupportsClaim,
    );
    let b = finding(
        &fixture,
        "primary-b",
        DecisionPhase::Primary,
        FindingDisposition::SupportsClaim,
    );
    let left = evaluate_bundle(&bundle(&fixture, vec![a.clone(), b.clone()], None))?;
    let right = evaluate_bundle(&bundle(&fixture, vec![b, a], None))?;
    assert_eq!(left, right);
    Ok(())
}

#[test]
fn overlapping_primary_and_appeal_quorums_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    fixture
        .profile
        .appeal_adjudicators
        .insert("primary-a".to_owned());
    let result = evaluate_bundle(&bundle(&fixture, Vec::new(), None));
    assert!(matches!(result, Err(DisputeError::AdjudicatorOverlap)));
    Ok(())
}

#[test]
fn finding_bound_to_other_case_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let mut invalid = finding(
        &fixture,
        "primary-a",
        DecisionPhase::Primary,
        FindingDisposition::SupportsClaim,
    );
    invalid.case_digest = digest_bytes("test.case", b"other")?;
    assert!(matches!(
        evaluate_bundle(&bundle(&fixture, vec![invalid], None)),
        Err(DisputeError::FindingBindingMismatch)
    ));
    Ok(())
}

#[test]
fn appeal_uses_disjoint_quorum_and_supersedes_primary() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let primary = evaluate_bundle(&bundle(
        &fixture,
        vec![
            finding(
                &fixture,
                "primary-a",
                DecisionPhase::Primary,
                FindingDisposition::RejectsClaim,
            ),
            finding(
                &fixture,
                "primary-b",
                DecisionPhase::Primary,
                FindingDisposition::RejectsClaim,
            ),
        ],
        None,
    ))?;
    let appeal = evaluate_bundle(&bundle(
        &fixture,
        vec![
            finding(
                &fixture,
                "appeal-a",
                DecisionPhase::Appeal,
                FindingDisposition::SupportsClaim,
            ),
            finding(
                &fixture,
                "appeal-b",
                DecisionPhase::Appeal,
                FindingDisposition::SupportsClaim,
            ),
        ],
        Some(primary.clone()),
    ))?;
    assert_eq!(appeal.status, DecisionStatus::ClaimUpheld);
    assert_eq!(appeal.supersedes, Some(primary.decision_digest));
    assert_eq!(appeal.finality_class, "automatic-appeal-final");
    Ok(())
}

#[test]
fn tampered_prior_decision_cannot_be_appealed() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let mut prior = evaluate_bundle(&bundle(&fixture, Vec::new(), None))?;
    prior.support_count = 99;
    let result = evaluate_bundle(&bundle(&fixture, Vec::new(), Some(prior)));
    assert!(matches!(result, Err(DisputeError::InvalidPriorDecision)));
    Ok(())
}
