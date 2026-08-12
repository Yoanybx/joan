//! Deterministic corpus generation and large-scale automatic-dispute simulation.

use joan_canonical::{CanonicalError, Digest, digest_bytes, digest_serializable};
use joan_case::{CaseState, CaseTransition, DisputeCase, NewCase, create_case, transition_case};
use joan_dispute::{
    AmbiguityFallback, AutomaticDecisionReceipt, AutomaticResolutionProfile, Claim, ClaimCode,
    DecisionPhase, DecisionStatus, DisputeEvaluationBundle, FindingDisposition, MachineFinding,
    RemedyKind, evaluate_bundle,
};
use joan_evidence::{
    Confidentiality, EvidenceGraph, EvidenceItem, EvidenceMutation, EvidenceMutationRequest,
    EvidenceVerification, create_evidence_graph, mutate_evidence,
};
use joan_mock_ledger::{
    ApplyDecisionRequest, LedgerError, ReserveRequest, apply_decision, create_ledger, reserve,
    verify_ledger,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const MAX_CASES: u64 = 1_000_000;

/// Deterministic simulation configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulationConfig {
    /// Schema identifier.
    pub schema: String,
    /// Reproducible pseudorandom seed.
    pub seed: u64,
    /// Number of unique contracts/cases to execute.
    pub cases: u64,
}

/// Corpus split preventing calibration/holdout contamination.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DatasetSplit {
    /// May be used to calibrate future policy thresholds.
    Calibration,
    /// Must remain untouched until evaluation.
    Holdout,
    /// Explicit attacks and pathological conditions.
    Adversarial,
}

/// Ground-truth scenario family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScenarioKind {
    /// Provider satisfied the objective contract.
    HonestProvider,
    /// Provider delivered nothing.
    NonDelivery,
    /// Provider output failed acceptance tests.
    AcceptanceFailure,
    /// A duplicate-charge claim is valid.
    DuplicateCharge,
    /// Provider exceeded a hard budget.
    BudgetExceeded,
    /// Provider exceeded granted effect scope.
    UnauthorizedScope,
    /// Settlement adapter and local receipt disagree.
    SettlementMismatch,
    /// A required repair failed.
    RepairFailure,
    /// Verified evidence is genuinely contradictory.
    ContradictoryEvidence,
    /// Primary adjudicators collude against an honest provider.
    PrimaryCollusion,
    /// A valid decision is submitted twice to the ledger.
    ReplayAttack,
    /// A finding is bound to a forged case root.
    BindingAttack,
}

/// Aggregate reproducible result from one simulation run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulationSummary {
    /// Schema identifier.
    pub schema: String,
    /// Exact configured seed.
    pub seed: u64,
    /// Requested unique cases.
    pub cases_requested: u64,
    /// Cases that completed every expected path.
    pub cases_completed: u64,
    /// Calibration split size.
    pub calibration_cases: u64,
    /// Holdout split size.
    pub holdout_cases: u64,
    /// Adversarial split size.
    pub adversarial_cases: u64,
    /// Ground-truth provider-fault count.
    pub provider_fault_cases: u64,
    /// Ground-truth invalid-claim count.
    pub invalid_claim_cases: u64,
    /// Ground-truth ambiguous count.
    pub ambiguous_cases: u64,
    /// Cases that exercised automatic appeal.
    pub appeals_executed: u64,
    /// Final decisions matching ground truth.
    pub final_correct: u64,
    /// Final decisions diverging from ground truth.
    pub final_incorrect: u64,
    /// Binding attacks rejected before decision.
    pub binding_attacks_blocked: u64,
    /// Duplicate ledger applications rejected.
    pub replay_attacks_blocked: u64,
    /// Colluding primary outcomes corrected by disjoint appeal.
    pub collusion_cases_corrected: u64,
    /// Conservation/root failures. Must remain zero.
    pub ledger_invariant_failures: u64,
    /// Digest over ordered per-case outcomes.
    pub corpus_digest: Digest,
    /// Digest over this summary excluding itself.
    pub summary_digest: Digest,
}

/// Simulation failure that prevents a valid aggregate result.
#[derive(Debug, Error)]
pub enum SimulationError {
    /// Canonical encoding or hashing failed.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    /// Case engine failed unexpectedly.
    #[error(transparent)]
    Case(#[from] joan_case::CaseError),
    /// Evidence engine failed unexpectedly.
    #[error(transparent)]
    Evidence(#[from] joan_evidence::EvidenceError),
    /// Dispute engine failed unexpectedly.
    #[error(transparent)]
    Dispute(#[from] joan_dispute::DisputeError),
    /// Mock ledger failed unexpectedly.
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    /// Unsupported configuration schema.
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(String),
    /// Requested case count is zero or above the defensive limit.
    #[error("simulation case count must be between 1 and {MAX_CASES}")]
    InvalidCaseCount,
    /// An attack that must fail unexpectedly succeeded.
    #[error("expected adversarial gate did not reject the attack")]
    AttackNotBlocked,
    /// Integer counter overflowed.
    #[error("simulation counter overflow")]
    CounterOverflow,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct CaseOutcome {
    index: u64,
    split: DatasetSplit,
    scenario: ScenarioKind,
    contract_digest: Digest,
    case_digest: Digest,
    expected_status: DecisionStatus,
    primary_status: DecisionStatus,
    final_status: DecisionStatus,
    final_correct: bool,
    decision_digest: Digest,
    ledger_root: Digest,
}

#[derive(Serialize)]
struct SummaryCore<'a> {
    schema: &'a str,
    seed: u64,
    cases_requested: u64,
    cases_completed: u64,
    calibration_cases: u64,
    holdout_cases: u64,
    adversarial_cases: u64,
    provider_fault_cases: u64,
    invalid_claim_cases: u64,
    ambiguous_cases: u64,
    appeals_executed: u64,
    final_correct: u64,
    final_incorrect: u64,
    binding_attacks_blocked: u64,
    replay_attacks_blocked: u64,
    collusion_cases_corrected: u64,
    ledger_invariant_failures: u64,
    corpus_digest: &'a Digest,
}

#[derive(Default)]
struct Counters {
    calibration_cases: u64,
    holdout_cases: u64,
    adversarial_cases: u64,
    provider_fault_cases: u64,
    invalid_claim_cases: u64,
    ambiguous_cases: u64,
    appeals_executed: u64,
    final_correct: u64,
    final_incorrect: u64,
    binding_attacks_blocked: u64,
    replay_attacks_blocked: u64,
    collusion_cases_corrected: u64,
    ledger_invariant_failures: u64,
}

struct SimulationFixture {
    case: DisputeCase,
    evidence: EvidenceGraph,
    profile: AutomaticResolutionProfile,
    claim: Claim,
    contract_digest: Digest,
}

/// Execute a deterministic corpus and return aggregate evidence only.
pub fn run_simulation(config: &SimulationConfig) -> Result<SimulationSummary, SimulationError> {
    if config.schema != "joan.dispute-simulation-config.v0" {
        return Err(SimulationError::UnsupportedSchema(config.schema.clone()));
    }
    if config.cases == 0 || config.cases > MAX_CASES {
        return Err(SimulationError::InvalidCaseCount);
    }
    let mut rng = DeterministicRng::new(config.seed);
    let mut counters = Counters::default();
    let mut cases_completed = 0_u64;
    let mut corpus_digest = digest_serializable(
        "joan.dispute-simulation-corpus-genesis.v0",
        &(config.seed, config.cases),
    )?;
    for index in 0..config.cases {
        let outcome = run_case(index, config.seed, &mut rng, &mut counters)?;
        let outcome_digest = digest_serializable("joan.dispute-simulation-case.v0", &outcome)?;
        corpus_digest = digest_serializable(
            "joan.dispute-simulation-corpus-chain.v0",
            &(index, &corpus_digest, &outcome_digest),
        )?;
        increment(&mut cases_completed)?;
    }

    build_summary(config, &counters, cases_completed, corpus_digest)
}

fn run_case(
    index: u64,
    seed: u64,
    rng: &mut DeterministicRng,
    counters: &mut Counters,
) -> Result<CaseOutcome, SimulationError> {
    let split = split_for(index);
    let scenario = scenario_for(index);
    increment_split(counters, split)?;
    increment_truth(counters, scenario)?;
    let fixture = fixture(index, seed, scenario, rng)?;
    let expected_status = expected_status(scenario);

    if scenario == ScenarioKind::BindingAttack {
        verify_binding_attack_is_blocked(index, &fixture)?;
        increment(&mut counters.binding_attacks_blocked)?;
    }

    let primary_findings = primary_findings(&fixture, scenario);
    let primary = evaluate_bundle(&primary_bundle(&fixture, primary_findings))?;
    let use_appeal = scenario == ScenarioKind::PrimaryCollusion
        || scenario == ScenarioKind::ContradictoryEvidence
        || index.is_multiple_of(5);
    let final_decision = if use_appeal {
        increment(&mut counters.appeals_executed)?;
        let appeal_findings = appeal_findings(&fixture, scenario);
        evaluate_bundle(&appeal_bundle(&fixture, appeal_findings, primary.clone()))?
    } else {
        primary.clone()
    };
    let final_correct = final_decision.status == expected_status;
    if final_correct {
        increment(&mut counters.final_correct)?;
    } else {
        increment(&mut counters.final_incorrect)?;
    }
    if scenario == ScenarioKind::PrimaryCollusion
        && primary.status != expected_status
        && final_correct
    {
        increment(&mut counters.collusion_cases_corrected)?;
    }

    let (ledger_root, replay_blocked) = settle_mock(
        index,
        &fixture.case,
        &fixture.contract_digest,
        &final_decision,
        scenario == ScenarioKind::ReplayAttack,
    )?;
    if replay_blocked {
        increment(&mut counters.replay_attacks_blocked)?;
    }
    Ok(CaseOutcome {
        index,
        split,
        scenario,
        contract_digest: fixture.contract_digest,
        case_digest: fixture.case.case_digest,
        expected_status,
        primary_status: primary.status,
        final_status: final_decision.status,
        final_correct,
        decision_digest: final_decision.decision_digest,
        ledger_root,
    })
}

fn verify_binding_attack_is_blocked(
    index: u64,
    fixture: &SimulationFixture,
) -> Result<(), SimulationError> {
    let forged = vec![finding(
        fixture,
        "primary-a",
        DecisionPhase::Primary,
        FindingDisposition::RejectsClaim,
        Some(digest_bytes(
            "joan.sim.forged-case.v0",
            &index.to_be_bytes(),
        )?),
    )];
    if matches!(
        evaluate_bundle(&primary_bundle(fixture, forged)),
        Err(joan_dispute::DisputeError::FindingBindingMismatch)
    ) {
        Ok(())
    } else {
        Err(SimulationError::AttackNotBlocked)
    }
}

fn build_summary(
    config: &SimulationConfig,
    counters: &Counters,
    cases_completed: u64,
    corpus_digest: Digest,
) -> Result<SimulationSummary, SimulationError> {
    let schema = "joan.dispute-simulation-summary.v0";
    let mut summary = SimulationSummary {
        schema: schema.to_owned(),
        seed: config.seed,
        cases_requested: config.cases,
        cases_completed,
        calibration_cases: counters.calibration_cases,
        holdout_cases: counters.holdout_cases,
        adversarial_cases: counters.adversarial_cases,
        provider_fault_cases: counters.provider_fault_cases,
        invalid_claim_cases: counters.invalid_claim_cases,
        ambiguous_cases: counters.ambiguous_cases,
        appeals_executed: counters.appeals_executed,
        final_correct: counters.final_correct,
        final_incorrect: counters.final_incorrect,
        binding_attacks_blocked: counters.binding_attacks_blocked,
        replay_attacks_blocked: counters.replay_attacks_blocked,
        collusion_cases_corrected: counters.collusion_cases_corrected,
        ledger_invariant_failures: counters.ledger_invariant_failures,
        corpus_digest,
        summary_digest: placeholder_digest(),
    };
    summary.summary_digest = digest_serializable(
        "joan.dispute-simulation-summary.v0",
        &SummaryCore {
            schema,
            seed: summary.seed,
            cases_requested: summary.cases_requested,
            cases_completed: summary.cases_completed,
            calibration_cases: summary.calibration_cases,
            holdout_cases: summary.holdout_cases,
            adversarial_cases: summary.adversarial_cases,
            provider_fault_cases: summary.provider_fault_cases,
            invalid_claim_cases: summary.invalid_claim_cases,
            ambiguous_cases: summary.ambiguous_cases,
            appeals_executed: summary.appeals_executed,
            final_correct: summary.final_correct,
            final_incorrect: summary.final_incorrect,
            binding_attacks_blocked: summary.binding_attacks_blocked,
            replay_attacks_blocked: summary.replay_attacks_blocked,
            collusion_cases_corrected: summary.collusion_cases_corrected,
            ledger_invariant_failures: summary.ledger_invariant_failures,
            corpus_digest: &summary.corpus_digest,
        },
    )?;
    Ok(summary)
}

fn fixture(
    index: u64,
    seed: u64,
    scenario: ScenarioKind,
    rng: &mut DeterministicRng,
) -> Result<SimulationFixture, SimulationError> {
    let contract_digest = digest_serializable(
        "joan.sim.contract.v0",
        &(seed, index, scenario, rng.next_u64()),
    )?;
    let policy_digest =
        digest_serializable("joan.sim.policy.v0", &(seed, index, 2_u64, rng.next_u64()))?;
    let value = 10_000_u64
        .checked_add(rng.next_u64() % 990_001)
        .ok_or(SimulationError::CounterOverflow)?;
    let case = create_case(&NewCase {
        schema: "joan.new-dispute-case.v0".to_owned(),
        case_id: format!("sim-case-{seed}-{index}"),
        contract_digest: contract_digest.clone(),
        transaction_digest: digest_serializable(
            "joan.sim.transaction.v0",
            &(seed, index, rng.next_u64()),
        )?,
        claimant_id: format!("buyer-{}", index % 97),
        respondent_id: format!("provider-{}", index % 89),
        policy_digest: policy_digest.clone(),
        value_microunits: value,
    })?;
    let case = advance_to_evaluation(case, index)?;
    let evidence = locked_evidence(&case.case_id, index, scenario)?;
    let claim_code = claim_code(scenario, index);
    let requested_remedy = match rng.next_u64() % 3 {
        0 => RemedyKind::FullRefund,
        1 => RemedyKind::Repair,
        _ => RemedyKind::Quarantine,
    };
    let fallback_bps = u16::try_from(2_500_u64 + (rng.next_u64() % 5_001))
        .map_err(|_| SimulationError::CounterOverflow)?;
    let profile = AutomaticResolutionProfile {
        schema: "joan.automatic-resolution-profile.v0".to_owned(),
        policy_digest,
        eligible_claim_codes: BTreeSet::from([
            ClaimCode::NonDelivery,
            ClaimCode::AcceptanceFailure,
            ClaimCode::DuplicateCharge,
            ClaimCode::BudgetExceeded,
            ClaimCode::UnauthorizedScope,
            ClaimCode::SettlementMismatch,
            ClaimCode::RepairFailure,
        ]),
        allowed_remedies: BTreeSet::from([
            RemedyKind::FullRefund,
            RemedyKind::ReleaseProvider,
            RemedyKind::Split,
            RemedyKind::Repair,
            RemedyKind::Quarantine,
        ]),
        max_value_microunits: 1_000_000,
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
            buyer_refund_bps: fallback_bps,
        },
        automatic_finality: true,
    };
    let claim = Claim {
        schema: "joan.dispute-claim.v0".to_owned(),
        claim_id: format!("claim-{seed}-{index}"),
        case_id: case.case_id.clone(),
        claimant_id: case.claimant_id.clone(),
        claim_code,
        requested_remedy,
        evidence_refs: vec!["primary-evidence".to_owned()],
    };
    Ok(SimulationFixture {
        case,
        evidence,
        profile,
        claim,
        contract_digest,
    })
}

fn advance_to_evaluation(
    mut case: DisputeCase,
    index: u64,
) -> Result<DisputeCase, SimulationError> {
    for (step, state) in [
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
        let request = CaseTransition {
            schema: "joan.case-transition.v0".to_owned(),
            expected_case_digest: case.case_digest.clone(),
            expected_revision: case.revision,
            from: case.state,
            to: state,
            actor_id: "simulation-case-engine".to_owned(),
            authority_ref: digest_bytes("joan.sim.authority.v0", &index.to_be_bytes())?,
            idempotency_key: format!("case-{index}-step-{step}"),
            reason_code: "simulation-procedure".to_owned(),
            evidence_refs: Vec::new(),
        };
        case = transition_case(&case, &request)?.0;
    }
    Ok(case)
}

fn locked_evidence(
    case_id: &str,
    index: u64,
    scenario: ScenarioKind,
) -> Result<EvidenceGraph, SimulationError> {
    let graph = create_evidence_graph(case_id)?;
    let item = EvidenceItem {
        evidence_id: "primary-evidence".to_owned(),
        issuer_id: "simulation-ground-truth".to_owned(),
        content_digest: digest_serializable(
            "joan.sim.evidence.v0",
            &(index, scenario, "ground-truth"),
        )?,
        source: "deterministic-simulation".to_owned(),
        acquired_at_epoch_seconds: 1_786_406_400_u64.saturating_add(index),
        content_type: "application/joan-simulation+json".to_owned(),
        relevance_code: format!("scenario-{scenario:?}"),
        confidentiality: Confidentiality::Restricted,
        verification: EvidenceVerification::Verified,
    };
    let add = evidence_request(&graph, index, "add", EvidenceMutation::AddItem { item })?;
    let graph = mutate_evidence(&graph, &add)?.0;
    let lock = evidence_request(&graph, index, "lock", EvidenceMutation::Lock)?;
    Ok(mutate_evidence(&graph, &lock)?.0)
}

fn evidence_request(
    graph: &EvidenceGraph,
    index: u64,
    action: &str,
    mutation: EvidenceMutation,
) -> Result<EvidenceMutationRequest, CanonicalError> {
    Ok(EvidenceMutationRequest {
        schema: "joan.evidence-mutation-request.v0".to_owned(),
        expected_graph_root: graph.graph_root.clone(),
        expected_revision: graph.revision,
        actor_id: "simulation-evidence-engine".to_owned(),
        authority_ref: digest_bytes("joan.sim.evidence-authority.v0", &index.to_be_bytes())?,
        idempotency_key: format!("evidence-{index}-{action}"),
        mutation,
    })
}

fn primary_findings(fixture: &SimulationFixture, scenario: ScenarioKind) -> Vec<MachineFinding> {
    let disposition = match expected_status(scenario) {
        DecisionStatus::ClaimUpheld => FindingDisposition::SupportsClaim,
        DecisionStatus::ClaimRejected => {
            if scenario == ScenarioKind::PrimaryCollusion {
                FindingDisposition::SupportsClaim
            } else {
                FindingDisposition::RejectsClaim
            }
        }
        DecisionStatus::FallbackApplied => FindingDisposition::Abstain,
    };
    if scenario == ScenarioKind::ContradictoryEvidence {
        vec![
            finding(
                fixture,
                "primary-a",
                DecisionPhase::Primary,
                FindingDisposition::SupportsClaim,
                None,
            ),
            finding(
                fixture,
                "primary-b",
                DecisionPhase::Primary,
                FindingDisposition::RejectsClaim,
                None,
            ),
            finding(
                fixture,
                "primary-c",
                DecisionPhase::Primary,
                FindingDisposition::Abstain,
                None,
            ),
        ]
    } else {
        vec![
            finding(
                fixture,
                "primary-a",
                DecisionPhase::Primary,
                disposition,
                None,
            ),
            finding(
                fixture,
                "primary-b",
                DecisionPhase::Primary,
                disposition,
                None,
            ),
        ]
    }
}

fn appeal_findings(fixture: &SimulationFixture, scenario: ScenarioKind) -> Vec<MachineFinding> {
    let disposition = match expected_status(scenario) {
        DecisionStatus::ClaimUpheld => FindingDisposition::SupportsClaim,
        DecisionStatus::ClaimRejected => FindingDisposition::RejectsClaim,
        DecisionStatus::FallbackApplied => FindingDisposition::Abstain,
    };
    if scenario == ScenarioKind::ContradictoryEvidence {
        vec![
            finding(
                fixture,
                "appeal-a",
                DecisionPhase::Appeal,
                FindingDisposition::SupportsClaim,
                None,
            ),
            finding(
                fixture,
                "appeal-b",
                DecisionPhase::Appeal,
                FindingDisposition::RejectsClaim,
                None,
            ),
        ]
    } else {
        vec![
            finding(
                fixture,
                "appeal-a",
                DecisionPhase::Appeal,
                disposition,
                None,
            ),
            finding(
                fixture,
                "appeal-b",
                DecisionPhase::Appeal,
                disposition,
                None,
            ),
        ]
    }
}

fn finding(
    fixture: &SimulationFixture,
    id: &str,
    phase: DecisionPhase,
    disposition: FindingDisposition,
    forged_case_digest: Option<Digest>,
) -> MachineFinding {
    MachineFinding {
        schema: "joan.machine-finding.v0".to_owned(),
        adjudicator_id: id.to_owned(),
        phase,
        case_digest: forged_case_digest.unwrap_or_else(|| fixture.case.case_digest.clone()),
        evidence_root: fixture.evidence.graph_root.clone(),
        policy_digest: fixture.profile.policy_digest.clone(),
        disposition,
        evidence_refs: if disposition == FindingDisposition::Abstain {
            Vec::new()
        } else {
            vec!["primary-evidence".to_owned()]
        },
    }
}

fn primary_bundle(
    fixture: &SimulationFixture,
    findings: Vec<MachineFinding>,
) -> DisputeEvaluationBundle {
    bundle(fixture, findings, None)
}

fn appeal_bundle(
    fixture: &SimulationFixture,
    findings: Vec<MachineFinding>,
    prior: AutomaticDecisionReceipt,
) -> DisputeEvaluationBundle {
    bundle(fixture, findings, Some(prior))
}

fn bundle(
    fixture: &SimulationFixture,
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

fn settle_mock(
    index: u64,
    case: &DisputeCase,
    contract_digest: &Digest,
    decision: &AutomaticDecisionReceipt,
    test_replay: bool,
) -> Result<(Digest, bool), SimulationError> {
    let buyer_funds = case
        .value_microunits
        .checked_mul(2)
        .ok_or(SimulationError::CounterOverflow)?;
    let ledger = create_ledger(BTreeMap::from([
        (case.claimant_id.clone(), buyer_funds),
        (case.respondent_id.clone(), 0),
    ]))?;
    let reserve_request = ReserveRequest {
        schema: "joan.mock-reserve-request.v0".to_owned(),
        expected_ledger_root: ledger.ledger_root.clone(),
        expected_revision: ledger.revision,
        hold_id: format!("sim-hold-{index}"),
        buyer_id: case.claimant_id.clone(),
        provider_id: case.respondent_id.clone(),
        contract_digest: contract_digest.clone(),
        amount_microunits: case.value_microunits,
        idempotency_key: format!("sim-reserve-{index}"),
    };
    let reserved = reserve(&ledger, &reserve_request)?.0;
    let apply_request = ApplyDecisionRequest {
        schema: "joan.mock-apply-decision-request.v0".to_owned(),
        expected_ledger_root: reserved.ledger_root.clone(),
        expected_revision: reserved.revision,
        hold_id: format!("sim-hold-{index}"),
        idempotency_key: format!("sim-decision-{index}"),
        decision: decision.clone(),
    };
    let resolved = apply_decision(&reserved, &apply_request)?.0;
    verify_ledger(&resolved)?;
    let replay_blocked = if test_replay {
        let replay = ApplyDecisionRequest {
            expected_ledger_root: resolved.ledger_root.clone(),
            expected_revision: resolved.revision,
            idempotency_key: format!("sim-decision-replay-{index}"),
            ..apply_request
        };
        if !matches!(
            apply_decision(&resolved, &replay),
            Err(LedgerError::HoldNotReserved)
        ) {
            return Err(SimulationError::AttackNotBlocked);
        }
        true
    } else {
        false
    };
    Ok((resolved.ledger_root, replay_blocked))
}

fn expected_status(scenario: ScenarioKind) -> DecisionStatus {
    match scenario {
        ScenarioKind::HonestProvider
        | ScenarioKind::PrimaryCollusion
        | ScenarioKind::BindingAttack => DecisionStatus::ClaimRejected,
        ScenarioKind::ContradictoryEvidence => DecisionStatus::FallbackApplied,
        ScenarioKind::NonDelivery
        | ScenarioKind::AcceptanceFailure
        | ScenarioKind::DuplicateCharge
        | ScenarioKind::BudgetExceeded
        | ScenarioKind::UnauthorizedScope
        | ScenarioKind::SettlementMismatch
        | ScenarioKind::RepairFailure
        | ScenarioKind::ReplayAttack => DecisionStatus::ClaimUpheld,
    }
}

fn claim_code(scenario: ScenarioKind, index: u64) -> ClaimCode {
    match scenario {
        ScenarioKind::NonDelivery | ScenarioKind::ReplayAttack => ClaimCode::NonDelivery,
        ScenarioKind::AcceptanceFailure
        | ScenarioKind::HonestProvider
        | ScenarioKind::ContradictoryEvidence
        | ScenarioKind::PrimaryCollusion
        | ScenarioKind::BindingAttack => ClaimCode::AcceptanceFailure,
        ScenarioKind::DuplicateCharge => ClaimCode::DuplicateCharge,
        ScenarioKind::BudgetExceeded => ClaimCode::BudgetExceeded,
        ScenarioKind::UnauthorizedScope => ClaimCode::UnauthorizedScope,
        ScenarioKind::SettlementMismatch => ClaimCode::SettlementMismatch,
        ScenarioKind::RepairFailure => ClaimCode::RepairFailure,
    }
    .rotate(index)
}

trait RotateClaimCode {
    fn rotate(self, index: u64) -> Self;
}

impl RotateClaimCode for ClaimCode {
    fn rotate(self, index: u64) -> Self {
        if index.is_multiple_of(17) && self == Self::AcceptanceFailure {
            Self::NonDelivery
        } else {
            self
        }
    }
}

fn split_for(index: u64) -> DatasetSplit {
    match index % 10 {
        0..=6 => DatasetSplit::Calibration,
        7 | 8 => DatasetSplit::Holdout,
        _ => DatasetSplit::Adversarial,
    }
}

fn scenario_for(index: u64) -> ScenarioKind {
    match index % 12 {
        0 => ScenarioKind::HonestProvider,
        1 => ScenarioKind::NonDelivery,
        2 => ScenarioKind::AcceptanceFailure,
        3 => ScenarioKind::DuplicateCharge,
        4 => ScenarioKind::BudgetExceeded,
        5 => ScenarioKind::UnauthorizedScope,
        6 => ScenarioKind::SettlementMismatch,
        7 => ScenarioKind::RepairFailure,
        8 => ScenarioKind::ContradictoryEvidence,
        9 => ScenarioKind::PrimaryCollusion,
        10 => ScenarioKind::ReplayAttack,
        _ => ScenarioKind::BindingAttack,
    }
}

fn increment_split(counters: &mut Counters, split: DatasetSplit) -> Result<(), SimulationError> {
    match split {
        DatasetSplit::Calibration => increment(&mut counters.calibration_cases),
        DatasetSplit::Holdout => increment(&mut counters.holdout_cases),
        DatasetSplit::Adversarial => increment(&mut counters.adversarial_cases),
    }
}

fn increment_truth(counters: &mut Counters, scenario: ScenarioKind) -> Result<(), SimulationError> {
    match expected_status(scenario) {
        DecisionStatus::ClaimUpheld => increment(&mut counters.provider_fault_cases),
        DecisionStatus::ClaimRejected => increment(&mut counters.invalid_claim_cases),
        DecisionStatus::FallbackApplied => increment(&mut counters.ambiguous_cases),
    }
}

fn increment(counter: &mut u64) -> Result<(), SimulationError> {
    *counter = counter
        .checked_add(1)
        .ok_or(SimulationError::CounterOverflow)?;
    Ok(())
}

struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x4a4f_414e_4a44_5231,
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.state
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
