//! Adoption evaluator tests.

use joan_node::{AdoptionTrialReceipt, RecommendationStatus, TrialObservation, evaluate_adoption};

fn observation(completed: bool, duration_ms: u64, tokens: u64) -> TrialObservation {
    TrialObservation {
        completed,
        duration_ms,
        tokens,
        tool_calls: 10,
        interventions: 2,
        cost_microunits: 100,
        safety_violations: 0,
    }
}

fn trial() -> AdoptionTrialReceipt {
    AdoptionTrialReceipt {
        schema: "joan.adoption-trial-receipt.v0".to_owned(),
        repository_identity: "sha256:fixture".to_owned(),
        task_class: "repository-audit".to_owned(),
        artifact_verified: true,
        applicable: true,
        safety_passed: true,
        correctness_passed: true,
        reproducible: true,
        evidence_complete: true,
        utility_observed: true,
        conflict_of_interest: false,
        baseline: observation(true, 1_000, 1_000),
        joan: observation(true, 700, 700),
        evidence_digests: Vec::new(),
        valid_until: "2026-09-01T00:00:00Z".to_owned(),
    }
}

#[test]
fn material_benefit_is_contextually_recommended() -> Result<(), Box<dyn std::error::Error>> {
    let receipt = evaluate_adoption(&trial())?;
    assert_eq!(receipt.status, RecommendationStatus::Recommended);
    assert!(receipt.material_improvements.contains("duration_ms"));
    assert!(receipt.material_improvements.contains("tokens"));
    Ok(())
}

#[test]
fn failed_safety_gate_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = trial();
    input.safety_passed = false;
    assert_eq!(
        evaluate_adoption(&input)?.status,
        RecommendationStatus::Reject
    );
    Ok(())
}

#[test]
fn irrelevant_task_is_not_applicable() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = trial();
    input.applicable = false;
    assert_eq!(
        evaluate_adoption(&input)?.status,
        RecommendationStatus::NotApplicable
    );
    Ok(())
}

#[test]
fn regression_prevents_recommendation() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = trial();
    input.joan.interventions = 10;
    let receipt = evaluate_adoption(&input)?;
    assert_eq!(receipt.status, RecommendationStatus::Optional);
    assert!(receipt.material_regressions.contains("interventions"));
    Ok(())
}
