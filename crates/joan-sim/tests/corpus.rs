//! Large deterministic dispute-corpus tests.

use joan_sim::{SimulationConfig, run_simulation};

#[test]
fn ten_thousand_unique_contract_disputes_complete() -> Result<(), Box<dyn std::error::Error>> {
    let summary = run_simulation(&SimulationConfig {
        schema: "joan.dispute-simulation-config.v0".to_owned(),
        seed: 144,
        cases: 10_000,
    })?;
    assert_eq!(summary.cases_completed, 10_000);
    assert_eq!(summary.final_incorrect, 0);
    assert_eq!(summary.ledger_invariant_failures, 0);
    assert!(summary.binding_attacks_blocked > 800);
    assert!(summary.replay_attacks_blocked > 800);
    assert!(summary.collusion_cases_corrected > 800);
    Ok(())
}

#[test]
fn same_seed_produces_identical_corpus_digest() -> Result<(), Box<dyn std::error::Error>> {
    let config = SimulationConfig {
        schema: "joan.dispute-simulation-config.v0".to_owned(),
        seed: 99,
        cases: 120,
    };
    assert_eq!(run_simulation(&config)?, run_simulation(&config)?);
    Ok(())
}

#[test]
fn different_seed_changes_corpus_digest() -> Result<(), Box<dyn std::error::Error>> {
    let left = run_simulation(&SimulationConfig {
        schema: "joan.dispute-simulation-config.v0".to_owned(),
        seed: 1,
        cases: 120,
    })?;
    let right = run_simulation(&SimulationConfig {
        schema: "joan.dispute-simulation-config.v0".to_owned(),
        seed: 2,
        cases: 120,
    })?;
    assert_ne!(left.corpus_digest, right.corpus_digest);
    Ok(())
}
