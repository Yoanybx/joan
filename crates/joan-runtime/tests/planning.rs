//! One-use effect authority and atomic planning tests.

use joan_compiler::execute_source;
use joan_instruction::{AuthorityEnvelope, AuthorityRoot, OneShotApproval};
use joan_runtime::{CapabilityLedger, RuntimePlanError, plan_effects};
use std::collections::BTreeSet;

fn execution() -> Result<joan_compiler::ExecutionReceipt, Box<dyn std::error::Error>> {
    Ok(execute_source(
        r#"
module calls;
fn main() -> i64 effects [api_call] {
  request api_call("provider-a", 1);
  request api_call("provider-b", 2);
  return 2;
}
"#,
    )?)
}

fn authority(execution: &joan_compiler::ExecutionReceipt) -> AuthorityEnvelope {
    AuthorityEnvelope {
        schema: "joan.authority-envelope.v0".to_owned(),
        host_identity: "test-host".to_owned(),
        task_id: execution.semantic_digest.value.clone(),
        path: "examples/calls.joan".to_owned(),
        task_kind: "agent-api-plan".to_owned(),
        roots: vec![AuthorityRoot {
            root_id: "operator".to_owned(),
            grants: BTreeSet::from(["api_call".to_owned()]),
            denies: BTreeSet::new(),
        }],
        approval_required: BTreeSet::from(["api_call".to_owned()]),
        approvable: BTreeSet::new(),
        approvals: execution
            .effect_requests
            .iter()
            .map(|request| OneShotApproval {
                nonce: request.request_id.clone(),
                task_id: execution.semantic_digest.value.clone(),
                capabilities: BTreeSet::from([request.effect.clone()]),
            })
            .collect(),
    }
}

#[test]
fn exact_approvals_are_consumed_atomically() -> Result<(), Box<dyn std::error::Error>> {
    let execution = execution()?;
    let authority = authority(&execution);
    let mut ledger = CapabilityLedger::default();
    let receipt = plan_effects(&execution, Some(&authority), &mut ledger)?;
    assert_eq!(receipt.status, "authorized");
    assert_eq!(receipt.effects.len(), 2);
    assert_eq!(ledger.len(), 2);
    Ok(())
}

#[test]
fn replay_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let execution = execution()?;
    let authority = authority(&execution);
    let mut ledger = CapabilityLedger::default();
    plan_effects(&execution, Some(&authority), &mut ledger)?;
    let Err(error) = plan_effects(&execution, Some(&authority), &mut ledger) else {
        return Err("approval replay unexpectedly succeeded".into());
    };
    assert!(matches!(error, RuntimePlanError::Replay(_)));
    Ok(())
}

#[test]
fn missing_second_approval_consumes_nothing() -> Result<(), Box<dyn std::error::Error>> {
    let execution = execution()?;
    let mut authority = authority(&execution);
    authority.approvals.pop();
    let mut ledger = CapabilityLedger::default();
    let Err(error) = plan_effects(&execution, Some(&authority), &mut ledger) else {
        return Err("partial authority unexpectedly succeeded".into());
    };
    assert!(matches!(error, RuntimePlanError::MissingApproval(_)));
    assert!(ledger.is_empty());
    Ok(())
}

#[test]
fn pure_execution_needs_no_authority() -> Result<(), Box<dyn std::error::Error>> {
    let execution = execute_source(
        r"
module pure;
fn main() -> i64 effects [] { return 42; }
",
    )?;
    let mut ledger = CapabilityLedger::default();
    let receipt = plan_effects(&execution, None, &mut ledger)?;
    assert_eq!(receipt.status, "pure");
    assert!(receipt.effects.is_empty());
    assert!(ledger.is_empty());
    Ok(())
}
