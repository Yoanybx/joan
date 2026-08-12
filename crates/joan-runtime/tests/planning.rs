//! One-use effect authority and atomic planning tests.

use joan_ast::InformationLabel;
use joan_compiler::{Value, execute_source};
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
                authority_slot: request.authority_slot.clone(),
                information: request.information.clone(),
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

#[test]
fn linear_slot_must_match_the_exact_one_shot_approval() -> Result<(), Box<dyn std::error::Error>> {
    let execution = execute_source(
        r#"
module linear;
fn main() -> unit effects [api_call] authorities [provider_once: api_call] {
  request api_call("provider-a") using provider_once;
  return;
}
"#,
    )?;
    let mut exact = authority(&execution);
    let mut ledger = CapabilityLedger::default();
    let receipt = plan_effects(&execution, Some(&exact), &mut ledger)?;
    assert_eq!(
        receipt.effects[0].authority_slot.as_deref(),
        Some("provider_once")
    );

    exact.approvals[0].authority_slot = Some("different_slot".to_owned());
    let mut fresh_ledger = CapabilityLedger::default();
    let Err(error) = plan_effects(&execution, Some(&exact), &mut fresh_ledger) else {
        return Err("mismatched linear slot unexpectedly authorized".into());
    };
    assert!(matches!(error, RuntimePlanError::MissingApproval(_)));
    assert!(fresh_ledger.is_empty());
    Ok(())
}

#[test]
fn linear_receipt_cannot_be_downgraded_before_planning() -> Result<(), Box<dyn std::error::Error>> {
    let mut execution = execute_source(
        r#"
module linear;
fn main() -> unit effects [api_call] authorities [provider_once: api_call] {
  request api_call("provider-a") using provider_once;
  return;
}
"#,
    )?;
    execution.effect_requests[0].authority_slot = None;
    let authority = authority(&execution);
    let mut ledger = CapabilityLedger::default();
    let Err(error) = plan_effects(&execution, Some(&authority), &mut ledger) else {
        return Err("downgraded linear receipt unexpectedly planned".into());
    };
    assert!(matches!(error, RuntimePlanError::ProfileMismatch));
    assert!(ledger.is_empty());
    Ok(())
}

#[test]
fn linear_approval_is_bound_to_payload_and_request_order() -> Result<(), Box<dyn std::error::Error>>
{
    let original = execute_source(
        r#"
module linear;
fn main() -> unit effects [api_call] authorities [first: api_call, second: api_call] {
  request api_call("provider-a") using first;
  request api_call("provider-b") using second;
  return;
}
"#,
    )?;
    let authority = authority(&original);

    let mut tampered_payload = original.clone();
    tampered_payload.effect_requests[0].arguments[0] = Value::String("changed".to_owned());
    let mut ledger = CapabilityLedger::default();
    let Err(error) = plan_effects(&tampered_payload, Some(&authority), &mut ledger) else {
        return Err("tampered linear payload unexpectedly planned".into());
    };
    assert!(matches!(error, RuntimePlanError::InvalidRequest(_)));
    assert!(ledger.is_empty());

    let mut reordered = original;
    reordered.effect_requests.swap(0, 1);
    let mut ledger = CapabilityLedger::default();
    let Err(error) = plan_effects(&reordered, Some(&authority), &mut ledger) else {
        return Err("reordered linear requests unexpectedly planned".into());
    };
    assert!(matches!(error, RuntimePlanError::InvalidRequest(_)));
    assert!(ledger.is_empty());
    Ok(())
}

#[test]
fn flow_approval_is_bound_to_exact_tenant_and_purpose() -> Result<(), Box<dyn std::error::Error>> {
    let execution = execute_source(
        r#"
module secure flow;
fn main() -> unit flow [public] effects [api_call] authorities [call_once: api_call] {
  let payload: string flow [secret, tenant:agent_a, purpose:handoff] = "classified";
  request api_call(payload) using call_once flow [secret, tenant:agent_a, purpose:handoff];
  return;
}
"#,
    )?;
    let exact = authority(&execution);
    let mut ledger = CapabilityLedger::default();
    let receipt = plan_effects(&execution, Some(&exact), &mut ledger)?;
    assert_eq!(receipt.schema, "joan.effect-plan-receipt.v1");
    assert_eq!(
        receipt.effects[0].information,
        execution.effect_requests[0].information
    );

    let mut wrong_purpose = authority(&execution);
    wrong_purpose.approvals[0].information = Some(InformationLabel::Secret {
        tenant: "agent_a".to_owned(),
        purpose: "billing".to_owned(),
    });
    let mut fresh_ledger = CapabilityLedger::default();
    let Err(error) = plan_effects(&execution, Some(&wrong_purpose), &mut fresh_ledger) else {
        return Err("wrong-purpose approval unexpectedly authorized".into());
    };
    assert!(matches!(error, RuntimePlanError::MissingApproval(_)));
    assert!(fresh_ledger.is_empty());

    let mut tampered = execution;
    tampered.effect_requests[0].information = Some(InformationLabel::Public);
    let mut fresh_ledger = CapabilityLedger::default();
    let Err(error) = plan_effects(&tampered, Some(&exact), &mut fresh_ledger) else {
        return Err("tampered request information unexpectedly planned".into());
    };
    assert!(matches!(error, RuntimePlanError::InvalidRequest(_)));
    assert!(fresh_ledger.is_empty());
    Ok(())
}
