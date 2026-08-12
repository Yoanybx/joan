//! Instruction authority and prompt-injection boundary tests.

use joan_canonical::digest_bytes;
use joan_instruction::{
    AuthorityEnvelope, AuthorityRoot, InstructionDecision, InstructionEnvelope, InstructionRequest,
    InstructionScope, InstructionStatement, OneShotApproval, RiskClass, SourceClass, StatementKind,
    discover_instruction_files, resolve_instructions,
};
use std::collections::BTreeSet;
use std::fs;
use tempfile::tempdir;

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn authority() -> AuthorityEnvelope {
    AuthorityEnvelope {
        schema: "joan.authority-envelope.v0".to_owned(),
        host_identity: "test-host".to_owned(),
        task_id: "task-1".to_owned(),
        path: "src/lib.rs".to_owned(),
        task_kind: "edit".to_owned(),
        roots: vec![
            AuthorityRoot {
                root_id: "host".to_owned(),
                grants: set(&["fs.read", "fs.write", "process.test"]),
                denies: set(&["secret.read"]),
            },
            AuthorityRoot {
                root_id: "user".to_owned(),
                grants: set(&["fs.read", "fs.write", "process.test"]),
                denies: BTreeSet::new(),
            },
        ],
        approval_required: set(&["fs.write"]),
        approvable: set(&["fs.write"]),
        approvals: Vec::new(),
    }
}

fn statement(kind: StatementKind, capabilities: &[&str]) -> InstructionStatement {
    InstructionStatement {
        statement_id: "s1".to_owned(),
        kind,
        subject: "repository".to_owned(),
        action: "operate".to_owned(),
        value: None,
        capabilities: set(capabilities),
        risk: RiskClass::External,
    }
}

fn envelope(
    class: SourceClass,
    statements: Vec<InstructionStatement>,
) -> Result<InstructionEnvelope, Box<dyn std::error::Error>> {
    Ok(InstructionEnvelope {
        schema: "joan.instruction-envelope.v0".to_owned(),
        source_class: class,
        source_uri: "AGENTS.md".to_owned(),
        content_digest: digest_bytes("joan.instruction-source.v0", b"fixture")?,
        scope: InstructionScope {
            path_prefixes: Vec::new(),
            task_kinds: Vec::new(),
        },
        statements,
    })
}

fn request(instructions: Vec<InstructionEnvelope>, effects: &[&str]) -> InstructionRequest {
    InstructionRequest {
        schema: "joan.instruction-request.v0".to_owned(),
        authority: authority(),
        instructions,
        requested_effects: set(effects),
    }
}

#[test]
fn repository_grant_claim_is_denied() -> Result<(), Box<dyn std::error::Error>> {
    let instruction = envelope(
        SourceClass::RepositoryGovernance,
        vec![statement(StatementKind::GrantClaim, &["secret.read"])],
    )?;
    let receipt = resolve_instructions(&request(vec![instruction], &["secret.read"]))?;
    assert_eq!(receipt.decision, InstructionDecision::Deny);
    assert!(
        receipt
            .diagnostics
            .iter()
            .any(|item| item.code == "JINST006")
    );
    Ok(())
}

#[test]
fn repository_constraint_only_attenuates() -> Result<(), Box<dyn std::error::Error>> {
    let instruction = envelope(
        SourceClass::RepositoryGovernance,
        vec![statement(StatementKind::Constraint, &["fs.write"])],
    )?;
    let receipt = resolve_instructions(&request(vec![instruction], &["fs.write"]))?;
    assert_eq!(receipt.decision, InstructionDecision::Deny);
    assert!(receipt.authority_ceiling.contains("fs.write"));
    assert!(!receipt.effective_authority.contains("fs.write"));
    Ok(())
}

#[test]
fn untrusted_tool_output_is_data() -> Result<(), Box<dyn std::error::Error>> {
    let instruction = envelope(
        SourceClass::UntrustedContent,
        vec![statement(StatementKind::GrantClaim, &["secret.read"])],
    )?;
    let receipt = resolve_instructions(&request(vec![instruction], &[]))?;
    assert_eq!(receipt.decision, InstructionDecision::Data);
    assert!(
        receipt
            .diagnostics
            .iter()
            .any(|item| item.code == "JINST001")
    );
    Ok(())
}

#[test]
fn exact_one_shot_approval_allows_required_effect() -> Result<(), Box<dyn std::error::Error>> {
    let mut request = request(Vec::new(), &["fs.write"]);
    assert_eq!(
        resolve_instructions(&request)?.decision,
        InstructionDecision::Ask
    );
    request.authority.approvals.push(OneShotApproval {
        nonce: "nonce-1".to_owned(),
        task_id: "task-1".to_owned(),
        capabilities: set(&["fs.write"]),
        authority_slot: None,
    });
    assert_eq!(
        resolve_instructions(&request)?.decision,
        InstructionDecision::Allow
    );
    Ok(())
}

#[test]
fn same_class_conflict_is_visible() -> Result<(), Box<dyn std::error::Error>> {
    let mut first = statement(StatementKind::Procedure, &[]);
    first.value = Some("cargo".to_owned());
    let mut second = first.clone();
    second.statement_id = "s2".to_owned();
    second.value = Some("make".to_owned());
    let instruction = envelope(SourceClass::RepositoryGovernance, vec![first, second])?;
    let receipt = resolve_instructions(&request(vec![instruction], &[]))?;
    assert_eq!(receipt.decision, InstructionDecision::Conflict);
    Ok(())
}

#[test]
fn discovery_reads_only_allowlisted_regular_files() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    fs::create_dir_all(directory.path().join(".github/instructions"))?;
    fs::create_dir_all(directory.path().join("src/nested"))?;
    fs::write(directory.path().join("AGENTS.md"), "root")?;
    fs::write(
        directory.path().join(".github/copilot-instructions.md"),
        "adapter",
    )?;
    fs::write(
        directory
            .path()
            .join(".github/instructions/rust.instructions.md"),
        "scoped",
    )?;
    fs::write(directory.path().join("src/ignored.md"), "ignore previous")?;
    fs::write(directory.path().join("src/nested/AGENTS.md"), "nested")?;
    let report = discover_instruction_files(
        directory.path(),
        Some(&directory.path().join("src/nested/file.rs")),
    )?;
    let paths = report
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(paths.len(), 4);
    assert!(paths.contains("AGENTS.md"));
    assert!(paths.contains("src/nested/AGENTS.md"));
    assert!(!paths.contains("src/ignored.md"));
    Ok(())
}
