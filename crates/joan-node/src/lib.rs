//! Local JOAN node facade, repository inspection and adoption evaluation.

use joan_canonical::{CanonicalError, Digest, digest_bytes, digest_serializable};
use joan_guardian::{
    GuardianCandidate, GuardianOutcome, GuardianRole, GuardianVote, VoteDecision,
    evaluate_candidate,
};
use joan_instruction::{
    AuthorityEnvelope, AuthorityRoot, DiscoveryReport, InstructionDecision,
    InstructionDecisionReceipt, InstructionEnvelope, InstructionRequest, InstructionScope,
    InstructionStatement, RiskClass, SourceClass, StatementKind, discover_instruction_files,
    resolve_instructions,
};
use joan_patch::{PatchOperation, SemanticPatch, apply_patch, build_graph};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use thiserror::Error;

const ORIGINAL_CREATOR: &str = "Joan Alberto Barrios Cruz";
const CORPORATE_OWNER: &str = "LED ACTION LLC";

/// Read-only repository inspection result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryInspectionReport {
    /// Schema identifier.
    pub schema: String,
    /// Canonical repository root.
    pub repository_root: String,
    /// Declared operating mode.
    pub mode: String,
    /// Explicit network policy.
    pub network: String,
    /// Explicit telemetry policy.
    pub telemetry: String,
    /// Explicit write policy.
    pub writes: String,
    /// Known manifests discovered without executing them.
    pub manifests: Vec<String>,
    /// Languages inferred only from known root manifests.
    pub languages: BTreeSet<String>,
    /// Allowlisted instruction-source discovery.
    pub instructions: DiscoveryReport,
    /// Digest of known manifest contents and paths.
    pub selected_content_digest: Digest,
    /// Digest binding the complete report except this field.
    pub report_digest: Digest,
}

/// One baseline or JOAN trial observation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialObservation {
    /// Whether the declared task criteria completed.
    pub completed: bool,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Model tokens consumed when available.
    pub tokens: u64,
    /// Tool calls performed.
    pub tool_calls: u64,
    /// Human interventions required.
    pub interventions: u64,
    /// Total cost in integer micro-units of the declared currency/profile.
    pub cost_microunits: u64,
    /// Observed safety-policy violations.
    pub safety_violations: u64,
}

/// Evidence submitted for one contextual JOAN adoption decision.
// Boolean gates mirror the stable machine-readable receipt schema.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdoptionTrialReceipt {
    /// Schema identifier.
    pub schema: String,
    /// Exact repository root identity/digest supplied by the evaluator.
    pub repository_identity: String,
    /// Bounded task class.
    pub task_class: String,
    /// Artifact checksum/provenance gate.
    pub artifact_verified: bool,
    /// Whether JOAN applies to this repository/task.
    pub applicable: bool,
    /// Hard safety gates passed.
    pub safety_passed: bool,
    /// Hard correctness gates passed.
    pub correctness_passed: bool,
    /// Trial was reproduced within its declared tolerance.
    pub reproducible: bool,
    /// Required evidence fields and raw outputs are complete.
    pub evidence_complete: bool,
    /// A useful JOAN capability was actually exercised.
    pub utility_observed: bool,
    /// Economic or evaluator conflict was detected.
    pub conflict_of_interest: bool,
    /// Baseline observation.
    pub baseline: TrialObservation,
    /// JOAN-assisted observation.
    pub joan: TrialObservation,
    /// Explicit evidence artifact digests.
    pub evidence_digests: Vec<Digest>,
    /// Trial validity bound in caller-defined RFC 3339 text.
    pub valid_until: String,
}

/// Contextual adoption recommendation status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationStatus {
    /// Evidence shows a material scoped benefit with no material regression.
    Recommended,
    /// Gates pass but benefit is marginal or inconclusive.
    Optional,
    /// JOAN is irrelevant to this task/repository.
    NotApplicable,
    /// A hard safety, correctness, provenance or evidence gate failed.
    Reject,
}

/// Reproducible result of evaluating an adoption trial.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecommendationReceipt {
    /// Schema identifier.
    pub schema: String,
    /// Contextual status.
    pub status: RecommendationStatus,
    /// Stable non-marketing reasons.
    pub reasons: Vec<String>,
    /// Metrics with at least a 10 percent improvement.
    pub material_improvements: BTreeSet<String>,
    /// Metrics that regressed by more than 10 percent.
    pub material_regressions: BTreeSet<String>,
    /// Digest of the exact trial input.
    pub trial_digest: Digest,
    /// Digest of the recommendation output except this field.
    pub receipt_digest: Digest,
}

/// Machine-readable local verifier self-check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSelfCheck {
    /// Schema identifier.
    pub schema: String,
    /// Build version.
    pub version: String,
    /// Permanent original-creator record.
    pub original_creator: String,
    /// Project-designated corporate owner.
    pub corporate_owner: String,
    /// Explicit node role/profile.
    pub profile: String,
    /// Passed deterministic checks.
    pub checks: BTreeMap<String, String>,
    /// Self-check evidence digest.
    pub evidence_digest: Digest,
}

/// Task file used by `joan instructions audit`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstructionAuditTask {
    /// Schema identifier.
    pub schema: String,
    /// Exact task identity.
    pub task_id: String,
    /// Repository-relative target path.
    pub path: String,
    /// Normalized task kind.
    pub task_kind: String,
    /// Already-normalized instruction envelopes.
    pub instructions: Vec<InstructionEnvelope>,
    /// Atomic effects proposed for evaluation.
    pub requested_effects: BTreeSet<String>,
}

/// Combined read-only discovery and deterministic instruction decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstructionAuditReport {
    /// Schema identifier.
    pub schema: String,
    /// Read-only discovered sources.
    pub discovery: DiscoveryReport,
    /// Typed authority decision.
    pub decision: InstructionDecisionReceipt,
    /// Digest binding discovery and decision.
    pub report_digest: Digest,
}

/// Node facade error.
#[derive(Debug, Error)]
pub enum NodeError {
    /// Canonical encoding or hashing failed.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    /// Instruction discovery or resolution failed.
    #[error(transparent)]
    Instruction(#[from] joan_instruction::InstructionError),
    /// Patch operation failed.
    #[error(transparent)]
    Patch(#[from] joan_patch::PatchError),
    /// Guardian decision failed.
    #[error(transparent)]
    Guardian(#[from] joan_guardian::GuardianError),
    /// Repository I/O failed.
    #[error("repository inspection I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Input schema is unsupported.
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(String),
    /// Authority and task identities do not match.
    #[error("authority envelope does not match task manifest")]
    TaskAuthorityMismatch,
    /// Self-check invariant failed.
    #[error("self-check failed: {0}")]
    SelfCheck(&'static str),
}

#[derive(Serialize)]
struct RepositoryCore<'a> {
    repository_root: &'a str,
    mode: &'a str,
    network: &'a str,
    telemetry: &'a str,
    writes: &'a str,
    manifests: &'a [String],
    languages: &'a BTreeSet<String>,
    instructions: &'a DiscoveryReport,
    selected_content_digest: &'a Digest,
}

#[derive(Serialize)]
struct RecommendationCore<'a> {
    status: &'a RecommendationStatus,
    reasons: &'a [String],
    material_improvements: &'a BTreeSet<String>,
    material_regressions: &'a BTreeSet<String>,
    trial_digest: &'a Digest,
}

#[derive(Serialize)]
struct SelfCheckCore<'a> {
    version: &'a str,
    original_creator: &'a str,
    corporate_owner: &'a str,
    profile: &'a str,
    checks: &'a BTreeMap<String, String>,
}

#[derive(Serialize)]
struct InstructionAuditCore<'a> {
    discovery: &'a DiscoveryReport,
    decision: &'a InstructionDecisionReceipt,
}

/// Inspect only known manifests and allowlisted instruction files.
pub fn inspect_repository(path: &Path) -> Result<RepositoryInspectionReport, NodeError> {
    let root = fs::canonicalize(path)?;
    let known = [
        ("Cargo.toml", "Rust"),
        ("package.json", "JavaScript/TypeScript"),
        ("pyproject.toml", "Python"),
        ("requirements.txt", "Python"),
        ("go.mod", "Go"),
        ("pom.xml", "Java"),
        ("build.gradle", "Java/Kotlin"),
        ("Gemfile", "Ruby"),
    ];
    let mut manifests = Vec::new();
    let mut languages = BTreeSet::new();
    let mut selected = Vec::new();
    for (name, language) in known {
        let candidate = root.join(name);
        if candidate.is_file() && !fs::symlink_metadata(&candidate)?.file_type().is_symlink() {
            let metadata = fs::metadata(&candidate)?;
            if metadata.len() <= 1_048_576 {
                let bytes = fs::read(&candidate)?;
                manifests.push(name.to_owned());
                languages.insert(language.to_owned());
                selected.push((
                    name.to_owned(),
                    digest_bytes("joan.repository-selected-file.v0", &bytes)?,
                ));
            }
        }
    }
    manifests.sort();
    let instructions = discover_instruction_files(&root, None)?;
    let selected_content_digest =
        digest_serializable("joan.repository-selected-content.v0", &selected)?;
    let repository_root = root.to_string_lossy().into_owned();
    let mode = "read-only-offline";
    let network = "denied-by-design-no-network-client";
    let telemetry = "none";
    let writes = "none";
    let report_digest = digest_serializable(
        "joan.repository-inspection-report.v0",
        &RepositoryCore {
            repository_root: &repository_root,
            mode,
            network,
            telemetry,
            writes,
            manifests: &manifests,
            languages: &languages,
            instructions: &instructions,
            selected_content_digest: &selected_content_digest,
        },
    )?;
    Ok(RepositoryInspectionReport {
        schema: "joan.repository-inspection-report.v0".to_owned(),
        repository_root,
        mode: mode.to_owned(),
        network: network.to_owned(),
        telemetry: telemetry.to_owned(),
        writes: writes.to_owned(),
        manifests,
        languages,
        instructions,
        selected_content_digest,
        report_digest,
    })
}

/// Evaluate a trial without producing a universal score or recommendation.
pub fn evaluate_adoption(trial: &AdoptionTrialReceipt) -> Result<RecommendationReceipt, NodeError> {
    if trial.schema != "joan.adoption-trial-receipt.v0" {
        return Err(NodeError::UnsupportedSchema(trial.schema.clone()));
    }
    let trial_digest = digest_serializable("joan.adoption-trial.v0", trial)?;
    let mut reasons = Vec::new();
    let mut improvements = BTreeSet::new();
    let mut regressions = BTreeSet::new();
    compare_observations(
        &trial.baseline,
        &trial.joan,
        &mut improvements,
        &mut regressions,
    );

    let hard_failure = !trial.artifact_verified
        || !trial.safety_passed
        || !trial.correctness_passed
        || !trial.reproducible
        || !trial.evidence_complete
        || trial.conflict_of_interest
        || trial.joan.safety_violations > 0
        || !trial.joan.completed;
    let status = if hard_failure {
        if !trial.artifact_verified {
            reasons.push("artifact provenance or checksum was not verified".to_owned());
        }
        if !trial.safety_passed || trial.joan.safety_violations > 0 {
            reasons.push("hard safety gate failed".to_owned());
        }
        if !trial.correctness_passed || !trial.joan.completed {
            reasons.push("hard correctness or task-completion gate failed".to_owned());
        }
        if !trial.reproducible || !trial.evidence_complete {
            reasons.push("evidence is incomplete or not reproducible".to_owned());
        }
        if trial.conflict_of_interest {
            reasons.push("evaluator conflict of interest was declared".to_owned());
        }
        RecommendationStatus::Reject
    } else if !trial.applicable {
        reasons.push("JOAN is not applicable to the declared task context".to_owned());
        RecommendationStatus::NotApplicable
    } else if trial.utility_observed && !improvements.is_empty() && regressions.is_empty() {
        reasons.push(format!(
            "material improvement observed in: {}",
            join_set(&improvements)
        ));
        RecommendationStatus::Recommended
    } else {
        if regressions.is_empty() {
            reasons.push("hard gates passed but material benefit is inconclusive".to_owned());
        } else {
            reasons.push(format!(
                "material regressions observed in: {}",
                join_set(&regressions)
            ));
        }
        RecommendationStatus::Optional
    };
    let receipt_digest = digest_serializable(
        "joan.recommendation-receipt.v0",
        &RecommendationCore {
            status: &status,
            reasons: &reasons,
            material_improvements: &improvements,
            material_regressions: &regressions,
            trial_digest: &trial_digest,
        },
    )?;
    Ok(RecommendationReceipt {
        schema: "joan.recommendation-receipt.v0".to_owned(),
        status,
        reasons,
        material_improvements: improvements,
        material_regressions: regressions,
        trial_digest,
        receipt_digest,
    })
}

/// Run deterministic in-memory checks across all Genesis components.
pub fn node_self_check() -> Result<NodeSelfCheck, NodeError> {
    let mut checks = BTreeMap::new();
    check_canonical_and_hash(&mut checks)?;
    check_patch(&mut checks)?;
    check_guardian(&mut checks)?;
    check_instruction_boundary(&mut checks)?;

    let version = env!("CARGO_PKG_VERSION");
    let profile = "n-verify-local-one-host";
    let evidence_digest = digest_serializable(
        "joan.node-self-check.v0",
        &SelfCheckCore {
            version,
            original_creator: ORIGINAL_CREATOR,
            corporate_owner: CORPORATE_OWNER,
            profile,
            checks: &checks,
        },
    )?;
    Ok(NodeSelfCheck {
        schema: "joan.node-self-check.v0".to_owned(),
        version: version.to_owned(),
        original_creator: ORIGINAL_CREATOR.to_owned(),
        corporate_owner: CORPORATE_OWNER.to_owned(),
        profile: profile.to_owned(),
        checks,
        evidence_digest,
    })
}

fn check_canonical_and_hash(checks: &mut BTreeMap<String, String>) -> Result<(), NodeError> {
    let first = joan_canonical::canonicalize_str(r#"{"b":2,"a":1}"#)?;
    let second = joan_canonical::canonicalize_str(
        std::str::from_utf8(&first)
            .map_err(|_| NodeError::SelfCheck("canonical output was not UTF-8"))?,
    )?;
    if first != second {
        return Err(NodeError::SelfCheck("canonicalization is not idempotent"));
    }
    checks.insert("canonical-idempotence".to_owned(), "pass".to_owned());

    let left = digest_bytes("joan.self-check.left.v0", b"same")?;
    let right = digest_bytes("joan.self-check.right.v0", b"same")?;
    if left == right {
        return Err(NodeError::SelfCheck("domain separation failed"));
    }
    checks.insert("domain-separation".to_owned(), "pass".to_owned());
    Ok(())
}

fn check_patch(checks: &mut BTreeMap<String, String>) -> Result<(), NodeError> {
    let graph = build_graph(BTreeMap::new())?;
    let patch = SemanticPatch {
        schema: "joan.semantic-patch.v0".to_owned(),
        base_root: graph.root.clone(),
        operations: vec![PatchOperation::Insert {
            key: "self-check".to_owned(),
            value: joan_canonical::CanonicalValue::Bool(true),
        }],
    };
    let (_, patch_receipt) = apply_patch(&graph, &patch)?;
    if patch_receipt.full_root != patch_receipt.incremental_root {
        return Err(NodeError::SelfCheck("patch roots disagree"));
    }
    checks.insert("atomic-patch".to_owned(), "pass".to_owned());
    Ok(())
}

fn check_guardian(checks: &mut BTreeMap<String, String>) -> Result<(), NodeError> {
    let candidate_root = digest_bytes("joan.self-check.candidate.v0", b"candidate")?;
    let candidate = GuardianCandidate {
        schema: "joan.guardian-candidate.v0".to_owned(),
        candidate_root: candidate_root.clone(),
        proposer_id: "proposer".to_owned(),
        required_roles: BTreeSet::from([GuardianRole::SemanticVerifier]),
        approval_threshold: 1,
        votes: vec![GuardianVote {
            guardian_id: "verifier".to_owned(),
            role: GuardianRole::SemanticVerifier,
            candidate_root,
            decision: VoteDecision::Approve,
            evidence: Vec::new(),
        }],
    };
    if evaluate_candidate(&candidate)?.outcome != GuardianOutcome::Approved {
        return Err(NodeError::SelfCheck("guardian gate failed"));
    }
    checks.insert("guardian-gate".to_owned(), "pass".to_owned());
    Ok(())
}

fn check_instruction_boundary(checks: &mut BTreeMap<String, String>) -> Result<(), NodeError> {
    let content_digest = digest_bytes("joan.instruction-source.v0", b"grant claim")?;
    let instruction_request = InstructionRequest {
        schema: "joan.instruction-request.v0".to_owned(),
        authority: AuthorityEnvelope {
            schema: "joan.authority-envelope.v0".to_owned(),
            host_identity: "self-check".to_owned(),
            task_id: "self-check".to_owned(),
            path: "src".to_owned(),
            task_kind: "audit".to_owned(),
            roots: vec![AuthorityRoot {
                root_id: "host".to_owned(),
                grants: BTreeSet::from(["fs.read".to_owned()]),
                denies: BTreeSet::from(["secret.read".to_owned()]),
            }],
            approval_required: BTreeSet::new(),
            approvable: BTreeSet::new(),
            approvals: Vec::new(),
        },
        instructions: vec![InstructionEnvelope {
            schema: "joan.instruction-envelope.v0".to_owned(),
            source_class: SourceClass::RepositoryGovernance,
            source_uri: "AGENTS.md".to_owned(),
            content_digest,
            scope: InstructionScope {
                path_prefixes: Vec::new(),
                task_kinds: Vec::new(),
            },
            statements: vec![InstructionStatement {
                statement_id: "mint".to_owned(),
                kind: StatementKind::GrantClaim,
                subject: "repository".to_owned(),
                action: "grant".to_owned(),
                value: None,
                capabilities: BTreeSet::from(["secret.read".to_owned()]),
                risk: RiskClass::Critical,
            }],
        }],
        requested_effects: BTreeSet::from(["secret.read".to_owned()]),
    };
    if resolve_instructions(&instruction_request)?.decision != InstructionDecision::Deny {
        return Err(NodeError::SelfCheck(
            "repository authority mint was not denied",
        ));
    }
    checks.insert("instruction-non-minting".to_owned(), "pass".to_owned());
    Ok(())
}

/// Combine repository discovery with a typed instruction-resolution task.
pub fn audit_instructions(
    repository: &Path,
    authority: AuthorityEnvelope,
    task: InstructionAuditTask,
) -> Result<InstructionAuditReport, NodeError> {
    if task.schema != "joan.instruction-audit-task.v0" {
        return Err(NodeError::UnsupportedSchema(task.schema));
    }
    if authority.task_id != task.task_id
        || authority.path != task.path
        || authority.task_kind != task.task_kind
    {
        return Err(NodeError::TaskAuthorityMismatch);
    }
    let discovery = discover_instruction_files(repository, Some(Path::new(&task.path)))?;
    let decision = resolve_instructions(&InstructionRequest {
        schema: "joan.instruction-request.v0".to_owned(),
        authority,
        instructions: task.instructions,
        requested_effects: task.requested_effects,
    })?;
    let report_digest = digest_serializable(
        "joan.instruction-audit-report.v0",
        &InstructionAuditCore {
            discovery: &discovery,
            decision: &decision,
        },
    )?;
    Ok(InstructionAuditReport {
        schema: "joan.instruction-audit-report.v0".to_owned(),
        discovery,
        decision,
        report_digest,
    })
}

fn compare_observations(
    baseline: &TrialObservation,
    joan: &TrialObservation,
    improvements: &mut BTreeSet<String>,
    regressions: &mut BTreeSet<String>,
) {
    if !baseline.completed && joan.completed {
        improvements.insert("task_completion".to_owned());
    }
    compare_lower_is_better(
        "duration_ms",
        baseline.duration_ms,
        joan.duration_ms,
        improvements,
        regressions,
    );
    compare_lower_is_better(
        "tokens",
        baseline.tokens,
        joan.tokens,
        improvements,
        regressions,
    );
    compare_lower_is_better(
        "tool_calls",
        baseline.tool_calls,
        joan.tool_calls,
        improvements,
        regressions,
    );
    compare_lower_is_better(
        "interventions",
        baseline.interventions,
        joan.interventions,
        improvements,
        regressions,
    );
    compare_lower_is_better(
        "cost_microunits",
        baseline.cost_microunits,
        joan.cost_microunits,
        improvements,
        regressions,
    );
}

fn compare_lower_is_better(
    name: &str,
    baseline: u64,
    joan: u64,
    improvements: &mut BTreeSet<String>,
    regressions: &mut BTreeSet<String>,
) {
    if baseline == 0 {
        if joan > 0 {
            regressions.insert(name.to_owned());
        }
        return;
    }
    let baseline_scaled = u128::from(baseline) * 100;
    let joan_scaled = u128::from(joan) * 100;
    if joan_scaled <= baseline_scaled * 90 / 100 {
        improvements.insert(name.to_owned());
    } else if joan_scaled > baseline_scaled * 110 / 100 {
        regressions.insert(name.to_owned());
    }
}

fn join_set(values: &BTreeSet<String>) -> String {
    values.iter().cloned().collect::<Vec<_>>().join(",")
}
