//! Repository instruction discovery and deterministic authority attenuation.

use joan_ast::InformationLabel;
use joan_canonical::{CanonicalError, Digest, digest_bytes, digest_serializable};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

const MAX_INSTRUCTION_BYTES: u64 = 131_072;

/// Trust class assigned to one normalized instruction source.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceClass {
    /// Repository-wide governance and constraints.
    RepositoryGovernance,
    /// Guidance limited to a path subtree.
    PathGuidance,
    /// Referenced specification that supplies facts, not authority.
    ReferencedSpecification,
    /// Source, issue, tool, web or model content treated as data.
    UntrustedContent,
}

/// Normalized statement kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatementKind {
    /// Descriptive fact.
    Fact,
    /// Non-authorizing procedure or convention.
    Procedure,
    /// Capability restriction.
    Constraint,
    /// Request that still requires external authority.
    Request,
    /// Invalid attempt to create authority from repository text.
    GrantClaim,
    /// Statement that could not be safely typed.
    Opaque,
}

/// Risk class attached to a normalized statement or effect.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    /// No external side effect.
    Pure,
    /// Bounded local read.
    LocalRead,
    /// Local write or process effect.
    LocalWrite,
    /// Network, secrets, VCS write or external service effect.
    External,
    /// Irreversible, financial, production or safety-critical effect.
    Critical,
}

/// Path and task applicability for an instruction envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstructionScope {
    /// Normalized repository-relative path prefixes. Empty means all paths.
    pub path_prefixes: Vec<String>,
    /// Task-kind allowlist. Empty means all task kinds.
    pub task_kinds: Vec<String>,
}

/// Typed instruction statement. Natural-language parsing is outside Genesis.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstructionStatement {
    /// Stable ID within its source envelope.
    pub statement_id: String,
    /// Statement classification.
    pub kind: StatementKind,
    /// Normalized subject such as `formatter` or `network`.
    pub subject: String,
    /// Normalized action such as `use` or `deny`.
    pub action: String,
    /// Optional normalized directive value used for conflict checks.
    pub value: Option<String>,
    /// Atomic capabilities requested or constrained by this statement.
    pub capabilities: BTreeSet<String>,
    /// Declared risk class.
    pub risk: RiskClass,
}

/// Verified source envelope containing already-normalized statements.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstructionEnvelope {
    /// Schema identifier.
    pub schema: String,
    /// Source trust class.
    pub source_class: SourceClass,
    /// Repository-relative or typed source URI.
    pub source_uri: String,
    /// Exact source-content digest.
    pub content_digest: Digest,
    /// Applicability scope.
    pub scope: InstructionScope,
    /// Typed statements.
    pub statements: Vec<InstructionStatement>,
}

/// One external host authority root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRoot {
    /// Root identity supplied by the host.
    pub root_id: String,
    /// Capabilities this root permits inside its domain.
    pub grants: BTreeSet<String>,
    /// Hard denies that survive composition.
    pub denies: BTreeSet<String>,
}

/// One-shot approval evidence tied to an exact task and capability set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OneShotApproval {
    /// Approval nonce. Genesis validates shape but has no durable replay ledger.
    pub nonce: String,
    /// Exact task identity.
    pub task_id: String,
    /// Exact approved capabilities.
    pub capabilities: BTreeSet<String>,
    /// Exact source authority slot for linear JOAN requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_slot: Option<String>,
    /// Exact tenant-purpose sink approved for a flow request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub information: Option<InformationLabel>,
}

/// Host-supplied authority ceiling and approval requirements.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityEnvelope {
    /// Schema identifier.
    pub schema: String,
    /// Host/runtime identity.
    pub host_identity: String,
    /// Exact task identity.
    pub task_id: String,
    /// Repository-relative task path.
    pub path: String,
    /// Normalized task kind.
    pub task_kind: String,
    /// Required authority roots whose grants are intersected.
    pub roots: Vec<AuthorityRoot>,
    /// Capabilities that require explicit approval even when granted.
    pub approval_required: BTreeSet<String>,
    /// Capabilities for which the host can request approval.
    pub approvable: BTreeSet<String>,
    /// Presented one-shot approvals.
    pub approvals: Vec<OneShotApproval>,
}

/// Complete deterministic instruction-resolution request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstructionRequest {
    /// Schema identifier.
    pub schema: String,
    /// External authority supplied by the host.
    pub authority: AuthorityEnvelope,
    /// Verified normalized repository/content envelopes.
    pub instructions: Vec<InstructionEnvelope>,
    /// Exact atomic effects proposed by the agent.
    pub requested_effects: BTreeSet<String>,
}

/// Deterministic resolver outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstructionDecision {
    /// Inputs supplied facts only.
    Data,
    /// Inputs supplied non-authorizing procedure guidance.
    Advise,
    /// Every requested effect is authorized and all obligations pass.
    Allow,
    /// A hard rule or missing authority rejects the request.
    Deny,
    /// Host approval could resolve the only missing obligation.
    Ask,
    /// Applicable instructions are contradictory.
    Conflict,
}

/// Stable resolver diagnostic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstructionDiagnostic {
    /// Stable code.
    pub code: String,
    /// Source URI when applicable.
    pub source_uri: Option<String>,
    /// Statement ID when applicable.
    pub statement_id: Option<String>,
    /// Non-secret explanation.
    pub message: String,
}

/// Reproducible instruction and authority decision receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstructionDecisionReceipt {
    /// Schema identifier.
    pub schema: String,
    /// Host/task envelope digest.
    pub authority_envelope_digest: Digest,
    /// Normalized instruction-envelope digests.
    pub instruction_digests: Vec<Digest>,
    /// External capability ceiling before repository attenuation.
    pub authority_ceiling: BTreeSet<String>,
    /// Capabilities removed by applicable repository constraints.
    pub repository_denies: BTreeSet<String>,
    /// Effective capability set.
    pub effective_authority: BTreeSet<String>,
    /// Exact requested effects.
    pub requested_effects: BTreeSet<String>,
    /// Deterministic result.
    pub decision: InstructionDecision,
    /// Stable findings and failed predicates.
    pub diagnostics: Vec<InstructionDiagnostic>,
    /// Digest of all decision inputs and outputs except this field.
    pub receipt_digest: Digest,
}

/// Discovered instruction source read without executing content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveredInstructionFile {
    /// Repository-relative path.
    pub path: String,
    /// Source-content digest.
    pub content_digest: Digest,
    /// File size in bytes.
    pub bytes: u64,
    /// Classification applied by discovery.
    pub content_class: String,
}

/// Read-only repository instruction discovery report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryReport {
    /// Schema identifier.
    pub schema: String,
    /// Canonical repository path used for containment checks.
    pub repository_root: String,
    /// Files safely read under the allowlist.
    pub files: Vec<DiscoveredInstructionFile>,
    /// Skipped candidates and containment findings.
    pub diagnostics: Vec<InstructionDiagnostic>,
    /// Digest binding the report.
    pub report_digest: Digest,
}

/// Instruction resolver or discovery failure.
#[derive(Debug, Error)]
pub enum InstructionError {
    /// Canonical encoding or hashing failed.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    /// Input/output file operation failed.
    #[error("I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Schema is unsupported.
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(String),
    /// No external authority root was supplied.
    #[error("authority envelope has no roots")]
    NoAuthorityRoots,
    /// Path is invalid or escapes the repository root.
    #[error("path escapes repository root")]
    PathEscape,
    /// Instruction file exceeded the Genesis byte bound.
    #[error("instruction file exceeds byte bound: {0}")]
    FileTooLarge(String),
    /// Instruction source was not valid UTF-8.
    #[error("instruction file is not valid UTF-8: {0}")]
    InvalidUtf8(String),
}

#[derive(Serialize)]
struct DecisionCore<'a> {
    authority_envelope_digest: &'a Digest,
    instruction_digests: &'a [Digest],
    authority_ceiling: &'a BTreeSet<String>,
    repository_denies: &'a BTreeSet<String>,
    effective_authority: &'a BTreeSet<String>,
    requested_effects: &'a BTreeSet<String>,
    decision: &'a InstructionDecision,
    diagnostics: &'a [InstructionDiagnostic],
}

#[derive(Serialize)]
struct DiscoveryCore<'a> {
    repository_root: &'a str,
    files: &'a [DiscoveredInstructionFile],
    diagnostics: &'a [InstructionDiagnostic],
}

struct InstructionAnalysis {
    repository_denies: BTreeSet<String>,
    diagnostics: Vec<InstructionDiagnostic>,
    flags: BTreeSet<AnalysisFlag>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum AnalysisFlag {
    HasAdvice,
    InvalidAuthorityClaim,
    OpaqueEffect,
    Conflict,
}

/// Resolve typed statements against an external authority ceiling.
pub fn resolve_instructions(
    request: &InstructionRequest,
) -> Result<InstructionDecisionReceipt, InstructionError> {
    validate_request_schemas(request)?;
    let authority_envelope_digest =
        digest_serializable("joan.authority-envelope.v0", &request.authority)?;
    let instruction_digests = request
        .instructions
        .iter()
        .map(|envelope| digest_serializable("joan.instruction-envelope.v0", envelope))
        .collect::<Result<Vec<_>, _>>()?;

    let (mut authority_ceiling, hard_denies) = external_ceiling(&request.authority)?;
    for denied in &hard_denies {
        authority_ceiling.remove(denied);
    }

    let mut analysis = analyze_instructions(request);

    let effective_authority = authority_ceiling
        .difference(&analysis.repository_denies)
        .cloned()
        .collect::<BTreeSet<_>>();
    let decision = decide_request(request, &hard_denies, &effective_authority, &mut analysis);

    let receipt_digest = digest_serializable(
        "joan.instruction-decision-receipt.v0",
        &DecisionCore {
            authority_envelope_digest: &authority_envelope_digest,
            instruction_digests: &instruction_digests,
            authority_ceiling: &authority_ceiling,
            repository_denies: &analysis.repository_denies,
            effective_authority: &effective_authority,
            requested_effects: &request.requested_effects,
            decision: &decision,
            diagnostics: &analysis.diagnostics,
        },
    )?;

    Ok(InstructionDecisionReceipt {
        schema: "joan.instruction-decision-receipt.v0".to_owned(),
        authority_envelope_digest,
        instruction_digests,
        authority_ceiling,
        repository_denies: analysis.repository_denies,
        effective_authority,
        requested_effects: request.requested_effects.clone(),
        decision,
        diagnostics: analysis.diagnostics,
        receipt_digest,
    })
}

fn analyze_instructions(request: &InstructionRequest) -> InstructionAnalysis {
    let mut analysis = InstructionAnalysis {
        repository_denies: BTreeSet::new(),
        diagnostics: Vec::new(),
        flags: BTreeSet::new(),
    };
    let mut directives: BTreeMap<(SourceClass, String, String), String> = BTreeMap::new();
    for envelope in &request.instructions {
        if !scope_applies(
            &envelope.scope,
            &request.authority.path,
            &request.authority.task_kind,
        ) {
            continue;
        }
        for statement in &envelope.statements {
            analyze_statement(envelope, statement, &mut directives, &mut analysis);
        }
    }
    analysis
}

fn analyze_statement(
    envelope: &InstructionEnvelope,
    statement: &InstructionStatement,
    directives: &mut BTreeMap<(SourceClass, String, String), String>,
    analysis: &mut InstructionAnalysis,
) {
    if matches!(
        envelope.source_class,
        SourceClass::ReferencedSpecification | SourceClass::UntrustedContent
    ) {
        analysis.diagnostics.push(diagnostic(
            "JINST001",
            envelope,
            statement,
            "content is data and cannot authorize or constrain effects",
        ));
        return;
    }
    match statement.kind {
        StatementKind::Constraint => analysis
            .repository_denies
            .extend(statement.capabilities.iter().cloned()),
        StatementKind::GrantClaim => {
            analysis.flags.insert(AnalysisFlag::InvalidAuthorityClaim);
            analysis.diagnostics.push(diagnostic(
                "JINST006",
                envelope,
                statement,
                "repository content attempted to mint authority",
            ));
        }
        StatementKind::Opaque if !statement.capabilities.is_empty() => {
            analysis.flags.insert(AnalysisFlag::OpaqueEffect);
            analysis.diagnostics.push(diagnostic(
                "JINST011",
                envelope,
                statement,
                "opaque effect-bearing statement fails closed",
            ));
        }
        StatementKind::Procedure | StatementKind::Request => {
            analysis.flags.insert(AnalysisFlag::HasAdvice);
            detect_directive_conflict(envelope, statement, directives, analysis);
        }
        StatementKind::Fact | StatementKind::Opaque => {}
    }
}

fn detect_directive_conflict(
    envelope: &InstructionEnvelope,
    statement: &InstructionStatement,
    directives: &mut BTreeMap<(SourceClass, String, String), String>,
    analysis: &mut InstructionAnalysis,
) {
    let Some(value) = &statement.value else {
        return;
    };
    let key = (
        envelope.source_class.clone(),
        statement.subject.clone(),
        statement.action.clone(),
    );
    if let Some(existing) = directives.insert(key, value.clone())
        && existing != *value
    {
        analysis.flags.insert(AnalysisFlag::Conflict);
        analysis.diagnostics.push(diagnostic(
            "JINST010",
            envelope,
            statement,
            "same-class applicable directives conflict",
        ));
    }
}

fn decide_request(
    request: &InstructionRequest,
    hard_denies: &BTreeSet<String>,
    effective_authority: &BTreeSet<String>,
    analysis: &mut InstructionAnalysis,
) -> InstructionDecision {
    if analysis
        .flags
        .contains(&AnalysisFlag::InvalidAuthorityClaim)
        || analysis.flags.contains(&AnalysisFlag::OpaqueEffect)
    {
        return InstructionDecision::Deny;
    }
    if analysis.flags.contains(&AnalysisFlag::Conflict) {
        return InstructionDecision::Conflict;
    }
    if request.requested_effects.is_empty() {
        return if analysis.flags.contains(&AnalysisFlag::HasAdvice) {
            InstructionDecision::Advise
        } else {
            InstructionDecision::Data
        };
    }
    let missing = request
        .requested_effects
        .difference(effective_authority)
        .cloned()
        .collect::<BTreeSet<_>>();
    if !missing.is_empty() {
        let hard_missing = missing.iter().any(|capability| {
            hard_denies.contains(capability) || analysis.repository_denies.contains(capability)
        });
        if !hard_missing && missing.is_subset(&request.authority.approvable) {
            return InstructionDecision::Ask;
        }
        analysis.diagnostics.push(InstructionDiagnostic {
            code: "JINST007".to_owned(),
            source_uri: None,
            statement_id: None,
            message: format!(
                "effects outside effective authority: {}",
                join_set(&missing)
            ),
        });
        return InstructionDecision::Deny;
    }
    let missing_approvals = request
        .requested_effects
        .intersection(&request.authority.approval_required)
        .filter(|capability| !has_exact_approval(&request.authority, capability))
        .cloned()
        .collect::<BTreeSet<_>>();
    if missing_approvals.is_empty() {
        InstructionDecision::Allow
    } else {
        analysis.diagnostics.push(InstructionDiagnostic {
            code: "JINST009".to_owned(),
            source_uri: None,
            statement_id: None,
            message: format!(
                "one-shot approval required: {}",
                join_set(&missing_approvals)
            ),
        });
        InstructionDecision::Ask
    }
}

/// Discover allowlisted instruction files without executing repository content.
pub fn discover_instruction_files(
    repository_root: &Path,
    task_path: Option<&Path>,
) -> Result<DiscoveryReport, InstructionError> {
    let root = fs::canonicalize(repository_root)?;
    if !root.is_dir() {
        return Err(InstructionError::PathEscape);
    }
    let mut candidates = BTreeSet::from([
        root.join("AGENTS.md"),
        root.join(".github/copilot-instructions.md"),
    ]);
    let instruction_dir = root.join(".github/instructions");
    if instruction_dir.is_dir() {
        for entry in fs::read_dir(&instruction_dir)? {
            let path = entry?.path();
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".instructions.md"))
            {
                candidates.insert(path);
            }
        }
    }
    if let Some(task_path) = task_path {
        add_nested_agent_candidates(&root, task_path, &mut candidates)?;
    }

    let mut files = Vec::new();
    let mut diagnostics = Vec::new();
    for candidate in candidates {
        if !candidate.exists() {
            continue;
        }
        let metadata = fs::symlink_metadata(&candidate)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            diagnostics.push(InstructionDiagnostic {
                code: "JINST002".to_owned(),
                source_uri: Some(relative_display(&root, &candidate)),
                statement_id: None,
                message: "non-regular or symlink instruction source ignored".to_owned(),
            });
            continue;
        }
        let canonical = fs::canonicalize(&candidate)?;
        if !canonical.starts_with(&root) {
            return Err(InstructionError::PathEscape);
        }
        if metadata.len() > MAX_INSTRUCTION_BYTES {
            return Err(InstructionError::FileTooLarge(relative_display(
                &root, &candidate,
            )));
        }
        let bytes = fs::read(&canonical)?;
        std::str::from_utf8(&bytes)
            .map_err(|_| InstructionError::InvalidUtf8(relative_display(&root, &candidate)))?;
        files.push(DiscoveredInstructionFile {
            path: relative_display(&root, &candidate),
            content_digest: digest_bytes("joan.instruction-source.v0", &bytes)?,
            bytes: metadata.len(),
            content_class: "guidance-not-authority".to_owned(),
        });
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let root_display = root.to_string_lossy().into_owned();
    let report_digest = digest_serializable(
        "joan.instruction-discovery-report.v0",
        &DiscoveryCore {
            repository_root: &root_display,
            files: &files,
            diagnostics: &diagnostics,
        },
    )?;
    Ok(DiscoveryReport {
        schema: "joan.instruction-discovery-report.v0".to_owned(),
        repository_root: root_display,
        files,
        diagnostics,
        report_digest,
    })
}

fn validate_request_schemas(request: &InstructionRequest) -> Result<(), InstructionError> {
    if request.schema != "joan.instruction-request.v0" {
        return Err(InstructionError::UnsupportedSchema(request.schema.clone()));
    }
    if request.authority.schema != "joan.authority-envelope.v0" {
        return Err(InstructionError::UnsupportedSchema(
            request.authority.schema.clone(),
        ));
    }
    for envelope in &request.instructions {
        if envelope.schema != "joan.instruction-envelope.v0" {
            return Err(InstructionError::UnsupportedSchema(envelope.schema.clone()));
        }
    }
    Ok(())
}

fn external_ceiling(
    authority: &AuthorityEnvelope,
) -> Result<(BTreeSet<String>, BTreeSet<String>), InstructionError> {
    let mut roots = authority.roots.iter();
    let first = roots.next().ok_or(InstructionError::NoAuthorityRoots)?;
    let mut ceiling = first.grants.clone();
    let mut denies = first.denies.clone();
    for root in roots {
        ceiling = ceiling
            .intersection(&root.grants)
            .cloned()
            .collect::<BTreeSet<_>>();
        denies.extend(root.denies.iter().cloned());
    }
    Ok((ceiling, denies))
}

fn scope_applies(scope: &InstructionScope, path: &str, task_kind: &str) -> bool {
    let path_applies = scope.path_prefixes.is_empty()
        || scope
            .path_prefixes
            .iter()
            .any(|prefix| path == prefix || path.starts_with(&format!("{prefix}/")));
    let task_applies =
        scope.task_kinds.is_empty() || scope.task_kinds.iter().any(|kind| kind == task_kind);
    path_applies && task_applies
}

fn has_exact_approval(authority: &AuthorityEnvelope, capability: &str) -> bool {
    authority.approvals.iter().any(|approval| {
        !approval.nonce.is_empty()
            && approval.task_id == authority.task_id
            && approval.capabilities.len() == 1
            && approval.capabilities.contains(capability)
    })
}

fn diagnostic(
    code: &str,
    envelope: &InstructionEnvelope,
    statement: &InstructionStatement,
    message: &str,
) -> InstructionDiagnostic {
    InstructionDiagnostic {
        code: code.to_owned(),
        source_uri: Some(envelope.source_uri.clone()),
        statement_id: Some(statement.statement_id.clone()),
        message: message.to_owned(),
    }
}

fn join_set(values: &BTreeSet<String>) -> String {
    values.iter().cloned().collect::<Vec<_>>().join(",")
}

fn add_nested_agent_candidates(
    root: &Path,
    task_path: &Path,
    candidates: &mut BTreeSet<PathBuf>,
) -> Result<(), InstructionError> {
    let absolute_task = if task_path.is_absolute() {
        task_path.to_path_buf()
    } else {
        root.join(task_path)
    };
    let nearest_existing = if absolute_task.exists() {
        fs::canonicalize(&absolute_task)?
    } else {
        let parent = absolute_task.parent().ok_or(InstructionError::PathEscape)?;
        fs::canonicalize(parent)?
    };
    if !nearest_existing.starts_with(root) {
        return Err(InstructionError::PathEscape);
    }
    let start = if nearest_existing.is_dir() {
        nearest_existing
    } else {
        nearest_existing
            .parent()
            .ok_or(InstructionError::PathEscape)?
            .to_path_buf()
    };
    for ancestor in start.ancestors() {
        if !ancestor.starts_with(root) {
            break;
        }
        candidates.insert(ancestor.join("AGENTS.md"));
        if ancestor == root {
            break;
        }
    }
    Ok(())
}

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}
