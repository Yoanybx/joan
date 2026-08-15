//! Offline, read-only pull-request evidence binding for JOAN repositories.

use joan_ast::InformationLabel;
use joan_bytecode::BytecodeVerificationReceipt;
use joan_canonical::{
    CanonicalError, Digest, Jce1Error, RegisteredDomainV1, digest_bytes_v1, digest_serializable_v1,
    from_serializable_v1, parse_strict, parse_strict_v1, to_canonical_bytes_v1,
};
use joan_compiler::{LanguageError, Value, compile_source, execute_bytecode};
use joan_identity::CanonicalAstIdentity;
use joan_instruction::{AuthorityEnvelope, AuthorityRoot, OneShotApproval};
use joan_package::{PackageError, resolve_package, verify_manifest_bytes};
use joan_runtime::{CapabilityLedger, RuntimePlanError, plan_effects};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value as JsonValue;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use thiserror::Error;

/// Repository policy schema consumed by the PR evaluator.
pub const PR_TRUST_POLICY_SCHEMA: &str = "joan.pr-trust-policy.v0";
/// Deterministic PR envelope schema emitted by the evaluator.
pub const PR_TRUST_ENVELOPE_SCHEMA: &str = "joan.pr-trust-envelope.v0";

const POLICY_PATH: &str = ".joan/pr-trust.json";
const MAX_POLICY_BYTES: u64 = 131_072;
const MAX_EVIDENCE_INDEX_BYTES: u64 = 1_048_576;
const MAX_EVIDENCE_RECEIPT_BYTES: u64 = 2 * 1_048_576;
const MAX_ENVELOPE_BYTES: usize = 4 * 1_048_576;
const MAX_SOURCE_FILES: usize = 100_000;
const MAX_SOURCE_FILE_BYTES: u64 = 64 * 1_048_576;
const MAX_SOURCE_TREE_BYTES: u64 = 1_073_741_824;
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1_048_576;
const MAX_DIRECTORY_DEPTH: usize = 64;
const SOURCE_TREE_PREFIX: &[u8] = b"JOAN\0SOURCE-TREE\0V2";
const EXPECTED_EXCLUDES: [&str; 5] = [".git", "target", ".joan/evidence", "**/.DS_Store", "**/._*"];
const VERIFICATION_RUNNER_PATH: &str = "tools/verification-runner.mjs";
const VERIFICATION_GATES_PATH: &str = "tools/verification-gates.v1.json";
const LEGACY_GATE_IDS: [&str; 10] = [
    "format",
    "clippy",
    "tests",
    "doc-tests",
    "release-build",
    "jce1",
    "c-digest-smoke",
    "payment-cost-vector",
    "cargo-deny",
    "cargo-audit",
];
const CURRENT_GATE_IDS: [&str; 11] = [
    "format",
    "clippy",
    "tests",
    "doc-tests",
    "release-build",
    "jce1",
    "c-digest-smoke",
    "payment-cost-vector",
    "tool-forge",
    "cargo-deny",
    "cargo-audit",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrTrustPolicy {
    schema: String,
    profile: String,
    repository: String,
    policy_source_path: String,
    package_manifest_path: String,
    package_store_path: String,
    evidence_index_path: String,
    policy_source_digest: Digest,
    package_manifest_digest: Digest,
    instruction_budget: u64,
    max_changed_files: u64,
    max_changed_bytes: u64,
    required_verification_runs: u64,
    required_gate_count: u64,
    required_jce1_passed: u64,
    network_policy: String,
    write_policy: String,
    telemetry_policy: String,
    claim_scope: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceTreeDigest {
    algorithm: String,
    profile: String,
    value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceTreeSnapshot {
    tree_digest: SourceTreeDigest,
    file_count: u64,
    excludes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ChangeKind {
    Added,
    Modified,
    Deleted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangedFile {
    path: String,
    change: ChangeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    base_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    base_content_digest: Option<Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_content_digest: Option<Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrCandidateReceipt {
    schema: String,
    status: String,
    repository: String,
    object_format: String,
    base_commit: String,
    head_commit: String,
    changed_files: Vec<ChangedFile>,
    total_changed_bytes: u64,
    candidate_digest: Digest,
}

#[derive(Serialize)]
struct PrCandidateCore<'a> {
    repository: &'a str,
    object_format: &'a str,
    base_commit: &'a str,
    head_commit: &'a str,
    changed_files: &'a [ChangedFile],
    total_changed_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceBinding {
    schema: String,
    status: String,
    source: SourceTreeSnapshot,
    evidence_index_digest: Digest,
    verification_run_ids: Vec<String>,
    required_gate_ids: Vec<String>,
    jce1_passed: u64,
    dispute_cases: u64,
    vulnerabilities_found: u64,
    claim_scope: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyProgramBinding {
    policy_source_path: String,
    package_manifest_path: String,
    policy_source_digest: Digest,
    package_manifest_digest: Digest,
    package_resolution_digest: Digest,
    semantic_identity: CanonicalAstIdentity,
    bytecode_verification: BytecodeVerificationReceipt,
    execution_receipt_digest: Digest,
    effect_plan_digest: Digest,
    instruction_budget: u64,
    instructions_executed: u64,
    planned_effect: String,
    authority_slot: String,
    information: InformationLabel,
}

/// Deterministic, offline PR requirements receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrTrustEnvelope {
    schema: String,
    status: String,
    claim_scope: String,
    network_policy: String,
    write_policy: String,
    telemetry_policy: String,
    candidate: PrCandidateReceipt,
    evidence: EvidenceBinding,
    policy_digest: Digest,
    program: PolicyProgramBinding,
    limitations: Vec<String>,
    envelope_digest: Digest,
}

#[derive(Serialize)]
struct PrTrustEnvelopeCore<'a> {
    schema: &'a str,
    status: &'a str,
    claim_scope: &'a str,
    network_policy: &'a str,
    write_policy: &'a str,
    telemetry_policy: &'a str,
    candidate: &'a PrCandidateReceipt,
    evidence: &'a EvidenceBinding,
    policy_digest: &'a Digest,
    program: &'a PolicyProgramBinding,
    limitations: &'a [String],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceIndex {
    schema: String,
    version: String,
    status: String,
    generated_at: String,
    source: SourceTreeSnapshot,
    inventory: JsonValue,
    conformance: JsonValue,
    supply_chain: JsonValue,
    verification: EvidenceVerification,
    benchmark: JsonValue,
    limitations: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceVerification {
    runner: JsonValue,
    gate_config: JsonValue,
    required_gate_ids: Vec<String>,
    runs: Vec<EvidenceRunSummary>,
    repeatability: EvidenceRepeatability,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceRepeatability {
    required_runs: u64,
    completed_runs: u64,
    unique_run_ids: u64,
    same_source: bool,
    same_observations: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceRunSummary {
    ordinal: u64,
    run_id: String,
    path: String,
    file_sha256: String,
    status: String,
    started_at: String,
    completed_at: String,
    source_digest: String,
    gate_count: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationReceipt {
    schema: String,
    version: String,
    run_id: String,
    status: String,
    started_at: String,
    completed_at: String,
    source: SourceTreeSnapshot,
    environment: JsonValue,
    gates: Vec<JsonValue>,
    summary: VerificationSummary,
    observations: JsonValue,
    supply_chain: JsonValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationSummary {
    required: u64,
    executed: u64,
    passed: u64,
    failed: u64,
}

struct ReceiptValidationContext<'a> {
    root: &'a Path,
    source: &'a SourceTreeSnapshot,
    required_gate_ids: &'a [String],
    supply_chain: &'a JsonValue,
    runner_sha256: &'a str,
    gate_config_sha256: &'a str,
    require_current_tooling: bool,
}

/// PR evaluation failure. Every variant rejects without executing host effects.
#[derive(Debug, Error)]
pub enum TrustError {
    /// Filesystem operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Strict JSON or v0 digest operation failed.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    /// JCE1 encoding or typed identity failed.
    #[error(transparent)]
    Jce1(#[from] Jce1Error),
    /// JSON did not match a closed machine contract.
    #[error("machine contract decode failed: {0}")]
    Decode(#[from] serde_json::Error),
    /// JOAN policy source failed compilation or bounded execution.
    #[error(transparent)]
    Language(#[from] LanguageError),
    /// Content-addressed package resolution failed.
    #[error(transparent)]
    Package(#[from] PackageError),
    /// One-shot authority planning failed.
    #[error(transparent)]
    Runtime(#[from] RuntimePlanError),
    /// Git inspection failed or returned an unsafe shape.
    #[error("git inspection rejected: {0}")]
    Git(String),
    /// A bounded policy, path or evidence invariant failed.
    #[error("PR trust requirements rejected: {0}")]
    Invalid(String),
    /// A saved envelope differs from a fresh evaluation.
    #[error("PR trust envelope does not match a fresh repository evaluation")]
    EnvelopeMismatch,
}

/// Evaluate one exact base/head pair in a clean local Git checkout.
///
/// The evaluator is offline and read-only. Its planned effect is data only and
/// is never dispatched to GitHub or another host.
pub fn evaluate_pr(
    repository: &Path,
    base_reference: &str,
    head_reference: &str,
) -> Result<PrTrustEnvelope, TrustError> {
    let root = canonical_directory(repository)?;
    let policy_path = safe_existing_path(&root, POLICY_PATH, PathKind::File)?;
    let policy: PrTrustPolicy = read_strict_bounded(&policy_path, MAX_POLICY_BYTES)?;
    validate_policy(&policy)?;

    let policy_digest = digest_serializable_v1(RegisteredDomainV1::PrTrustPolicy, &policy)?;
    let candidate = inspect_candidate(&root, &policy, base_reference, head_reference)?;
    let source = source_tree_snapshot(&root)?;
    let evidence = verify_evidence(&root, &policy, &source)?;
    let program = verify_policy_program(&root, &policy, &candidate)?;
    let limitations = vec![
        "Local Git identity and receipts do not prove code safety or reviewer independence"
            .to_owned(),
        "The planned publication effect is not executed by JOAN".to_owned(),
        "A clean checkout does not replace signatures, branch protection or external audit"
            .to_owned(),
        "The envelope proves only the exact offline requirements and artifacts it binds".to_owned(),
    ];
    let mut envelope = PrTrustEnvelope {
        schema: PR_TRUST_ENVELOPE_SCHEMA.to_owned(),
        status: "requirements-satisfied".to_owned(),
        claim_scope: policy.claim_scope.clone(),
        network_policy: policy.network_policy.clone(),
        write_policy: policy.write_policy.clone(),
        telemetry_policy: policy.telemetry_policy.clone(),
        candidate,
        evidence,
        policy_digest,
        program,
        limitations,
        envelope_digest: empty_digest(RegisteredDomainV1::PrTrustEnvelope),
    };
    envelope.envelope_digest = digest_serializable_v1(
        RegisteredDomainV1::PrTrustEnvelope,
        &envelope_core(&envelope),
    )?;
    Ok(envelope)
}

/// Decode an exact JCE1 envelope and compare it with a fresh evaluation.
pub fn verify_pr_envelope(
    repository: &Path,
    envelope_bytes: &[u8],
) -> Result<PrTrustEnvelope, TrustError> {
    let payload = envelope_bytes.strip_suffix(b"\n").unwrap_or(envelope_bytes);
    if payload.len() > MAX_ENVELOPE_BYTES {
        return Err(TrustError::Invalid(format!(
            "envelope exceeds {MAX_ENVELOPE_BYTES} bytes"
        )));
    }
    let text = std::str::from_utf8(payload)
        .map_err(|_| TrustError::Invalid("envelope is not UTF-8".to_owned()))?;
    let canonical = parse_strict_v1(text)?;
    if to_canonical_bytes_v1(&canonical)? != payload {
        return Err(TrustError::Invalid(
            "envelope is not exact canonical JCE1".to_owned(),
        ));
    }
    let envelope: PrTrustEnvelope = serde_json::from_value(canonical.to_serde_value())?;
    validate_envelope_digest(&envelope)?;
    let observed = evaluate_pr(
        repository,
        &envelope.candidate.base_commit,
        &envelope.candidate.head_commit,
    )?;
    if observed != envelope {
        return Err(TrustError::EnvelopeMismatch);
    }
    Ok(observed)
}

fn envelope_core(envelope: &PrTrustEnvelope) -> PrTrustEnvelopeCore<'_> {
    PrTrustEnvelopeCore {
        schema: &envelope.schema,
        status: &envelope.status,
        claim_scope: &envelope.claim_scope,
        network_policy: &envelope.network_policy,
        write_policy: &envelope.write_policy,
        telemetry_policy: &envelope.telemetry_policy,
        candidate: &envelope.candidate,
        evidence: &envelope.evidence,
        policy_digest: &envelope.policy_digest,
        program: &envelope.program,
        limitations: &envelope.limitations,
    }
}

fn validate_envelope_digest(envelope: &PrTrustEnvelope) -> Result<(), TrustError> {
    if envelope.schema != PR_TRUST_ENVELOPE_SCHEMA
        || envelope.status != "requirements-satisfied"
        || envelope.limitations.len() != 4
    {
        return Err(TrustError::Invalid(
            "envelope status or limitation contract is invalid".to_owned(),
        ));
    }
    let expected = digest_serializable_v1(
        RegisteredDomainV1::PrTrustEnvelope,
        &envelope_core(envelope),
    )?;
    if envelope.envelope_digest != expected {
        return Err(TrustError::Invalid("envelope digest mismatch".to_owned()));
    }
    Ok(())
}

fn validate_policy(policy: &PrTrustPolicy) -> Result<(), TrustError> {
    if policy.schema != PR_TRUST_POLICY_SCHEMA
        || policy.profile != "offline-read-only-v0"
        || policy.repository.is_empty()
        || policy.repository.len() > 256
        || policy.network_policy != "denied-no-network-client"
        || policy.write_policy != "denied"
        || policy.telemetry_policy != "none"
        || policy.claim_scope != "offline-local-evidence-binding-not-code-safety-or-pr-approval"
    {
        return Err(TrustError::Invalid(
            "policy identity or operating mode is invalid".to_owned(),
        ));
    }
    for path in [
        &policy.policy_source_path,
        &policy.package_manifest_path,
        &policy.package_store_path,
        &policy.evidence_index_path,
    ] {
        validate_relative_path(path)?;
    }
    validate_digest_shape(&policy.policy_source_digest, RegisteredDomainV1::Source)?;
    validate_digest_shape(
        &policy.package_manifest_digest,
        RegisteredDomainV1::PackageManifest,
    )?;
    if !(1..=1_000_000).contains(&policy.instruction_budget)
        || !(1..=1_024).contains(&policy.max_changed_files)
        || !(1..=64 * 1_048_576).contains(&policy.max_changed_bytes)
        || policy.required_verification_runs != 3
        || policy.required_gate_count != 11
        || policy.required_jce1_passed != 27
    {
        return Err(TrustError::Invalid(
            "policy limits or required evidence counts are invalid".to_owned(),
        ));
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "one flat Git candidate boundary keeps every accepted status, path and byte binding reviewable"
)]
fn inspect_candidate(
    root: &Path,
    policy: &PrTrustPolicy,
    base_reference: &str,
    head_reference: &str,
) -> Result<PrCandidateReceipt, TrustError> {
    validate_git_reference(base_reference)?;
    validate_git_reference(head_reference)?;
    let status = git(
        root,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?;
    if !status.is_empty() {
        return Err(TrustError::Invalid(
            "Git worktree or index is not clean".to_owned(),
        ));
    }
    let base_commit = resolve_commit(root, base_reference)?;
    let head_commit = resolve_commit(root, head_reference)?;
    if base_commit == head_commit {
        return Err(TrustError::Invalid(
            "base and head commits must differ".to_owned(),
        ));
    }
    let checked_out = resolve_commit(root, "HEAD")?;
    if checked_out != head_commit {
        return Err(TrustError::Invalid(
            "head commit is not the checked-out HEAD".to_owned(),
        ));
    }
    git(
        root,
        &["merge-base", "--is-ancestor", &base_commit, &head_commit],
    )?;
    let object_format = git_text(root, &["rev-parse", "--show-object-format"])?;
    if object_format != "sha1" && object_format != "sha256" {
        return Err(TrustError::Git("unsupported Git object format".to_owned()));
    }
    let expected_hex = if object_format == "sha1" { 40 } else { 64 };
    validate_hex(&base_commit, expected_hex, "base commit")?;
    validate_hex(&head_commit, expected_hex, "head commit")?;

    let diff = git(
        root,
        &[
            "diff",
            "--name-status",
            "-z",
            "--no-renames",
            &base_commit,
            &head_commit,
            "--",
        ],
    )?;
    let fields = diff
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    if fields.len() % 2 != 0 {
        return Err(TrustError::Git(
            "name-status output has an incomplete record".to_owned(),
        ));
    }
    let record_count = fields.len() / 2;
    if record_count == 0
        || u64::try_from(record_count)
            .map_err(|_| TrustError::Invalid("changed-file count exceeds u64".to_owned()))?
            > policy.max_changed_files
    {
        return Err(TrustError::Invalid(format!(
            "changed-file count must be 1..={}",
            policy.max_changed_files
        )));
    }
    let mut changed_files = Vec::with_capacity(record_count);
    let mut total_changed_bytes = 0_u64;
    for pair in fields.chunks_exact(2) {
        let status = std::str::from_utf8(pair[0])
            .map_err(|_| TrustError::Git("change status is not UTF-8".to_owned()))?;
        let path = std::str::from_utf8(pair[1])
            .map_err(|_| TrustError::Invalid("Git path is not UTF-8".to_owned()))?;
        validate_relative_path(path)?;
        let change = match status {
            "A" => ChangeKind::Added,
            "M" => ChangeKind::Modified,
            "D" => ChangeKind::Deleted,
            _ => {
                return Err(TrustError::Invalid(format!(
                    "unsupported Git change status `{status}`"
                )));
            }
        };
        let base_blob = if change == ChangeKind::Added {
            None
        } else {
            Some(read_git_regular_blob(
                root,
                &base_commit,
                path,
                policy.max_changed_bytes,
            )?)
        };
        let current_blob = if change == ChangeKind::Deleted {
            None
        } else {
            let committed =
                read_git_regular_blob(root, &head_commit, path, policy.max_changed_bytes)?;
            let file = safe_existing_path(root, path, PathKind::File)?;
            let checkout = read_bounded_file(&file, policy.max_changed_bytes)?;
            if committed != checkout {
                return Err(TrustError::Invalid(format!(
                    "checked-out bytes for `{path}` differ from the head Git blob"
                )));
            }
            Some(committed)
        };
        for bytes in base_blob.iter().chain(current_blob.iter()) {
            total_changed_bytes = total_changed_bytes
                .checked_add(u64::try_from(bytes.len()).map_err(|_| {
                    TrustError::Invalid("changed file length exceeds u64".to_owned())
                })?)
                .ok_or_else(|| TrustError::Invalid("changed-byte total overflow".to_owned()))?;
        }
        if total_changed_bytes > policy.max_changed_bytes {
            return Err(TrustError::Invalid(format!(
                "changed bytes exceed {}",
                policy.max_changed_bytes
            )));
        }
        let base_bytes = base_blob
            .as_ref()
            .map(Vec::len)
            .map(u64::try_from)
            .transpose()
            .map_err(|_| TrustError::Invalid("base file length exceeds u64".to_owned()))?;
        let base_content_digest = base_blob
            .as_deref()
            .map(|bytes| digest_bytes_v1(RegisteredDomainV1::Source, bytes))
            .transpose()?;
        let current_bytes = current_blob
            .as_ref()
            .map(Vec::len)
            .map(u64::try_from)
            .transpose()
            .map_err(|_| TrustError::Invalid("current file length exceeds u64".to_owned()))?;
        let current_content_digest = current_blob
            .as_deref()
            .map(|bytes| digest_bytes_v1(RegisteredDomainV1::Source, bytes))
            .transpose()?;
        changed_files.push(ChangedFile {
            path: path.to_owned(),
            change,
            base_bytes,
            base_content_digest,
            current_bytes,
            current_content_digest,
        });
    }
    if !changed_files
        .windows(2)
        .all(|window| window[0].path.as_bytes() < window[1].path.as_bytes())
    {
        return Err(TrustError::Invalid(
            "changed paths are not unique and bytewise sorted".to_owned(),
        ));
    }
    let core = PrCandidateCore {
        repository: &policy.repository,
        object_format: &object_format,
        base_commit: &base_commit,
        head_commit: &head_commit,
        changed_files: &changed_files,
        total_changed_bytes,
    };
    let candidate_digest = digest_serializable_v1(RegisteredDomainV1::PrCandidate, &core)?;
    Ok(PrCandidateReceipt {
        schema: "joan.pr-candidate-receipt.v0".to_owned(),
        status: "bound-clean-worktree".to_owned(),
        repository: policy.repository.clone(),
        object_format,
        base_commit,
        head_commit,
        changed_files,
        total_changed_bytes,
        candidate_digest,
    })
}

fn verify_evidence(
    root: &Path,
    policy: &PrTrustPolicy,
    source: &SourceTreeSnapshot,
) -> Result<EvidenceBinding, TrustError> {
    verify_evidence_with_mode(root, policy, source, true)
}

#[allow(
    clippy::too_many_lines,
    reason = "current and historical evidence share all receipt invariants except current-tooling authorization"
)]
fn verify_evidence_with_mode(
    root: &Path,
    policy: &PrTrustPolicy,
    source: &SourceTreeSnapshot,
    require_current_tooling: bool,
) -> Result<EvidenceBinding, TrustError> {
    validate_source_tree_snapshot(source)?;
    let path = safe_existing_path(root, &policy.evidence_index_path, PathKind::File)?;
    let bytes = read_bounded_file(&path, MAX_EVIDENCE_INDEX_BYTES)?;
    let index: EvidenceIndex = decode_strict(&bytes)?;
    if index.schema != "joan.evidence-index.v2"
        || index.version != env!("CARGO_PKG_VERSION")
        || index.status != "local-verification-passed-with-receipts"
        || index.generated_at.is_empty()
        || index.source != *source
        || index.limitations.is_empty()
    {
        return Err(TrustError::Invalid(
            "evidence index identity, status or source tree is invalid".to_owned(),
        ));
    }
    let indexed_gate_count = u64::try_from(index.verification.required_gate_ids.len())
        .map_err(|_| TrustError::Invalid("gate count exceeds u64".to_owned()))?;
    validate_gate_profile(
        &index.verification.required_gate_ids,
        require_current_tooling,
    )?;
    let expected_gate_count = if require_current_tooling {
        policy.required_gate_count
    } else {
        indexed_gate_count
    };
    if indexed_gate_count != expected_gate_count
        || !all_unique(&index.verification.required_gate_ids)
        || index.verification.runs.len()
            != usize::try_from(policy.required_verification_runs)
                .map_err(|_| TrustError::Invalid("run count exceeds usize".to_owned()))?
        || index.verification.repeatability.required_runs != policy.required_verification_runs
        || index.verification.repeatability.completed_runs != policy.required_verification_runs
        || index.verification.repeatability.unique_run_ids != policy.required_verification_runs
        || !index.verification.repeatability.same_source
        || !index.verification.repeatability.same_observations
    {
        return Err(TrustError::Invalid(
            "evidence repeatability or required gate contract is invalid".to_owned(),
        ));
    }
    let runner_sha256 = validate_evidence_file_binding(
        root,
        &index.verification.runner,
        "verification runner",
        VERIFICATION_RUNNER_PATH,
        require_current_tooling,
    )?;
    let gate_config_sha256 = validate_evidence_file_binding(
        root,
        &index.verification.gate_config,
        "gate configuration",
        VERIFICATION_GATES_PATH,
        require_current_tooling,
    )?;
    let jce1_passed = json_u64(&index.conformance, "/jce1/passed", "JCE1 passed")?;
    let dispute_cases = json_u64(&index.conformance, "/jdr1/cases", "JDR1 cases")?;
    let vulnerabilities_found = json_u64(
        &index.supply_chain,
        "/cargo_audit/vulnerabilities_found",
        "cargo-audit vulnerabilities",
    )?;
    if jce1_passed != policy.required_jce1_passed
        || json_str(&index.conformance, "/jce1/status", "JCE1 status")?
            != "passed-local-cross-implementation"
        || dispute_cases != 10_000
        || vulnerabilities_found != 0
        || json_str(
            &index.supply_chain,
            "/cargo_audit/status",
            "cargo-audit status",
        )? != "passed"
        || json_str(
            &index.supply_chain,
            "/cargo_deny/status",
            "cargo-deny status",
        )? != "passed"
        || json_bool(
            &index.benchmark,
            "/language_superiority_claim",
            "benchmark superiority claim",
        )?
    {
        return Err(TrustError::Invalid(
            "conformance, simulation, supply-chain or claim gate failed".to_owned(),
        ));
    }
    if !index.inventory.is_object() {
        return Err(TrustError::Invalid(
            "evidence inventory is not an object".to_owned(),
        ));
    }
    let mut run_ids = Vec::new();
    let mut first_observations: Option<JsonValue> = None;
    let receipt_context = ReceiptValidationContext {
        root,
        source,
        required_gate_ids: &index.verification.required_gate_ids,
        supply_chain: &index.supply_chain,
        runner_sha256: &runner_sha256,
        gate_config_sha256: &gate_config_sha256,
        require_current_tooling,
    };
    for (position, run) in index.verification.runs.iter().enumerate() {
        let expected_ordinal = u64::try_from(position + 1)
            .map_err(|_| TrustError::Invalid("run ordinal exceeds u64".to_owned()))?;
        if run.ordinal != expected_ordinal
            || run.status != "passed"
            || run.gate_count != expected_gate_count
            || run.source_digest != source.tree_digest.value
            || run.started_at.is_empty()
            || run.completed_at.is_empty()
        {
            return Err(TrustError::Invalid(format!(
                "evidence run {} summary is invalid",
                position + 1
            )));
        }
        validate_hex(&run.file_sha256, 64, "receipt file SHA-256")?;
        let receipt_path = safe_existing_path(root, &run.path, PathKind::File)?;
        if !run.path.starts_with(".joan/evidence/runs/") {
            return Err(TrustError::Invalid(
                "receipt path is outside the evidence run directory".to_owned(),
            ));
        }
        let receipt_bytes = read_bounded_file(&receipt_path, MAX_EVIDENCE_RECEIPT_BYTES)?;
        if raw_sha256(&receipt_bytes) != run.file_sha256 {
            return Err(TrustError::Invalid(format!(
                "evidence run {} file hash mismatch",
                position + 1
            )));
        }
        let receipt: VerificationReceipt = decode_strict(&receipt_bytes)?;
        validate_verification_receipt(&receipt, run, &receipt_context)?;
        if let Some(observations) = &first_observations {
            if observations != &receipt.observations {
                return Err(TrustError::Invalid(
                    "verification receipt observations differ".to_owned(),
                ));
            }
        } else {
            first_observations = Some(receipt.observations.clone());
        }
        run_ids.push(run.run_id.clone());
    }
    if !all_unique(&run_ids) {
        return Err(TrustError::Invalid(
            "verification run IDs are not unique".to_owned(),
        ));
    }
    Ok(EvidenceBinding {
        schema: "joan.pr-evidence-binding.v0".to_owned(),
        status: if require_current_tooling {
            "three-local-runs-bound"
        } else {
            "historical-three-local-runs-inspection-only"
        }
        .to_owned(),
        source: source.clone(),
        evidence_index_digest: digest_bytes_v1(RegisteredDomainV1::PrTrustEvidence, &bytes)?,
        verification_run_ids: run_ids,
        required_gate_ids: index.verification.required_gate_ids,
        jce1_passed,
        dispute_cases,
        vulnerabilities_found,
        claim_scope: if require_current_tooling {
            "local-receipts-not-independent-attestation"
        } else {
            "historical-local-receipts-not-current-authorization"
        }
        .to_owned(),
    })
}

fn validate_verification_receipt(
    receipt: &VerificationReceipt,
    summary: &EvidenceRunSummary,
    context: &ReceiptValidationContext<'_>,
) -> Result<(), TrustError> {
    let required_gate_count = u64::try_from(context.required_gate_ids.len())
        .map_err(|_| TrustError::Invalid("receipt gate count exceeds u64".to_owned()))?;
    if receipt.schema != "joan.verification-run-receipt.v1"
        || receipt.version != env!("CARGO_PKG_VERSION")
        || receipt.run_id != summary.run_id
        || receipt.status != "passed"
        || receipt.started_at != summary.started_at
        || receipt.completed_at != summary.completed_at
        || receipt.source != *context.source
        || receipt.summary.required != required_gate_count
        || receipt.summary.executed != required_gate_count
        || receipt.summary.passed != required_gate_count
        || receipt.summary.failed != 0
        || receipt.gates.len() != context.required_gate_ids.len()
        || receipt.supply_chain != *context.supply_chain
    {
        return Err(TrustError::Invalid(format!(
            "verification receipt {} contract mismatch",
            summary.ordinal
        )));
    }
    validate_timestamp_pair(
        &receipt.started_at,
        &receipt.completed_at,
        "verification receipt",
    )?;
    validate_receipt_environment(
        context.root,
        &receipt.environment,
        context.runner_sha256,
        context.gate_config_sha256,
        required_gate_count == 11,
        context.require_current_tooling,
    )?;
    for (gate, expected_id) in receipt.gates.iter().zip(context.required_gate_ids) {
        validate_gate_receipt(
            context.root,
            gate,
            expected_id,
            context.require_current_tooling,
        )?;
    }
    Ok(())
}

fn validate_receipt_environment(
    root: &Path,
    environment: &JsonValue,
    runner_sha256: &str,
    gate_config_sha256: &str,
    gate_config_required: bool,
    require_current_tooling: bool,
) -> Result<(), TrustError> {
    if json_str(environment, "/runner_sha256", "receipt runner SHA-256")? != runner_sha256 {
        return Err(TrustError::Invalid(
            "receipt runner SHA-256 does not match evidence index".to_owned(),
        ));
    }
    match environment
        .pointer("/gate_config_sha256")
        .and_then(JsonValue::as_str)
    {
        Some(observed) => {
            validate_hex(observed, 64, "receipt gate configuration SHA-256")?;
            if observed != gate_config_sha256 {
                return Err(TrustError::Invalid(
                    "receipt gate configuration SHA-256 does not match evidence index".to_owned(),
                ));
            }
        }
        None if !gate_config_required => {}
        None => {
            return Err(TrustError::Invalid(
                "current receipt omits gate configuration SHA-256".to_owned(),
            ));
        }
    }
    let tools = environment
        .pointer("/tools")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| TrustError::Invalid("receipt tool inventory is missing".to_owned()))?;
    let expected = ["node", "cargo", "rustc", "cargo-audit", "cargo-deny"];
    if tools.len() != expected.len() {
        return Err(TrustError::Invalid("receipt tool count drift".to_owned()));
    }
    for (tool, expected_id) in tools.iter().zip(expected) {
        if json_str(tool, "/id", "tool id")? != expected_id
            || json_str(tool, "/version", "tool version")?.is_empty()
        {
            return Err(TrustError::Invalid(
                "receipt tool inventory is not the required ordered set".to_owned(),
            ));
        }
        validate_executable_binding(
            json_str(tool, "/path", "tool path")?,
            json_str(tool, "/sha256", "tool SHA-256")?,
            &format!("tool `{expected_id}`"),
            require_current_tooling,
        )?;
        if require_current_tooling {
            validate_resolved_command_path(
                root,
                expected_id,
                json_str(tool, "/path", "tool path")?,
                &format!("tool `{expected_id}`"),
            )?;
        }
    }
    Ok(())
}

fn validate_gate_receipt(
    root: &Path,
    gate: &JsonValue,
    expected_id: &str,
    require_current_tooling: bool,
) -> Result<(), TrustError> {
    if json_str(gate, "/id", "gate id")? != expected_id
        || json_str(gate, "/status", "gate status")? != "passed"
        || json_i64(gate, "/exit_code", "gate exit code")? != 0
        || gate.pointer("/signal") != Some(&JsonValue::Null)
    {
        return Err(TrustError::Invalid(format!(
            "verification gate `{expected_id}` did not pass exactly"
        )));
    }
    let expected_argv = expected_gate_argv(expected_id)?;
    let observed_argv = gate
        .pointer("/argv")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| TrustError::Invalid(format!("gate `{expected_id}` argv is missing")))?;
    if observed_argv.len() != expected_argv.len()
        || !observed_argv
            .iter()
            .zip(expected_argv.iter().copied())
            .all(|(observed, expected)| observed.as_str() == Some(expected))
    {
        return Err(TrustError::Invalid(format!(
            "verification gate `{expected_id}` argv drift"
        )));
    }
    let executable_path = json_str(gate, "/executable_path", "gate executable path")?;
    let repository_command = expected_argv[0].starts_with("./");
    validate_executable_binding(
        executable_path,
        json_str(gate, "/executable_sha256", "gate executable SHA-256")?,
        &format!("gate `{expected_id}` executable"),
        require_current_tooling && !repository_command,
    )?;
    if require_current_tooling {
        if repository_command {
            validate_repository_command_path(
                root,
                expected_argv[0],
                executable_path,
                json_str(gate, "/executable_sha256", "gate executable SHA-256")?,
                &format!("gate `{expected_id}` executable"),
            )?;
        } else {
            validate_resolved_command_path(
                root,
                expected_argv[0],
                executable_path,
                &format!("gate `{expected_id}` executable"),
            )?;
        }
    }
    validate_timestamp_pair(
        json_str(gate, "/started_at", "gate start timestamp")?,
        json_str(gate, "/completed_at", "gate completion timestamp")?,
        &format!("gate `{expected_id}`"),
    )?;
    for stream in ["stdout", "stderr"] {
        let prefix = format!("/{stream}");
        let value = gate.pointer(&prefix).ok_or_else(|| {
            TrustError::Invalid(format!("gate `{expected_id}` {stream} receipt is missing"))
        })?;
        let bytes = json_u64(value, "/bytes", "gate stream byte count")?;
        if bytes > 128 * 1_048_576 {
            return Err(TrustError::Invalid(format!(
                "gate `{expected_id}` {stream} exceeds the receipt bound"
            )));
        }
        validate_hex(
            json_str(value, "/sha256", "gate stream SHA-256")?,
            64,
            "gate stream SHA-256",
        )?;
    }
    Ok(())
}

fn validate_executable_binding(
    path: &str,
    expected_sha256: &str,
    label: &str,
    require_current_file: bool,
) -> Result<(), TrustError> {
    validate_hex(expected_sha256, 64, label)?;
    let candidate = Path::new(path);
    if !candidate.is_absolute() {
        return Err(TrustError::Invalid(format!("{label} path is not absolute")));
    }
    if require_current_file {
        let canonical = fs::canonicalize(candidate)?;
        if canonical.to_str() != Some(path) {
            return Err(TrustError::Invalid(format!(
                "{label} path is not canonical UTF-8"
            )));
        }
        let metadata = fs::symlink_metadata(&canonical)?;
        if !metadata.is_file() {
            return Err(TrustError::Invalid(format!(
                "{label} is not a regular file"
            )));
        }
        let bytes = read_bounded_file(&canonical, MAX_EXECUTABLE_BYTES)?;
        if raw_sha256(&bytes) != expected_sha256 {
            return Err(TrustError::Invalid(format!(
                "{label} current file hash mismatch"
            )));
        }
    }
    Ok(())
}

fn validate_resolved_command_path(
    root: &Path,
    command: &str,
    observed_path: &str,
    label: &str,
) -> Result<(), TrustError> {
    let resolved = if command.contains('/') {
        fs::canonicalize(root.join(command))?
    } else {
        let path = std::env::var_os("PATH")
            .ok_or_else(|| TrustError::Invalid("PATH is unavailable".to_owned()))?;
        std::env::split_paths(&path)
            .map(|directory| directory.join(command))
            .find_map(|candidate| fs::canonicalize(candidate).ok())
            .ok_or_else(|| TrustError::Invalid(format!("{label} command is unavailable on PATH")))?
    };
    if resolved.to_str() != Some(observed_path) {
        return Err(TrustError::Invalid(format!(
            "{label} does not match the command resolved from PATH"
        )));
    }
    Ok(())
}

fn validate_repository_command_path(
    root: &Path,
    command: &str,
    observed_path: &str,
    expected_sha256: &str,
    label: &str,
) -> Result<(), TrustError> {
    let relative = command
        .strip_prefix("./")
        .ok_or_else(|| TrustError::Invalid(format!("{label} is not repository-relative")))?;
    validate_relative_path(relative)?;
    let observed = Path::new(observed_path);
    if !observed.is_absolute()
        || observed
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || !observed.ends_with(relative)
    {
        return Err(TrustError::Invalid(format!(
            "{label} does not preserve its repository path"
        )));
    }
    let current = safe_existing_path(root, relative, PathKind::File)?;
    if raw_sha256(&read_bounded_file(&current, MAX_EXECUTABLE_BYTES)?) != expected_sha256 {
        return Err(TrustError::Invalid(format!(
            "{label} current repository file hash mismatch"
        )));
    }
    Ok(())
}

fn validate_timestamp_pair(started: &str, completed: &str, label: &str) -> Result<(), TrustError> {
    if !is_canonical_utc_timestamp(started)
        || !is_canonical_utc_timestamp(completed)
        || completed < started
    {
        return Err(TrustError::Invalid(format!(
            "{label} timestamps are invalid or reversed"
        )));
    }
    Ok(())
}

fn is_canonical_utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 24
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'.'
        || bytes[23] != b'Z'
    {
        return false;
    }
    for index in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18, 20, 21, 22] {
        if !bytes[index].is_ascii_digit() {
            return false;
        }
    }
    let number = |start: usize, end: usize| {
        bytes[start..end]
            .iter()
            .fold(0_u32, |value, digit| value * 10 + u32::from(digit - b'0'))
    };
    (1..=12).contains(&number(5, 7))
        && (1..=31).contains(&number(8, 10))
        && number(11, 13) <= 23
        && number(14, 16) <= 59
        && number(17, 19) <= 59
}

fn expected_gate_argv(id: &str) -> Result<&'static [&'static str], TrustError> {
    let argv: &[&str] = match id {
        "format" => &["cargo", "fmt", "--check"],
        "clippy" => &[
            "cargo",
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
        "tests" => &["cargo", "test", "--workspace", "--all-features", "--locked"],
        "doc-tests" => &["cargo", "test", "--doc", "--workspace", "--locked"],
        "release-build" => &["cargo", "build", "--workspace", "--release", "--locked"],
        "jce1" => &["./scripts/verify-jce1.sh"],
        "c-digest-smoke" => &["./scripts/benchmark-digest.sh", "1024", "1000"],
        "payment-cost-vector" => &["./scripts/verify-payment-cost.sh"],
        "tool-forge" => &["./scripts/verify-tool-forge.sh"],
        "cargo-deny" => &["cargo", "deny", "--locked", "check"],
        "cargo-audit" => &["cargo", "audit", "--json"],
        _ => {
            return Err(TrustError::Invalid(format!(
                "verification gate `{id}` is unknown"
            )));
        }
    };
    Ok(argv)
}

#[allow(
    clippy::too_many_lines,
    reason = "the composition boundary keeps package, language, authority and flow invariants auditable in sequence"
)]
fn verify_policy_program(
    root: &Path,
    policy: &PrTrustPolicy,
    candidate: &PrCandidateReceipt,
) -> Result<PolicyProgramBinding, TrustError> {
    let source_path = safe_existing_path(root, &policy.policy_source_path, PathKind::File)?;
    let source_bytes = read_bounded_file(&source_path, 1_048_576)?;
    let observed_source_digest = digest_bytes_v1(RegisteredDomainV1::Source, &source_bytes)?;
    if observed_source_digest != policy.policy_source_digest {
        return Err(TrustError::Invalid(
            "policy source digest mismatch".to_owned(),
        ));
    }
    let source = std::str::from_utf8(&source_bytes)
        .map_err(|_| TrustError::Invalid("policy source is not UTF-8".to_owned()))?;
    let artifact = compile_source(source)?;
    let execution = execute_bytecode(&artifact.bytecode, policy.instruction_budget)?;
    let request = execution.effect_requests.as_slice();
    let [request] = request else {
        return Err(TrustError::Invalid(
            "policy program must emit exactly one effect request".to_owned(),
        ));
    };
    let expected_information = InformationLabel::Secret {
        tenant: "github".to_owned(),
        purpose: "pr_review".to_owned(),
    };
    if artifact.schema != "joan.compile-artifact.v3"
        || execution.schema != "joan.execution-receipt.v3"
        || execution.result != Value::Unit
        || execution.instructions_executed > policy.instruction_budget
        || request.request_index != 0
        || request.function != "main"
        || request.effect != "publish_pr_assessment"
        || request.authority_slot.as_deref() != Some("publish_once")
        || request.information.as_ref() != Some(&expected_information)
        || request.arguments != [Value::String("requirements-satisfied".to_owned())]
    {
        return Err(TrustError::Invalid(
            "policy program does not match the bounded PR assessment contract".to_owned(),
        ));
    }

    let manifest_path = safe_existing_path(root, &policy.package_manifest_path, PathKind::File)?;
    let manifest_bytes = read_bounded_file(&manifest_path, 1_048_576)?;
    let (_, observed_manifest_digest) = verify_manifest_bytes(&manifest_bytes)?;
    if observed_manifest_digest != policy.package_manifest_digest {
        return Err(TrustError::Invalid(
            "policy package manifest digest mismatch".to_owned(),
        ));
    }
    let store_path = safe_existing_path(root, &policy.package_store_path, PathKind::Directory)?;
    let package_receipt = resolve_package(&manifest_bytes, &store_path)?;
    if package_receipt.root_manifest_digest != policy.package_manifest_digest
        || !package_receipt
            .source_digests
            .contains(&policy.policy_source_digest)
        || package_receipt.network_policy != "denied-no-network-client"
        || package_receipt.store_mode != "read-only"
    {
        return Err(TrustError::Invalid(
            "policy package resolution does not bind the exact source".to_owned(),
        ));
    }

    let capabilities = BTreeSet::from([request.effect.clone()]);
    let authority = AuthorityEnvelope {
        schema: "joan.authority-envelope.v0".to_owned(),
        host_identity: "joan-pr-trust-local-evaluator".to_owned(),
        task_id: execution.semantic_digest.value.clone(),
        path: format!("pr/{}", candidate.candidate_digest.value),
        task_kind: "plan-pr-assessment".to_owned(),
        roots: vec![AuthorityRoot {
            root_id: "local-no-dispatch-root".to_owned(),
            grants: capabilities.clone(),
            denies: BTreeSet::new(),
        }],
        approval_required: capabilities.clone(),
        approvable: capabilities.clone(),
        approvals: vec![OneShotApproval {
            nonce: request.request_id.clone(),
            task_id: execution.semantic_digest.value.clone(),
            capabilities,
            authority_slot: request.authority_slot.clone(),
            information: request.information.clone(),
        }],
    };
    let mut ledger = CapabilityLedger::default();
    let plan = plan_effects(&execution, Some(&authority), &mut ledger)?;
    if plan.status != "authorized" || plan.effects.len() != 1 || ledger.len() != 1 {
        return Err(TrustError::Invalid(
            "policy effect was not planned exactly once".to_owned(),
        ));
    }
    Ok(PolicyProgramBinding {
        policy_source_path: policy.policy_source_path.clone(),
        package_manifest_path: policy.package_manifest_path.clone(),
        policy_source_digest: policy.policy_source_digest.clone(),
        package_manifest_digest: policy.package_manifest_digest.clone(),
        package_resolution_digest: digest_serializable_v1(
            RegisteredDomainV1::PrTrustEvidence,
            &package_receipt,
        )?,
        semantic_identity: execution.semantic_identity.clone(),
        bytecode_verification: artifact.verification,
        execution_receipt_digest: digest_serializable_v1(
            RegisteredDomainV1::PrTrustEvidence,
            &execution,
        )?,
        effect_plan_digest: plan.plan_digest,
        instruction_budget: policy.instruction_budget,
        instructions_executed: execution.instructions_executed,
        planned_effect: request.effect.clone(),
        authority_slot: request
            .authority_slot
            .clone()
            .ok_or_else(|| TrustError::Invalid("policy authority slot is absent".to_owned()))?,
        information: expected_information,
    })
}

fn source_tree_snapshot(root: &Path) -> Result<SourceTreeSnapshot, TrustError> {
    let mut files = Vec::new();
    collect_source_files(root, root, 0, &mut files)?;
    files.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    if files.len() > MAX_SOURCE_FILES {
        return Err(TrustError::Invalid(format!(
            "source tree exceeds {MAX_SOURCE_FILES} files"
        )));
    }
    let mut tree = Sha256::new();
    tree.update(SOURCE_TREE_PREFIX);
    let mut total_bytes = 0_u64;
    for (relative, absolute) in &files {
        let bytes = read_bounded_file(absolute, MAX_SOURCE_FILE_BYTES)?;
        let length = u64::try_from(bytes.len())
            .map_err(|_| TrustError::Invalid("source file length exceeds u64".to_owned()))?;
        total_bytes = total_bytes
            .checked_add(length)
            .ok_or_else(|| TrustError::Invalid("source tree byte count overflow".to_owned()))?;
        if total_bytes > MAX_SOURCE_TREE_BYTES {
            return Err(TrustError::Invalid(format!(
                "source tree exceeds {MAX_SOURCE_TREE_BYTES} bytes"
            )));
        }
        let path_length = u64::try_from(relative.len())
            .map_err(|_| TrustError::Invalid("source path length exceeds u64".to_owned()))?;
        tree.update(path_length.to_be_bytes());
        tree.update(relative.as_bytes());
        tree.update(Sha256::digest(&bytes));
    }
    Ok(SourceTreeSnapshot {
        tree_digest: SourceTreeDigest {
            algorithm: "sha256".to_owned(),
            profile: "joan-source-tree-v2".to_owned(),
            value: lower_hex(&tree.finalize()),
        },
        file_count: u64::try_from(files.len())
            .map_err(|_| TrustError::Invalid("source file count exceeds u64".to_owned()))?,
        excludes: EXPECTED_EXCLUDES.iter().map(ToString::to_string).collect(),
    })
}

fn validate_source_tree_snapshot(source: &SourceTreeSnapshot) -> Result<(), TrustError> {
    if source.tree_digest.algorithm != "sha256"
        || source.tree_digest.profile != "joan-source-tree-v2"
        || source.file_count == 0
        || source.file_count
            > u64::try_from(MAX_SOURCE_FILES)
                .map_err(|_| TrustError::Invalid("source file limit exceeds u64".to_owned()))?
        || !source
            .excludes
            .iter()
            .map(String::as_str)
            .eq(EXPECTED_EXCLUDES)
    {
        return Err(TrustError::Invalid(
            "source tree snapshot shape is invalid".to_owned(),
        ));
    }
    validate_hex(&source.tree_digest.value, 64, "source tree digest")
}

fn collect_source_files(
    root: &Path,
    directory: &Path,
    depth: usize,
    files: &mut Vec<(String, PathBuf)>,
) -> Result<(), TrustError> {
    if depth > MAX_DIRECTORY_DEPTH {
        return Err(TrustError::Invalid(format!(
            "source tree depth exceeds {MAX_DIRECTORY_DEPTH}"
        )));
    }
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| TrustError::Invalid("source path escaped repository".to_owned()))?;
        let relative_text = path_to_slash(relative)?;
        if source_path_excluded(&relative_text) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(TrustError::Invalid(format!(
                "source tree contains symlink `{relative_text}`"
            )));
        }
        if metadata.is_dir() {
            collect_source_files(root, &path, depth + 1, files)?;
        } else if metadata.is_file() {
            files.push((relative_text, path));
        } else {
            return Err(TrustError::Invalid(format!(
                "source tree contains non-regular entry `{relative_text}`"
            )));
        }
    }
    Ok(())
}

fn source_path_excluded(path: &str) -> bool {
    if path == ".git"
        || path.starts_with(".git/")
        || path == "target"
        || path.starts_with("target/")
        || path == ".joan/evidence"
        || path.starts_with(".joan/evidence/")
    {
        return true;
    }
    path.split('/')
        .any(|component| component == ".DS_Store" || component.starts_with("._"))
}

fn validate_digest_shape(digest: &Digest, domain: RegisteredDomainV1) -> Result<(), TrustError> {
    if digest.algorithm != "sha256"
        || digest.profile != "joan-hash-v1"
        || digest.domain != domain.as_str()
    {
        return Err(TrustError::Invalid(format!(
            "digest does not use `{}`",
            domain.as_str()
        )));
    }
    validate_hex(&digest.value, 64, "typed digest")
}

fn empty_digest(domain: RegisteredDomainV1) -> Digest {
    Digest {
        algorithm: "sha256".to_owned(),
        profile: "joan-hash-v1".to_owned(),
        domain: domain.as_str().to_owned(),
        value: "0".repeat(64),
    }
}

fn resolve_commit(root: &Path, reference: &str) -> Result<String, TrustError> {
    git_text(
        root,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{reference}^{{commit}}"),
        ],
    )
}

fn validate_git_reference(reference: &str) -> Result<(), TrustError> {
    if reference.is_empty()
        || reference.len() > 256
        || reference
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(TrustError::Invalid(
            "Git reference is empty, oversized or contains control bytes".to_owned(),
        ));
    }
    Ok(())
}

fn git_text(root: &Path, arguments: &[&str]) -> Result<String, TrustError> {
    let bytes = git(root, arguments)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| TrustError::Git("Git output is not UTF-8".to_owned()))?;
    Ok(text.trim_end_matches(['\r', '\n']).to_owned())
}

fn read_git_regular_blob(
    root: &Path,
    commit: &str,
    path: &str,
    limit: u64,
) -> Result<Vec<u8>, TrustError> {
    let tree = git(root, &["ls-tree", "-z", "--full-tree", commit, "--", path])?;
    let records = tree
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
        .collect::<Vec<_>>();
    let [record] = records.as_slice() else {
        return Err(TrustError::Invalid(format!(
            "Git tree must contain exactly one entry for `{path}`"
        )));
    };
    let metadata = record
        .split(|byte| *byte == b'\t')
        .next()
        .ok_or_else(|| TrustError::Git("Git tree record is malformed".to_owned()))?;
    let metadata = std::str::from_utf8(metadata)
        .map_err(|_| TrustError::Git("Git tree metadata is not UTF-8".to_owned()))?;
    if !(metadata.starts_with("100644 blob ") || metadata.starts_with("100755 blob ")) {
        return Err(TrustError::Invalid(format!(
            "Git entry `{path}` is not a regular file"
        )));
    }
    let object = format!("{commit}:{path}");
    let size = git_text(root, &["cat-file", "-s", &object])?
        .parse::<u64>()
        .map_err(|_| TrustError::Git("Git blob size is not u64".to_owned()))?;
    if size > limit {
        return Err(TrustError::Invalid(format!(
            "Git blob `{path}` exceeds {limit} bytes"
        )));
    }
    let bytes = git(root, &["cat-file", "blob", &object])?;
    if u64::try_from(bytes.len())
        .map_err(|_| TrustError::Invalid("Git blob length exceeds u64".to_owned()))?
        != size
    {
        return Err(TrustError::Git(format!(
            "Git blob `{path}` size changed while reading"
        )));
    }
    Ok(bytes)
}

fn git(root: &Path, arguments: &[&str]) -> Result<Vec<u8>, TrustError> {
    let output = Command::new("git")
        .arg("--no-optional-locks")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(TrustError::Git(stderr.trim().to_owned()));
    }
    Ok(output.stdout)
}

#[derive(Clone, Copy)]
enum PathKind {
    File,
    Directory,
}

fn canonical_directory(path: &Path) -> Result<PathBuf, TrustError> {
    let canonical = fs::canonicalize(path)?;
    if !fs::metadata(&canonical)?.is_dir() {
        return Err(TrustError::Invalid(
            "repository root is not a directory".to_owned(),
        ));
    }
    Ok(canonical)
}

fn safe_existing_path(root: &Path, relative: &str, kind: PathKind) -> Result<PathBuf, TrustError> {
    validate_relative_path(relative)?;
    let mut current = root.to_path_buf();
    for component in Path::new(relative).components() {
        let Component::Normal(component) = component else {
            return Err(TrustError::Invalid(format!(
                "path `{relative}` is not normalized"
            )));
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() {
            return Err(TrustError::Invalid(format!(
                "path `{relative}` contains a symlink"
            )));
        }
    }
    let valid_kind = match kind {
        PathKind::File => fs::metadata(&current)?.is_file(),
        PathKind::Directory => fs::metadata(&current)?.is_dir(),
    };
    if !valid_kind {
        return Err(TrustError::Invalid(format!(
            "path `{relative}` has an unexpected file type"
        )));
    }
    Ok(current)
}

fn validate_relative_path(path: &str) -> Result<(), TrustError> {
    if path.is_empty()
        || path.len() > 4_096
        || path.contains('\\')
        || path
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(TrustError::Invalid(format!(
            "path `{path}` is empty, oversized or non-portable"
        )));
    }
    let candidate = Path::new(path);
    if candidate.is_absolute()
        || !candidate
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        || path.split('/').any(|component| {
            component.is_empty()
                || component == ".git"
                || component == ".DS_Store"
                || component.starts_with("._")
        })
    {
        return Err(TrustError::Invalid(format!(
            "path `{path}` is not a safe normalized repository path"
        )));
    }
    Ok(())
}

fn path_to_slash(path: &Path) -> Result<String, TrustError> {
    let mut components = Vec::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err(TrustError::Invalid(
                "source path is not normalized".to_owned(),
            ));
        };
        components.push(
            component
                .to_str()
                .ok_or_else(|| TrustError::Invalid("source path is not UTF-8".to_owned()))?,
        );
    }
    Ok(components.join("/"))
}

fn read_bounded_file(path: &Path, limit: u64) -> Result<Vec<u8>, TrustError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(TrustError::Invalid(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > limit {
        return Err(TrustError::Invalid(format!(
            "{} exceeds {limit} bytes",
            path.display()
        )));
    }
    let bytes = fs::read(path)?;
    if u64::try_from(bytes.len())
        .map_err(|_| TrustError::Invalid("file length exceeds u64".to_owned()))?
        > limit
    {
        return Err(TrustError::Invalid(format!(
            "{} exceeds {limit} bytes",
            path.display()
        )));
    }
    Ok(bytes)
}

fn read_strict_bounded<T: DeserializeOwned>(path: &Path, limit: u64) -> Result<T, TrustError> {
    let bytes = read_bounded_file(path, limit)?;
    decode_strict(&bytes)
}

fn decode_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, TrustError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| TrustError::Invalid("JSON input is not UTF-8".to_owned()))?;
    let value = parse_strict(text)?;
    Ok(serde_json::from_value(value.to_serde_value())?)
}

fn validate_gate_profile(
    required_gate_ids: &[String],
    require_current_tooling: bool,
) -> Result<(), TrustError> {
    let matches = |expected: &[&str]| {
        required_gate_ids
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied())
    };
    if matches(&CURRENT_GATE_IDS) || (!require_current_tooling && matches(&LEGACY_GATE_IDS)) {
        return Ok(());
    }
    Err(TrustError::Invalid(
        "verification gate profile is not an allowed ordered profile".to_owned(),
    ))
}

fn validate_evidence_file_binding(
    root: &Path,
    value: &JsonValue,
    label: &str,
    expected_path: &str,
    require_current_file: bool,
) -> Result<String, TrustError> {
    let path = json_str(value, "/path", label)?;
    validate_relative_path(path)?;
    if path != expected_path {
        return Err(TrustError::Invalid(format!(
            "{label} path is not the canonical repository path"
        )));
    }
    let expected = json_str(value, "/file_sha256", label)?;
    validate_hex(expected, 64, label)?;
    if require_current_file {
        let absolute = safe_existing_path(root, path, PathKind::File)?;
        let bytes = read_bounded_file(&absolute, 2 * 1_048_576)?;
        if raw_sha256(&bytes) != expected {
            return Err(TrustError::Invalid(format!(
                "{label} current file hash mismatch"
            )));
        }
    }
    Ok(expected.to_owned())
}

fn json_str<'a>(value: &'a JsonValue, pointer: &str, label: &str) -> Result<&'a str, TrustError> {
    value
        .pointer(pointer)
        .and_then(JsonValue::as_str)
        .ok_or_else(|| TrustError::Invalid(format!("{label} is missing or not a string")))
}

fn json_u64(value: &JsonValue, pointer: &str, label: &str) -> Result<u64, TrustError> {
    value
        .pointer(pointer)
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| TrustError::Invalid(format!("{label} is missing or not u64")))
}

fn json_i64(value: &JsonValue, pointer: &str, label: &str) -> Result<i64, TrustError> {
    value
        .pointer(pointer)
        .and_then(JsonValue::as_i64)
        .ok_or_else(|| TrustError::Invalid(format!("{label} is missing or not i64")))
}

fn json_bool(value: &JsonValue, pointer: &str, label: &str) -> Result<bool, TrustError> {
    value
        .pointer(pointer)
        .and_then(JsonValue::as_bool)
        .ok_or_else(|| TrustError::Invalid(format!("{label} is missing or not boolean")))
}

fn all_unique(values: &[String]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn validate_hex(value: &str, length: usize, label: &str) -> Result<(), TrustError> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(TrustError::Invalid(format!(
            "{label} is not {length} lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn raw_sha256(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

/// Encode an envelope as exact canonical JCE1 bytes.
pub fn encode_envelope(envelope: &PrTrustEnvelope) -> Result<Vec<u8>, TrustError> {
    validate_envelope_digest(envelope)?;
    Ok(to_canonical_bytes_v1(&from_serializable_v1(envelope)?)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    #[test]
    fn relative_paths_reject_escape_and_platform_metadata() {
        for path in [
            "",
            "/tmp/a",
            "../a",
            "a/../b",
            "a\\b",
            ".git/config",
            "a/._x",
        ] {
            assert!(validate_relative_path(path).is_err(), "accepted {path}");
        }
        assert!(validate_relative_path("examples/pr-trust/policy.joan").is_ok());
    }

    #[test]
    fn source_exclusions_are_exact() {
        for path in [
            ".git/config",
            "target/debug/a",
            ".joan/evidence/latest.json",
            "x/.DS_Store",
            "x/._metadata",
        ] {
            assert!(source_path_excluded(path), "did not exclude {path}");
        }
        assert!(!source_path_excluded(".github/workflows/ci.yml"));
        assert!(!source_path_excluded("src/target.rs"));
    }

    #[test]
    fn source_snapshot_shape_rejects_historical_spoofing() -> Result<(), TrustError> {
        let root = workspace_root();
        let source = source_tree_snapshot(&root)?;
        validate_source_tree_snapshot(&source)?;

        let mut invalid = source.clone();
        invalid.tree_digest.profile = "joan-source-tree-v1".to_owned();
        assert!(validate_source_tree_snapshot(&invalid).is_err());
        invalid = source.clone();
        invalid.tree_digest.value = "z".repeat(64);
        assert!(validate_source_tree_snapshot(&invalid).is_err());
        invalid = source.clone();
        invalid.file_count = 0;
        assert!(validate_source_tree_snapshot(&invalid).is_err());
        invalid = source;
        invalid.excludes.swap(0, 1);
        assert!(validate_source_tree_snapshot(&invalid).is_err());
        Ok(())
    }

    #[test]
    fn typed_digest_shape_is_fail_closed() -> Result<(), TrustError> {
        let digest = digest_bytes_v1(RegisteredDomainV1::Source, b"policy")?;
        validate_digest_shape(&digest, RegisteredDomainV1::Source)?;
        assert!(validate_digest_shape(&digest, RegisteredDomainV1::PrTrustPolicy).is_err());
        Ok(())
    }

    #[test]
    fn git_candidate_binds_base_and_head_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = git_fixture()?;
        let policy = test_policy()?;
        let candidate = inspect_candidate(fixture.path(), &policy, "HEAD^", "HEAD")?;
        assert_eq!(candidate.status, "bound-clean-worktree");
        assert_eq!(candidate.changed_files.len(), 2);
        assert_eq!(candidate.changed_files[0].path, "a.txt");
        assert_eq!(candidate.changed_files[0].change, ChangeKind::Modified);
        assert!(candidate.changed_files[0].base_content_digest.is_some());
        assert!(candidate.changed_files[0].current_content_digest.is_some());
        assert_eq!(candidate.changed_files[1].path, "b.txt");
        assert_eq!(candidate.changed_files[1].change, ChangeKind::Added);
        assert!(candidate.changed_files[1].base_content_digest.is_none());
        assert!(candidate.total_changed_bytes > 0);
        validate_digest_shape(&candidate.candidate_digest, RegisteredDomainV1::PrCandidate)?;
        Ok(())
    }

    #[test]
    fn dirty_worktree_and_non_head_candidate_fail_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = git_fixture()?;
        let policy = test_policy()?;
        assert!(inspect_candidate(fixture.path(), &policy, "HEAD^", "HEAD^").is_err());
        fs::write(fixture.path().join("a.txt"), b"dirty\n")?;
        assert!(inspect_candidate(fixture.path(), &policy, "HEAD^", "HEAD").is_err());
        Ok(())
    }

    #[test]
    fn rust_source_tree_matches_the_frozen_node_profile() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = workspace_root();
        let rust = source_tree_snapshot(&root)?;
        let output = Command::new("node")
            .args(["tools/evidence-index.mjs", "source"])
            .current_dir(&root)
            .output()?;
        assert!(output.status.success());
        let node: SourceTreeSnapshot = serde_json::from_slice(&output.stdout)?;
        assert_eq!(rust, node);
        Ok(())
    }

    #[test]
    fn checked_in_policy_is_packaged_bounded_and_one_shot() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = workspace_root();
        let policy: PrTrustPolicy = read_strict_bounded(&root.join(POLICY_PATH), MAX_POLICY_BYTES)?;
        validate_policy(&policy)?;
        let candidate = dummy_candidate()?;
        let program = verify_policy_program(&root, &policy, &candidate)?;
        assert_eq!(program.planned_effect, "publish_pr_assessment");
        assert_eq!(program.authority_slot, "publish_once");
        assert_eq!(
            program.information,
            InformationLabel::Secret {
                tenant: "github".to_owned(),
                purpose: "pr_review".to_owned(),
            }
        );
        assert!(program.instructions_executed <= program.instruction_budget);
        Ok(())
    }

    #[test]
    fn historical_receipts_remain_deeply_verifiable_while_current_tree_advances()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = workspace_root();
        let policy = test_policy()?;
        let bytes = fs::read(root.join(".joan/evidence/latest.json"))?;
        let index: EvidenceIndex = decode_strict(&bytes)?;
        let binding = verify_evidence_with_mode(&root, &policy, &index.source, false)?;
        assert_eq!(
            binding.status,
            "historical-three-local-runs-inspection-only"
        );
        assert_eq!(
            binding.claim_scope,
            "historical-local-receipts-not-current-authorization"
        );
        assert_eq!(binding.verification_run_ids.len(), 3);
        assert_eq!(binding.jce1_passed, 27);
        assert_eq!(binding.dispute_cases, 10_000);
        assert_eq!(binding.vulnerabilities_found, 0);
        Ok(())
    }

    #[test]
    fn gate_profiles_reject_current_downgrade_and_unknown_order() {
        let legacy = LEGACY_GATE_IDS.map(str::to_owned);
        let current = CURRENT_GATE_IDS.map(str::to_owned);
        assert!(validate_gate_profile(&legacy, false).is_ok());
        assert!(validate_gate_profile(&legacy, true).is_err());
        assert!(validate_gate_profile(&current, false).is_ok());
        assert!(validate_gate_profile(&current, true).is_ok());

        let mut reordered = current;
        reordered.swap(0, 1);
        assert!(validate_gate_profile(&reordered, false).is_err());
        assert!(validate_gate_profile(&reordered, true).is_err());
    }

    #[test]
    fn current_receipt_requires_exact_runner_and_gate_config_digests()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = workspace_root();
        let index: EvidenceIndex =
            decode_strict(&fs::read(root.join(".joan/evidence/latest.json"))?)?;
        let receipt_path = root.join(&index.verification.runs[0].path);
        let receipt: VerificationReceipt = decode_strict(&fs::read(receipt_path)?)?;
        let runner_sha256 = json_str(
            &index.verification.runner,
            "/file_sha256",
            "verification runner",
        )?;
        let gate_config_sha256 = json_str(
            &index.verification.gate_config,
            "/file_sha256",
            "gate configuration",
        )?;

        let mut historical_environment = receipt.environment.clone();
        historical_environment
            .as_object_mut()
            .ok_or("receipt environment is not an object")?
            .remove("gate_config_sha256");
        validate_receipt_environment(
            &root,
            &historical_environment,
            runner_sha256,
            gate_config_sha256,
            false,
            false,
        )?;
        assert!(
            validate_receipt_environment(
                &root,
                &historical_environment,
                runner_sha256,
                gate_config_sha256,
                true,
                true,
            )
            .is_err()
        );

        let mut current_environment = receipt.environment.clone();
        current_environment
            .as_object_mut()
            .ok_or("receipt environment is not an object")?
            .insert(
                "gate_config_sha256".to_owned(),
                JsonValue::String(gate_config_sha256.to_owned()),
            );
        bind_tool_to_current_executable(&mut current_environment, 0, "node")?;
        validate_receipt_environment(
            &root,
            &current_environment,
            runner_sha256,
            gate_config_sha256,
            true,
            true,
        )?;

        current_environment["runner_sha256"] = JsonValue::String("0".repeat(64));
        assert!(
            validate_receipt_environment(
                &root,
                &current_environment,
                runner_sha256,
                gate_config_sha256,
                true,
                true,
            )
            .is_err()
        );
        current_environment["runner_sha256"] = JsonValue::String(runner_sha256.to_owned());
        current_environment["gate_config_sha256"] = JsonValue::String("0".repeat(64));
        assert!(
            validate_receipt_environment(
                &root,
                &current_environment,
                runner_sha256,
                gate_config_sha256,
                true,
                true,
            )
            .is_err()
        );

        current_environment["gate_config_sha256"] =
            JsonValue::String(gate_config_sha256.to_owned());
        let cargo_path = current_environment["tools"][1]["path"].clone();
        let cargo_sha256 = current_environment["tools"][1]["sha256"].clone();
        current_environment["tools"][0]["path"] = cargo_path;
        current_environment["tools"][0]["sha256"] = cargo_sha256;
        assert!(
            validate_receipt_environment(
                &root,
                &current_environment,
                runner_sha256,
                gate_config_sha256,
                true,
                true,
            )
            .is_err()
        );
        Ok(())
    }

    fn bind_tool_to_current_executable(
        environment: &mut JsonValue,
        index: usize,
        command: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let current =
            std::env::split_paths(&std::env::var_os("PATH").ok_or("PATH is unavailable")?)
                .map(|directory| directory.join(command))
                .find_map(|candidate| fs::canonicalize(candidate).ok())
                .ok_or_else(|| format!("{command} is unavailable on PATH"))?;
        environment["tools"][index]["path"] = JsonValue::String(
            current
                .to_str()
                .ok_or("current executable path is not UTF-8")?
                .to_owned(),
        );
        environment["tools"][index]["sha256"] = JsonValue::String(raw_sha256(&read_bounded_file(
            &current,
            MAX_EXECUTABLE_BYTES,
        )?));
        Ok(())
    }

    #[test]
    fn gate_receipts_bind_argv_time_signal_and_executable_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = workspace_root();
        let index: EvidenceIndex =
            decode_strict(&fs::read(root.join(".joan/evidence/latest.json"))?)?;
        let receipt: VerificationReceipt =
            decode_strict(&fs::read(root.join(&index.verification.runs[0].path))?)?;
        let gate = receipt.gates[0].clone();
        validate_gate_receipt(&root, &gate, "format", true)?;

        let relocated = TempDir::new()?;
        fs::create_dir_all(relocated.path().join("scripts"))?;
        fs::copy(
            root.join("scripts/verify-jce1.sh"),
            relocated.path().join("scripts/verify-jce1.sh"),
        )?;
        validate_gate_receipt(relocated.path(), &receipt.gates[5], "jce1", true)?;

        let mut escaped = receipt.gates[5].clone();
        escaped["executable_path"] = JsonValue::String(format!(
            "{}/../repo/scripts/verify-jce1.sh",
            relocated.path().display()
        ));
        assert!(validate_gate_receipt(&root, &escaped, "jce1", true).is_err());

        let mut invalid = gate.clone();
        invalid["argv"] = serde_json::json!(["cargo", "fmt"]);
        assert!(validate_gate_receipt(&root, &invalid, "format", false).is_err());
        invalid = gate.clone();
        invalid["signal"] = JsonValue::String("SIGTERM".to_owned());
        assert!(validate_gate_receipt(&root, &invalid, "format", false).is_err());
        invalid = gate.clone();
        invalid["executable_sha256"] = JsonValue::String("x".repeat(64));
        assert!(validate_gate_receipt(&root, &invalid, "format", false).is_err());
        invalid = gate.clone();
        invalid["completed_at"] = JsonValue::String("not-a-time".to_owned());
        assert!(validate_gate_receipt(&root, &invalid, "format", false).is_err());
        invalid = gate;
        let node_tool = &receipt.environment["tools"][0];
        invalid["executable_path"] = node_tool["path"].clone();
        invalid["executable_sha256"] = node_tool["sha256"].clone();
        assert!(validate_gate_receipt(&root, &invalid, "format", true).is_err());
        Ok(())
    }

    #[test]
    fn stale_source_cannot_use_the_current_authorization_path()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = workspace_root();
        let policy = test_policy()?;
        let index: EvidenceIndex =
            decode_strict(&fs::read(root.join(".joan/evidence/latest.json"))?)?;
        let mut stale = index.source;
        stale.tree_digest.value = "0".repeat(64);
        let Err(error) = verify_evidence_with_mode(&root, &policy, &stale, true) else {
            return Err("stale source unexpectedly authorized as current".into());
        };
        assert!(error.to_string().contains("source tree is invalid"));
        Ok(())
    }

    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .map_or_else(
                || PathBuf::from(env!("CARGO_MANIFEST_DIR")),
                Path::to_path_buf,
            )
    }

    fn test_policy() -> Result<PrTrustPolicy, TrustError> {
        read_strict_bounded(&workspace_root().join(POLICY_PATH), MAX_POLICY_BYTES)
    }

    fn dummy_candidate() -> Result<PrCandidateReceipt, TrustError> {
        let changed_files = vec![ChangedFile {
            path: "README.md".to_owned(),
            change: ChangeKind::Modified,
            base_bytes: Some(1),
            base_content_digest: Some(digest_bytes_v1(RegisteredDomainV1::Source, b"a")?),
            current_bytes: Some(1),
            current_content_digest: Some(digest_bytes_v1(RegisteredDomainV1::Source, b"b")?),
        }];
        let core = PrCandidateCore {
            repository: "joan-local-checkout",
            object_format: "sha1",
            base_commit: "0000000000000000000000000000000000000000",
            head_commit: "1111111111111111111111111111111111111111",
            changed_files: &changed_files,
            total_changed_bytes: 2,
        };
        let candidate_digest = digest_serializable_v1(RegisteredDomainV1::PrCandidate, &core)?;
        Ok(PrCandidateReceipt {
            schema: "joan.pr-candidate-receipt.v0".to_owned(),
            status: "bound-clean-worktree".to_owned(),
            repository: "joan-local-checkout".to_owned(),
            object_format: "sha1".to_owned(),
            base_commit: "0000000000000000000000000000000000000000".to_owned(),
            head_commit: "1111111111111111111111111111111111111111".to_owned(),
            changed_files,
            total_changed_bytes: 2,
            candidate_digest,
        })
    }

    fn git_fixture() -> Result<TempDir, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        git_success(directory.path(), &["init", "-q"])?;
        git_success(directory.path(), &["config", "user.name", "JOAN Test"])?;
        git_success(
            directory.path(),
            &["config", "user.email", "joan-test@example.invalid"],
        )?;
        fs::write(directory.path().join("a.txt"), b"base\n")?;
        git_success(directory.path(), &["add", "a.txt"])?;
        git_success(directory.path(), &["commit", "-q", "-m", "base"])?;
        fs::write(directory.path().join("a.txt"), b"head\n")?;
        fs::write(directory.path().join("b.txt"), b"added\n")?;
        git_success(directory.path(), &["add", "a.txt", "b.txt"])?;
        git_success(directory.path(), &["commit", "-q", "-m", "head"])?;
        Ok(directory)
    }

    fn git_success(root: &Path, arguments: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
        let status = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(arguments)
            .env("LC_ALL", "C")
            .status()?;
        if !status.success() {
            return Err(format!("git command failed: {arguments:?}").into());
        }
        Ok(())
    }
}
