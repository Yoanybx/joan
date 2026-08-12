//! Immutable-at-lock, content-addressed evidence graphs for JOAN disputes.

use joan_canonical::{CanonicalError, Digest, digest_serializable};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const MAX_ITEMS: usize = 10_000;
const MAX_RELATIONS: usize = 50_000;
const MAX_IDEMPOTENCY_KEYS: usize = 60_000;

/// Verification status assigned to an evidence reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceVerification {
    /// The item has not passed its declared verifier profile.
    Unverified,
    /// The item's integrity/provenance gate passed.
    Verified,
    /// The item failed integrity or provenance validation.
    Rejected,
}

/// Disclosure class for evidence metadata and content retrieval.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidentiality {
    /// Metadata and referenced content may be publicly disclosed.
    Public,
    /// Access requires a separately authorized role.
    Restricted,
    /// Only a commitment/reference is allowed in normal receipts.
    SecretReference,
}

/// One content-addressed evidence item. Content is stored outside this graph.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceItem {
    /// Stable item identifier within the case.
    pub evidence_id: String,
    /// Identity asserting or preserving the item.
    pub issuer_id: String,
    /// Digest of the exact external content bytes or typed object.
    pub content_digest: Digest,
    /// Stable provenance/source code.
    pub source: String,
    /// Acquisition time supplied by the profile.
    pub acquired_at_epoch_seconds: u64,
    /// Media or schema type.
    pub content_type: String,
    /// Stable relevance code tied to a claim or rule.
    pub relevance_code: String,
    /// Disclosure class.
    pub confidentiality: Confidentiality,
    /// Integrity/provenance result.
    pub verification: EvidenceVerification,
}

/// Directed semantic relation between evidence items.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceRelationKind {
    /// Source item supports the target assertion/item.
    Supports,
    /// Source item contradicts the target assertion/item.
    Contradicts,
    /// Source item was derived from the target.
    DerivedFrom,
    /// Source item independently reproduced the target.
    Reproduces,
    /// Source item supersedes but does not erase the target.
    Supersedes,
    /// Source item is a redacted view of the target.
    Redacts,
    /// Source item invalidates the target under a declared rule.
    Invalidates,
    /// Source item independently corroborates the target.
    Corroborates,
}

/// One uniquely identified evidence relation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRelation {
    /// Stable relation identifier.
    pub relation_id: String,
    /// Source evidence identifier.
    pub from_evidence_id: String,
    /// Target evidence identifier.
    pub to_evidence_id: String,
    /// Typed relation.
    pub kind: EvidenceRelationKind,
}

/// Evidence-graph mutation supported before lock.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum EvidenceMutation {
    /// Add one evidence item.
    AddItem {
        /// Item to add.
        item: EvidenceItem,
    },
    /// Add one relation between existing items.
    AddRelation {
        /// Relation to add.
        relation: EvidenceRelation,
    },
    /// Permanently lock this graph revision for adjudication.
    Lock,
}

/// Exact-precondition request for one evidence mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceMutationRequest {
    /// Schema identifier.
    pub schema: String,
    /// Expected current graph root.
    pub expected_graph_root: Digest,
    /// Expected current revision.
    pub expected_revision: u64,
    /// Authorized logical actor.
    pub actor_id: String,
    /// External authority/policy reference.
    pub authority_ref: Digest,
    /// Consume-once operation key.
    pub idempotency_key: String,
    /// Requested mutation.
    pub mutation: EvidenceMutation,
}

/// Content-addressed evidence graph for one case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceGraph {
    /// Schema identifier.
    pub schema: String,
    /// Stable associated case identifier.
    pub case_id: String,
    /// Items sorted by stable identifier.
    pub items: BTreeMap<String, EvidenceItem>,
    /// Relations sorted by stable relation identifier.
    pub relations: BTreeMap<String, EvidenceRelation>,
    /// True once no additional mutation is permitted.
    pub locked: bool,
    /// Monotonic graph revision.
    pub revision: u64,
    /// Consumed mutation keys.
    pub consumed_idempotency_keys: BTreeSet<String>,
    /// Digest over every protected field above.
    pub graph_root: Digest,
}

/// Evidence mutation receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceMutationReceipt {
    /// Schema identifier.
    pub schema: String,
    /// Stable case identifier.
    pub case_id: String,
    /// Previous graph root.
    pub prior_graph_root: Digest,
    /// New graph root.
    pub new_graph_root: Digest,
    /// New graph revision.
    pub revision: u64,
    /// Digest of the mutation request.
    pub mutation_digest: Digest,
    /// True only after the isolated candidate passed validation.
    pub committed: bool,
    /// Whether this mutation locked the graph.
    pub locked: bool,
}

/// Evidence graph failure.
#[derive(Debug, Error)]
pub enum EvidenceError {
    /// Canonical encoding or hashing failed.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    /// An unsupported schema was supplied.
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(String),
    /// A required string field was empty.
    #[error("required field is empty: {0}")]
    EmptyField(&'static str),
    /// Stored graph root does not match protected fields.
    #[error("stored evidence graph root is invalid")]
    InvalidStoredRoot,
    /// Expected root did not match.
    #[error("expected evidence graph root does not match")]
    StaleRoot,
    /// Expected revision did not match.
    #[error("expected evidence graph revision does not match")]
    StaleRevision,
    /// Locked graphs are immutable.
    #[error("evidence graph is locked")]
    Locked,
    /// Consume-once key was already used.
    #[error("evidence mutation idempotency key was already consumed")]
    Replay,
    /// Item identifier already exists.
    #[error("duplicate evidence item: {0}")]
    DuplicateItem(String),
    /// Relation identifier already exists.
    #[error("duplicate evidence relation: {0}")]
    DuplicateRelation(String),
    /// Relation endpoint does not exist.
    #[error("evidence relation references missing item: {0}")]
    MissingRelationEndpoint(String),
    /// Self-relation is forbidden.
    #[error("evidence relation cannot reference the same item twice")]
    SelfRelation,
    /// At least one verified item is required before lock.
    #[error("evidence graph cannot lock without verified evidence")]
    NoVerifiedEvidence,
    /// A defensive collection limit was exceeded.
    #[error("evidence graph capacity exhausted")]
    Capacity,
    /// Monotonic revision overflowed.
    #[error("evidence graph revision overflow")]
    RevisionOverflow,
}

#[derive(Serialize)]
struct GraphCore<'a> {
    schema: &'a str,
    case_id: &'a str,
    items: &'a BTreeMap<String, EvidenceItem>,
    relations: &'a BTreeMap<String, EvidenceRelation>,
    locked: bool,
    revision: u64,
    consumed_idempotency_keys: &'a BTreeSet<String>,
}

/// Create an empty, unlocked evidence graph.
pub fn create_evidence_graph(case_id: &str) -> Result<EvidenceGraph, EvidenceError> {
    require_nonempty(case_id, "case_id")?;
    let mut graph = EvidenceGraph {
        schema: "joan.evidence-graph.v0".to_owned(),
        case_id: case_id.to_owned(),
        items: BTreeMap::new(),
        relations: BTreeMap::new(),
        locked: false,
        revision: 0,
        consumed_idempotency_keys: BTreeSet::new(),
        graph_root: placeholder_digest(),
    };
    graph.graph_root = compute_graph_root(&graph)?;
    Ok(graph)
}

/// Verify the graph root and internal map identities.
pub fn verify_evidence_graph(graph: &EvidenceGraph) -> Result<(), EvidenceError> {
    if graph.schema != "joan.evidence-graph.v0" {
        return Err(EvidenceError::UnsupportedSchema(graph.schema.clone()));
    }
    for (key, item) in &graph.items {
        if key != &item.evidence_id {
            return Err(EvidenceError::InvalidStoredRoot);
        }
    }
    for (key, relation) in &graph.relations {
        if key != &relation.relation_id {
            return Err(EvidenceError::InvalidStoredRoot);
        }
        validate_relation(graph, relation)?;
    }
    if compute_graph_root(graph)? != graph.graph_root {
        return Err(EvidenceError::InvalidStoredRoot);
    }
    Ok(())
}

/// Apply one mutation to an isolated clone.
pub fn mutate_evidence(
    graph: &EvidenceGraph,
    request: &EvidenceMutationRequest,
) -> Result<(EvidenceGraph, EvidenceMutationReceipt), EvidenceError> {
    verify_evidence_graph(graph)?;
    if request.schema != "joan.evidence-mutation-request.v0" {
        return Err(EvidenceError::UnsupportedSchema(request.schema.clone()));
    }
    require_nonempty(&request.actor_id, "actor_id")?;
    require_nonempty(&request.idempotency_key, "idempotency_key")?;
    if graph.locked {
        return Err(EvidenceError::Locked);
    }
    if request.expected_graph_root != graph.graph_root {
        return Err(EvidenceError::StaleRoot);
    }
    if request.expected_revision != graph.revision {
        return Err(EvidenceError::StaleRevision);
    }
    if graph
        .consumed_idempotency_keys
        .contains(&request.idempotency_key)
    {
        return Err(EvidenceError::Replay);
    }
    if graph.consumed_idempotency_keys.len() >= MAX_IDEMPOTENCY_KEYS {
        return Err(EvidenceError::Capacity);
    }

    let prior_graph_root = graph.graph_root.clone();
    let mut candidate = graph.clone();
    apply_mutation(&mut candidate, &request.mutation)?;
    candidate
        .consumed_idempotency_keys
        .insert(request.idempotency_key.clone());
    candidate.revision = candidate
        .revision
        .checked_add(1)
        .ok_or(EvidenceError::RevisionOverflow)?;
    candidate.graph_root = compute_graph_root(&candidate)?;
    let receipt = EvidenceMutationReceipt {
        schema: "joan.evidence-mutation-receipt.v0".to_owned(),
        case_id: graph.case_id.clone(),
        prior_graph_root,
        new_graph_root: candidate.graph_root.clone(),
        revision: candidate.revision,
        mutation_digest: digest_serializable("joan.evidence-mutation-request.v0", request)?,
        committed: true,
        locked: candidate.locked,
    };
    Ok((candidate, receipt))
}

fn apply_mutation(
    graph: &mut EvidenceGraph,
    mutation: &EvidenceMutation,
) -> Result<(), EvidenceError> {
    match mutation {
        EvidenceMutation::AddItem { item } => {
            require_nonempty(&item.evidence_id, "evidence_id")?;
            require_nonempty(&item.issuer_id, "issuer_id")?;
            require_nonempty(&item.source, "source")?;
            require_nonempty(&item.content_type, "content_type")?;
            require_nonempty(&item.relevance_code, "relevance_code")?;
            if graph.items.len() >= MAX_ITEMS {
                return Err(EvidenceError::Capacity);
            }
            if graph.items.contains_key(&item.evidence_id) {
                return Err(EvidenceError::DuplicateItem(item.evidence_id.clone()));
            }
            graph.items.insert(item.evidence_id.clone(), item.clone());
        }
        EvidenceMutation::AddRelation { relation } => {
            require_nonempty(&relation.relation_id, "relation_id")?;
            if graph.relations.len() >= MAX_RELATIONS {
                return Err(EvidenceError::Capacity);
            }
            if graph.relations.contains_key(&relation.relation_id) {
                return Err(EvidenceError::DuplicateRelation(
                    relation.relation_id.clone(),
                ));
            }
            validate_relation(graph, relation)?;
            graph
                .relations
                .insert(relation.relation_id.clone(), relation.clone());
        }
        EvidenceMutation::Lock => {
            if !graph
                .items
                .values()
                .any(|item| item.verification == EvidenceVerification::Verified)
            {
                return Err(EvidenceError::NoVerifiedEvidence);
            }
            graph.locked = true;
        }
    }
    Ok(())
}

fn validate_relation(
    graph: &EvidenceGraph,
    relation: &EvidenceRelation,
) -> Result<(), EvidenceError> {
    if relation.from_evidence_id == relation.to_evidence_id {
        return Err(EvidenceError::SelfRelation);
    }
    for endpoint in [&relation.from_evidence_id, &relation.to_evidence_id] {
        if !graph.items.contains_key(endpoint) {
            return Err(EvidenceError::MissingRelationEndpoint(endpoint.clone()));
        }
    }
    Ok(())
}

fn compute_graph_root(graph: &EvidenceGraph) -> Result<Digest, CanonicalError> {
    digest_serializable(
        "joan.evidence-graph.v0",
        &GraphCore {
            schema: &graph.schema,
            case_id: &graph.case_id,
            items: &graph.items,
            relations: &graph.relations,
            locked: graph.locked,
            revision: graph.revision,
            consumed_idempotency_keys: &graph.consumed_idempotency_keys,
        },
    )
}

fn require_nonempty(value: &str, field: &'static str) -> Result<(), EvidenceError> {
    if value.trim().is_empty() {
        Err(EvidenceError::EmptyField(field))
    } else {
        Ok(())
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
