//! Atomic semantic patch validation over a canonical flat test graph.

use joan_canonical::{CanonicalError, CanonicalValue, Digest, digest_serializable};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Immutable graph snapshot used by the Genesis patch verifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphBundle {
    /// Schema identifier.
    pub schema: String,
    /// Flat graph nodes keyed by stable test identifiers.
    pub nodes: BTreeMap<String, CanonicalValue>,
    /// Merkle-like root over sorted leaf digests.
    pub root: Digest,
}

/// Atomic operation supported by the Genesis test graph.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum PatchOperation {
    /// Insert a key that must not already exist.
    Insert {
        /// Target key.
        key: String,
        /// New canonical value.
        value: CanonicalValue,
    },
    /// Replace a key if its current node digest matches.
    Replace {
        /// Target key.
        key: String,
        /// Expected digest of the current node value.
        expected_digest: Digest,
        /// Replacement canonical value.
        value: CanonicalValue,
    },
    /// Remove a key if its current node digest matches.
    Remove {
        /// Target key.
        key: String,
        /// Expected digest of the current node value.
        expected_digest: Digest,
    },
}

/// Patch bound to one exact graph root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticPatch {
    /// Schema identifier.
    pub schema: String,
    /// Exact root against which operations were authored.
    pub base_root: Digest,
    /// Ordered operations. Multiple operations on one key are rejected.
    pub operations: Vec<PatchOperation>,
}

/// Evidence emitted after a patch commits to an isolated copy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchReceipt {
    /// Schema identifier.
    pub schema: String,
    /// Original graph root.
    pub base_root: Digest,
    /// Committed graph root.
    pub new_root: Digest,
    /// Digest of the ordered operation list.
    pub operations_digest: Digest,
    /// Sorted keys affected by the transaction.
    pub affected_keys: Vec<String>,
    /// Independently computed full root.
    pub full_root: Digest,
    /// Independently maintained leaf-map root.
    pub incremental_root: Digest,
    /// True only after every precondition and root agreement passes.
    pub committed: bool,
}

/// Patch verification failure.
#[derive(Debug, Error)]
pub enum PatchError {
    /// Canonical encoding or hashing failed.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    /// Input schema is unsupported.
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(String),
    /// Stored graph root does not match its nodes.
    #[error("graph root is invalid")]
    InvalidGraphRoot,
    /// Patch targets a different base snapshot.
    #[error("patch base root does not match graph root")]
    StaleBase,
    /// Operation list is empty.
    #[error("patch has no operations")]
    EmptyPatch,
    /// One key appears in more than one operation.
    #[error("conflicting operations target key: {0}")]
    DuplicateTarget(String),
    /// Key is empty or exceeds the Genesis bound.
    #[error("invalid graph key")]
    InvalidKey,
    /// Insert target already exists.
    #[error("insert target already exists: {0}")]
    AlreadyExists(String),
    /// Replace or remove target does not exist.
    #[error("target does not exist: {0}")]
    MissingTarget(String),
    /// Expected node digest did not match current state.
    #[error("expected node digest mismatch for key: {0}")]
    ExpectedDigestMismatch(String),
    /// Full and incremental recomputation disagreed.
    #[error("full and incremental roots disagree")]
    RecomputeDisagreement,
}

#[derive(Serialize)]
struct LeafInput<'a> {
    key: &'a str,
    value: &'a CanonicalValue,
}

/// Build a verified graph bundle from canonical nodes.
pub fn build_graph(nodes: BTreeMap<String, CanonicalValue>) -> Result<GraphBundle, PatchError> {
    validate_keys(nodes.keys())?;
    let root = full_graph_root(&nodes)?;
    Ok(GraphBundle {
        schema: "joan.test-graph.v0".to_owned(),
        nodes,
        root,
    })
}

/// Verify a graph's schema and stored root.
pub fn verify_graph(graph: &GraphBundle) -> Result<(), PatchError> {
    if graph.schema != "joan.test-graph.v0" {
        return Err(PatchError::UnsupportedSchema(graph.schema.clone()));
    }
    validate_keys(graph.nodes.keys())?;
    if full_graph_root(&graph.nodes)? != graph.root {
        return Err(PatchError::InvalidGraphRoot);
    }
    Ok(())
}

/// Compute a node-value digest used by replace/remove preconditions.
pub fn node_digest(value: &CanonicalValue) -> Result<Digest, PatchError> {
    Ok(digest_serializable("joan.graph-node.v0", value)?)
}

/// Validate and apply a patch to an isolated copy.
///
/// The input bundle is never mutated. An error returns no partial graph.
pub fn apply_patch(
    graph: &GraphBundle,
    patch: &SemanticPatch,
) -> Result<(GraphBundle, PatchReceipt), PatchError> {
    verify_graph(graph)?;
    if patch.schema != "joan.semantic-patch.v0" {
        return Err(PatchError::UnsupportedSchema(patch.schema.clone()));
    }
    if patch.base_root != graph.root {
        return Err(PatchError::StaleBase);
    }
    if patch.operations.is_empty() {
        return Err(PatchError::EmptyPatch);
    }

    let mut targets = BTreeSet::new();
    for operation in &patch.operations {
        let key = operation_key(operation);
        validate_key(key)?;
        if !targets.insert(key.to_owned()) {
            return Err(PatchError::DuplicateTarget(key.to_owned()));
        }
    }

    let mut staged_nodes = graph.nodes.clone();
    let mut staged_leaves = leaf_digest_map(&graph.nodes)?;
    for operation in &patch.operations {
        apply_operation(&mut staged_nodes, &mut staged_leaves, operation)?;
    }

    let full_root = full_graph_root(&staged_nodes)?;
    let incremental_root = root_from_leaf_digests(&staged_leaves)?;
    if full_root != incremental_root {
        return Err(PatchError::RecomputeDisagreement);
    }

    let new_graph = GraphBundle {
        schema: graph.schema.clone(),
        nodes: staged_nodes,
        root: full_root.clone(),
    };
    let receipt = PatchReceipt {
        schema: "joan.patch-receipt.v0".to_owned(),
        base_root: graph.root.clone(),
        new_root: full_root.clone(),
        operations_digest: digest_serializable("joan.patch-operations.v0", &patch.operations)?,
        affected_keys: targets.into_iter().collect(),
        full_root,
        incremental_root,
        committed: true,
    };
    Ok((new_graph, receipt))
}

fn apply_operation(
    nodes: &mut BTreeMap<String, CanonicalValue>,
    leaves: &mut BTreeMap<String, Digest>,
    operation: &PatchOperation,
) -> Result<(), PatchError> {
    match operation {
        PatchOperation::Insert { key, value } => {
            if nodes.contains_key(key) {
                return Err(PatchError::AlreadyExists(key.clone()));
            }
            nodes.insert(key.clone(), value.clone());
            leaves.insert(key.clone(), leaf_digest(key, value)?);
        }
        PatchOperation::Replace {
            key,
            expected_digest,
            value,
        } => {
            let current = nodes
                .get(key)
                .ok_or_else(|| PatchError::MissingTarget(key.clone()))?;
            if node_digest(current)? != *expected_digest {
                return Err(PatchError::ExpectedDigestMismatch(key.clone()));
            }
            nodes.insert(key.clone(), value.clone());
            leaves.insert(key.clone(), leaf_digest(key, value)?);
        }
        PatchOperation::Remove {
            key,
            expected_digest,
        } => {
            let current = nodes
                .get(key)
                .ok_or_else(|| PatchError::MissingTarget(key.clone()))?;
            if node_digest(current)? != *expected_digest {
                return Err(PatchError::ExpectedDigestMismatch(key.clone()));
            }
            nodes.remove(key);
            leaves.remove(key);
        }
    }
    Ok(())
}

fn full_graph_root(nodes: &BTreeMap<String, CanonicalValue>) -> Result<Digest, PatchError> {
    root_from_leaf_digests(&leaf_digest_map(nodes)?)
}

fn leaf_digest_map(
    nodes: &BTreeMap<String, CanonicalValue>,
) -> Result<BTreeMap<String, Digest>, PatchError> {
    nodes
        .iter()
        .map(|(key, value)| Ok((key.clone(), leaf_digest(key, value)?)))
        .collect()
}

fn leaf_digest(key: &str, value: &CanonicalValue) -> Result<Digest, PatchError> {
    Ok(digest_serializable(
        "joan.graph-leaf.v0",
        &LeafInput { key, value },
    )?)
}

fn root_from_leaf_digests(leaves: &BTreeMap<String, Digest>) -> Result<Digest, PatchError> {
    let ordered: Vec<&Digest> = leaves.values().collect();
    Ok(digest_serializable("joan.graph-root.v0", &ordered)?)
}

fn operation_key(operation: &PatchOperation) -> &str {
    match operation {
        PatchOperation::Insert { key, .. }
        | PatchOperation::Replace { key, .. }
        | PatchOperation::Remove { key, .. } => key,
    }
}

fn validate_keys<'a>(keys: impl Iterator<Item = &'a String>) -> Result<(), PatchError> {
    for key in keys {
        validate_key(key)?;
    }
    Ok(())
}

fn validate_key(key: &str) -> Result<(), PatchError> {
    if key.is_empty() || key.len() > 1024 || key.contains('\0') {
        return Err(PatchError::InvalidKey);
    }
    Ok(())
}
