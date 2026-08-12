//! Atomic patch contract tests.

use joan_canonical::{CanonicalValue, digest_bytes};
use joan_patch::{
    PatchError, PatchOperation, SemanticPatch, apply_patch, build_graph, node_digest, verify_graph,
};
use std::collections::BTreeMap;

fn graph() -> Result<joan_patch::GraphBundle, Box<dyn std::error::Error>> {
    build_graph(BTreeMap::from([
        ("a".to_owned(), CanonicalValue::String("one".to_owned())),
        ("b".to_owned(), CanonicalValue::String("two".to_owned())),
    ]))
    .map_err(Into::into)
}

#[test]
fn successful_patch_has_agreeing_roots() -> Result<(), Box<dyn std::error::Error>> {
    let base = graph()?;
    let expected = node_digest(base.nodes.get("a").ok_or("missing fixture node")?)?;
    let patch = SemanticPatch {
        schema: "joan.semantic-patch.v0".to_owned(),
        base_root: base.root.clone(),
        operations: vec![
            PatchOperation::Replace {
                key: "a".to_owned(),
                expected_digest: expected,
                value: CanonicalValue::String("changed".to_owned()),
            },
            PatchOperation::Insert {
                key: "c".to_owned(),
                value: CanonicalValue::Bool(true),
            },
        ],
    };
    let (updated, receipt) = apply_patch(&base, &patch)?;
    verify_graph(&updated)?;
    assert_eq!(receipt.full_root, receipt.incremental_root);
    assert!(receipt.committed);
    assert_ne!(base.root, updated.root);
    assert_eq!(
        base.nodes.get("a"),
        Some(&CanonicalValue::String("one".to_owned()))
    );
    Ok(())
}

#[test]
fn failed_precondition_leaves_input_unchanged() -> Result<(), Box<dyn std::error::Error>> {
    let base = graph()?;
    let before = base.clone();
    let patch = SemanticPatch {
        schema: "joan.semantic-patch.v0".to_owned(),
        base_root: base.root.clone(),
        operations: vec![PatchOperation::Remove {
            key: "a".to_owned(),
            expected_digest: digest_bytes("joan.graph-node.v0", b"wrong")?,
        }],
    };
    assert!(matches!(
        apply_patch(&base, &patch),
        Err(PatchError::ExpectedDigestMismatch(key)) if key == "a"
    ));
    assert_eq!(base, before);
    Ok(())
}

#[test]
fn duplicate_targets_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let base = graph()?;
    let patch = SemanticPatch {
        schema: "joan.semantic-patch.v0".to_owned(),
        base_root: base.root.clone(),
        operations: vec![
            PatchOperation::Insert {
                key: "c".to_owned(),
                value: CanonicalValue::Null,
            },
            PatchOperation::Insert {
                key: "c".to_owned(),
                value: CanonicalValue::Bool(false),
            },
        ],
    };
    assert!(matches!(
        apply_patch(&base, &patch),
        Err(PatchError::DuplicateTarget(key)) if key == "c"
    ));
    Ok(())
}

#[test]
fn replay_against_new_root_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let base = graph()?;
    let patch = SemanticPatch {
        schema: "joan.semantic-patch.v0".to_owned(),
        base_root: base.root.clone(),
        operations: vec![PatchOperation::Insert {
            key: "c".to_owned(),
            value: CanonicalValue::Null,
        }],
    };
    let (updated, _) = apply_patch(&base, &patch)?;
    assert!(matches!(
        apply_patch(&updated, &patch),
        Err(PatchError::StaleBase)
    ));
    Ok(())
}

#[test]
fn invalid_stored_graph_root_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut base = graph()?;
    base.root = digest_bytes("joan.graph-root.v0", b"forged")?;
    assert!(matches!(
        verify_graph(&base),
        Err(PatchError::InvalidGraphRoot)
    ));
    Ok(())
}
