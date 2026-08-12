//! Evidence graph integrity and lock tests.

use joan_canonical::digest_bytes;
use joan_evidence::{
    Confidentiality, EvidenceError, EvidenceGraph, EvidenceItem, EvidenceMutation,
    EvidenceMutationRequest, EvidenceRelation, EvidenceRelationKind, EvidenceVerification,
    create_evidence_graph, mutate_evidence, verify_evidence_graph,
};

fn request(
    graph: &EvidenceGraph,
    key: &str,
    mutation: EvidenceMutation,
) -> Result<EvidenceMutationRequest, Box<dyn std::error::Error>> {
    Ok(EvidenceMutationRequest {
        schema: "joan.evidence-mutation-request.v0".to_owned(),
        expected_graph_root: graph.graph_root.clone(),
        expected_revision: graph.revision,
        actor_id: "evidence-custodian".to_owned(),
        authority_ref: digest_bytes("test.authority", b"evidence-authority")?,
        idempotency_key: key.to_owned(),
        mutation,
    })
}

fn item(
    id: &str,
    status: EvidenceVerification,
) -> Result<EvidenceItem, Box<dyn std::error::Error>> {
    Ok(EvidenceItem {
        evidence_id: id.to_owned(),
        issuer_id: "test-runner".to_owned(),
        content_digest: digest_bytes("test.evidence", id.as_bytes())?,
        source: "reproducible-test".to_owned(),
        acquired_at_epoch_seconds: 1_786_406_400,
        content_type: "application/json".to_owned(),
        relevance_code: "acceptance-test".to_owned(),
        confidentiality: Confidentiality::Restricted,
        verification: status,
    })
}

fn add_item(
    graph: &EvidenceGraph,
    id: &str,
    key: &str,
) -> Result<EvidenceGraph, Box<dyn std::error::Error>> {
    let request = request(
        graph,
        key,
        EvidenceMutation::AddItem {
            item: item(id, EvidenceVerification::Verified)?,
        },
    )?;
    Ok(mutate_evidence(graph, &request)?.0)
}

#[test]
fn add_relate_and_lock_is_reproducible() -> Result<(), Box<dyn std::error::Error>> {
    let graph = create_evidence_graph("case-001")?;
    let graph = add_item(&graph, "delivery", "add-delivery")?;
    let graph = add_item(&graph, "test-result", "add-test")?;
    let relation = EvidenceRelation {
        relation_id: "test-reproduces-delivery".to_owned(),
        from_evidence_id: "test-result".to_owned(),
        to_evidence_id: "delivery".to_owned(),
        kind: EvidenceRelationKind::Reproduces,
    };
    let relation_request = request(&graph, "relate", EvidenceMutation::AddRelation { relation })?;
    let (graph, _) = mutate_evidence(&graph, &relation_request)?;
    let lock = request(&graph, "lock", EvidenceMutation::Lock)?;
    let (locked, receipt) = mutate_evidence(&graph, &lock)?;
    assert!(locked.locked);
    assert!(receipt.committed);
    verify_evidence_graph(&locked)?;
    Ok(())
}

#[test]
fn locked_graph_rejects_every_mutation() -> Result<(), Box<dyn std::error::Error>> {
    let graph = add_item(&create_evidence_graph("case-001")?, "delivery", "add")?;
    let lock = request(&graph, "lock", EvidenceMutation::Lock)?;
    let (locked, _) = mutate_evidence(&graph, &lock)?;
    let add = request(
        &locked,
        "late",
        EvidenceMutation::AddItem {
            item: item("late", EvidenceVerification::Verified)?,
        },
    )?;
    assert!(matches!(
        mutate_evidence(&locked, &add),
        Err(EvidenceError::Locked)
    ));
    Ok(())
}

#[test]
fn missing_relation_endpoint_fails_atomically() -> Result<(), Box<dyn std::error::Error>> {
    let graph = add_item(&create_evidence_graph("case-001")?, "delivery", "add")?;
    let before = graph.clone();
    let invalid = request(
        &graph,
        "bad-relation",
        EvidenceMutation::AddRelation {
            relation: EvidenceRelation {
                relation_id: "missing".to_owned(),
                from_evidence_id: "delivery".to_owned(),
                to_evidence_id: "absent".to_owned(),
                kind: EvidenceRelationKind::Supports,
            },
        },
    )?;
    assert!(matches!(
        mutate_evidence(&graph, &invalid),
        Err(EvidenceError::MissingRelationEndpoint(_))
    ));
    assert_eq!(graph, before);
    Ok(())
}

#[test]
fn unverified_only_graph_cannot_lock() -> Result<(), Box<dyn std::error::Error>> {
    let graph = create_evidence_graph("case-001")?;
    let add = request(
        &graph,
        "add-unverified",
        EvidenceMutation::AddItem {
            item: item("claim", EvidenceVerification::Unverified)?,
        },
    )?;
    let (graph, _) = mutate_evidence(&graph, &add)?;
    let lock = request(&graph, "lock", EvidenceMutation::Lock)?;
    assert!(matches!(
        mutate_evidence(&graph, &lock),
        Err(EvidenceError::NoVerifiedEvidence)
    ));
    Ok(())
}

#[test]
fn stale_root_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let graph = create_evidence_graph("case-001")?;
    let mut add = request(
        &graph,
        "add",
        EvidenceMutation::AddItem {
            item: item("delivery", EvidenceVerification::Verified)?,
        },
    )?;
    add.expected_graph_root = digest_bytes("test.graph", b"stale")?;
    assert!(matches!(
        mutate_evidence(&graph, &add),
        Err(EvidenceError::StaleRoot)
    ));
    Ok(())
}

#[test]
fn protected_item_tampering_breaks_root() -> Result<(), Box<dyn std::error::Error>> {
    let mut graph = add_item(&create_evidence_graph("case-001")?, "delivery", "add")?;
    if let Some(item) = graph.items.get_mut("delivery") {
        item.relevance_code = "tampered".to_owned();
    }
    assert!(matches!(
        verify_evidence_graph(&graph),
        Err(EvidenceError::InvalidStoredRoot)
    ));
    Ok(())
}
