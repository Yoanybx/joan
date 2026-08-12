//! Semantic identity bundle tests.

use joan_canonical::digest_bytes;
use joan_identity::{
    ComponentDigests, IdentityError, NodeRef, PackageDescriptor, build_bundle, verify_bundle,
    verify_node_ref,
};

fn components(body: &[u8]) -> Result<ComponentDigests, Box<dyn std::error::Error>> {
    Ok(ComponentDigests {
        source: digest_bytes("joan.source.v0", body)?,
        token: digest_bytes("joan.token.v0", body)?,
        structural: digest_bytes("joan.structural.v0", body)?,
        interface: digest_bytes("joan.interface.v0", b"fn run(input: Text) -> Text")?,
        behavior: digest_bytes("joan.behavior.v0", body)?,
        effect: digest_bytes("joan.effect.v0", b"pure")?,
        policy: digest_bytes("joan.policy.v0", b"none")?,
        dependency: digest_bytes("joan.dependency.v0", b"empty")?,
    })
}

fn package() -> PackageDescriptor {
    PackageDescriptor {
        namespace: "org.joan".to_owned(),
        name: "example".to_owned(),
        edition: "genesis".to_owned(),
    }
}

#[test]
fn body_change_preserves_symbol_but_changes_root() -> Result<(), Box<dyn std::error::Error>> {
    let first = build_bundle(&package(), "function", "run", 1, components(b"body-a")?)?;
    let second = build_bundle(&package(), "function", "run", 1, components(b"body-b")?)?;
    assert_eq!(first.symbol_id, second.symbol_id);
    assert_ne!(first.program_root, second.program_root);
    verify_bundle(&first)?;
    verify_bundle(&second)?;
    Ok(())
}

#[test]
fn rename_changes_symbol_identity() -> Result<(), Box<dyn std::error::Error>> {
    let first = build_bundle(&package(), "function", "run", 1, components(b"body")?)?;
    let second = build_bundle(&package(), "function", "execute", 1, components(b"body")?)?;
    assert_ne!(first.symbol_id, second.symbol_id);
    Ok(())
}

#[test]
fn modified_bundle_root_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut bundle = build_bundle(&package(), "function", "run", 1, components(b"body")?)?;
    bundle.components.policy = digest_bytes("joan.policy.v0", b"changed")?;
    assert!(matches!(
        verify_bundle(&bundle),
        Err(IdentityError::Mismatch("program_root"))
    ));
    Ok(())
}

#[test]
fn stale_node_reference_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let bundle = build_bundle(&package(), "function", "run", 1, components(b"body")?)?;
    let node_ref = NodeRef {
        schema: "joan.node-ref.v0".to_owned(),
        base_root: bundle.program_root.clone(),
        symbol_id: bundle.symbol_id,
        expected_digest: bundle.components.structural,
    };
    verify_node_ref(&node_ref, &bundle.program_root, &node_ref.expected_digest)?;
    let stale = digest_bytes("joan.structural.v0", b"stale")?;
    assert!(verify_node_ref(&node_ref, &bundle.program_root, &stale).is_err());
    Ok(())
}
