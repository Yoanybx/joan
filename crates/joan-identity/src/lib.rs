//! Semantic identity bundles built from separate, domain-tagged digests.

use joan_canonical::{CanonicalError, Digest, digest_serializable};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Source-independent package identity inputs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageDescriptor {
    /// Globally scoped package namespace.
    pub namespace: String,
    /// Package name inside the namespace.
    pub name: String,
    /// Compatibility edition.
    pub edition: String,
}

/// Stable symbol identity inputs that exclude implementation body details.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SymbolDescriptor {
    /// Derived package identity.
    pub package_id: Digest,
    /// Symbol kind such as `function` or `mission`.
    pub kind: String,
    /// Declared symbol name.
    pub name: String,
    /// Declared argument count.
    pub arity: u64,
    /// Exact public interface digest.
    pub interface_digest: Digest,
}

/// Separate semantic dimensions. No single digest is claimed to prove equivalence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentDigests {
    /// Original source representation digest.
    pub source: Digest,
    /// Canonical token stream digest.
    pub token: Digest,
    /// Canonical structural digest.
    pub structural: Digest,
    /// Public interface digest.
    pub interface: Digest,
    /// Behavior-contract digest.
    pub behavior: Digest,
    /// Effect-row digest.
    pub effect: Digest,
    /// Policy-contract digest.
    pub policy: Digest,
    /// Dependency-root digest.
    pub dependency: Digest,
}

/// Reproducible identity bundle for one symbol in one package snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticIdentityBundle {
    /// Schema identifier.
    pub schema: String,
    /// Package identity.
    pub package_id: Digest,
    /// Symbol identity.
    pub symbol_id: Digest,
    /// Separated semantic dimensions.
    pub components: ComponentDigests,
    /// Root binding all identity inputs above.
    pub program_root: Digest,
}

/// Snapshot-scoped reference to one semantic node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRef {
    /// Schema identifier.
    pub schema: String,
    /// Exact base program root.
    pub base_root: Digest,
    /// Exact symbol identity.
    pub symbol_id: Digest,
    /// Expected current node digest.
    pub expected_digest: Digest,
}

/// Identity construction or verification error.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// Canonical encoding or hashing failed.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    /// Input schema is unsupported.
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(String),
    /// A digest has invalid tags or malformed hexadecimal bytes.
    #[error("malformed digest in field {0}")]
    MalformedDigest(&'static str),
    /// A derived identity did not match the supplied value.
    #[error("identity mismatch in field {0}")]
    Mismatch(&'static str),
}

#[derive(Serialize)]
struct RootInput<'a> {
    package_id: &'a Digest,
    symbol_id: &'a Digest,
    components: &'a ComponentDigests,
}

/// Derive a package ID from namespace, name and edition.
pub fn derive_package_id(descriptor: &PackageDescriptor) -> Result<Digest, IdentityError> {
    Ok(digest_serializable("joan.package-id.v0", descriptor)?)
}

/// Derive a symbol ID without including implementation-body digests.
pub fn derive_symbol_id(descriptor: &SymbolDescriptor) -> Result<Digest, IdentityError> {
    Ok(digest_serializable("joan.symbol-id.v0", descriptor)?)
}

/// Build a fully bound semantic identity bundle.
pub fn build_bundle(
    package: &PackageDescriptor,
    symbol_kind: &str,
    symbol_name: &str,
    arity: u64,
    components: ComponentDigests,
) -> Result<SemanticIdentityBundle, IdentityError> {
    let package_id = derive_package_id(package)?;
    let symbol_id = derive_symbol_id(&SymbolDescriptor {
        package_id: package_id.clone(),
        kind: symbol_kind.to_owned(),
        name: symbol_name.to_owned(),
        arity,
        interface_digest: components.interface.clone(),
    })?;
    let program_root = derive_program_root(&package_id, &symbol_id, &components)?;
    Ok(SemanticIdentityBundle {
        schema: "joan.semantic-identity-bundle.v0".to_owned(),
        package_id,
        symbol_id,
        components,
        program_root,
    })
}

/// Verify schema, digest shapes and the bundle root.
pub fn verify_bundle(bundle: &SemanticIdentityBundle) -> Result<(), IdentityError> {
    if bundle.schema != "joan.semantic-identity-bundle.v0" {
        return Err(IdentityError::UnsupportedSchema(bundle.schema.clone()));
    }
    for (name, digest) in bundle_digests(bundle) {
        validate_digest_shape(digest).map_err(|()| IdentityError::MalformedDigest(name))?;
    }
    let expected = derive_program_root(&bundle.package_id, &bundle.symbol_id, &bundle.components)?;
    if expected != bundle.program_root {
        return Err(IdentityError::Mismatch("program_root"));
    }
    Ok(())
}

/// Verify that a node reference still points at the supplied base and node digest.
pub fn verify_node_ref(
    node_ref: &NodeRef,
    current_base_root: &Digest,
    current_node_digest: &Digest,
) -> Result<(), IdentityError> {
    if node_ref.schema != "joan.node-ref.v0" {
        return Err(IdentityError::UnsupportedSchema(node_ref.schema.clone()));
    }
    if node_ref.base_root != *current_base_root {
        return Err(IdentityError::Mismatch("base_root"));
    }
    if node_ref.expected_digest != *current_node_digest {
        return Err(IdentityError::Mismatch("expected_digest"));
    }
    Ok(())
}

fn derive_program_root(
    package_id: &Digest,
    symbol_id: &Digest,
    components: &ComponentDigests,
) -> Result<Digest, IdentityError> {
    Ok(digest_serializable(
        "joan.program-root.v0",
        &RootInput {
            package_id,
            symbol_id,
            components,
        },
    )?)
}

fn bundle_digests(bundle: &SemanticIdentityBundle) -> [(&'static str, &Digest); 11] {
    [
        ("package_id", &bundle.package_id),
        ("symbol_id", &bundle.symbol_id),
        ("source", &bundle.components.source),
        ("token", &bundle.components.token),
        ("structural", &bundle.components.structural),
        ("interface", &bundle.components.interface),
        ("behavior", &bundle.components.behavior),
        ("effect", &bundle.components.effect),
        ("policy", &bundle.components.policy),
        ("dependency", &bundle.components.dependency),
        ("program_root", &bundle.program_root),
    ]
}

fn validate_digest_shape(digest: &Digest) -> Result<(), ()> {
    if digest.algorithm != "sha256"
        || digest.profile != "joan-hash-v0"
        || digest.domain.is_empty()
        || digest.value.len() != 64
        || !digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(());
    }
    Ok(())
}
