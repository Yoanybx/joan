//! Semantic identity bundles built from separate, domain-tagged digests.

use joan_ast::CanonicalProgram;
use joan_canonical::{
    CanonicalError, CanonicalValue, Digest, Jce1Error, RegisteredDomainV1, digest_bytes_v1,
    digest_serializable, from_serializable_v1, parse_strict_v1, to_canonical_bytes_v1,
    verify_typed_digest_v1,
};
use serde::{Deserialize, Serialize};
use std::str;
use thiserror::Error;

const CANONICAL_AST_IDENTITY_SCHEMA_V0: &str = "joan.canonical-ast-identity.v0";

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

/// Typed identity of one exact canonical JOAN AST encoding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalAstIdentity {
    /// Identity descriptor schema.
    pub schema: String,
    /// Canonical encoding profile.
    pub encoding: String,
    /// AST schema covered by the digest.
    pub ast_schema: String,
    /// JCE1 digest of the exact canonical AST bytes.
    pub digest: Digest,
}

/// Canonical bytes plus their typed identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedCanonicalAst {
    /// Exact JCE1 bytes.
    pub bytes: Vec<u8>,
    /// Typed identity of `bytes`.
    pub identity: CanonicalAstIdentity,
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
    /// JCE1 encoding, domain or digest validation failed.
    #[error(transparent)]
    Jce1(#[from] Jce1Error),
    /// Input schema is unsupported.
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(String),
    /// A digest has invalid tags or malformed hexadecimal bytes.
    #[error("malformed digest in field {0}")]
    MalformedDigest(&'static str),
    /// A derived identity did not match the supplied value.
    #[error("identity mismatch in field {0}")]
    Mismatch(&'static str),
    /// AST bytes were not exact canonical JCE1 or lacked the required schema.
    #[error("canonical AST bytes are not an exact joan.canonical-ast.v0 JCE1 value")]
    NonCanonicalAst,
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

/// Encode a canonical AST value and derive its typed JCE1 identity.
pub fn encode_canonical_ast(ast: &CanonicalProgram) -> Result<EncodedCanonicalAst, IdentityError> {
    if ast.schema != CanonicalProgram::SCHEMA {
        return Err(IdentityError::UnsupportedSchema(ast.schema.clone()));
    }
    let value = from_serializable_v1(ast)?;
    let bytes = to_canonical_bytes_v1(&value)?;
    let identity = CanonicalAstIdentity {
        schema: CANONICAL_AST_IDENTITY_SCHEMA_V0.to_owned(),
        encoding: "JCE1".to_owned(),
        ast_schema: CanonicalProgram::SCHEMA.to_owned(),
        digest: digest_bytes_v1(RegisteredDomainV1::LanguageCanonicalAst, &bytes)?,
    };
    verify_canonical_ast_identity(&identity, &bytes)?;
    Ok(EncodedCanonicalAst { bytes, identity })
}

/// Verify the fixed tags and digest shape of a canonical AST identity descriptor.
pub fn verify_canonical_ast_identity_descriptor(
    identity: &CanonicalAstIdentity,
) -> Result<(), IdentityError> {
    if identity.schema != CANONICAL_AST_IDENTITY_SCHEMA_V0 {
        return Err(IdentityError::UnsupportedSchema(identity.schema.clone()));
    }
    if identity.encoding != "JCE1" {
        return Err(IdentityError::Mismatch("encoding"));
    }
    if identity.ast_schema != CanonicalProgram::SCHEMA {
        return Err(IdentityError::UnsupportedSchema(
            identity.ast_schema.clone(),
        ));
    }
    if identity.digest.algorithm != "sha256"
        || identity.digest.profile != "joan-hash-v1"
        || identity.digest.domain != RegisteredDomainV1::LanguageCanonicalAst.as_str()
        || identity.digest.value.len() != 64
        || !identity
            .digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(IdentityError::MalformedDigest("digest"));
    }
    Ok(())
}

/// Verify exact canonical AST bytes against their schema and typed digest.
pub fn verify_canonical_ast_identity(
    identity: &CanonicalAstIdentity,
    bytes: &[u8],
) -> Result<(), IdentityError> {
    verify_canonical_ast_identity_descriptor(identity)?;
    let text = str::from_utf8(bytes).map_err(|_| IdentityError::NonCanonicalAst)?;
    let value = parse_strict_v1(text)?;
    let CanonicalValue::Object(fields) = &value else {
        return Err(IdentityError::NonCanonicalAst);
    };
    if fields.get("schema") != Some(&CanonicalValue::String(CanonicalProgram::SCHEMA.to_owned())) {
        return Err(IdentityError::NonCanonicalAst);
    }
    if to_canonical_bytes_v1(&value)? != bytes {
        return Err(IdentityError::NonCanonicalAst);
    }
    verify_typed_digest_v1(
        RegisteredDomainV1::LanguageCanonicalAst,
        bytes,
        &identity.digest,
    )?;
    Ok(())
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
