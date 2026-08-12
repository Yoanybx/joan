//! Offline, content-addressed JOAN package manifests and resolution.

use joan_canonical::{
    CanonicalError, Digest, Jce1Error, RegisteredDomainV1, digest_bytes_v1, from_serializable_v1,
    parse_strict_v1, to_canonical_bytes_v1, verify_typed_digest_v1,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::str;
use thiserror::Error;

/// Exact package-manifest schema accepted by this resolver.
pub const PACKAGE_MANIFEST_SCHEMA: &str = "joan.package-manifest.v0";
/// Exact machine receipt schema emitted after resolution.
pub const PACKAGE_RESOLUTION_RECEIPT_SCHEMA: &str = "joan.package-resolution-receipt.v0";
/// Maximum packages reachable from one root manifest.
pub const MAX_PACKAGES: usize = 1_024;
/// Maximum modules across one resolved graph.
pub const MAX_MODULES: usize = 4_096;
/// Maximum dependency depth.
pub const MAX_DEPENDENCY_DEPTH: usize = 64;
/// Maximum unique source bytes across one resolved graph.
pub const MAX_TOTAL_SOURCE_BYTES: u64 = 64 * 1_048_576;

const MAX_MANIFEST_BYTES: u64 = 1_048_576;
const MAX_SOURCE_BYTES: u64 = 1_048_576;
const MAX_MODULES_PER_PACKAGE: usize = 1_024;
const MAX_DEPENDENCIES_PER_PACKAGE: usize = 256;

/// Human-readable coordinates. They are labels, never package authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageCoordinate {
    /// Reverse-DNS-style ASCII namespace.
    pub namespace: String,
    /// Lowercase ASCII package name.
    pub name: String,
    /// Compatibility edition label.
    pub edition: String,
}

/// One source module pinned to exact JCE1 source bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageModule {
    /// Module identifier declared inside the source.
    pub module: String,
    /// Normalized relative materialization path.
    pub path: String,
    /// Exact `joan.source.v1` identity.
    pub source_digest: Digest,
}

/// One dependency alias pinned to an exact manifest identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyPin {
    /// Local ASCII alias. It does not participate in remote discovery.
    pub alias: String,
    /// Exact `joan.package-manifest.v1` identity.
    pub manifest_digest: Digest,
}

/// Canonical package contract. Its digest is the package's authoritative identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageManifest {
    /// Manifest schema.
    pub schema: String,
    /// Human-readable coordinates.
    pub package: PackageCoordinate,
    /// Module selected as the package entry point.
    pub root_module: String,
    /// Modules sorted strictly by module name.
    pub modules: Vec<PackageModule>,
    /// Dependencies sorted strictly by alias.
    pub dependencies: Vec<DependencyPin>,
}

/// Exact canonical bytes and their authoritative package identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedPackageManifest {
    /// Exact JCE1 manifest bytes.
    pub bytes: Vec<u8>,
    /// Typed digest of `bytes`.
    pub digest: Digest,
}

/// One package included in a successful resolution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedPackage {
    /// Human-readable coordinates from the verified manifest.
    pub package: PackageCoordinate,
    /// Authoritative manifest identity.
    pub manifest_digest: Digest,
}

/// Deterministic proof that an exact local package graph resolved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageResolutionReceipt {
    /// Receipt schema.
    pub schema: String,
    /// Successful resolution status.
    pub status: String,
    /// Resolver implementation profile.
    pub resolver: String,
    /// Explicit network policy.
    pub network_policy: String,
    /// Explicit store access mode.
    pub store_mode: String,
    /// Transitive root identity supplied by the caller.
    pub root_manifest_digest: Digest,
    /// Packages sorted by manifest digest.
    pub packages: Vec<ResolvedPackage>,
    /// Unique source identities sorted by digest.
    pub source_digests: Vec<Digest>,
    /// Total declared modules across all packages.
    pub module_count: u64,
    /// Total bytes across unique verified sources.
    pub total_source_bytes: u64,
}

/// Package encoding, validation, store or resolution failure.
#[derive(Debug, Error)]
pub enum PackageError {
    /// Shared canonical JSON failure.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    /// JCE1 encoding or typed digest failure.
    #[error(transparent)]
    Jce1(#[from] Jce1Error),
    /// Manifest bytes were not valid UTF-8.
    #[error("package manifest is not valid UTF-8")]
    ManifestUtf8,
    /// Typed deserialization failed.
    #[error("package manifest decode failed: {0}")]
    Decode(String),
    /// Input was semantically invalid.
    #[error("invalid package manifest: {0}")]
    InvalidManifest(String),
    /// Input bytes were valid JSON but not the one canonical JCE1 representation.
    #[error("package manifest bytes are not exact canonical JCE1")]
    NonCanonicalManifest,
    /// A digest envelope had wrong tags or malformed hexadecimal bytes.
    #[error("malformed typed digest in {0}")]
    MalformedDigest(&'static str),
    /// A local object could not be read safely.
    #[error("package store read failed for {path}: {source}")]
    StoreIo {
        /// Object path.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// A store component was a symlink or unexpected file type.
    #[error("unsafe package store path: {0}")]
    UnsafeStorePath(PathBuf),
    /// A verified object was absent.
    #[error("package store object is missing: {0}")]
    MissingObject(PathBuf),
    /// An object exceeded a defensive byte bound.
    #[error("package store object {path} has {actual} bytes; limit is {limit}")]
    ObjectTooLarge {
        /// Object path.
        path: PathBuf,
        /// Observed bytes.
        actual: u64,
        /// Maximum accepted bytes.
        limit: u64,
    },
    /// Stored bytes did not match their requested content address.
    #[error("package store content digest mismatch: {0}")]
    DigestMismatch(PathBuf),
    /// Source bytes were not valid UTF-8 or parseable JOAN.
    #[error("invalid JOAN source object {digest}: {reason}")]
    InvalidSource {
        /// Source digest value.
        digest: String,
        /// Stable rejection context.
        reason: String,
    },
    /// Source module declaration did not match the manifest.
    #[error("source module mismatch: manifest declares {expected}, source declares {actual}")]
    ModuleMismatch {
        /// Manifest module.
        expected: String,
        /// Parsed source module.
        actual: String,
    },
    /// A transitive bound was exceeded.
    #[error("package resolution limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// The dependency graph contained a cycle.
    #[error("package dependency cycle detected at manifest {0}")]
    DependencyCycle(String),
    /// Two identities attempted to claim the same human coordinate.
    #[error("package coordinate {coordinate} maps to both {first} and {second}")]
    CoordinateCollision {
        /// Conflicting coordinate.
        coordinate: String,
        /// First manifest digest value.
        first: String,
        /// Second manifest digest value.
        second: String,
    },
}

/// Validate, canonicalize and identify one typed manifest.
pub fn encode_manifest(manifest: &PackageManifest) -> Result<EncodedPackageManifest, PackageError> {
    validate_manifest(manifest)?;
    let value = from_serializable_v1(manifest)?;
    let bytes = to_canonical_bytes_v1(&value)?;
    let digest = digest_bytes_v1(RegisteredDomainV1::PackageManifest, &bytes)?;
    Ok(EncodedPackageManifest { bytes, digest })
}

/// Decode exact JCE1 bytes, validate their contract and derive their identity.
pub fn verify_manifest_bytes(bytes: &[u8]) -> Result<(PackageManifest, Digest), PackageError> {
    let payload = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let text = str::from_utf8(payload).map_err(|_| PackageError::ManifestUtf8)?;
    let value = parse_strict_v1(text)?;
    if to_canonical_bytes_v1(&value)? != payload {
        return Err(PackageError::NonCanonicalManifest);
    }
    let manifest: PackageManifest = serde_json::from_value(value.to_serde_value())
        .map_err(|error| PackageError::Decode(error.to_string()))?;
    validate_manifest(&manifest)?;
    let digest = digest_bytes_v1(RegisteredDomainV1::PackageManifest, payload)?;
    Ok((manifest, digest))
}

/// Resolve one exact manifest and every pinned object from a read-only local store.
///
/// The store layout is `manifests/sha256/<digest>.json` and
/// `sources/sha256/<digest>.joan`. This function performs no network or writes.
pub fn resolve_package(
    root_manifest_bytes: &[u8],
    store: &Path,
) -> Result<PackageResolutionReceipt, PackageError> {
    ensure_store_root(store)?;
    let (root_manifest, root_digest) = verify_manifest_bytes(root_manifest_bytes)?;
    let mut resolver = Resolver::new(store);
    resolver.visit(root_manifest, root_digest.clone(), 0)?;
    Ok(PackageResolutionReceipt {
        schema: PACKAGE_RESOLUTION_RECEIPT_SCHEMA.to_owned(),
        status: "resolved".to_owned(),
        resolver: "joan-content-addressed-offline-v0".to_owned(),
        network_policy: "denied-no-network-client".to_owned(),
        store_mode: "read-only".to_owned(),
        root_manifest_digest: root_digest,
        packages: resolver.packages.into_values().collect(),
        source_digests: resolver
            .sources
            .into_values()
            .map(|source| source.digest)
            .collect(),
        module_count: resolver.module_count,
        total_source_bytes: resolver.total_source_bytes,
    })
}

fn validate_manifest(manifest: &PackageManifest) -> Result<(), PackageError> {
    if manifest.schema != PACKAGE_MANIFEST_SCHEMA {
        return Err(PackageError::InvalidManifest(format!(
            "unsupported schema {}",
            manifest.schema
        )));
    }
    validate_namespace(&manifest.package.namespace)?;
    validate_lower_name("package name", &manifest.package.name, false)?;
    validate_edition(&manifest.package.edition)?;
    validate_identifier("root module", &manifest.root_module)?;
    if manifest.modules.is_empty() || manifest.modules.len() > MAX_MODULES_PER_PACKAGE {
        return Err(PackageError::InvalidManifest(format!(
            "module count must be 1..={MAX_MODULES_PER_PACKAGE}"
        )));
    }
    if manifest.dependencies.len() > MAX_DEPENDENCIES_PER_PACKAGE {
        return Err(PackageError::InvalidManifest(format!(
            "dependency count exceeds {MAX_DEPENDENCIES_PER_PACKAGE}"
        )));
    }
    let mut paths = BTreeSet::new();
    let mut previous_module: Option<&str> = None;
    let mut has_root = false;
    for module in &manifest.modules {
        validate_identifier("module", &module.module)?;
        validate_module_path(&module.path)?;
        validate_digest_shape(
            &module.source_digest,
            RegisteredDomainV1::Source,
            "modules.source_digest",
        )?;
        if previous_module.is_some_and(|previous| previous >= module.module.as_str()) {
            return Err(PackageError::InvalidManifest(
                "modules must be strictly sorted by module".to_owned(),
            ));
        }
        previous_module = Some(&module.module);
        if !paths.insert(module.path.as_str()) {
            return Err(PackageError::InvalidManifest(
                "module paths must be unique".to_owned(),
            ));
        }
        has_root |= module.module == manifest.root_module;
    }
    if !has_root {
        return Err(PackageError::InvalidManifest(
            "root_module is not present in modules".to_owned(),
        ));
    }
    let mut previous_alias: Option<&str> = None;
    let mut dependency_digests = BTreeSet::new();
    for dependency in &manifest.dependencies {
        validate_lower_name("dependency alias", &dependency.alias, true)?;
        validate_digest_shape(
            &dependency.manifest_digest,
            RegisteredDomainV1::PackageManifest,
            "dependencies.manifest_digest",
        )?;
        if previous_alias.is_some_and(|previous| previous >= dependency.alias.as_str()) {
            return Err(PackageError::InvalidManifest(
                "dependencies must be strictly sorted by alias".to_owned(),
            ));
        }
        previous_alias = Some(&dependency.alias);
        if !dependency_digests.insert(dependency.manifest_digest.value.as_str()) {
            return Err(PackageError::InvalidManifest(
                "dependency manifest digests must be unique".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_namespace(namespace: &str) -> Result<(), PackageError> {
    if namespace.is_empty() || namespace.len() > 255 {
        return Err(PackageError::InvalidManifest(
            "namespace length must be 1..=255".to_owned(),
        ));
    }
    for segment in namespace.split('.') {
        validate_lower_name("namespace segment", segment, false)?;
    }
    Ok(())
}

fn validate_lower_name(field: &str, value: &str, underscore: bool) -> Result<(), PackageError> {
    if value.is_empty() || value.len() > 64 {
        return Err(PackageError::InvalidManifest(format!(
            "{field} length must be 1..=64"
        )));
    }
    let mut bytes = value.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || byte == b'-'
                || (underscore && byte == b'_')
        })
    {
        return Err(PackageError::InvalidManifest(format!(
            "{field} must use lowercase ASCII name syntax"
        )));
    }
    Ok(())
}

fn validate_edition(edition: &str) -> Result<(), PackageError> {
    let mut bytes = edition.bytes();
    if edition.len() > 32
        || !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'.'
        })
    {
        return Err(PackageError::InvalidManifest(
            "edition must use 1..=32 lowercase ASCII label bytes".to_owned(),
        ));
    }
    Ok(())
}

fn validate_identifier(field: &str, value: &str) -> Result<(), PackageError> {
    if value.is_empty() || value.len() > 128 {
        return Err(PackageError::InvalidManifest(format!(
            "{field} length must be 1..=128"
        )));
    }
    let mut bytes = value.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(PackageError::InvalidManifest(format!(
            "{field} must use JOAN ASCII identifier syntax"
        )));
    }
    Ok(())
}

fn validate_module_path(path: &str) -> Result<(), PackageError> {
    let parsed = Path::new(path);
    if path.is_empty()
        || path.len() > 1_024
        || path.contains('\\')
        || parsed.extension() != Some(OsStr::new("joan"))
    {
        return Err(PackageError::InvalidManifest(
            "module path must be a normalized relative .joan path".to_owned(),
        ));
    }
    if parsed.is_absolute() {
        return Err(PackageError::InvalidManifest(
            "module path must contain only UTF-8 normal components".to_owned(),
        ));
    }
    let mut normalized = Vec::new();
    for component in parsed.components() {
        let Component::Normal(component) = component else {
            return Err(PackageError::InvalidManifest(
                "module path must contain only UTF-8 normal components".to_owned(),
            ));
        };
        normalized.push(component.to_str().ok_or_else(|| {
            PackageError::InvalidManifest(
                "module path must contain only UTF-8 normal components".to_owned(),
            )
        })?);
    }
    if normalized.join("/") != path {
        return Err(PackageError::InvalidManifest(
            "module path must be lexically normalized".to_owned(),
        ));
    }
    Ok(())
}

fn validate_digest_shape(
    digest: &Digest,
    domain: RegisteredDomainV1,
    field: &'static str,
) -> Result<(), PackageError> {
    if digest.algorithm != "sha256"
        || digest.profile != "joan-hash-v1"
        || digest.domain != domain.as_str()
        || digest.value.len() != 64
        || !digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PackageError::MalformedDigest(field));
    }
    Ok(())
}

#[derive(Debug)]
struct VerifiedSource {
    digest: Digest,
    module: String,
}

struct Resolver<'a> {
    store: &'a Path,
    visiting: BTreeSet<String>,
    packages: BTreeMap<String, ResolvedPackage>,
    coordinates: BTreeMap<String, String>,
    sources: BTreeMap<String, VerifiedSource>,
    module_count: u64,
    total_source_bytes: u64,
}

impl<'a> Resolver<'a> {
    fn new(store: &'a Path) -> Self {
        Self {
            store,
            visiting: BTreeSet::new(),
            packages: BTreeMap::new(),
            coordinates: BTreeMap::new(),
            sources: BTreeMap::new(),
            module_count: 0,
            total_source_bytes: 0,
        }
    }

    fn visit(
        &mut self,
        manifest: PackageManifest,
        digest: Digest,
        depth: usize,
    ) -> Result<(), PackageError> {
        if self.packages.contains_key(&digest.value) {
            return Ok(());
        }
        if depth > MAX_DEPENDENCY_DEPTH {
            return Err(PackageError::LimitExceeded("dependency depth"));
        }
        if self.packages.len() + self.visiting.len() >= MAX_PACKAGES {
            return Err(PackageError::LimitExceeded("package count"));
        }
        if !self.visiting.insert(digest.value.clone()) {
            return Err(PackageError::DependencyCycle(digest.value));
        }

        let coordinate = format!(
            "{}/{}@{}",
            manifest.package.namespace, manifest.package.name, manifest.package.edition
        );
        if let Some(first) = self.coordinates.get(&coordinate) {
            if first != &digest.value {
                self.visiting.remove(&digest.value);
                return Err(PackageError::CoordinateCollision {
                    coordinate,
                    first: first.clone(),
                    second: digest.value,
                });
            }
        } else {
            self.coordinates
                .insert(coordinate.clone(), digest.value.clone());
        }

        let result = self.visit_contents(&manifest, &digest, depth);
        self.visiting.remove(&digest.value);
        result?;
        self.packages.insert(
            digest.value.clone(),
            ResolvedPackage {
                package: manifest.package,
                manifest_digest: digest,
            },
        );
        Ok(())
    }

    fn visit_contents(
        &mut self,
        manifest: &PackageManifest,
        digest: &Digest,
        depth: usize,
    ) -> Result<(), PackageError> {
        let module_count = u64::try_from(manifest.modules.len())
            .map_err(|_| PackageError::LimitExceeded("module count"))?;
        self.module_count = self
            .module_count
            .checked_add(module_count)
            .ok_or(PackageError::LimitExceeded("module count"))?;
        if self.module_count > MAX_MODULES as u64 {
            return Err(PackageError::LimitExceeded("module count"));
        }
        for module in &manifest.modules {
            self.verify_source(module)?;
        }
        for dependency in &manifest.dependencies {
            if dependency.manifest_digest == *digest {
                return Err(PackageError::DependencyCycle(digest.value.clone()));
            }
            let path = object_path(
                self.store,
                "manifests",
                &dependency.manifest_digest.value,
                "json",
            );
            let bytes = read_store_object(self.store, &path, MAX_MANIFEST_BYTES)?;
            let (child, observed) = verify_manifest_bytes(&bytes)?;
            if observed != dependency.manifest_digest {
                return Err(PackageError::DigestMismatch(path));
            }
            self.visit(child, observed, depth + 1)?;
        }
        Ok(())
    }

    fn verify_source(&mut self, module: &PackageModule) -> Result<(), PackageError> {
        if let Some(source) = self.sources.get(&module.source_digest.value) {
            if source.module != module.module {
                return Err(PackageError::ModuleMismatch {
                    expected: module.module.clone(),
                    actual: source.module.clone(),
                });
            }
            return Ok(());
        }
        let path = object_path(self.store, "sources", &module.source_digest.value, "joan");
        let bytes = read_store_object(self.store, &path, MAX_SOURCE_BYTES)?;
        verify_typed_digest_v1(RegisteredDomainV1::Source, &bytes, &module.source_digest)
            .map_err(|_| PackageError::DigestMismatch(path.clone()))?;
        let text = str::from_utf8(&bytes).map_err(|error| PackageError::InvalidSource {
            digest: module.source_digest.value.clone(),
            reason: error.to_string(),
        })?;
        let program = joan_syntax::parse(text).map_err(|report| PackageError::InvalidSource {
            digest: module.source_digest.value.clone(),
            reason: report.diagnostics.first().map_or_else(
                || "source parser rejected input".to_owned(),
                |item| item.message.clone(),
            ),
        })?;
        if program.module != module.module {
            return Err(PackageError::ModuleMismatch {
                expected: module.module.clone(),
                actual: program.module,
            });
        }
        let length = u64::try_from(bytes.len())
            .map_err(|_| PackageError::LimitExceeded("total source bytes"))?;
        self.total_source_bytes = self
            .total_source_bytes
            .checked_add(length)
            .ok_or(PackageError::LimitExceeded("total source bytes"))?;
        if self.total_source_bytes > MAX_TOTAL_SOURCE_BYTES {
            return Err(PackageError::LimitExceeded("total source bytes"));
        }
        self.sources.insert(
            module.source_digest.value.clone(),
            VerifiedSource {
                digest: module.source_digest.clone(),
                module: module.module.clone(),
            },
        );
        Ok(())
    }
}

fn ensure_store_root(store: &Path) -> Result<(), PackageError> {
    let metadata = fs::symlink_metadata(store).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            PackageError::MissingObject(store.to_path_buf())
        } else {
            PackageError::StoreIo {
                path: store.to_path_buf(),
                source,
            }
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(PackageError::UnsafeStorePath(store.to_path_buf()));
    }
    Ok(())
}

fn object_path(store: &Path, class: &str, value: &str, extension: &str) -> PathBuf {
    store
        .join(class)
        .join("sha256")
        .join(format!("{value}.{extension}"))
}

fn read_store_object(store: &Path, path: &Path, limit: u64) -> Result<Vec<u8>, PackageError> {
    let relative = path
        .strip_prefix(store)
        .map_err(|_| PackageError::UnsafeStorePath(path.to_path_buf()))?;
    let mut current = store.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(PackageError::UnsafeStorePath(path.to_path_buf()));
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current).map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                PackageError::MissingObject(current.clone())
            } else {
                PackageError::StoreIo {
                    path: current.clone(),
                    source,
                }
            }
        })?;
        if metadata.file_type().is_symlink() {
            return Err(PackageError::UnsafeStorePath(current));
        }
        if current == path {
            if !metadata.is_file() {
                return Err(PackageError::UnsafeStorePath(current));
            }
            if metadata.len() > limit {
                return Err(PackageError::ObjectTooLarge {
                    path: current,
                    actual: metadata.len(),
                    limit,
                });
            }
        } else if !metadata.is_dir() {
            return Err(PackageError::UnsafeStorePath(current));
        }
    }
    let bytes = fs::read(path).map_err(|source| PackageError::StoreIo {
        path: path.to_path_buf(),
        source,
    })?;
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual > limit {
        return Err(PackageError::ObjectTooLarge {
            path: path.to_path_buf(),
            actual,
            limit,
        });
    }
    Ok(bytes)
}
