//! Content addressing, deterministic resolution and fail-closed store tests.

use joan_canonical::{Digest, RegisteredDomainV1, digest_bytes_v1};
use joan_package::{
    DependencyPin, PACKAGE_MANIFEST_SCHEMA, PackageCoordinate, PackageError, PackageManifest,
    PackageModule, encode_manifest, resolve_package, verify_manifest_bytes,
};
use std::fs;
use std::path::Path;
use tempfile::tempdir;

#[test]
fn resolves_a_transitive_graph_deterministically() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let store = directory.path();

    let math_source = source("math", "answer", 42);
    let math_source_digest = put_source(store, &math_source)?;
    let math = manifest(
        "org.ledaction.joan",
        "math",
        "math",
        math_source_digest,
        vec![],
    );
    let encoded_math = encode_manifest(&math)?;
    put_manifest(store, &encoded_math.digest, &encoded_math.bytes)?;

    let app_source = source("app", "main", 7);
    let app_source_digest = put_source(store, &app_source)?;
    let app = manifest(
        "org.ledaction.joan",
        "app",
        "app",
        app_source_digest,
        vec![DependencyPin {
            alias: "math".to_owned(),
            manifest_digest: encoded_math.digest,
        }],
    );
    let encoded_app = encode_manifest(&app)?;

    let first = resolve_package(&encoded_app.bytes, store)?;
    let second = resolve_package(&encoded_app.bytes, store)?;
    assert_eq!(first, second);
    assert_eq!(first.root_manifest_digest, encoded_app.digest);
    assert_eq!(first.packages.len(), 2);
    assert_eq!(first.source_digests.len(), 2);
    assert_eq!(first.module_count, 2);
    assert_eq!(first.network_policy, "denied-no-network-client");
    assert_eq!(first.store_mode, "read-only");
    Ok(())
}

#[test]
fn rejects_noncanonical_manifest_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let source_digest = digest_bytes_v1(RegisteredDomainV1::Source, b"source")?;
    let manifest = manifest(
        "org.ledaction.joan",
        "pretty",
        "pretty",
        source_digest,
        vec![],
    );
    let pretty = serde_json::to_vec_pretty(&manifest)?;
    assert!(matches!(
        verify_manifest_bytes(&pretty),
        Err(PackageError::NonCanonicalManifest)
    ));
    Ok(())
}

#[test]
fn one_git_text_lf_does_not_change_manifest_identity() -> Result<(), Box<dyn std::error::Error>> {
    let source_digest = digest_bytes_v1(RegisteredDomainV1::Source, b"source")?;
    let encoded = encode_manifest(&manifest(
        "org.ledaction.joan",
        "framed",
        "framed",
        source_digest,
        vec![],
    ))?;
    let mut framed = encoded.bytes.clone();
    framed.push(b'\n');
    let (_, observed) = verify_manifest_bytes(&framed)?;
    assert_eq!(observed, encoded.digest);
    framed.push(b'\n');
    assert!(verify_manifest_bytes(&framed).is_err());
    Ok(())
}

#[test]
fn changing_a_human_label_changes_package_identity() -> Result<(), Box<dyn std::error::Error>> {
    let source_digest = digest_bytes_v1(RegisteredDomainV1::Source, b"same")?;
    let first = manifest(
        "org.ledaction.joan",
        "first",
        "same",
        source_digest.clone(),
        vec![],
    );
    let second = manifest(
        "org.ledaction.joan",
        "second",
        "same",
        source_digest,
        vec![],
    );
    assert_ne!(
        encode_manifest(&first)?.digest,
        encode_manifest(&second)?.digest
    );
    Ok(())
}

#[test]
fn rejects_unsorted_modules_and_unsafe_paths() -> Result<(), Box<dyn std::error::Error>> {
    let digest = digest_bytes_v1(RegisteredDomainV1::Source, b"same")?;
    let mut manifest = manifest(
        "org.ledaction.joan",
        "bad-order",
        "zeta",
        digest.clone(),
        vec![],
    );
    manifest.modules.push(PackageModule {
        module: "alpha".to_owned(),
        path: "src/alpha.joan".to_owned(),
        source_digest: digest,
    });
    assert!(matches!(
        encode_manifest(&manifest),
        Err(PackageError::InvalidManifest(reason)) if reason.contains("strictly sorted")
    ));

    manifest.modules.truncate(1);
    manifest.modules[0].path = "../escape.joan".to_owned();
    assert!(matches!(
        encode_manifest(&manifest),
        Err(PackageError::InvalidManifest(reason)) if reason.contains("normal")
    ));

    manifest.modules[0].path = "src//zeta.joan".to_owned();
    assert!(matches!(
        encode_manifest(&manifest),
        Err(PackageError::InvalidManifest(reason)) if reason.contains("normalized")
    ));
    Ok(())
}

#[test]
fn rejects_mutated_source_at_a_valid_address() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let store = directory.path();
    let expected = source("app", "main", 1);
    let source_digest = put_source(store, &expected)?;
    let path = source_path(store, &source_digest);
    fs::write(path, source("app", "main", 2))?;
    let root = encode_manifest(&manifest(
        "org.ledaction.joan",
        "app",
        "app",
        source_digest,
        vec![],
    ))?;
    assert!(matches!(
        resolve_package(&root.bytes, store),
        Err(PackageError::DigestMismatch(_))
    ));
    Ok(())
}

#[test]
fn rejects_source_module_substitution() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let store = directory.path();
    let source_digest = put_source(store, &source("other", "main", 1))?;
    let root = encode_manifest(&manifest(
        "org.ledaction.joan",
        "app",
        "app",
        source_digest,
        vec![],
    ))?;
    assert!(matches!(
        resolve_package(&root.bytes, store),
        Err(PackageError::ModuleMismatch { expected, actual })
            if expected == "app" && actual == "other"
    ));
    Ok(())
}

#[test]
fn rejects_missing_dependency_object() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let store = directory.path();
    let source_digest = put_source(store, &source("app", "main", 1))?;
    let missing = digest_bytes_v1(RegisteredDomainV1::PackageManifest, b"missing")?;
    let root = encode_manifest(&manifest(
        "org.ledaction.joan",
        "app",
        "app",
        source_digest,
        vec![DependencyPin {
            alias: "missing".to_owned(),
            manifest_digest: missing,
        }],
    ))?;
    assert!(matches!(
        resolve_package(&root.bytes, store),
        Err(PackageError::MissingObject(_))
    ));
    Ok(())
}

#[test]
fn rejects_two_identities_for_one_coordinate() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let store = directory.path();

    let first_source = put_source(store, &source("first", "value", 1))?;
    let first = encode_manifest(&manifest(
        "org.ledaction.joan",
        "shared",
        "first",
        first_source,
        vec![],
    ))?;
    put_manifest(store, &first.digest, &first.bytes)?;

    let second_source = put_source(store, &source("second", "value", 2))?;
    let second = encode_manifest(&manifest(
        "org.ledaction.joan",
        "shared",
        "second",
        second_source,
        vec![],
    ))?;
    put_manifest(store, &second.digest, &second.bytes)?;

    let root_source = put_source(store, &source("root", "main", 0))?;
    let root = encode_manifest(&manifest(
        "org.ledaction.joan",
        "root",
        "root",
        root_source,
        vec![
            DependencyPin {
                alias: "first".to_owned(),
                manifest_digest: first.digest,
            },
            DependencyPin {
                alias: "second".to_owned(),
                manifest_digest: second.digest,
            },
        ],
    ))?;
    assert!(matches!(
        resolve_package(&root.bytes, store),
        Err(PackageError::CoordinateCollision { coordinate, .. })
            if coordinate == "org.ledaction.joan/shared@alpha-1"
    ));
    Ok(())
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_store_objects() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let directory = tempdir()?;
    let store = directory.path();
    let bytes = source("app", "main", 1);
    let digest = digest_bytes_v1(RegisteredDomainV1::Source, &bytes)?;
    let target = store.join("outside.joan");
    fs::write(&target, &bytes)?;
    let path = source_path(store, &digest);
    let parent = path.parent().ok_or("source path has no parent")?;
    fs::create_dir_all(parent)?;
    symlink(target, path)?;
    let root = encode_manifest(&manifest(
        "org.ledaction.joan",
        "app",
        "app",
        digest,
        vec![],
    ))?;
    assert!(matches!(
        resolve_package(&root.bytes, store),
        Err(PackageError::UnsafeStorePath(_))
    ));
    Ok(())
}

fn source(module: &str, function: &str, value: i64) -> Vec<u8> {
    format!("module {module};\nfn {function}() -> i64 effects [] {{\n  return {value};\n}}\n")
        .into_bytes()
}

fn manifest(
    namespace: &str,
    name: &str,
    module: &str,
    source_digest: Digest,
    dependencies: Vec<DependencyPin>,
) -> PackageManifest {
    PackageManifest {
        schema: PACKAGE_MANIFEST_SCHEMA.to_owned(),
        package: PackageCoordinate {
            namespace: namespace.to_owned(),
            name: name.to_owned(),
            edition: "alpha-1".to_owned(),
        },
        root_module: module.to_owned(),
        modules: vec![PackageModule {
            module: module.to_owned(),
            path: format!("src/{module}.joan"),
            source_digest,
        }],
        dependencies,
    }
}

fn put_source(store: &Path, bytes: &[u8]) -> Result<Digest, Box<dyn std::error::Error>> {
    let digest = digest_bytes_v1(RegisteredDomainV1::Source, bytes)?;
    let path = source_path(store, &digest);
    fs::create_dir_all(path.parent().ok_or("source path has no parent")?)?;
    fs::write(path, bytes)?;
    Ok(digest)
}

fn put_manifest(
    store: &Path,
    digest: &Digest,
    bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let path = store
        .join("manifests")
        .join("sha256")
        .join(format!("{}.json", digest.value));
    fs::create_dir_all(path.parent().ok_or("manifest path has no parent")?)?;
    fs::write(path, bytes)?;
    Ok(())
}

fn source_path(store: &Path, digest: &Digest) -> std::path::PathBuf {
    store
        .join("sources")
        .join("sha256")
        .join(format!("{}.joan", digest.value))
}
