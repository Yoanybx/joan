//! Repository-level machine contract and founder-attribution tests.

use joan_canonical::parse_strict;
use joan_canonical::{RegisteredDomainV1, digest_bytes_v1};
use joan_compiler::{canonicalize_source_ast, compile_source};
use joan_native::compile_bytecode;
use joan_package::{
    PACKAGE_MANIFEST_SCHEMA, PackageCoordinate, PackageManifest, PackageModule, encode_manifest,
    resolve_package,
};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

const FOUNDER: &str = "Joan Alberto Barrios Cruz";
const CORPORATE_OWNER: &str = "LED ACTION LLC";
const INCORRECT_ATTRIBUTION: &str = "Gepsy Gainza";

#[test]
fn protected_founder_records_are_consistent() -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root();
    for path in [
        "AUTHORS.md",
        "COPYRIGHT",
        "LICENSE",
        "NOTICE",
        "ORIGIN.md",
        "OWNERSHIP.md",
        "GOVERNANCE.md",
        ".joan/origin.json",
        ".joan/project.json",
    ] {
        let content = fs::read_to_string(root.join(path))?;
        assert!(
            content.contains(FOUNDER),
            "missing founder attribution in {path}"
        );
        assert!(
            content.contains(CORPORATE_OWNER),
            "missing corporate owner attribution in {path}"
        );
        assert!(
            !content.contains(INCORRECT_ATTRIBUTION),
            "incorrect attribution found in {path}"
        );
    }
    Ok(())
}

#[test]
fn every_machine_contract_is_strict_json() -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root();
    let mut files = Vec::new();
    collect_json(&root.join(".joan"), &mut files)?;
    collect_json(&root.join("schemas"), &mut files)?;
    collect_json(&root.join("vectors/canonical"), &mut files)?;
    collect_json(&root.join("vectors/adoption"), &mut files)?;
    collect_json(&root.join("vectors/jce1"), &mut files)?;
    collect_json(&root.join("vectors/language-differential"), &mut files)?;
    collect_json(&root.join("vectors/payment-cost"), &mut files)?;
    collect_json(&root.join("benchmarks/agent-scorecard"), &mut files)?;
    assert!(!files.is_empty());
    for path in files {
        parse_strict(&fs::read_to_string(&path)?).map_err(|error| {
            format!(
                "strict JSON contract failed for {}: {error}",
                path.display()
            )
        })?;
    }
    Ok(())
}

#[test]
fn every_schema_is_valid_draft_2020_12() -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root();
    let mut schemas = Vec::new();
    collect_json(&root.join("schemas"), &mut schemas)?;
    assert!(!schemas.is_empty());
    for path in schemas {
        let schema = read_json(&path)?;
        jsonschema::draft202012::meta::validate(&schema).map_err(|error| {
            format!(
                "Draft 2020-12 schema validation failed for {}: {error}",
                path.display()
            )
        })?;
    }
    Ok(())
}

#[test]
fn compiler_canonical_ast_matches_its_schema() -> Result<(), Box<dyn std::error::Error>> {
    let encoded = canonicalize_source_ast(
        r#"module contract;
fn main() -> i64 effects [audit] {
  request audit("schema");
  return 9223372036854775807;
}
"#,
    )?;
    let instance: Value = serde_json::from_slice(&encoded.bytes)?;
    let schema = read_json(&workspace_root().join("schemas/canonical-ast.v0.schema.json"))?;
    let validator = jsonschema::draft202012::options().build(&schema)?;
    if let Err(error) = validator.validate(&instance) {
        return Err(format!("compiler canonical AST does not match its schema: {error}").into());
    }
    Ok(())
}

#[test]
fn linear_compiler_artifacts_match_their_versioned_schemas()
-> Result<(), Box<dyn std::error::Error>> {
    let artifact = compile_source(
        r#"module contract;
fn main() -> unit effects [audit] authorities [audit_once: audit] {
  request audit("schema") using audit_once;
  return;
}
"#,
    )?;
    validate_instance(
        &serde_json::to_value(&artifact.bytecode.canonical_ast)?,
        "schemas/canonical-ast.v1.schema.json",
    )?;
    validate_instance(
        &serde_json::to_value(&artifact.bytecode.semantic_identity)?,
        "schemas/canonical-ast-identity.v1.schema.json",
    )?;
    validate_instance(
        &serde_json::to_value(&artifact.bytecode)?,
        "schemas/bytecode-program.v2.schema.json",
    )?;
    validate_instance(
        &serde_json::to_value(&artifact.verification)?,
        "schemas/bytecode-verification-receipt.v1.schema.json",
    )?;
    Ok(())
}

#[test]
fn information_flow_artifacts_match_their_versioned_schemas()
-> Result<(), Box<dyn std::error::Error>> {
    let artifact = compile_source(
        r#"module secure flow;
fn main() -> unit flow [public] effects [audit] authorities [audit_once: audit] {
  let event: string flow [secret, tenant:agent_a, purpose:audit] = "schema";
  request audit(event) using audit_once flow [secret, tenant:agent_a, purpose:audit];
  return;
}
"#,
    )?;
    validate_instance(
        &serde_json::to_value(&artifact.bytecode.canonical_ast)?,
        "schemas/canonical-ast.v2.schema.json",
    )?;
    validate_instance(
        &serde_json::to_value(&artifact.bytecode.semantic_identity)?,
        "schemas/canonical-ast-identity.v2.schema.json",
    )?;
    validate_instance(
        &serde_json::to_value(&artifact.bytecode)?,
        "schemas/bytecode-program.v3.schema.json",
    )?;
    validate_instance(
        &serde_json::to_value(&artifact.verification)?,
        "schemas/bytecode-verification-receipt.v2.schema.json",
    )?;
    Ok(())
}

#[test]
fn bytecode_and_verification_receipt_match_their_schemas() -> Result<(), Box<dyn std::error::Error>>
{
    let artifact =
        compile_source("module contract;\nfn main() -> i64 effects [] { return 42; }\n")?;
    validate_instance(
        &serde_json::to_value(&artifact.bytecode)?,
        "schemas/bytecode-program.v1.schema.json",
    )?;
    validate_instance(
        &serde_json::to_value(&artifact.verification)?,
        "schemas/bytecode-verification-receipt.v0.schema.json",
    )?;
    Ok(())
}

#[test]
fn package_manifest_and_receipt_match_their_schemas() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = directory.path();
    let source = b"module contract;\nfn main() -> i64 effects [] {\n  return 1;\n}\n";
    let source_digest = digest_bytes_v1(RegisteredDomainV1::Source, source)?;
    let source_path = store
        .join("sources")
        .join("sha256")
        .join(format!("{}.joan", source_digest.value));
    fs::create_dir_all(source_path.parent().ok_or("source path has no parent")?)?;
    fs::write(source_path, source)?;
    let encoded = encode_manifest(&PackageManifest {
        schema: PACKAGE_MANIFEST_SCHEMA.to_owned(),
        package: PackageCoordinate {
            namespace: "org.ledaction.joan".to_owned(),
            name: "contract".to_owned(),
            edition: "alpha-1".to_owned(),
        },
        root_module: "contract".to_owned(),
        modules: vec![PackageModule {
            module: "contract".to_owned(),
            path: "src/contract.joan".to_owned(),
            source_digest,
        }],
        dependencies: vec![],
    })?;
    let receipt = resolve_package(&encoded.bytes, store)?;
    validate_instance(
        &serde_json::from_slice(&encoded.bytes)?,
        "schemas/package-manifest.v0.schema.json",
    )?;
    validate_instance(
        &serde_json::to_value(receipt)?,
        "schemas/package-resolution-receipt.v0.schema.json",
    )?;
    Ok(())
}

#[test]
fn native_receipts_match_their_schemas() -> Result<(), Box<dyn std::error::Error>> {
    let artifact = compile_source(
        r"module native_contract;
fn multiply(left: i64, right: i64) -> i64 effects [] {
  return left * right;
}
fn main() -> i64 effects [] {
  return 0;
}
",
    )?;
    let native = compile_bytecode(&artifact.bytecode)?;
    let execution = native.invoke(
        "multiply",
        &[joan_bytecode::Value::I64(6), joan_bytecode::Value::I64(7)],
        100,
    )?;
    validate_instance(
        &serde_json::to_value(native.receipt())?,
        "schemas/native-compile-receipt.v0.schema.json",
    )?;
    validate_instance(
        &serde_json::to_value(execution)?,
        "schemas/native-execution-receipt.v0.schema.json",
    )?;
    Ok(())
}

#[test]
fn joan_manifests_match_their_schemas() -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root();
    let retriever = LocalSchemaRetriever::load()?;
    for (instance_path, schema_path) in manifest_schema_pairs() {
        let instance = read_json(&root.join(instance_path))?;
        let schema = read_json(&root.join(schema_path))?;
        let validator = jsonschema::draft202012::options()
            .should_validate_formats(true)
            .with_retriever(retriever.clone())
            .build(&schema)
            .map_err(|error| format!("schema build failed for {schema_path}: {error}"))?;
        if let Err(error) = validator.validate(&instance) {
            return Err(format!("{instance_path} does not match {schema_path}: {error}").into());
        }
    }
    Ok(())
}

#[test]
fn manifest_schemas_reject_unknown_fields() -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root();
    let retriever = LocalSchemaRetriever::load()?;
    for (instance_path, schema_path) in manifest_schema_pairs() {
        let mut instance = read_json(&root.join(instance_path))?;
        instance
            .as_object_mut()
            .ok_or_else(|| format!("manifest is not an object: {instance_path}"))?
            .insert("unexpected_field".to_owned(), Value::Bool(true));
        let schema = read_json(&root.join(schema_path))?;
        let validator = jsonschema::draft202012::options()
            .with_retriever(retriever.clone())
            .build(&schema)?;
        assert!(
            !validator.is_valid(&instance),
            "unknown field accepted by {schema_path}"
        );
    }
    Ok(())
}

#[test]
fn differential_language_report_matches_its_schema() -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root();
    let temporary = tempfile::tempdir()?;
    let report_path = temporary.path().join("report.json");
    let output = Command::new("node")
        .args([
            "tools/language-differential-runner.mjs",
            env!("CARGO_BIN_EXE_joan"),
            "vectors/language-differential/corpus-v1.json",
        ])
        .arg(&report_path)
        .env("JOAN_DIFFERENTIAL_TMPDIR", temporary.path())
        .current_dir(&root)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "differential runner failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let report = read_json(&report_path)?;
    validate_instance(
        &report,
        "schemas/language-differential-report.v1.schema.json",
    )?;
    assert_eq!(report["total"], 76);
    assert_eq!(report["passed"], 76);
    assert_eq!(report["failed"], 0);
    Ok(())
}

#[test]
fn agent_scorecard_report_matches_its_schema() -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root();
    let temporary = tempfile::tempdir()?;
    let report_path = temporary.path().join("report.json");
    let output = Command::new("node")
        .args([
            "tools/agent-scorecard-runner.mjs",
            env!("CARGO_BIN_EXE_joan"),
            "benchmarks/agent-scorecard/workloads-v1.json",
        ])
        .arg(&report_path)
        .args([
            "--samples",
            "3",
            "--prepare-samples",
            "1",
            "--mode",
            "smoke",
        ])
        .env("JOAN_SCORECARD_TMPDIR", temporary.path())
        .current_dir(&root)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "agent scorecard runner failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let report = read_json(&report_path)?;
    validate_instance(&report, "schemas/agent-scorecard-report.v1.schema.json")?;
    assert_eq!(
        report["qualification"]["status"],
        "baseline-only-not-qualified"
    );
    assert_eq!(report["qualification"]["correctness_equivalent"], true);
    assert_eq!(report["safety"]["protection"]["joan"]["protected"], 4);
    assert_eq!(report["universal_language_superiority_claim"], false);
    Ok(())
}

#[test]
fn native_backend_report_matches_its_schema_when_supplied() -> Result<(), Box<dyn std::error::Error>>
{
    let Ok(path) = std::env::var("JOAN_NATIVE_BACKEND_REPORT_INPUT") else {
        return Ok(());
    };
    validate_instance(
        &read_json(Path::new(&path))?,
        "schemas/native-backend-benchmark-report.v0.schema.json",
    )
}

#[test]
fn verification_receipts_match_their_schema() -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root();
    let receipt_directory = root.join(".joan/evidence/runs");
    if !receipt_directory.exists() {
        return Ok(());
    }
    let schema = read_json(&root.join("schemas/verification-run-receipt.v1.schema.json"))?;
    let validator = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)?;
    let mut receipts = Vec::new();
    collect_json(&receipt_directory, &mut receipts)?;
    for path in receipts {
        let receipt = read_json(&path)?;
        if let Err(error) = validator.validate(&receipt) {
            return Err(format!(
                "{} is not a valid verification receipt: {error}",
                path.display()
            )
            .into());
        }
    }
    Ok(())
}

#[test]
fn invalid_vectors_remain_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root().join("vectors/invalid");
    for name in ["duplicate-key.json", "floating-point.json"] {
        let text = fs::read_to_string(root.join(name))?;
        assert!(
            parse_strict(&text).is_err(),
            "invalid vector accepted: {name}"
        );
    }
    Ok(())
}

#[test]
fn source_tree_v2_ignores_appledouble_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root();
    let baseline = source_snapshot(&root)?;
    let mut metadata = tempfile::Builder::new()
        .prefix("._joan-source-tree-v2-")
        .tempfile_in(&root)?;
    metadata.write_all(b"platform metadata is not source")?;
    metadata.flush()?;
    let observed = source_snapshot(&root)?;
    assert_eq!(observed, baseline);
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

fn manifest_schema_pairs() -> [(&'static str, &'static str); 15] {
    [
        (
            ".joan/adoption.json",
            "schemas/adoption-manifest.v0.schema.json",
        ),
        (
            ".joan/conformance.json",
            "schemas/conformance-manifest.v1.schema.json",
        ),
        (
            ".joan/evidence/latest.json",
            "schemas/evidence-index.v2.schema.json",
        ),
        (
            ".joan/origin.json",
            "schemas/origin-manifest.v0.schema.json",
        ),
        (
            ".joan/project.json",
            "schemas/project-manifest.v0.schema.json",
        ),
        (
            ".joan/pr-trust.json",
            "schemas/pr-trust-policy.v0.schema.json",
        ),
        (
            ".joan/update-policy.json",
            "schemas/update-policy.v0.schema.json",
        ),
        (
            "vectors/payment-cost/scenario-v0.json",
            "schemas/payment-cost-scenario.v0.schema.json",
        ),
        (
            "vectors/payment-cost/report-v0.json",
            "schemas/payment-cost-report.v0.schema.json",
        ),
        (
            "vectors/language-differential/corpus-v1.json",
            "schemas/language-differential-corpus.v1.schema.json",
        ),
        (
            "tools/verification-gates.v1.json",
            "schemas/verification-gates.v1.schema.json",
        ),
        (
            "benchmarks/agent-scorecard/workloads-v1.json",
            "schemas/agent-scorecard-workloads.v1.schema.json",
        ),
        (
            "benchmarks/results/2026-08-12-mac15-4-agent-scorecard.json",
            "schemas/agent-scorecard-report.v1.schema.json",
        ),
        (
            "benchmarks/native-backend/manifest-v0.json",
            "schemas/native-backend-benchmark-manifest.v0.schema.json",
        ),
        (
            "benchmarks/results/2026-08-13-mac15-4-native-backend.json",
            "schemas/native-backend-benchmark-report.v0.schema.json",
        ),
    ]
}

fn read_json(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn validate_instance(
    instance: &Value,
    schema_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let schema = read_json(&workspace_root().join(schema_path))?;
    let validator = jsonschema::draft202012::options()
        .with_retriever(LocalSchemaRetriever::load()?)
        .build(&schema)?;
    if let Err(error) = validator.validate(instance) {
        return Err(format!("instance does not match {schema_path}: {error}").into());
    }
    Ok(())
}

#[derive(Clone)]
struct LocalSchemaRetriever {
    schemas: HashMap<String, Value>,
}

impl LocalSchemaRetriever {
    fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let mut paths = Vec::new();
        collect_json(&workspace_root().join("schemas"), &mut paths)?;
        let mut schemas = HashMap::new();
        for path in paths {
            let schema = read_json(&path)?;
            let id = schema
                .get("$id")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("schema has no string $id: {}", path.display()))?;
            schemas.insert(id.to_owned(), schema);
        }
        Ok(Self { schemas })
    }
}

impl jsonschema::Retrieve for LocalSchemaRetriever {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        self.schemas
            .get(uri.as_str())
            .cloned()
            .ok_or_else(|| format!("local schema not found: {uri}").into())
    }
}

fn source_snapshot(root: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    let output = Command::new("node")
        .args(["tools/evidence-index.mjs", "source"])
        .current_dir(root)
        .output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn collect_json(directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), std::io::Error> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_json(&path, files)?;
        } else if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            files.push(path);
        }
    }
    Ok(())
}
