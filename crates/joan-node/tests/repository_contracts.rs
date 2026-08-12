//! Repository-level machine contract and founder-attribution tests.

use joan_canonical::parse_strict;
use serde_json::Value;
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
    collect_json(&root.join("vectors/payment-cost"), &mut files)?;
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
fn joan_manifests_match_their_schemas() -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root();
    for (instance_path, schema_path) in manifest_schema_pairs() {
        let instance = read_json(&root.join(instance_path))?;
        let schema = read_json(&root.join(schema_path))?;
        let validator = jsonschema::draft202012::options()
            .should_validate_formats(true)
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
    for (instance_path, schema_path) in manifest_schema_pairs() {
        let mut instance = read_json(&root.join(instance_path))?;
        instance
            .as_object_mut()
            .ok_or_else(|| format!("manifest is not an object: {instance_path}"))?
            .insert("unexpected_field".to_owned(), Value::Bool(true));
        let schema = read_json(&root.join(schema_path))?;
        let validator = jsonschema::draft202012::options().build(&schema)?;
        assert!(
            !validator.is_valid(&instance),
            "unknown field accepted by {schema_path}"
        );
    }
    Ok(())
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

fn manifest_schema_pairs() -> [(&'static str, &'static str); 9] {
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
            "tools/verification-gates.v1.json",
            "schemas/verification-gates.v1.schema.json",
        ),
    ]
}

fn read_json(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
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
