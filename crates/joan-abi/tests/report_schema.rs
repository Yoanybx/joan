//! Strict validation for a generated L15 native ABI receipt.

use serde_json::Value;
use std::{env, fs, path::PathBuf};

#[test]
fn generated_native_abi_report_matches_strict_schema() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(report_path) = env::var("JOAN_NATIVE_ABI_REPORT_INPUT") else {
        return Ok(());
    };
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let schema: Value = serde_json::from_slice(&fs::read(
        root.join("schemas/native-abi-report.v1.schema.json"),
    )?)?;
    let report: Value = serde_json::from_slice(&fs::read(report_path)?)?;
    let validator = jsonschema::draft202012::options().build(&schema)?;
    if let Err(error) = validator.validate(&report) {
        return Err(format!("native ABI report schema validation failed: {error}").into());
    }
    Ok(())
}
