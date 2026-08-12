//! Frozen-suite execution and negative-control tests.

use joan_conformance::run_jce1_suite;
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn frozen_suite_passes_all_vectors() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = fs::read(suite_path())?;
    let report = run_jce1_suite(&bytes, "rust-test")?;
    assert_eq!(report.total, 27);
    assert_eq!(report.passed, 27);
    assert_eq!(report.failed, 0);
    Ok(())
}

#[test]
fn wrong_expected_digest_is_visible_in_report() -> Result<(), Box<dyn std::error::Error>> {
    let suite = fs::read_to_string(suite_path())?;
    let mutated = suite.replace(
        "d03ac76923137a6ca6fcaa7c0f8bbe540d924df9738b0452943025266d93e51c",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let report = run_jce1_suite(mutated.as_bytes(), "rust-negative-control")?;
    assert_eq!(report.total, 27);
    assert_eq!(report.passed, 26);
    assert_eq!(report.failed, 1);
    assert_eq!(report.results[19].id, "H002");
    assert_eq!(report.results[19].status, "failed");
    Ok(())
}

#[test]
fn wrong_specification_hash_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let suite = fs::read_to_string(suite_path())?;
    let marker = "\"spec_freeze_sha256\": \"";
    let start = suite.find(marker).ok_or("missing specification hash")? + marker.len();
    let mut mutated = suite;
    mutated.replace_range(start..start + 64, &"0".repeat(64));
    let Err(error) = run_jce1_suite(mutated.as_bytes(), "rust-negative-control") else {
        return Err("wrong specification hash was accepted".into());
    };
    assert!(error.to_string().contains("does not match"));
    Ok(())
}

fn suite_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/jce1/conformance-v1.json")
}
