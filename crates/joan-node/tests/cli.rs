//! End-to-end CLI tests.

use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn self_check_reports_founder_and_passes() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_joan"))
        .args(["node", "self-check"])
        .output()?;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("Joan Alberto Barrios Cruz"));
    assert!(stdout.contains("LED ACTION LLC"));
    assert!(stdout.contains("instruction-non-minting"));
    Ok(())
}

#[test]
fn dispute_simulation_is_available_to_agents() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_joan"))
        .args([
            "dispute", "simulate", "--cases", "24", "--seed", "144", "--json",
        ])
        .output()?;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains(r#""cases_completed":24"#));
    assert!(stdout.contains(r#""final_incorrect":0"#));
    assert!(stdout.contains(r#""ledger_invariant_failures":0"#));
    Ok(())
}

#[test]
fn repo_inspection_is_byte_preserving() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    fs::write(
        directory.path().join("Cargo.toml"),
        "[package]\nname='fixture'\n",
    )?;
    fs::write(directory.path().join("AGENTS.md"), "Do not write files.\n")?;
    let before_manifest = fs::read(directory.path().join("Cargo.toml"))?;
    let before_agents = fs::read(directory.path().join("AGENTS.md"))?;
    let output = Command::new(env!("CARGO_BIN_EXE_joan"))
        .arg("repo")
        .arg("inspect")
        .arg(directory.path())
        .arg("--json")
        .output()?;
    assert!(output.status.success());
    assert_eq!(
        before_manifest,
        fs::read(directory.path().join("Cargo.toml"))?
    );
    assert_eq!(before_agents, fs::read(directory.path().join("AGENTS.md"))?);
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("read-only-offline"));
    assert!(stdout.contains("Cargo.toml"));
    Ok(())
}

#[test]
fn duplicate_json_keys_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let input = directory.path().join("duplicate.json");
    fs::write(&input, r#"{"a":1,"a":2}"#)?;
    let output = Command::new(env!("CARGO_BIN_EXE_joan"))
        .arg("canonicalize")
        .arg(input)
        .output()?;
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("duplicate"));
    Ok(())
}

#[test]
fn jce1_conformance_is_available_to_agents() -> Result<(), Box<dyn std::error::Error>> {
    let suite = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/jce1/conformance-v1.json");
    let output = Command::new(env!("CARGO_BIN_EXE_joan"))
        .arg("conformance")
        .arg("jce1")
        .arg(suite)
        .arg("--json")
        .output()?;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains(r#""total":27"#));
    assert!(stdout.contains(r#""passed":27"#));
    assert!(stdout.contains(r#""failed":0"#));
    Ok(())
}

#[test]
fn digest_benchmark_reports_bounded_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_joan"))
        .args([
            "benchmark",
            "digest-v1",
            "--bytes",
            "64",
            "--iterations",
            "10",
            "--json",
        ])
        .output()?;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains(r#""schema":"joan.digest-benchmark.v1""#));
    assert!(
        stdout
            .contains(r#""claim_scope":"implementation-microbenchmark-not-language-superiority""#)
    );
    Ok(())
}

#[test]
fn language_commands_are_available_to_agents() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let program = directory.path().join("agent.joan");
    fs::write(
        &program,
        "module agent;\nfn main()->i64 effects[]{return 40+2;}\n",
    )?;

    let check = Command::new(env!("CARGO_BIN_EXE_joan"))
        .arg("check")
        .arg(&program)
        .arg("--json")
        .output()?;
    assert!(check.status.success());
    assert!(String::from_utf8(check.stdout)?.contains(r#""status":"accepted""#));

    let run = Command::new(env!("CARGO_BIN_EXE_joan"))
        .arg("run")
        .arg(&program)
        .arg("--json")
        .output()?;
    assert!(run.status.success());
    let stdout = String::from_utf8(run.stdout)?;
    assert!(stdout.contains(r#""status":"completed""#));
    assert!(stdout.contains(r#""type":"i64","value":42"#));
    Ok(())
}

#[test]
fn language_diagnostics_are_machine_readable() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let program = directory.path().join("invalid.joan");
    fs::write(
        &program,
        "module invalid;\nfn main() -> i64 effects [] { return true; }\n",
    )?;
    let output = Command::new(env!("CARGO_BIN_EXE_joan"))
        .arg("check")
        .arg(&program)
        .arg("--json")
        .output()?;
    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains(r#""schema":"joan.diagnostic-report.v0""#));
    assert!(stdout.contains(r#""code":"J2035""#));
    Ok(())
}
