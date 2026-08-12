//! JOAN local verification command-line interface.

use joan_canonical::{
    CanonicalValue, RegisteredDomainV1, canonical_set_v1, canonicalize_str, canonicalize_str_v1,
    digest_bytes, digest_bytes_v1, from_serializable, parse_strict, parse_strict_v1,
    to_canonical_bytes, to_canonical_bytes_v1,
};
use joan_compiler::{LanguageError, check_source, compile_source, execute_source};
use joan_conformance::{benchmark_digest_v1, run_jce1_suite};
use joan_dispute::DisputeEvaluationBundle;
use joan_guardian::GuardianCandidate;
use joan_identity::{SemanticIdentityBundle, verify_bundle};
use joan_instruction::AuthorityEnvelope;
use joan_node::{
    AdoptionTrialReceipt, InstructionAuditTask, audit_instructions, evaluate_adoption,
    inspect_repository, node_self_check,
};
use joan_package::resolve_package;
use joan_patch::{GraphBundle, SemanticPatch, apply_patch};
use joan_sim::SimulationConfig;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

fn main() {
    if let Err(error) = run() {
        let _ = writeln!(io::stderr(), "joan: {error}");
        std::process::exit(2);
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the flat CLI dispatcher keeps command authority visible at one boundary"
)]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [command, input] if command == "check" => {
            let source = read_text(input)?;
            write_json(&language_result(check_source(&source))?)?;
        }
        [command, input, flag] if command == "check" && flag == "--json" => {
            let source = read_text(input)?;
            write_json(&language_result(check_source(&source))?)?;
        }
        [command, input] if command == "fmt" => {
            let source = read_text(input)?;
            io::stdout().write_all(format_result(&source)?.as_bytes())?;
        }
        [command, input, flag] if command == "fmt" && flag == "--check" => {
            let source = read_text(input)?;
            let formatted = format_result(&source)?;
            if source != formatted {
                return Err("source is not canonically formatted".into());
            }
        }
        [command, input, flag] if command == "compile" && flag == "--json" => {
            let source = read_text(input)?;
            write_json(&language_result(compile_source(&source))?)?;
        }
        [command, input, flag] if command == "run" && flag == "--json" => {
            let source = read_text(input)?;
            write_json(&language_result(execute_source(&source))?)?;
        }
        [command, input] if command == "canonicalize" => {
            let text = read_text(input)?;
            io::stdout().write_all(&canonicalize_str(&text)?)?;
            io::stdout().write_all(b"\n")?;
        }
        [command, input] if command == "canonicalize-v1" => {
            let text = read_text(input)?;
            io::stdout().write_all(&canonicalize_str_v1(&text)?)?;
            io::stdout().write_all(b"\n")?;
        }
        [command, input] if command == "canonical-set-v1" => {
            let text = read_text(input)?;
            let CanonicalValue::Array(values) = parse_strict_v1(&text)? else {
                return Err("canonical-set-v1 input must be a JSON array".into());
            };
            let set = canonical_set_v1(values)?;
            io::stdout().write_all(&to_canonical_bytes_v1(&set)?)?;
            io::stdout().write_all(b"\n")?;
        }
        [command, domain, input] if command == "digest" => {
            let bytes = read_bytes(input)?;
            write_json(&digest_bytes(domain, &bytes)?)?;
        }
        [command, domain, input] if command == "digest-v1" => {
            let bytes = read_bytes(input)?;
            let domain = RegisteredDomainV1::parse(domain)?;
            write_json(&digest_bytes_v1(domain, &bytes)?)?;
        }
        [group, profile, suite, flag]
            if group == "conformance" && profile == "jce1" && flag == "--json" =>
        {
            verify_jce1_suite(suite)?;
        }
        [group, operation, rest @ ..] if group == "benchmark" && operation == "digest-v1" => {
            if !rest.iter().any(|argument| argument == "--json") {
                return Err("benchmark digest-v1 requires --json".into());
            }
            let payload_bytes = option_text(rest, "--bytes")?.parse::<usize>()?;
            let iterations = option_text(rest, "--iterations")?.parse::<u64>()?;
            write_json(&benchmark_digest_v1(payload_bytes, iterations)?)?;
        }
        [group, command, bundle] if group == "identity" && command == "verify" => {
            let bundle: SemanticIdentityBundle = read_json(bundle)?;
            verify_bundle(&bundle)?;
            write_json(&serde_json::json!({
                "schema": "joan.command-result.v0",
                "command": "identity.verify",
                "status": "verified",
                "program_root": bundle.program_root,
            }))?;
        }
        [group, command, base, patch] if group == "patch" && command == "verify" => {
            let base: GraphBundle = read_json(base)?;
            let patch: SemanticPatch = read_json(patch)?;
            let (_, receipt) = apply_patch(&base, &patch)?;
            write_json(&receipt)?;
        }
        [group, command, manifest, rest @ ..] if group == "package" && command == "resolve" => {
            if !rest.iter().any(|argument| argument == "--json") {
                return Err("package resolve requires --json".into());
            }
            let store = option_value(rest, "--store")?;
            let manifest_bytes = read_bounded_bytes(manifest, 1_048_577)?;
            write_json(&resolve_package(&manifest_bytes, store)?)?;
        }
        [group, command, candidate] if group == "guardian" && command == "evaluate" => {
            let candidate: GuardianCandidate = read_json(candidate)?;
            write_json(&joan_guardian::evaluate_candidate(&candidate)?)?;
        }
        [group, command] if group == "node" && command == "self-check" => {
            write_json(&node_self_check()?)?;
        }
        [group, command, path, flag]
            if group == "repo" && command == "inspect" && flag == "--json" =>
        {
            write_json(&inspect_repository(Path::new(path))?)?;
        }
        [group, command, trial, flag]
            if group == "adoption" && command == "evaluate" && flag == "--json" =>
        {
            let trial: AdoptionTrialReceipt = read_json(trial)?;
            write_json(&evaluate_adoption(&trial)?)?;
        }
        [group, command, bundle, flag]
            if group == "dispute" && command == "evaluate" && flag == "--json" =>
        {
            let bundle: DisputeEvaluationBundle = read_json(bundle)?;
            write_json(&joan_dispute::evaluate_bundle(&bundle)?)?;
        }
        [group, command, rest @ ..] if group == "dispute" && command == "simulate" => {
            if !rest.iter().any(|argument| argument == "--json") {
                return Err("dispute simulate requires --json".into());
            }
            let cases = option_text(rest, "--cases")?.parse::<u64>()?;
            let seed = option_text(rest, "--seed")?.parse::<u64>()?;
            write_json(&joan_sim::run_simulation(&SimulationConfig {
                schema: "joan.dispute-simulation-config.v0".to_owned(),
                seed,
                cases,
            })?)?;
        }
        [group, command, repository, rest @ ..]
            if group == "instructions" && command == "audit" =>
        {
            let authority_path = option_value(rest, "--authority-envelope")?;
            let task_path = option_value(rest, "--task")?;
            if !rest.iter().any(|argument| argument == "--json") {
                return Err("instructions audit requires --json".into());
            }
            let authority: AuthorityEnvelope = read_json(authority_path)?;
            let task: InstructionAuditTask = read_json(task_path)?;
            write_json(&audit_instructions(Path::new(repository), authority, task)?)?;
        }
        _ => return Err(usage().into()),
    }
    Ok(())
}

fn verify_jce1_suite(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = read_bytes(path)?;
    let report = run_jce1_suite(&bytes, "rust-joan-canonical")?;
    write_json(&report)?;
    if report.failed > 0 {
        return Err(format!("{} JCE1 conformance vectors failed", report.failed).into());
    }
    Ok(())
}

fn usage() -> &'static str {
    "usage:\n  joan check <program.joan> [--json]\n  joan fmt <program.joan> [--check]\n  joan compile <program.joan> --json\n  joan run <program.joan> --json\n  joan canonicalize <file|->\n  joan canonicalize-v1 <file|->\n  joan canonical-set-v1 <array-file|->\n  joan digest <domain> <file|->\n  joan digest-v1 <registered-domain> <file|->\n  joan conformance jce1 <suite.json> --json\n  joan benchmark digest-v1 --bytes <count> --iterations <count> --json\n  joan identity verify <bundle.json>\n  joan patch verify <graph.json> <patch.json>\n  joan package resolve <manifest.json> --store <dir> --json\n  joan guardian evaluate <candidate.json>\n  joan node self-check\n  joan repo inspect <path> --json\n  joan adoption evaluate <trial.json> --json\n  joan dispute evaluate <bundle.json> --json\n  joan dispute simulate --cases <count> --seed <seed> --json\n  joan instructions audit <repo> --authority-envelope <file> --task <file> --json"
}

fn language_result<T>(result: Result<T, LanguageError>) -> Result<T, Box<dyn std::error::Error>> {
    match result {
        Ok(value) => Ok(value),
        Err(LanguageError::Diagnostics(report)) => {
            write_json(&report)?;
            Err("JOAN source rejected; diagnostic report written to stdout".into())
        }
        Err(error) => Err(error.into()),
    }
}

fn format_result(source: &str) -> Result<String, Box<dyn std::error::Error>> {
    match joan_syntax::format_source(source) {
        Ok(formatted) => Ok(formatted),
        Err(report) => {
            write_json(&report)?;
            Err("JOAN source rejected; diagnostic report written to stdout".into())
        }
    }
}

fn read_text(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = read_bytes(path)?;
    String::from_utf8(bytes).map_err(Into::into)
}

fn read_bytes(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if path == "-" {
        let mut bytes = Vec::new();
        io::stdin().read_to_end(&mut bytes)?;
        Ok(bytes)
    } else {
        Ok(fs::read(path)?)
    }
}

fn read_bounded_bytes(path: &str, max_bytes: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = if path == "-" {
        let limit = u64::try_from(max_bytes)?.saturating_add(1);
        let mut bytes = Vec::new();
        io::stdin().take(limit).read_to_end(&mut bytes)?;
        bytes
    } else {
        let metadata = fs::metadata(path)?;
        if metadata.len() > u64::try_from(max_bytes)? {
            return Err(format!("input exceeds {max_bytes} byte limit").into());
        }
        fs::read(path)?
    };
    if bytes.len() > max_bytes {
        return Err(format!("input exceeds {max_bytes} byte limit").into());
    }
    Ok(bytes)
}

fn read_json<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<T, Box<dyn std::error::Error>> {
    let text = fs::read_to_string(path)?;
    let canonical = parse_strict(&text)?;
    Ok(serde_json::from_value(canonical.to_serde_value())?)
}

fn write_json<T: Serialize>(value: &T) -> Result<(), Box<dyn std::error::Error>> {
    let canonical = from_serializable(value)?;
    io::stdout().write_all(&to_canonical_bytes(&canonical)?)?;
    io::stdout().write_all(b"\n")?;
    Ok(())
}

fn option_value<'a>(
    arguments: &'a [String],
    name: &str,
) -> Result<&'a Path, Box<dyn std::error::Error>> {
    let index = arguments
        .iter()
        .position(|argument| argument == name)
        .ok_or_else(|| format!("missing required option {name}"))?;
    let value = arguments
        .get(index + 1)
        .ok_or_else(|| format!("missing value for option {name}"))?;
    Ok(Path::new(value))
}

fn option_text<'a>(
    arguments: &'a [String],
    name: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    let index = arguments
        .iter()
        .position(|argument| argument == name)
        .ok_or_else(|| format!("missing required option {name}"))?;
    arguments
        .get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| format!("missing value for option {name}").into())
}
