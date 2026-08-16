//! Repository-level machine contract and founder-attribution tests.

use joan_canonical::parse_strict;
use joan_canonical::{RegisteredDomainV1, digest_bytes_v1};
use joan_compiler::{canonicalize_source_ast, compile_source};
use joan_guardian::{GuardianCandidate, GuardianRole, GuardianVote, VoteDecision};
use joan_host::{
    HostExecutionReason, HostExecutionReceipt, HostExecutionStatus, HostOperation,
    completed_run_response, decode_request_frame, encode_request_frame,
};
use joan_native::compile_bytecode;
use joan_package::{
    PACKAGE_MANIFEST_SCHEMA, PackageCoordinate, PackageManifest, PackageModule, encode_manifest,
    resolve_package,
};
use joan_tool_forge::{
    ToolOperation, ToolSpec, ToolTestCase, Value as ToolValue, evaluate_promotion, finalize_tool,
    forge_tool, verify_spec, verify_tool,
};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
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
        "NOTICE",
        "ORIGIN.md",
        "OWNERSHIP.md",
        "GOVERNANCE.md",
        "LEGAL-ASSET-INVENTORY.md",
        "RELEASE-CUSTODY.md",
        "TRADEMARKS.md",
        ".joan/origin.json",
        ".joan/project.json",
        ".joan/publication-readiness.json",
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
fn public_license_and_cargo_metadata_are_apache_2() -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root();
    let license = fs::read(root.join("LICENSE"))?;
    let license_digest = digest_bytes_v1(RegisteredDomainV1::Source, &license)?;
    assert_eq!(
        license_digest.value, "e60a3f171a2b358717290ac050e1549365c26c9822d76317991d4ebd31d39432",
        "canonical Apache-2.0 license text drifted"
    );

    let root_manifest = fs::read_to_string(root.join("Cargo.toml"))?;
    assert!(root_manifest.contains("license = \"Apache-2.0\""));
    assert!(!root_manifest.contains("license-file ="));

    for entry in fs::read_dir(root.join("crates"))? {
        let manifest = entry?.path().join("Cargo.toml");
        if manifest.is_file() {
            let content = fs::read_to_string(&manifest)?;
            assert!(
                content.contains("license.workspace = true"),
                "crate license metadata drifted in {}",
                manifest.display()
            );
            assert!(!content.contains("license-file.workspace"));
        }
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
    collect_json(&root.join("vectors/tool-forge-v0"), &mut files)?;
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
fn tool_forge_artifacts_match_their_schemas() -> Result<(), Box<dyn std::error::Error>> {
    let spec = ToolSpec {
        schema: "joan.tool-spec.v0".to_owned(),
        name: "add_cost".to_owned(),
        tenant: "agent_alpha".to_owned(),
        purpose: "costing".to_owned(),
        instruction_budget: 64,
        operation: ToolOperation::AddI64,
        tests: vec![ToolTestCase {
            name: "answer".to_owned(),
            arguments: vec![ToolValue::I64(20), ToolValue::I64(22)],
            expected: ToolValue::I64(42),
        }],
    };
    let spec_receipt = verify_spec(&spec)?;
    let bundle = forge_tool(&spec)?;
    let verification = verify_tool(&spec, &bundle)?;
    let evidence = vec![bundle.source_digest.clone(), bundle.bytecode_digest.clone()];
    let vote = |guardian_id: &str, role: GuardianRole| GuardianVote {
        guardian_id: guardian_id.to_owned(),
        role,
        candidate_root: bundle.bundle_digest.clone(),
        decision: VoteDecision::Approve,
        evidence: evidence.clone(),
    };
    let candidate = GuardianCandidate {
        schema: "joan.guardian-candidate.v0".to_owned(),
        candidate_root: bundle.bundle_digest.clone(),
        proposer_id: "tool-generator".to_owned(),
        required_roles: BTreeSet::from([
            GuardianRole::SemanticVerifier,
            GuardianRole::TestGuardian,
            GuardianRole::PolicyGatekeeper,
        ]),
        approval_threshold: 3,
        votes: vec![
            vote("semantic-verifier", GuardianRole::SemanticVerifier),
            vote("test-verifier", GuardianRole::TestGuardian),
            vote("policy-verifier", GuardianRole::PolicyGatekeeper),
        ],
    };
    let finalization = finalize_tool(&spec, &bundle, &verification, &candidate)?;
    let promotion = evaluate_promotion(&spec, &bundle, &verification, &candidate, &finalization)?;
    for (instance, schema) in [
        (
            serde_json::to_value(&spec)?,
            "schemas/tool-spec.v0.schema.json",
        ),
        (
            serde_json::to_value(&spec_receipt)?,
            "schemas/tool-spec-verification-receipt.v0.schema.json",
        ),
        (
            serde_json::to_value(&bundle)?,
            "schemas/tool-bundle.v0.schema.json",
        ),
        (
            serde_json::to_value(&verification)?,
            "schemas/tool-verification-receipt.v0.schema.json",
        ),
        (
            serde_json::to_value(&finalization)?,
            "schemas/tool-finalization-receipt.v0.schema.json",
        ),
        (
            serde_json::to_value(&promotion)?,
            "schemas/tool-promotion-decision.v0.schema.json",
        ),
    ] {
        validate_instance(&instance, schema)?;
    }

    let mut contradictory_spec_receipt = serde_json::to_value(&spec_receipt)?;
    contradictory_spec_receipt["findings"] = serde_json::json!([{
        "code": "TF0001",
        "message": "verified receipts cannot contain findings"
    }]);
    assert_invalid_instance(
        &contradictory_spec_receipt,
        "schemas/tool-spec-verification-receipt.v0.schema.json",
    )?;

    let mut wrong_domain = serde_json::to_value(&verification)?;
    wrong_domain["receipt_digest"]["domain"] = Value::String("joan.tool-spec.v1".to_owned());
    assert_invalid_instance(
        &wrong_domain,
        "schemas/tool-verification-receipt.v0.schema.json",
    )?;

    let mut fabricated_finalization = serde_json::to_value(&finalization)?;
    fabricated_finalization["guardian"] = Value::Null;
    assert_invalid_instance(
        &fabricated_finalization,
        "schemas/tool-finalization-receipt.v0.schema.json",
    )?;

    let mut contradictory_promotion = serde_json::to_value(&promotion)?;
    contradictory_promotion["reasons"] = serde_json::json!(["unexpected"]);
    assert_invalid_instance(
        &contradictory_promotion,
        "schemas/tool-promotion-decision.v0.schema.json",
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
fn host_protocol_receipts_match_their_schemas() -> Result<(), Box<dyn std::error::Error>> {
    let artifact = compile_source(
        r"module host_contract;
fn multiply(left: i64, right: i64) -> i64 effects [] {
  return left * right;
}
fn main() -> i64 effects [] {
  return 0;
}
",
    )?;
    let operation = HostOperation::Run {
        function: "multiply".to_owned(),
        arguments: vec![joan_bytecode::Value::I64(6), joan_bytecode::Value::I64(7)],
        instruction_budget: 100,
    };
    let (_, frame) = encode_request_frame(&artifact.bytecode, operation)?;
    let request = decode_request_frame(&frame)?.control;
    validate_instance(
        &serde_json::to_value(&request)?,
        "schemas/host-execution-request.v1.schema.json",
    )?;

    let native = compile_bytecode(&artifact.bytecode)?;
    let execution = native.invoke(
        "multiply",
        &[joan_bytecode::Value::I64(6), joan_bytecode::Value::I64(7)],
        100,
    )?;
    let response = completed_run_response(&request, native.receipt().clone(), execution)?;
    validate_instance(
        &serde_json::to_value(&response)?,
        "schemas/host-executor-response.v1.schema.json",
    )?;

    let receipt = HostExecutionReceipt {
        schema: "joan.host-execution-receipt.v1".to_owned(),
        status: HostExecutionStatus::Completed,
        reason: HostExecutionReason::ExecutorCompleted,
        limits: request.limits,
        request_digest: request.request_digest,
        semantic_digest: request.semantic_digest,
        bytecode_digest: request.bytecode_digest,
        child_exit_code: Some(0),
        child_unix_signal: None,
        executor_response_digest: Some(response.response_digest),
        compile_receipt: response.compile_receipt,
        execution_receipt: response.execution_receipt,
        detail: None,
        receipt_digest: digest_bytes_v1(
            RegisteredDomainV1::HostExecutionReceiptV2,
            b"schema-fixture",
        )?,
    };
    let receipt_value = serde_json::to_value(&receipt)?;
    validate_instance(
        &receipt_value,
        "schemas/host-execution-receipt.v1.schema.json",
    )?;

    let mut contradictory_exit = receipt_value.clone();
    contradictory_exit["child_unix_signal"] = Value::from(9);
    assert_invalid_instance(
        &contradictory_exit,
        "schemas/host-execution-receipt.v1.schema.json",
    )?;

    let mut contradictory_memory = receipt_value.clone();
    contradictory_memory["limits"]["memory_limit_kind"] = Value::String("unavailable".to_owned());
    contradictory_memory["limits"]["memory_limit_bytes"] = Value::from(1);
    assert_invalid_instance(
        &contradictory_memory,
        "schemas/host-execution-receipt.v1.schema.json",
    )?;

    let mut contradictory = receipt_value;
    contradictory["status"] = Value::String("unknown".to_owned());
    contradictory["reason"] = Value::String("timeout".to_owned());
    assert_invalid_instance(
        &contradictory,
        "schemas/host-execution-receipt.v1.schema.json",
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
fn publication_workflow_remains_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root();
    let readiness = read_json(&root.join(".joan/publication-readiness.json"))?;
    assert_eq!(readiness["status"], "blocked");
    assert_eq!(readiness["publication_effect"], "not-executed");
    assert_eq!(readiness["official_repository"]["configured"], true);
    assert_eq!(readiness["official_repository"]["owner"], "Yoanybx");
    assert_eq!(readiness["official_repository"]["name"], "joan");
    assert_eq!(readiness["legal"]["license_decision_approved"], true);
    assert_eq!(
        readiness["legal"]["license_profile"],
        "apache-2.0-open-core"
    );
    assert_eq!(readiness["release"]["public_release_approved"], false);
    assert_eq!(readiness["release"]["codeowners_configured"], true);
    assert!(root.join(".github/CODEOWNERS").is_file());

    for path in [
        "LEGAL-ASSET-INVENTORY.md",
        "RELEASE-CUSTODY.md",
        "TRADEMARKS.md",
        "scripts/verify-publication-readiness.sh",
        "scripts/verify-release-installation.sh",
        "tools/publication-readiness.mjs",
        "tools/publication-readiness.test.mjs",
    ] {
        assert!(
            root.join(path).is_file(),
            "publication control is absent: {path}"
        );
    }

    let workflow = fs::read_to_string(root.join(".github/workflows/release.yml"))?;
    for contract in [
        "authorize:",
        "needs: authorize",
        "environment: release",
        "JOAN_RELEASE_APPROVAL_ID",
        "JOAN_RELEASE_APPROVED_COMMIT",
        "JOAN_RELEASE_APPROVED_TAG",
        "./scripts/verify-publication-readiness.sh release",
    ] {
        assert!(
            workflow.contains(contract),
            "release authorization contract is absent: {contract}"
        );
    }

    let contributing = fs::read_to_string(root.join("CONTRIBUTING.md"))?;
    assert!(contributing.contains("not accepting external code contributions"));
    assert!(contributing.contains("this file is not that agreement"));

    let packager = fs::read_to_string(root.join("scripts/package-release.sh"))?;
    for contract in [
        "cp \"$executor_binary\" \"$stage/joan-executor\"",
        "find \"$stage\" -exec touch -h -t 200001010000.00",
        "find \"$package\" -print | LC_ALL=C sort",
        "--format ustar --no-recursion",
        "gzip -n -9 -c",
    ] {
        assert!(
            packager.contains(contract),
            "reproducible release-package contract is absent: {contract}"
        );
    }
    let installer = fs::read_to_string(root.join("scripts/install-release.sh"))?;
    for contract in [
        "candidate_executor=",
        "executor_destination=",
        "\"$executor_destination\" --self-check",
        "install_started=1",
        "install_committed=1",
        "installation did not commit; previous binary set restored.",
    ] {
        assert!(
            installer.contains(contract),
            "two-binary installation contract is absent: {contract}"
        );
    }
    Ok(())
}

#[test]
fn cross_host_evidence_mode_is_explicit_and_strict_by_default()
-> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root();
    let verifier = fs::read_to_string(root.join("scripts/verify-all.sh"))?;
    for contract in [
        "evidence_mode=\"strict\"",
        "--portable-evidence",
        "check-portable \"$receipt\"",
        "node tools/evidence-index.mjs check",
        "node tools/evidence-index.mjs check-current \"$receipt\"",
    ] {
        assert!(
            verifier.contains(contract),
            "verification evidence-mode contract is absent: {contract}"
        );
    }
    assert!(!verifier.contains("JOAN_EVIDENCE_MODE"));

    for path in [
        ".github/workflows/guardian.yml",
        ".github/workflows/release.yml",
        "scripts/run-independent-rerun.sh",
    ] {
        let consumer = fs::read_to_string(root.join(path))?;
        assert!(
            consumer.contains("verify-all.sh --portable-evidence"),
            "cross-host consumer does not select portable evidence explicitly: {path}"
        );
    }

    let guardian = fs::read_to_string(root.join(".github/workflows/guardian.yml"))?;
    for contract in [
        "persist-credentials: false",
        "fetch-depth: 0",
        "julia-actions/setup-julia@4c0cb0fce8556fdb04a90347310e5db8b1f98fb9",
        "version: \"1.12.7\"",
        "test \"$(julia --startup-file=no -e 'print(VERSION)')\" = '1.12.7'",
        "JOAN_NATIVE_BENCHMARK_REQUIRE_JULIA: \"1\"",
        "cargo install --locked ripgrep@15.1.0",
        "test \"$(rg --version | sed -n '1p')\" = 'ripgrep 15.1.0'",
    ] {
        assert!(
            guardian.contains(contract),
            "guardian cross-host prerequisite is absent: {contract}"
        );
    }
    assert!(!guardian.contains("apt-get"));

    for path in [
        "scripts/test-differential-reference-preflight.sh",
        "scripts/verify-differential-language.sh",
    ] {
        let differential = fs::read_to_string(root.join(path))?;
        assert!(differential.contains("JOAN_DIFFERENTIAL_TMPDIR:-${TMPDIR:-/tmp}"));
        assert!(!differential.contains("/Volumes/ParallesWin 1"));
    }

    let refresh = fs::read_to_string(root.join("scripts/refresh-evidence.sh"))?;
    assert!(refresh.contains("node tools/evidence-index.mjs check"));
    assert!(refresh.contains("native_report='.joan/evidence/native-abi-v1.json'"));
    assert!(refresh.contains(
        "JOAN_NATIVE_ABI_REPORT=\"$temporary_native_report\" ./scripts/verify-native-abi.sh"
    ));
    assert!(refresh.contains("cp \"$backup_directory/native-abi-v1.json\" \"$native_report\""));
    assert!(refresh.contains("mv \"$staged_native_report\" \"$native_report\""));
    assert!(!refresh.contains("check-portable"));
    Ok(())
}

#[test]
fn hosted_julia_benchmark_is_required_and_locally_scoped() -> Result<(), Box<dyn std::error::Error>>
{
    let root = workspace_root();
    let benchmark_runner = fs::read_to_string(root.join("tools/native-backend-benchmark.mjs"))?;
    for contract in [
        "requiredByEnvironment(process.env, \"JOAN_NATIVE_BENCHMARK_REQUIRE_JULIA\")",
        "requireAvailableTool(requireJulia, tools.julia, \"Julia\")",
        "missing_required_tool_rejected: true",
    ] {
        assert!(
            benchmark_runner.contains(contract),
            "native benchmark required-tool contract is absent: {contract}"
        );
    }

    let julia_kernel = fs::read_to_string(root.join("benchmarks/native-backend/julia/kernels.jl"))?;
    for contract in [
        "const MAX_ITERATIONS = UInt64(10_000_000)",
        "function main(args::Vector{String})::Int",
        "UInt64(1) <= iterations <= MAX_ITERATIONS",
        "exit(main(ARGS))",
    ] {
        assert!(
            julia_kernel.contains(contract),
            "Julia hosted benchmark contract is absent: {contract}"
        );
    }
    for global_binding in [
        "workload_name",
        "workload",
        "iterations",
        "seed",
        "state",
        "checksum",
        "instructions",
        "started",
        "runtime_ns",
    ] {
        assert!(
            !julia_kernel
                .lines()
                .any(|line| line.starts_with(global_binding)),
            "Julia benchmark mutable state escaped main: {global_binding}"
        );
    }
    Ok(())
}

#[test]
fn duplicate_dependency_exceptions_are_exact() -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root();
    let policy = fs::read_to_string(root.join("deny.toml"))?;
    assert!(policy.contains("multiple-versions = \"deny\""));
    assert!(policy.contains("crate = \"bitflags@1.3.2\""));
    assert!(policy.contains("legacy bitflags branch while rustix uses v2"));
    assert!(policy.contains("crate = \"hashbrown@0.16.1\""));
    assert!(policy.contains("gimli 0.33.0 in pinned Cranelift 0.134.3"));
    assert!(policy.contains("crate = \"windows-sys@0.52.0\""));
    assert!(policy.contains("region 3.0.2 in pinned cranelift-jit 0.134.3"));
    assert_eq!(
        policy
            .lines()
            .filter(|line| line.trim_start().starts_with("{ crate ="))
            .count(),
        3,
        "dependency policy must contain exactly three duplicate exceptions"
    );
    assert!(root.join("scripts/verify-dependency-policy.sh").is_file());
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
fn independent_rerun_receipt_matches_its_schema_when_supplied()
-> Result<(), Box<dyn std::error::Error>> {
    let Ok(path) = std::env::var("JOAN_INDEPENDENT_RERUN_RECEIPT_INPUT") else {
        return Ok(());
    };
    validate_instance(
        &read_json(Path::new(&path))?,
        "schemas/independent-rerun-receipt.v0.schema.json",
    )
}

#[test]
fn sbom_artifacts_match_their_schemas_when_supplied() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(directory) = std::env::var("JOAN_SBOM_ARTIFACT_DIRECTORY") else {
        return Ok(());
    };
    let directory = Path::new(&directory);
    validate_instance(
        &read_json(&directory.join("receipt.json"))?,
        "schemas/sbom-evidence.v0.schema.json",
    )?;
    validate_instance(
        &read_json(&directory.join("workspace-index.json"))?,
        "schemas/sbom-workspace-index.v0.schema.json",
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
fn eleven_gate_receipt_requires_gate_config_digest() -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root();
    let schema = read_json(&root.join("schemas/verification-run-receipt.v1.schema.json"))?;
    let validator = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)?;
    let current_receipt = current_receipt_schema_fixture(&root)?;
    if let Err(error) = validator.validate(&current_receipt) {
        return Err(format!("current 11-gate receipt was rejected: {error}").into());
    }

    let mut receipt = current_receipt.clone();
    receipt["environment"]
        .as_object_mut()
        .ok_or("receipt environment is not an object")?
        .remove("gate_config_sha256");
    assert!(
        !validator.is_valid(&receipt),
        "11-gate receipt without gate-config digest was accepted"
    );

    let mut missing_gate = current_receipt.clone();
    missing_gate["gates"]
        .as_array_mut()
        .ok_or("receipt gates are not an array")?
        .pop();
    assert!(
        !validator.is_valid(&missing_gate),
        "11/11 summary with only 10 gate results was accepted"
    );

    let mut reordered = current_receipt.clone();
    reordered["gates"]
        .as_array_mut()
        .ok_or("receipt gates are not an array")?
        .swap(0, 1);
    assert!(
        !validator.is_valid(&reordered),
        "reordered current gate profile was accepted"
    );

    let mut failed = current_receipt.clone();
    failed["status"] = Value::String("failed".to_owned());
    let failed_gates = failed["gates"]
        .as_array_mut()
        .ok_or("receipt gates are not an array")?;
    failed_gates.truncate(3);
    failed_gates[2]["status"] = Value::String("failed".to_owned());
    failed_gates[2]["exit_code"] = serde_json::json!(1);
    failed["summary"] =
        serde_json::json!({"required": 11, "executed": 3, "passed": 2, "failed": 1});
    failed["supply_chain"]["cargo_audit"]["status"] = Value::String("failed".to_owned());
    failed["supply_chain"]["cargo_deny"]["status"] = Value::String("failed".to_owned());
    if let Err(error) = validator.validate(&failed) {
        return Err(format!("partial failed receipt was rejected: {error}").into());
    }

    let mut inconsistent_summary = failed.clone();
    inconsistent_summary["summary"]["passed"] = serde_json::json!(1);
    assert!(
        !validator.is_valid(&inconsistent_summary),
        "failed receipt with a false passed count was accepted"
    );

    let mut trailing_gate = failed.clone();
    trailing_gate["gates"]
        .as_array_mut()
        .ok_or("receipt gates are not an array")?
        .push(current_receipt["gates"][3].clone());
    trailing_gate["summary"] =
        serde_json::json!({"required": 11, "executed": 4, "passed": 3, "failed": 1});
    assert!(
        !validator.is_valid(&trailing_gate),
        "failed receipt with a gate after the first failure was accepted"
    );

    failed["status"] = Value::String("passed".to_owned());
    assert!(
        !validator.is_valid(&failed),
        "partial failed run was accepted as passed"
    );
    Ok(())
}

#[test]
fn evidence_index_rejects_mixed_gate_profiles() -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root();
    let schema = read_json(&root.join("schemas/evidence-index.v2.schema.json"))?;
    let validator = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .with_retriever(LocalSchemaRetriever::load()?)
        .build(&schema)?;
    let mut index = current_evidence_schema_fixture(&root)?;
    index["verification"]["runs"][0]["gate_count"] = serde_json::json!(10);
    assert!(
        !validator.is_valid(&index),
        "11-gate profile with a 10-gate run was accepted"
    );
    index = current_evidence_schema_fixture(&root)?;
    index["verification"]["required_gate_ids"]
        .as_array_mut()
        .ok_or("required gate IDs are not an array")?
        .swap(0, 1);
    assert!(
        !validator.is_valid(&index),
        "reordered evidence gate profile was accepted"
    );
    index = current_evidence_schema_fixture(&root)?;
    index["verification"]["runs"] = serde_json::json!([]);
    index["verification"]["repeatability"] = serde_json::json!({
        "required_runs": 3,
        "completed_runs": 0,
        "unique_run_ids": 0,
        "same_source": false,
        "same_observations": false
    });
    assert!(
        !validator.is_valid(&index),
        "passed evidence index without receipts was accepted"
    );
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

fn manifest_schema_pairs() -> [(&'static str, &'static str); 17] {
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
            ".joan/publication-readiness.json",
            "schemas/publication-readiness.v0.schema.json",
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
        (
            "audit/independent-rerun-v0/manifest.json",
            "schemas/independent-rerun-manifest.v0.schema.json",
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

fn assert_invalid_instance(
    instance: &Value,
    schema_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let schema = read_json(&workspace_root().join(schema_path))?;
    let validator = jsonschema::draft202012::options()
        .with_retriever(LocalSchemaRetriever::load()?)
        .build(&schema)?;
    if validator.is_valid(instance) {
        return Err(format!("invalid instance unexpectedly matches {schema_path}").into());
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

fn current_receipt_schema_fixture(root: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    let mut receipt = read_json(&root.join(".joan/evidence/runs/run-1.json"))?;
    match receipt["summary"]["required"].as_u64() {
        Some(10) => {
            let gates = receipt["gates"]
                .as_array_mut()
                .ok_or("receipt gates are not an array")?;
            let mut tool_forge = gates
                .get(7)
                .ok_or("legacy receipt omits payment-cost-vector")?
                .clone();
            tool_forge["id"] = Value::String("tool-forge".to_owned());
            tool_forge["argv"] = serde_json::json!(["./scripts/verify-tool-forge.sh"]);
            gates.insert(8, tool_forge);
        }
        Some(11) => {}
        _ => return Err("receipt fixture has an unsupported gate profile".into()),
    }
    receipt["environment"]["gate_config_sha256"] = Value::String("0".repeat(64));
    receipt["summary"] =
        serde_json::json!({"required": 11, "executed": 11, "passed": 11, "failed": 0});
    Ok(receipt)
}

fn current_evidence_schema_fixture(root: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    let mut index = read_json(&root.join(".joan/evidence/latest.json"))?;
    index["verification"]["required_gate_ids"] = serde_json::json!([
        "format",
        "clippy",
        "tests",
        "doc-tests",
        "release-build",
        "jce1",
        "c-digest-smoke",
        "payment-cost-vector",
        "tool-forge",
        "cargo-deny",
        "cargo-audit"
    ]);
    for run in index["verification"]["runs"]
        .as_array_mut()
        .ok_or("evidence runs are not an array")?
    {
        run["gate_count"] = serde_json::json!(11);
    }
    Ok(index)
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
