//! Executable cross-implementation conformance checks for frozen JOAN profiles.

use joan_canonical::{
    CanonicalError, CanonicalValue, DecodeLimits, Digest, Jce1Error, RegisteredDomainV1,
    canonical_set_v1, canonicalize_str_v1, digest_bytes_v1, digest_value_bytes_v1, parse_strict_v1,
    to_canonical_bytes_v1, verify_typed_digest_v1,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::BTreeSet;
use std::hint::black_box;
use std::time::Instant;
use thiserror::Error;

const SUITE_SCHEMA: &str = "joan.jce1-conformance-suite.v1";
const REPORT_SCHEMA: &str = "joan.jce1-conformance-report.v1";
const JCE1_SPEC_BYTES: &[u8] = include_bytes!("../../../spec/canonical-profile-jce1.md");

/// Reproducible digest microbenchmark result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DigestBenchmarkReport {
    /// Report contract identifier.
    pub schema: String,
    /// Exact implementation and cryptographic backend.
    pub implementation: String,
    /// Deterministically generated payload size.
    pub payload_bytes: usize,
    /// Timed digest operations.
    pub iterations: u64,
    /// Monotonic elapsed time.
    pub elapsed_ns: u64,
    /// Integer operations per second.
    pub operations_per_second: u64,
    /// Integer payload bytes per second.
    pub bytes_per_second: u64,
    /// Last typed digest, used to prove equivalent output.
    pub digest: Digest,
    /// Scope statement preventing language-level overclaims.
    pub claim_scope: String,
}

/// One deterministic implementation observation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseResult {
    /// Stable vector identifier.
    pub id: String,
    /// `passed` or `failed`.
    pub status: String,
    /// Deterministic observation for successful vectors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation: Option<Value>,
    /// Stable error class for failed vectors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_class: Option<String>,
    /// Human-readable failure context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Machine-readable result for a complete JCE1 vector suite.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceReport {
    /// Report contract identifier.
    pub schema: String,
    /// Name of the implementation under test.
    pub implementation: String,
    /// Typed identity of the exact suite bytes.
    pub suite_digest: Digest,
    /// Number of executed vectors.
    pub total: usize,
    /// Number of passing vectors.
    pub passed: usize,
    /// Number of failing vectors.
    pub failed: usize,
    /// Per-vector observations.
    pub results: Vec<CaseResult>,
}

/// Invalid suite or conformance execution.
#[derive(Debug, Error)]
pub enum ConformanceError {
    /// The suite did not satisfy its executable contract.
    #[error("invalid conformance suite: {0}")]
    Suite(String),
    /// JCE1 rejected an operation.
    #[error(transparent)]
    Jce1(#[from] Jce1Error),
    /// The manifest could not be decoded into its typed envelope.
    #[error("conformance manifest decode failed: {0}")]
    Decode(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Suite {
    schema: String,
    spec_freeze_sha256: String,
    cases: Vec<Value>,
}

/// Execute every vector while preserving failures in the returned report.
pub fn run_jce1_suite(
    suite_bytes: &[u8],
    implementation: &str,
) -> Result<ConformanceReport, ConformanceError> {
    let suite_text = std::str::from_utf8(suite_bytes)
        .map_err(|error| ConformanceError::Decode(error.to_string()))?;
    let canonical = parse_strict_v1(suite_text)?;
    let suite: Suite = serde_json::from_value(canonical.to_serde_value())
        .map_err(|error| ConformanceError::Decode(error.to_string()))?;
    if suite.schema != SUITE_SCHEMA {
        return Err(ConformanceError::Suite(format!(
            "unsupported schema {}",
            suite.schema
        )));
    }
    if suite.spec_freeze_sha256 != jce1_spec_sha256() {
        return Err(ConformanceError::Suite(
            "spec_freeze_sha256 does not match spec/canonical-profile-jce1.md".to_owned(),
        ));
    }
    if suite.cases.len() != 27 {
        return Err(ConformanceError::Suite(format!(
            "JCE1 v1 requires exactly 27 vectors; found {}",
            suite.cases.len()
        )));
    }

    let mut identifiers = BTreeSet::new();
    let mut results = Vec::with_capacity(suite.cases.len());
    for test_case in &suite.cases {
        let identifier = required_string(test_case, "id")?.to_owned();
        if !identifiers.insert(identifier.clone()) {
            return Err(ConformanceError::Suite(format!(
                "duplicate vector identifier {identifier}"
            )));
        }
        match run_case(test_case) {
            Ok(observation) => results.push(CaseResult {
                id: identifier,
                status: "passed".to_owned(),
                observation: Some(observation),
                error_class: None,
                message: None,
            }),
            Err(error) => results.push(CaseResult {
                id: identifier,
                status: "failed".to_owned(),
                observation: None,
                error_class: Some(classify_conformance_error(&error).to_owned()),
                message: Some(error.to_string()),
            }),
        }
    }

    let failed = results
        .iter()
        .filter(|result| result.status == "failed")
        .count();
    Ok(ConformanceReport {
        schema: REPORT_SCHEMA.to_owned(),
        implementation: implementation.to_owned(),
        suite_digest: digest_bytes_v1(RegisteredDomainV1::ConformanceVector, suite_bytes)?,
        total: results.len(),
        passed: results.len() - failed,
        failed,
        results,
    })
}

fn jce1_spec_sha256() -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hash = Sha256::new();
    hash.update(JCE1_SPEC_BYTES);
    let mut output = String::with_capacity(64);
    for byte in hash.finalize() {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

/// Benchmark the exact JCE1 source-domain digest over a deterministic payload.
pub fn benchmark_digest_v1(
    payload_bytes: usize,
    iterations: u64,
) -> Result<DigestBenchmarkReport, ConformanceError> {
    if payload_bytes == 0 || payload_bytes > DecodeLimits::default().max_bytes {
        return Err(suite_error("payload bytes must be between 1 and 1048576"));
    }
    if iterations == 0 || iterations > 100_000_000 {
        return Err(suite_error("iterations must be between 1 and 100000000"));
    }
    let payload = (0..payload_bytes)
        .map(|index| {
            u8::try_from((index * 31 + 17) % 251).map_err(|error| suite_error(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    for _ in 0..iterations.min(100) {
        black_box(digest_value_bytes_v1(RegisteredDomainV1::Source, &payload)?);
    }
    let start = Instant::now();
    let mut digest_value = None;
    for _ in 0..iterations {
        digest_value = Some(black_box(digest_value_bytes_v1(
            RegisteredDomainV1::Source,
            black_box(&payload),
        )?));
    }
    let elapsed_ns = u64::try_from(start.elapsed().as_nanos())
        .map_err(|error| suite_error(error.to_string()))?
        .max(1);
    let operations_per_second = iterations.saturating_mul(1_000_000_000) / elapsed_ns;
    let bytes_per_second = operations_per_second.saturating_mul(payload_bytes as u64);
    ensure(
        digest_value.is_some(),
        "benchmark produced no raw digest value",
    )?;
    let digest = digest_bytes_v1(RegisteredDomainV1::Source, &payload)?;
    Ok(DigestBenchmarkReport {
        schema: "joan.digest-benchmark.v1".to_owned(),
        implementation: "rust-sha2-0.11.0".to_owned(),
        payload_bytes,
        iterations,
        elapsed_ns,
        operations_per_second,
        bytes_per_second,
        digest,
        claim_scope: "implementation-microbenchmark-not-language-superiority".to_owned(),
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the operation match keeps the executable vector semantics auditable in one place"
)]
fn run_case(test_case: &Value) -> Result<Value, ConformanceError> {
    match required_string(test_case, "operation")? {
        "canonicalize" => {
            let outputs = canonicalize_inputs(required_array(test_case, "inputs")?)?;
            let expected = required_string(test_case, "expected_output")?;
            ensure(
                outputs.iter().all(|output| output == expected),
                "output mismatch",
            )?;
            Ok(json!({ "outputs": outputs }))
        }
        "canonicalize-distinct" => {
            let outputs = canonicalize_inputs(required_array(test_case, "inputs")?)?;
            let expected = string_array(required_array(test_case, "expected_outputs")?)?;
            ensure(outputs == expected, "distinct output mismatch")?;
            ensure(
                outputs.iter().collect::<BTreeSet<_>>().len() == outputs.len(),
                "outputs were not distinct",
            )?;
            Ok(json!({ "outputs": outputs }))
        }
        "reject" => {
            let expected = required_string(test_case, "expected_error")?;
            let errors = required_array(test_case, "inputs")?
                .iter()
                .map(|input| expect_reject(value_string(input)?, expected))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(json!({ "errors": errors }))
        }
        "schema-reject" => {
            let value = parse_strict_v1(required_string(test_case, "input")?)?;
            let CanonicalValue::Object(fields) = value else {
                return Err(suite_error("schema-reject input must be an object"));
            };
            let allowed = string_array(required_array(test_case, "allowed_fields")?)?
                .into_iter()
                .collect::<BTreeSet<_>>();
            let mut unknown = fields
                .keys()
                .filter(|key| !allowed.contains(key.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            unknown.sort();
            let mut expected = string_array(required_array(test_case, "expected_unknown")?)?;
            expected.sort();
            ensure(unknown == expected, "unknown fields mismatch")?;
            Ok(json!({ "unknown": unknown }))
        }
        "resource-bounds" => {
            let limits = DecodeLimits::default();
            let inputs = [
                format!("\"{}\"", "x".repeat(limits.max_bytes)),
                format!("{}null{}", "[".repeat(65), "]".repeat(65)),
                format!("[{}]", vec!["null"; limits.max_nodes].join(",")),
                format!("\"{}\"", "x".repeat(limits.max_string_bytes + 1)),
            ];
            let errors = inputs
                .iter()
                .map(|input| expect_reject(input, "resource"))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(json!({ "errors": errors }))
        }
        "domain-distinct" => {
            let payload = required_string(test_case, "payload")?.as_bytes();
            let values = string_array(required_array(test_case, "domains")?)?
                .iter()
                .map(|domain| {
                    let registered = RegisteredDomainV1::parse(domain)?;
                    Ok(digest_bytes_v1(registered, payload)?.value)
                })
                .collect::<Result<Vec<_>, ConformanceError>>()?;
            ensure(
                values.iter().collect::<BTreeSet<_>>().len() == values.len(),
                "domain-separated digests collided",
            )?;
            Ok(json!({ "values": values }))
        }
        "fixed-digest" => {
            let domain = RegisteredDomainV1::parse(required_string(test_case, "domain")?)?;
            let payload = decode_hex(required_string(test_case, "payload_hex")?)?;
            let digest = digest_bytes_v1(domain, &payload)?;
            ensure(
                digest.value == required_string(test_case, "expected_value")?,
                "fixed digest mismatch",
            )?;
            Ok(json!({ "digest": digest }))
        }
        "typed-digest-reject" => {
            let domain = RegisteredDomainV1::parse(required_string(test_case, "domain")?)?;
            let payload = required_string(test_case, "payload")?.as_bytes();
            let valid = digest_bytes_v1(domain, payload)?;
            let variants = [
                Digest {
                    algorithm: "sha512".to_owned(),
                    ..valid.clone()
                },
                Digest {
                    profile: "joan-hash-v0".to_owned(),
                    ..valid.clone()
                },
                Digest {
                    domain: "joan.source.v1".to_owned(),
                    ..valid.clone()
                },
                Digest {
                    value: "0".repeat(64),
                    ..valid
                },
            ];
            let errors = variants
                .iter()
                .map(|variant| {
                    verify_typed_digest_v1(domain, payload, variant)
                        .err()
                        .map_or_else(
                            || Err(suite_error("typed digest mutation was accepted")),
                            |error| Ok(classify_jce1_error(&error).to_owned()),
                        )
                })
                .collect::<Result<Vec<_>, _>>()?;
            ensure(
                errors.iter().all(|error| error == "digest"),
                "typed digest mutation returned the wrong error class",
            )?;
            Ok(json!({ "errors": errors }))
        }
        "domain-reject" => {
            let errors = string_array(required_array(test_case, "domains")?)?
                .iter()
                .map(|domain| match RegisteredDomainV1::parse(domain) {
                    Ok(_) => Err(suite_error(format!(
                        "invalid domain was accepted: {domain}"
                    ))),
                    Err(error) => Ok(classify_jce1_error(&error).to_owned()),
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(json!({ "errors": errors }))
        }
        "payload-bound" => {
            let domain = RegisteredDomainV1::parse(required_string(test_case, "domain")?)?;
            let accepted = required_usize(test_case, "accepted_bytes")?;
            let rejected = required_usize(test_case, "rejected_bytes")?;
            digest_bytes_v1(domain, &vec![0_u8; accepted])?;
            let observed = digest_bytes_v1(domain, &vec![0_u8; rejected])
                .err()
                .map(|error| classify_jce1_error(&error).to_owned());
            ensure(
                observed.as_deref() == Some("resource"),
                "oversized payload was accepted",
            )?;
            Ok(json!({ "accepted": accepted, "rejected": observed }))
        }
        "set-permutations" => {
            let outputs = required_array(test_case, "sets")?
                .iter()
                .map(canonicalize_set)
                .collect::<Result<Vec<_>, _>>()?;
            let expected = required_string(test_case, "expected_output")?;
            ensure(
                outputs.iter().all(|output| output == expected),
                "canonical set mismatch",
            )?;
            Ok(json!({ "outputs": outputs }))
        }
        "set-duplicate" => {
            let input = value_to_canonical_array(required_value(test_case, "values")?)?;
            let observed = canonical_set_v1(input)
                .err()
                .map(|error| classify_jce1_error(&error).to_owned());
            ensure(
                observed.as_deref() == Some("duplicate-set"),
                "duplicate set element was accepted",
            )?;
            Ok(json!({ "error": observed }))
        }
        "synthetic-set-tie" => {
            let mut records = required_array(test_case, "records")?.clone();
            records.sort_by(|left, right| {
                let left_digest = value_field_string(left, "digest").unwrap_or_default();
                let right_digest = value_field_string(right, "digest").unwrap_or_default();
                let left_bytes = value_field_string(left, "bytes_hex").unwrap_or_default();
                let right_bytes = value_field_string(right, "bytes_hex").unwrap_or_default();
                left_digest
                    .cmp(right_digest)
                    .then_with(|| left_bytes.cmp(right_bytes))
            });
            let labels = records
                .iter()
                .map(|record| value_field_string(record, "label").map(str::to_owned))
                .collect::<Result<Vec<_>, _>>()?;
            let expected = string_array(required_array(test_case, "expected_labels")?)?;
            ensure(labels == expected, "synthetic set tie-break mismatch")?;
            Ok(json!({ "labels": labels }))
        }
        operation => Err(suite_error(format!("unsupported operation: {operation}"))),
    }
}

fn canonicalize_inputs(inputs: &[Value]) -> Result<Vec<String>, ConformanceError> {
    inputs
        .iter()
        .map(|input| {
            let bytes = canonicalize_str_v1(value_string(input)?)?;
            String::from_utf8(bytes).map_err(|error| suite_error(error.to_string()))
        })
        .collect()
}

fn canonicalize_set(value: &Value) -> Result<String, ConformanceError> {
    let set = canonical_set_v1(value_to_canonical_array(value)?)?;
    String::from_utf8(to_canonical_bytes_v1(&set)?).map_err(|error| suite_error(error.to_string()))
}

fn value_to_canonical_array(value: &Value) -> Result<Vec<CanonicalValue>, ConformanceError> {
    let encoded = serde_json::to_string(value).map_err(|error| suite_error(error.to_string()))?;
    let CanonicalValue::Array(values) = parse_strict_v1(&encoded)? else {
        return Err(suite_error("set vector must contain an array"));
    };
    Ok(values)
}

fn expect_reject(input: &str, expected: &str) -> Result<String, ConformanceError> {
    match canonicalize_str_v1(input) {
        Ok(_) => Err(suite_error(format!(
            "input was accepted; expected {expected}"
        ))),
        Err(error) => {
            let observed = classify_jce1_error(&error);
            ensure(
                observed == expected,
                format!("expected {expected}, observed {observed}"),
            )?;
            Ok(observed.to_owned())
        }
    }
}

fn classify_conformance_error(error: &ConformanceError) -> &'static str {
    match error {
        ConformanceError::Jce1(error) => classify_jce1_error(error),
        ConformanceError::Suite(_) | ConformanceError::Decode(_) => "conformance",
    }
}

fn classify_jce1_error(error: &Jce1Error) -> &'static str {
    match error {
        Jce1Error::UnsafeInteger(_) => "unsafe-integer",
        Jce1Error::PayloadTooLarge { .. }
        | Jce1Error::Canonical(
            CanonicalError::InputTooLarge { .. }
            | CanonicalError::DepthExceeded { .. }
            | CanonicalError::NodeCountExceeded { .. }
            | CanonicalError::StringTooLarge { .. },
        ) => "resource",
        Jce1Error::UnregisteredDomain(_) => "domain",
        Jce1Error::DuplicateSetElement => "duplicate-set",
        Jce1Error::Canonical(CanonicalError::DigestMismatch) => "digest",
        Jce1Error::Canonical(_) => "canonical-json",
    }
}

fn ensure(condition: bool, message: impl Into<String>) -> Result<(), ConformanceError> {
    if condition {
        Ok(())
    } else {
        Err(suite_error(message))
    }
}

fn suite_error(message: impl Into<String>) -> ConformanceError {
    ConformanceError::Suite(message.into())
}

fn required_value<'a>(value: &'a Value, field: &str) -> Result<&'a Value, ConformanceError> {
    value
        .as_object()
        .and_then(|object| object.get(field))
        .ok_or_else(|| suite_error(format!("missing field {field}")))
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, ConformanceError> {
    value_field_string(value, field)
}

fn value_field_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, ConformanceError> {
    required_value(value, field)?
        .as_str()
        .ok_or_else(|| suite_error(format!("field {field} must be a string")))
}

fn required_array<'a>(value: &'a Value, field: &str) -> Result<&'a Vec<Value>, ConformanceError> {
    required_value(value, field)?
        .as_array()
        .ok_or_else(|| suite_error(format!("field {field} must be an array")))
}

fn required_usize(value: &Value, field: &str) -> Result<usize, ConformanceError> {
    let integer = required_value(value, field)?
        .as_u64()
        .ok_or_else(|| suite_error(format!("field {field} must be an unsigned integer")))?;
    usize::try_from(integer).map_err(|error| suite_error(error.to_string()))
}

fn value_string(value: &Value) -> Result<&str, ConformanceError> {
    value
        .as_str()
        .ok_or_else(|| suite_error("vector input must be a string"))
}

fn string_array(values: &[Value]) -> Result<Vec<String>, ConformanceError> {
    values
        .iter()
        .map(|value| value_string(value).map(str::to_owned))
        .collect()
}

fn decode_hex(value: &str) -> Result<Vec<u8>, ConformanceError> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(suite_error(
            "payload_hex must contain complete hexadecimal bytes",
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|error| suite_error(error.to_string()))?;
            u8::from_str_radix(text, 16).map_err(|error| suite_error(error.to_string()))
        })
        .collect()
}
