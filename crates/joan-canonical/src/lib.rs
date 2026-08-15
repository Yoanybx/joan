//! Strict canonical JSON values and domain-separated SHA-256 digests.

use serde::de::{Deserialize, Deserializer, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::ser::{Serialize, Serializer};
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use thiserror::Error;

const HASH_PREFIX: &[u8] = b"JOAN\0HASH\0V0";
const HASH_PREFIX_V1: &[u8] = b"JOAN\0HASH\0V1";
const HASH_PROFILE_V1: &str = "joan-hash-v1";
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_V1_PAYLOAD_BYTES: usize = 1_048_576;

/// Default defensive decoding bounds for Genesis inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeLimits {
    /// Maximum encoded input bytes.
    pub max_bytes: usize,
    /// Maximum recursive JSON depth.
    pub max_depth: usize,
    /// Maximum aggregate value and key count.
    pub max_nodes: usize,
    /// Maximum bytes in one string or object key.
    pub max_string_bytes: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_bytes: 1_048_576,
            max_depth: 64,
            max_nodes: 100_000,
            max_string_bytes: 262_144,
        }
    }
}

/// Integer forms accepted by the canonical JSON subset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonicalInteger {
    /// Signed 64-bit JSON integer.
    Signed(i64),
    /// Unsigned 64-bit JSON integer.
    Unsigned(u64),
}

/// JSON value with sorted object keys, duplicate rejection and no floats.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonicalValue {
    /// JSON null.
    Null,
    /// JSON boolean.
    Bool(bool),
    /// JSON integer. Larger or decimal values must use validated strings.
    Integer(CanonicalInteger),
    /// JSON string.
    String(String),
    /// Ordered JSON array.
    Array(Vec<Self>),
    /// JSON object sorted lexicographically by key bytes.
    Object(BTreeMap<String, Self>),
}

/// Algorithm/profile/domain-tagged digest.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Digest {
    /// Hash algorithm identifier.
    pub algorithm: String,
    /// Hash construction profile identifier.
    pub profile: String,
    /// Domain-separation label.
    pub domain: String,
    /// Lowercase hexadecimal digest bytes.
    pub value: String,
}

/// Registered digest domains available to the additive JCE1 profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegisteredDomainV1 {
    /// Canonical set element identity.
    CanonicalSetElement,
    /// Canonical JOAN language AST identity.
    LanguageCanonicalAst,
    /// Canonical JOAN AST with linear authority slots.
    LanguageCanonicalAstLinear,
    /// Canonical JOAN AST with tenant-purpose information labels.
    LanguageCanonicalAstInformation,
    /// One conformance vector or vector manifest.
    ConformanceVector,
    /// Source-byte identity.
    Source,
    /// Canonical package-manifest identity.
    PackageManifest,
    /// Complete verified bytecode-program identity.
    BytecodeProgram,
    /// Complete verified bytecode program with linear authority slots.
    BytecodeProgramLinear,
    /// Complete verified bytecode program with information-flow labels.
    BytecodeProgramInformation,
    /// Dispute case identity.
    DisputeCase,
    /// Dispute claim identity.
    DisputeClaim,
    /// Automatic-resolution profile identity.
    ResolutionProfile,
    /// Evidence graph identity.
    EvidenceGraph,
    /// Machine-finding identity.
    MachineFinding,
    /// Decision-authorization proof identity.
    DecisionAuthorizationProof,
    /// Effect-application request identity.
    EffectApplication,
    /// Mock-ledger identity.
    MockLedger,
    /// Reproducible benchmark-manifest identity.
    BenchmarkManifest,
    /// Native-code artifact identity bound to verified bytecode and backend configuration.
    NativeArtifact,
    /// One relocatable native-code image before address-dependent JIT linking.
    NativeCode,
    /// One bounded request sent to a JOAN native executor process.
    HostExecutionRequest,
    /// One resource-policy-bound request sent to a JOAN native executor process.
    HostExecutionRequestV2,
    /// One bounded response emitted by a JOAN native executor process.
    HostExecutorResponse,
    /// One response bound to a resource-policy-bound host request.
    HostExecutorResponseV2,
    /// Controller receipt for one isolated native execution attempt.
    HostExecutionReceipt,
    /// Controller receipt with resource policy and signal observability.
    HostExecutionReceiptV2,
    /// Offline pull-request candidate identity.
    PrCandidate,
    /// Versioned pull-request trust policy identity.
    PrTrustPolicy,
    /// Evidence artifact bound into a pull-request trust envelope.
    PrTrustEvidence,
    /// Complete pull-request trust envelope identity.
    PrTrustEnvelope,
    /// Declarative specification for one bounded generated tool.
    ToolSpec,
    /// Static verification receipt for one bounded tool specification.
    ToolSpecVerification,
    /// Complete generated tool bundle identity.
    ToolBundle,
    /// Independent tool verification receipt identity.
    ToolVerification,
    /// Guardian-bound tool finalization receipt identity.
    ToolFinalization,
    /// Final tool promotion decision identity.
    ToolPromotion,
}

impl RegisteredDomainV1 {
    /// Stable lowercase domain identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CanonicalSetElement => "joan.canonical-set-element.v1",
            Self::LanguageCanonicalAst => "joan.language-canonical-ast.v1",
            Self::LanguageCanonicalAstLinear => "joan.language-canonical-ast.v2",
            Self::LanguageCanonicalAstInformation => "joan.language-canonical-ast.v3",
            Self::ConformanceVector => "joan.conformance-vector.v1",
            Self::Source => "joan.source.v1",
            Self::PackageManifest => "joan.package-manifest.v1",
            Self::BytecodeProgram => "joan.bytecode-program.v1",
            Self::BytecodeProgramLinear => "joan.bytecode-program.v2",
            Self::BytecodeProgramInformation => "joan.bytecode-program.v3",
            Self::DisputeCase => "joan.dispute-case.v1",
            Self::DisputeClaim => "joan.dispute-claim.v1",
            Self::ResolutionProfile => "joan.resolution-profile.v1",
            Self::EvidenceGraph => "joan.evidence-graph.v1",
            Self::MachineFinding => "joan.machine-finding.v1",
            Self::DecisionAuthorizationProof => "joan.decision-authorization-proof.v1",
            Self::EffectApplication => "joan.effect-application.v1",
            Self::MockLedger => "joan.mock-ledger.v1",
            Self::BenchmarkManifest => "joan.benchmark-manifest.v1",
            Self::NativeArtifact => "joan.native-artifact.v1",
            Self::NativeCode => "joan.native-code.v1",
            Self::HostExecutionRequest => "joan.host-execution-request.v1",
            Self::HostExecutionRequestV2 => "joan.host-execution-request.v2",
            Self::HostExecutorResponse => "joan.host-executor-response.v1",
            Self::HostExecutorResponseV2 => "joan.host-executor-response.v2",
            Self::HostExecutionReceipt => "joan.host-execution-receipt.v1",
            Self::HostExecutionReceiptV2 => "joan.host-execution-receipt.v2",
            Self::PrCandidate => "joan.pr-candidate.v1",
            Self::PrTrustPolicy => "joan.pr-trust-policy.v1",
            Self::PrTrustEvidence => "joan.pr-trust-evidence.v1",
            Self::PrTrustEnvelope => "joan.pr-trust-envelope.v1",
            Self::ToolSpec => "joan.tool-spec.v1",
            Self::ToolSpecVerification => "joan.tool-spec-verification.v1",
            Self::ToolBundle => "joan.tool-bundle.v1",
            Self::ToolVerification => "joan.tool-verification.v1",
            Self::ToolFinalization => "joan.tool-finalization.v1",
            Self::ToolPromotion => "joan.tool-promotion.v1",
        }
    }

    /// Parse an exact registered domain identifier.
    pub fn parse(value: &str) -> Result<Self, Jce1Error> {
        let domain = match value {
            "joan.canonical-set-element.v1" => Self::CanonicalSetElement,
            "joan.language-canonical-ast.v1" => Self::LanguageCanonicalAst,
            "joan.language-canonical-ast.v2" => Self::LanguageCanonicalAstLinear,
            "joan.language-canonical-ast.v3" => Self::LanguageCanonicalAstInformation,
            "joan.conformance-vector.v1" => Self::ConformanceVector,
            "joan.source.v1" => Self::Source,
            "joan.package-manifest.v1" => Self::PackageManifest,
            "joan.bytecode-program.v1" => Self::BytecodeProgram,
            "joan.bytecode-program.v2" => Self::BytecodeProgramLinear,
            "joan.bytecode-program.v3" => Self::BytecodeProgramInformation,
            "joan.dispute-case.v1" => Self::DisputeCase,
            "joan.dispute-claim.v1" => Self::DisputeClaim,
            "joan.resolution-profile.v1" => Self::ResolutionProfile,
            "joan.evidence-graph.v1" => Self::EvidenceGraph,
            "joan.machine-finding.v1" => Self::MachineFinding,
            "joan.decision-authorization-proof.v1" => Self::DecisionAuthorizationProof,
            "joan.effect-application.v1" => Self::EffectApplication,
            "joan.mock-ledger.v1" => Self::MockLedger,
            "joan.benchmark-manifest.v1" => Self::BenchmarkManifest,
            "joan.native-artifact.v1" => Self::NativeArtifact,
            "joan.native-code.v1" => Self::NativeCode,
            "joan.host-execution-request.v1" => Self::HostExecutionRequest,
            "joan.host-execution-request.v2" => Self::HostExecutionRequestV2,
            "joan.host-executor-response.v1" => Self::HostExecutorResponse,
            "joan.host-executor-response.v2" => Self::HostExecutorResponseV2,
            "joan.host-execution-receipt.v1" => Self::HostExecutionReceipt,
            "joan.host-execution-receipt.v2" => Self::HostExecutionReceiptV2,
            "joan.pr-candidate.v1" => Self::PrCandidate,
            "joan.pr-trust-policy.v1" => Self::PrTrustPolicy,
            "joan.pr-trust-evidence.v1" => Self::PrTrustEvidence,
            "joan.pr-trust-envelope.v1" => Self::PrTrustEnvelope,
            "joan.tool-spec.v1" => Self::ToolSpec,
            "joan.tool-spec-verification.v1" => Self::ToolSpecVerification,
            "joan.tool-bundle.v1" => Self::ToolBundle,
            "joan.tool-verification.v1" => Self::ToolVerification,
            "joan.tool-finalization.v1" => Self::ToolFinalization,
            "joan.tool-promotion.v1" => Self::ToolPromotion,
            _ => return Err(Jce1Error::UnregisteredDomain(value.to_owned())),
        };
        Ok(domain)
    }
}

/// Canonicalization or digest validation error.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CanonicalError {
    /// Input exceeded the byte limit.
    #[error("input has {actual} bytes; limit is {limit}")]
    InputTooLarge {
        /// Observed byte count.
        actual: usize,
        /// Configured maximum byte count.
        limit: usize,
    },
    /// JSON was malformed or violated strict decoding rules.
    #[error("strict JSON decode failed: {0}")]
    Json(String),
    /// Recursive depth exceeded the configured bound.
    #[error("JSON depth {actual} exceeds limit {limit}")]
    DepthExceeded {
        /// Observed recursive depth.
        actual: usize,
        /// Configured maximum depth.
        limit: usize,
    },
    /// Aggregate node count exceeded the configured bound.
    #[error("JSON node count {actual} exceeds limit {limit}")]
    NodeCountExceeded {
        /// Observed aggregate node count.
        actual: usize,
        /// Configured maximum node count.
        limit: usize,
    },
    /// One string or key exceeded the configured byte bound.
    #[error("JSON string has {actual} bytes; limit is {limit}")]
    StringTooLarge {
        /// Observed string byte count.
        actual: usize,
        /// Configured maximum string byte count.
        limit: usize,
    },
    /// A typed value could not be serialized into the canonical subset.
    #[error("serialization failed: {0}")]
    Serialization(String),
    /// The domain label was empty or invalid.
    #[error("digest domain must be non-empty printable ASCII")]
    InvalidDomain,
    /// A supplied digest tag or value did not match recomputation.
    #[error("digest verification failed")]
    DigestMismatch,
}

/// JCE1 canonicalization, set, domain or digest failure.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Jce1Error {
    /// Shared strict-JSON or digest failure.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    /// A JSON integer exceeded the exact I-JSON interoperable range.
    #[error("integer is outside the JCE1 safe JSON range: {0}")]
    UnsafeInteger(String),
    /// A hash payload exceeded the frozen JCE1 bound.
    #[error("JCE1 payload has {actual} bytes; limit is {limit}")]
    PayloadTooLarge {
        /// Observed payload bytes.
        actual: usize,
        /// Maximum accepted payload bytes.
        limit: usize,
    },
    /// The requested domain is not in the JCE1 registry.
    #[error("unregistered JCE1 digest domain: {0}")]
    UnregisteredDomain(String),
    /// A semantic set repeated the same canonical element.
    #[error("duplicate JCE1 canonical set element")]
    DuplicateSetElement,
}

struct CanonicalVisitor;

impl<'de> Visitor<'de> for CanonicalVisitor {
    type Value = CanonicalValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict JSON without floating-point numbers or duplicate keys")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(CanonicalValue::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(CanonicalValue::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(CanonicalValue::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(CanonicalValue::Integer(CanonicalInteger::Signed(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(CanonicalValue::Integer(CanonicalInteger::Unsigned(value)))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(
            "floating-point JSON numbers are forbidden; use a validated string",
        ))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(CanonicalValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(CanonicalValue::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<CanonicalValue>()? {
            values.push(value);
        }
        Ok(CanonicalValue::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom(format!("duplicate object key: {key}")));
            }
            let value = map.next_value::<CanonicalValue>()?;
            values.insert(key, value);
        }
        Ok(CanonicalValue::Object(values))
    }
}

impl<'de> Deserialize<'de> for CanonicalValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(CanonicalVisitor)
    }
}

impl Serialize for CanonicalValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_serde_value().serialize(serializer)
    }
}

impl CanonicalValue {
    /// Convert the value to `serde_json::Value` without changing semantics.
    #[must_use]
    pub fn to_serde_value(&self) -> serde_json::Value {
        match self {
            Self::Null => serde_json::Value::Null,
            Self::Bool(value) => serde_json::Value::Bool(*value),
            Self::Integer(CanonicalInteger::Signed(value)) => (*value).into(),
            Self::Integer(CanonicalInteger::Unsigned(value)) => (*value).into(),
            Self::String(value) => serde_json::Value::String(value.clone()),
            Self::Array(values) => {
                serde_json::Value::Array(values.iter().map(Self::to_serde_value).collect())
            }
            Self::Object(values) => serde_json::Value::Object(
                values
                    .iter()
                    .map(|(key, value)| (key.clone(), value.to_serde_value()))
                    .collect(),
            ),
        }
    }
}

/// Parse strict JSON with default bounds.
pub fn parse_strict(input: &str) -> Result<CanonicalValue, CanonicalError> {
    parse_strict_with_limits(input, DecodeLimits::default())
}

/// Parse strict JSON with caller-supplied bounds.
pub fn parse_strict_with_limits(
    input: &str,
    limits: DecodeLimits,
) -> Result<CanonicalValue, CanonicalError> {
    if input.len() > limits.max_bytes {
        return Err(CanonicalError::InputTooLarge {
            actual: input.len(),
            limit: limits.max_bytes,
        });
    }

    let mut deserializer = serde_json::Deserializer::from_str(input);
    let value = CanonicalValue::deserialize(&mut deserializer)
        .map_err(|error| CanonicalError::Json(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| CanonicalError::Json(error.to_string()))?;
    validate_bounds(&value, limits)?;
    Ok(value)
}

/// Serialize a strict value into deterministic canonical JSON bytes.
pub fn to_canonical_bytes(value: &CanonicalValue) -> Result<Vec<u8>, CanonicalError> {
    let mut output = String::new();
    write_canonical(value, &mut output)?;
    Ok(output.into_bytes())
}

/// Parse and canonicalize a JSON string.
pub fn canonicalize_str(input: &str) -> Result<Vec<u8>, CanonicalError> {
    to_canonical_bytes(&parse_strict(input)?)
}

/// Parse strict JSON and apply the frozen JCE1 safe-integer restrictions.
pub fn parse_strict_v1(input: &str) -> Result<CanonicalValue, Jce1Error> {
    let value = parse_strict(input)?;
    validate_jce1_value(&value)?;
    Ok(value)
}

/// Serialize a value using RFC 8785 UTF-16 property ordering and JCE1 restrictions.
pub fn to_canonical_bytes_v1(value: &CanonicalValue) -> Result<Vec<u8>, Jce1Error> {
    validate_jce1_value(value)?;
    let mut output = String::new();
    write_canonical_v1(value, &mut output)?;
    Ok(output.into_bytes())
}

/// Parse and canonicalize one JCE1 JSON input.
pub fn canonicalize_str_v1(input: &str) -> Result<Vec<u8>, Jce1Error> {
    to_canonical_bytes_v1(&parse_strict_v1(input)?)
}

/// Convert any serializable typed value into the strict canonical subset.
pub fn from_serializable<T: Serialize>(value: &T) -> Result<CanonicalValue, CanonicalError> {
    let encoded = serde_json::to_string(value)
        .map_err(|error| CanonicalError::Serialization(error.to_string()))?;
    parse_strict(&encoded)
}

/// Convert a serializable value into the JCE1 canonical subset.
pub fn from_serializable_v1<T: Serialize>(value: &T) -> Result<CanonicalValue, Jce1Error> {
    let encoded = serde_json::to_string(value)
        .map_err(|error| CanonicalError::Serialization(error.to_string()))?;
    parse_strict_v1(&encoded)
}

/// Hash arbitrary bytes with explicit JOAN domain separation.
pub fn digest_bytes(domain: &str, payload: &[u8]) -> Result<Digest, CanonicalError> {
    validate_domain(domain)?;
    let mut hasher = Sha256::new();
    hasher.update(HASH_PREFIX);
    update_length_delimited(&mut hasher, domain.as_bytes());
    update_length_delimited(&mut hasher, payload);
    let value = lower_hex(&hasher.finalize());
    Ok(Digest {
        algorithm: "sha256".to_owned(),
        profile: "joan-hash-v0".to_owned(),
        domain: domain.to_owned(),
        value,
    })
}

/// Hash bytes with the frozen JCE1 preimage and a registered typed domain.
pub fn digest_bytes_v1(domain: RegisteredDomainV1, payload: &[u8]) -> Result<Digest, Jce1Error> {
    let value = digest_value_bytes_v1(domain, payload)?;
    Ok(Digest {
        algorithm: "sha256".to_owned(),
        profile: HASH_PROFILE_V1.to_owned(),
        domain: domain.as_str().to_owned(),
        value: lower_hex(&value),
    })
}

/// Hash bytes into the raw 32-byte JCE1 value without allocating its typed envelope.
///
/// Raw bytes are not a complete JOAN identity and must not be stored or verified without the
/// algorithm, profile and registered domain carried by [`Digest`].
pub fn digest_value_bytes_v1(
    domain: RegisteredDomainV1,
    payload: &[u8],
) -> Result<[u8; 32], Jce1Error> {
    if payload.len() > MAX_V1_PAYLOAD_BYTES {
        return Err(Jce1Error::PayloadTooLarge {
            actual: payload.len(),
            limit: MAX_V1_PAYLOAD_BYTES,
        });
    }
    let mut hasher = Sha256::new();
    hasher.update(HASH_PREFIX_V1);
    update_length_delimited(&mut hasher, HASH_PROFILE_V1.as_bytes());
    update_length_delimited(&mut hasher, domain.as_str().as_bytes());
    update_length_delimited(&mut hasher, payload);
    Ok(hasher.finalize().into())
}

/// Hash a canonical value in the supplied domain.
pub fn digest_canonical(domain: &str, value: &CanonicalValue) -> Result<Digest, CanonicalError> {
    digest_bytes(domain, &to_canonical_bytes(value)?)
}

/// Hash a JCE1 canonical value under a registered domain.
pub fn digest_canonical_v1(
    domain: RegisteredDomainV1,
    value: &CanonicalValue,
) -> Result<Digest, Jce1Error> {
    digest_bytes_v1(domain, &to_canonical_bytes_v1(value)?)
}

/// Canonicalize and hash a serializable typed value.
pub fn digest_serializable<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<Digest, CanonicalError> {
    digest_canonical(domain, &from_serializable(value)?)
}

/// Canonicalize and hash a serializable value with JCE1.
pub fn digest_serializable_v1<T: Serialize>(
    domain: RegisteredDomainV1,
    value: &T,
) -> Result<Digest, Jce1Error> {
    digest_canonical_v1(domain, &from_serializable_v1(value)?)
}

/// Recompute and compare a domain-tagged digest.
pub fn verify_digest(digest: &Digest, payload: &[u8]) -> Result<(), CanonicalError> {
    if digest.algorithm != "sha256" || digest.profile != "joan-hash-v0" {
        return Err(CanonicalError::DigestMismatch);
    }
    let recomputed = digest_bytes(&digest.domain, payload)?;
    if constant_time_eq(recomputed.value.as_bytes(), digest.value.as_bytes()) {
        Ok(())
    } else {
        Err(CanonicalError::DigestMismatch)
    }
}

/// Verify the exact JCE1 algorithm, profile, registered domain and payload digest.
pub fn verify_typed_digest_v1(
    domain: RegisteredDomainV1,
    payload: &[u8],
    digest: &Digest,
) -> Result<(), Jce1Error> {
    if digest.algorithm != "sha256"
        || digest.profile != HASH_PROFILE_V1
        || digest.domain != domain.as_str()
        || digest.value.len() != 64
        || !digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CanonicalError::DigestMismatch.into());
    }
    let recomputed = digest_bytes_v1(domain, payload)?;
    if constant_time_eq(recomputed.value.as_bytes(), digest.value.as_bytes()) {
        Ok(())
    } else {
        Err(CanonicalError::DigestMismatch.into())
    }
}

/// Canonicalize an unordered semantic set with digest ordering and byte tie-breaks.
pub fn canonical_set_v1(values: Vec<CanonicalValue>) -> Result<CanonicalValue, Jce1Error> {
    let mut seen = BTreeSet::new();
    let mut entries = Vec::with_capacity(values.len());
    for value in values {
        let bytes = to_canonical_bytes_v1(&value)?;
        if !seen.insert(bytes.clone()) {
            return Err(Jce1Error::DuplicateSetElement);
        }
        let digest = digest_bytes_v1(RegisteredDomainV1::CanonicalSetElement, &bytes)?;
        entries.push((digest.value, bytes, value));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    Ok(CanonicalValue::Array(
        entries.into_iter().map(|(_, _, value)| value).collect(),
    ))
}

fn validate_domain(domain: &str) -> Result<(), CanonicalError> {
    if domain.is_empty()
        || !domain
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b':')
    {
        return Err(CanonicalError::InvalidDomain);
    }
    Ok(())
}

fn validate_jce1_value(value: &CanonicalValue) -> Result<(), Jce1Error> {
    match value {
        CanonicalValue::Integer(CanonicalInteger::Signed(integer)) => {
            if integer.unsigned_abs() > MAX_SAFE_JSON_INTEGER {
                return Err(Jce1Error::UnsafeInteger(integer.to_string()));
            }
        }
        CanonicalValue::Integer(CanonicalInteger::Unsigned(integer)) => {
            if *integer > MAX_SAFE_JSON_INTEGER {
                return Err(Jce1Error::UnsafeInteger(integer.to_string()));
            }
        }
        CanonicalValue::Array(values) => {
            for item in values {
                validate_jce1_value(item)?;
            }
        }
        CanonicalValue::Object(values) => {
            for item in values.values() {
                validate_jce1_value(item)?;
            }
        }
        CanonicalValue::Null | CanonicalValue::Bool(_) | CanonicalValue::String(_) => {}
    }
    Ok(())
}

fn validate_bounds(value: &CanonicalValue, limits: DecodeLimits) -> Result<(), CanonicalError> {
    let mut nodes = 0_usize;
    validate_node(value, 1, limits, &mut nodes)
}

fn validate_node(
    value: &CanonicalValue,
    depth: usize,
    limits: DecodeLimits,
    nodes: &mut usize,
) -> Result<(), CanonicalError> {
    if depth > limits.max_depth {
        return Err(CanonicalError::DepthExceeded {
            actual: depth,
            limit: limits.max_depth,
        });
    }
    *nodes = nodes.saturating_add(1);
    if *nodes > limits.max_nodes {
        return Err(CanonicalError::NodeCountExceeded {
            actual: *nodes,
            limit: limits.max_nodes,
        });
    }
    match value {
        CanonicalValue::String(text) => validate_string(text, limits),
        CanonicalValue::Array(values) => {
            for item in values {
                validate_node(item, depth + 1, limits, nodes)?;
            }
            Ok(())
        }
        CanonicalValue::Object(values) => {
            for (key, item) in values {
                validate_string(key, limits)?;
                validate_node(item, depth + 1, limits, nodes)?;
            }
            Ok(())
        }
        CanonicalValue::Null | CanonicalValue::Bool(_) | CanonicalValue::Integer(_) => Ok(()),
    }
}

fn validate_string(value: &str, limits: DecodeLimits) -> Result<(), CanonicalError> {
    if value.len() > limits.max_string_bytes {
        return Err(CanonicalError::StringTooLarge {
            actual: value.len(),
            limit: limits.max_string_bytes,
        });
    }
    Ok(())
}

fn write_canonical(value: &CanonicalValue, output: &mut String) -> Result<(), CanonicalError> {
    match value {
        CanonicalValue::Null => output.push_str("null"),
        CanonicalValue::Bool(true) => output.push_str("true"),
        CanonicalValue::Bool(false) => output.push_str("false"),
        CanonicalValue::Integer(CanonicalInteger::Signed(value)) => {
            output.push_str(&value.to_string());
        }
        CanonicalValue::Integer(CanonicalInteger::Unsigned(value)) => {
            output.push_str(&value.to_string());
        }
        CanonicalValue::String(value) => output.push_str(
            &serde_json::to_string(value)
                .map_err(|error| CanonicalError::Serialization(error.to_string()))?,
        ),
        CanonicalValue::Array(values) => {
            output.push('[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_canonical(item, output)?;
            }
            output.push(']');
        }
        CanonicalValue::Object(values) => {
            output.push('{');
            for (index, (key, item)) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(key)
                        .map_err(|error| CanonicalError::Serialization(error.to_string()))?,
                );
                output.push(':');
                write_canonical(item, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn write_canonical_v1(value: &CanonicalValue, output: &mut String) -> Result<(), CanonicalError> {
    match value {
        CanonicalValue::Null => output.push_str("null"),
        CanonicalValue::Bool(true) => output.push_str("true"),
        CanonicalValue::Bool(false) => output.push_str("false"),
        CanonicalValue::Integer(CanonicalInteger::Signed(value)) => {
            output.push_str(&value.to_string());
        }
        CanonicalValue::Integer(CanonicalInteger::Unsigned(value)) => {
            output.push_str(&value.to_string());
        }
        CanonicalValue::String(value) => output.push_str(
            &serde_json::to_string(value)
                .map_err(|error| CanonicalError::Serialization(error.to_string()))?,
        ),
        CanonicalValue::Array(values) => {
            output.push('[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_canonical_v1(item, output)?;
            }
            output.push(']');
        }
        CanonicalValue::Object(values) => {
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.encode_utf16().cmp(right.0.encode_utf16()));
            output.push('{');
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(key)
                        .map_err(|error| CanonicalError::Serialization(error.to_string()))?,
                );
                output.push(':');
                write_canonical_v1(item, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn update_length_delimited(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left_byte, right_byte) in left.iter().zip(right) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}
