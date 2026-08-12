//! JCE1 Unicode, safe-integer, domain, digest and semantic-set gates.

use joan_canonical::{
    CanonicalError, CanonicalValue, Jce1Error, RegisteredDomainV1, canonical_set_v1,
    canonicalize_str, canonicalize_str_v1, digest_bytes_v1, digest_value_bytes_v1, parse_strict_v1,
    to_canonical_bytes_v1, verify_typed_digest_v1,
};
use std::fmt::Write;

#[test]
fn utf16_property_order_matches_jcs_discriminator() -> Result<(), Box<dyn std::error::Error>> {
    let input = "{\"\u{e000}\":\"bmp-private\",\"\u{1f600}\":\"emoji\"}";
    assert_eq!(
        canonicalize_str(input)?,
        "{\"\u{e000}\":\"bmp-private\",\"\u{1f600}\":\"emoji\"}".as_bytes()
    );
    assert_eq!(
        canonicalize_str_v1(input)?,
        "{\"\u{1f600}\":\"emoji\",\"\u{e000}\":\"bmp-private\"}".as_bytes()
    );
    Ok(())
}

#[test]
fn rfc_8785_property_order_sample_matches() -> Result<(), Box<dyn std::error::Error>> {
    let input = concat!(
        "{",
        "\"€\":\"Euro Sign\",",
        "\"\\r\":\"Carriage Return\",",
        "\"דּ\":\"Hebrew Letter Dalet With Dagesh\",",
        "\"1\":\"One\",",
        "\"😀\":\"Emoji: Grinning Face\",",
        "\"\u{80}\":\"Control\",",
        "\"ö\":\"Latin Small Letter O With Diaeresis\"",
        "}"
    );
    let expected = concat!(
        "{",
        "\"\\r\":\"Carriage Return\",",
        "\"1\":\"One\",",
        "\"\u{80}\":\"Control\",",
        "\"ö\":\"Latin Small Letter O With Diaeresis\",",
        "\"€\":\"Euro Sign\",",
        "\"😀\":\"Emoji: Grinning Face\",",
        "\"דּ\":\"Hebrew Letter Dalet With Dagesh\"",
        "}"
    );
    assert_eq!(canonicalize_str_v1(input)?, expected.as_bytes());
    Ok(())
}

#[test]
fn safe_integer_boundaries_are_exact() -> Result<(), Box<dyn std::error::Error>> {
    canonicalize_str_v1("{\"max\":9007199254740991,\"min\":-9007199254740991}")?;
    assert!(matches!(
        canonicalize_str_v1("{\"unsafe\":9007199254740992}"),
        Err(Jce1Error::UnsafeInteger(value)) if value == "9007199254740992"
    ));
    assert!(matches!(
        canonicalize_str_v1("{\"unsafe\":-9007199254740992}"),
        Err(Jce1Error::UnsafeInteger(value)) if value == "-9007199254740992"
    ));
    Ok(())
}

#[test]
fn floating_point_and_negative_zero_remain_rejected() {
    for input in ["{\"value\":1.5}", "{\"value\":1e3}", "{\"value\":-0}"] {
        assert!(matches!(
            canonicalize_str_v1(input),
            Err(Jce1Error::Canonical(CanonicalError::Json(_)))
        ));
    }
}

#[test]
fn domains_are_closed_and_typed() -> Result<(), Box<dyn std::error::Error>> {
    let domain = RegisteredDomainV1::parse("joan.source.v1")?;
    assert_eq!(domain, RegisteredDomainV1::Source);
    assert!(matches!(
        RegisteredDomainV1::parse("joan:source:v1"),
        Err(Jce1Error::UnregisteredDomain(value)) if value == "joan:source:v1"
    ));
    assert!(matches!(
        RegisteredDomainV1::parse("JOAN.SOURCE.V1"),
        Err(Jce1Error::UnregisteredDomain(_))
    ));
    Ok(())
}

#[test]
fn language_canonical_ast_domain_is_registered() -> Result<(), Box<dyn std::error::Error>> {
    let domain = RegisteredDomainV1::parse("joan.language-canonical-ast.v1")?;
    assert_eq!(domain, RegisteredDomainV1::LanguageCanonicalAst);
    let linear = RegisteredDomainV1::parse("joan.language-canonical-ast.v2")?;
    assert_eq!(linear, RegisteredDomainV1::LanguageCanonicalAstLinear);
    Ok(())
}

#[test]
fn package_manifest_domain_is_registered() -> Result<(), Box<dyn std::error::Error>> {
    let domain = RegisteredDomainV1::parse("joan.package-manifest.v1")?;
    assert_eq!(domain, RegisteredDomainV1::PackageManifest);
    Ok(())
}

#[test]
fn bytecode_program_domain_is_registered() -> Result<(), Box<dyn std::error::Error>> {
    let domain = RegisteredDomainV1::parse("joan.bytecode-program.v1")?;
    assert_eq!(domain, RegisteredDomainV1::BytecodeProgram);
    let linear = RegisteredDomainV1::parse("joan.bytecode-program.v2")?;
    assert_eq!(linear, RegisteredDomainV1::BytecodeProgramLinear);
    Ok(())
}

#[test]
fn pr_trust_domains_are_registered() -> Result<(), Box<dyn std::error::Error>> {
    for (name, expected) in [
        ("joan.pr-candidate.v1", RegisteredDomainV1::PrCandidate),
        ("joan.pr-trust-policy.v1", RegisteredDomainV1::PrTrustPolicy),
        (
            "joan.pr-trust-evidence.v1",
            RegisteredDomainV1::PrTrustEvidence,
        ),
        (
            "joan.pr-trust-envelope.v1",
            RegisteredDomainV1::PrTrustEnvelope,
        ),
    ] {
        assert_eq!(RegisteredDomainV1::parse(name)?, expected);
    }
    Ok(())
}

#[test]
fn typed_digest_rejects_profile_domain_and_payload_substitution()
-> Result<(), Box<dyn std::error::Error>> {
    let payload = b"JOAN JCE1 fixed payload";
    let digest = digest_bytes_v1(RegisteredDomainV1::ConformanceVector, payload)?;
    verify_typed_digest_v1(RegisteredDomainV1::ConformanceVector, payload, &digest)?;
    assert!(verify_typed_digest_v1(RegisteredDomainV1::Source, payload, &digest).is_err());
    assert!(
        verify_typed_digest_v1(RegisteredDomainV1::ConformanceVector, b"different", &digest)
            .is_err()
    );
    let mut wrong_profile = digest;
    wrong_profile.profile = "joan-hash-v0".to_owned();
    assert!(
        verify_typed_digest_v1(
            RegisteredDomainV1::ConformanceVector,
            payload,
            &wrong_profile
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn canonical_set_is_permutation_invariant_and_rejects_duplicates()
-> Result<(), Box<dyn std::error::Error>> {
    let first = vec![
        parse_strict_v1("\"non-delivery\"")?,
        parse_strict_v1("\"acceptance-failure\"")?,
        parse_strict_v1("\"budget-exceeded\"")?,
    ];
    let second = first.iter().rev().cloned().collect();
    let first_set = canonical_set_v1(first)?;
    let second_set = canonical_set_v1(second)?;
    assert_eq!(first_set, second_set);
    assert_eq!(
        to_canonical_bytes_v1(&first_set)?,
        to_canonical_bytes_v1(&second_set)?
    );
    assert!(matches!(
        canonical_set_v1(vec![
            CanonicalValue::String("same".to_owned()),
            CanonicalValue::String("same".to_owned()),
        ]),
        Err(Jce1Error::DuplicateSetElement)
    ));
    Ok(())
}

#[test]
fn v1_payload_bound_is_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let accepted = vec![0_u8; 1_048_576];
    digest_bytes_v1(RegisteredDomainV1::Source, &accepted)?;
    let rejected = vec![0_u8; 1_048_577];
    assert!(matches!(
        digest_bytes_v1(RegisteredDomainV1::Source, &rejected),
        Err(Jce1Error::PayloadTooLarge {
            actual: 1_048_577,
            limit: 1_048_576
        })
    ));
    Ok(())
}

#[test]
fn raw_and_typed_digest_paths_agree() -> Result<(), Box<dyn std::error::Error>> {
    let payload = b"raw-typed-equivalence";
    let raw = digest_value_bytes_v1(RegisteredDomainV1::Source, payload)?;
    let typed = digest_bytes_v1(RegisteredDomainV1::Source, payload)?;
    let mut raw_hex = String::with_capacity(64);
    for byte in raw {
        write!(&mut raw_hex, "{byte:02x}")?;
    }
    assert_eq!(raw_hex, typed.value);
    Ok(())
}
