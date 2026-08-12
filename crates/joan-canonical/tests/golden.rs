//! Canonical encoding golden and property tests.

use joan_canonical::{
    CanonicalError, DecodeLimits, canonicalize_str, digest_bytes, parse_strict,
    parse_strict_with_limits, verify_digest,
};
use proptest::prelude::*;

#[test]
fn object_keys_are_sorted() -> Result<(), Box<dyn std::error::Error>> {
    let actual = canonicalize_str(r#"{"z":1,"a":2,"m":[true,null]}"#)?;
    assert_eq!(actual, br#"{"a":2,"m":[true,null],"z":1}"#);
    Ok(())
}

#[test]
fn duplicate_keys_are_rejected() {
    let error = parse_strict(r#"{"a":1,"a":2}"#);
    assert!(matches!(error, Err(CanonicalError::Json(message)) if message.contains("duplicate")));
}

#[test]
fn floating_point_numbers_are_rejected() {
    let error = parse_strict(r#"{"value":1.25}"#);
    assert!(
        matches!(error, Err(CanonicalError::Json(message)) if message.contains("floating-point"))
    );
}

#[test]
fn canonicalization_is_idempotent() -> Result<(), Box<dyn std::error::Error>> {
    let once = canonicalize_str(r#"{"b":"x","a":[3,2,1]}"#)?;
    let text = std::str::from_utf8(&once)?;
    let twice = canonicalize_str(text)?;
    assert_eq!(once, twice);
    Ok(())
}

#[test]
fn domains_change_the_digest() -> Result<(), Box<dyn std::error::Error>> {
    let left = digest_bytes("joan.test.left.v0", b"same")?;
    let right = digest_bytes("joan.test.right.v0", b"same")?;
    assert_ne!(left.value, right.value);
    verify_digest(&left, b"same")?;
    assert!(verify_digest(&left, b"different").is_err());
    Ok(())
}

#[test]
fn limits_fail_closed() {
    let limits = DecodeLimits {
        max_bytes: 8,
        ..DecodeLimits::default()
    };
    assert!(matches!(
        parse_strict_with_limits(r#"{"long":true}"#, limits),
        Err(CanonicalError::InputTooLarge { .. })
    ));
}

proptest! {
    #[test]
    fn map_input_order_does_not_change_output(a in any::<i64>(), b in any::<i64>()) {
        let first = format!(r#"{{"a":{a},"b":{b}}}"#);
        let second = format!(r#"{{"b":{b},"a":{a}}}"#);
        let first_result = canonicalize_str(&first);
        let second_result = canonicalize_str(&second);
        prop_assert_eq!(first_result, second_result);
    }
}
