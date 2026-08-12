//! JOAN Lattice framing, canonicality, and hostile-input tests.

use joan_lattice::{
    FLAG_RECEIPT_REQUIRED, FrameError, FrameParts, HEADER_LEN, Level, decode, encode,
};
use proptest::prelude::*;

#[test]
fn round_trip_borrows_sections_from_the_encoded_frame() -> Result<(), Box<dyn std::error::Error>> {
    let schema = [7u8; 32];
    let intent = [9u8; 32];
    let shape = b"schema-known-by-digest";
    let evidence = b"only-the-unknown-block";
    let encoded = encode(&FrameParts {
        schema_digest: &schema,
        intent_digest: &intent,
        flags: FLAG_RECEIPT_REQUIRED,
        levels: [b"", shape, b"call", b"permit", evidence, b""],
    })?;
    let decoded = decode(&encoded)?;
    assert_eq!(decoded.flags(), FLAG_RECEIPT_REQUIRED);
    assert_eq!(decoded.schema_digest(), schema);
    assert_eq!(decoded.intent_digest(), intent);
    assert_eq!(decoded.level(Level::Shape), shape);
    assert_eq!(decoded.level(Level::Evidence), evidence);

    let frame_start = encoded.as_ptr() as usize;
    let frame_end = frame_start + encoded.len();
    let section_start = decoded.level(Level::Evidence).as_ptr() as usize;
    assert!((frame_start..frame_end).contains(&section_start));
    Ok(())
}

#[test]
fn empty_knowledge_difference_is_one_fixed_header() -> Result<(), Box<dyn std::error::Error>> {
    let schema = [1u8; 32];
    let intent = [2u8; 32];
    let encoded = encode(&FrameParts {
        schema_digest: &schema,
        intent_digest: &intent,
        flags: 0,
        levels: [b""; 6],
    })?;
    assert_eq!(encoded.len(), HEADER_LEN);
    assert_eq!(decode(&encoded)?.level(Level::Result), b"");
    Ok(())
}

#[test]
fn noncanonical_level_map_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let schema = [1u8; 32];
    let intent = [2u8; 32];
    let mut encoded = encode(&FrameParts {
        schema_digest: &schema,
        intent_digest: &intent,
        flags: 0,
        levels: [b"", b"shape", b"", b"", b"", b""],
    })?;
    encoded[6] = 0;
    encoded[7] = 0;
    assert_eq!(decode(&encoded), Err(FrameError::NonCanonicalLevelMap));
    Ok(())
}

#[test]
fn trailing_bytes_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let schema = [1u8; 32];
    let intent = [2u8; 32];
    let mut encoded = encode(&FrameParts {
        schema_digest: &schema,
        intent_digest: &intent,
        flags: 0,
        levels: [b""; 6],
    })?;
    encoded.push(0);
    assert_eq!(decode(&encoded), Err(FrameError::LengthMismatch));
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = decode(&bytes);
    }
}
