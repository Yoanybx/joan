//! Native binding to all currently verified bytecode semantic profiles.

use joan_abi::{
    JoanAbiStatusV1, SEMANTIC_PROFILE_INFORMATION_V1, SEMANTIC_PROFILE_LEGACY_V1,
    SEMANTIC_PROFILE_LINEAR_V1, binding_from_verified_bytecode_v1, validate_borrowed_lattice_v1,
};
use joan_compiler::compile_source;
use joan_lattice::{FrameParts, encode};

const CASES: [(&str, u16); 3] = [
    (
        include_str!("../../../examples/hello.joan"),
        SEMANTIC_PROFILE_LEGACY_V1,
    ),
    (
        include_str!("../../../examples/linear-agent-handoff.joan"),
        SEMANTIC_PROFILE_LINEAR_V1,
    ),
    (
        include_str!("../../../examples/tenant-safe-handoff.joan"),
        SEMANTIC_PROFILE_INFORMATION_V1,
    ),
];

#[test]
fn verified_compiler_identities_cross_native_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let frame = encode(&FrameParts {
        schema_digest: &[7u8; 32],
        intent_digest: &[9u8; 32],
        flags: 0,
        levels: [b"", b"", b"handoff", b"permit", b"", b"receipt"],
    })?;

    for (source, expected_profile) in CASES {
        let artifact = compile_source(source)?;
        let binding = binding_from_verified_bytecode_v1(&artifact.bytecode)
            .map_err(|status| format!("verified bytecode binding failed: {status:?}"))?;
        assert_eq!(binding.semantic_profile, expected_profile);
        let view = validate_borrowed_lattice_v1(&frame, &binding)
            .map_err(|status| format!("native view failed: {status:?}"))?;
        assert_eq!(view.semantic_root, binding.semantic_root);
        assert_eq!(view.semantic_profile, expected_profile);

        let mut tampered = artifact.bytecode.clone();
        tampered.semantic_digest.value.replace_range(
            ..1,
            if &tampered.semantic_digest.value[..1] == "0" {
                "1"
            } else {
                "0"
            },
        );
        assert_eq!(
            binding_from_verified_bytecode_v1(&tampered),
            Err(JoanAbiStatusV1::InvalidBinding)
        );
    }
    Ok(())
}
