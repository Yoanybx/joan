//! Stable C ABI metadata and safe validation for borrowed JOAN Lattice frames.

#![deny(unsafe_code)]

#[cfg(not(target_pointer_width = "64"))]
compile_error!("JOAN native ABI v1 is frozen only for 64-bit targets");

use joan_bytecode::{
    BYTECODE_PROGRAM_INFORMATION_SCHEMA, BYTECODE_PROGRAM_LINEAR_SCHEMA, BYTECODE_PROGRAM_SCHEMA,
    BytecodeProgram, verify_bytecode,
};
use joan_lattice::{FrameError, Level, MAX_FRAME_LEN, decode};

#[allow(unsafe_code)]
mod ffi;

pub use ffi::{
    joan_abi_lattice_view_size_v1, joan_abi_max_buffer_len_v1, joan_abi_program_binding_size_v1,
    joan_abi_version_v1, joan_lattice_validate_v1,
};

/// Stable ABI version implemented by this crate.
pub const ABI_VERSION_V1: u16 = 1;
/// Number of bytes in a semantic program root.
pub const SEMANTIC_ROOT_LEN_V1: usize = 32;
/// Number of zero-copy Lattice level spans returned by the ABI.
pub const LEVEL_COUNT_V1: usize = 6;
/// Maximum accepted input buffer length.
pub const MAX_BUFFER_LEN_V1: u64 = MAX_FRAME_LEN as u64;
/// Canonical AST v1 profile without linear or information-flow metadata.
pub const SEMANTIC_PROFILE_LEGACY_V1: u16 = 1;
/// Canonical AST v2 profile with linear authority metadata.
pub const SEMANTIC_PROFILE_LINEAR_V1: u16 = 2;
/// Canonical AST v3 profile with tenant-purpose information-flow metadata.
pub const SEMANTIC_PROFILE_INFORMATION_V1: u16 = 3;

const LEVELS: [Level; LEVEL_COUNT_V1] = [
    Level::Frame,
    Level::Shape,
    Level::Intent,
    Level::Authority,
    Level::Evidence,
    Level::Result,
];

/// Stable status codes returned across the C boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum JoanAbiStatusV1 {
    /// Input was accepted and the output view is complete.
    Ok = 0,
    /// A required pointer was null.
    NullArgument = 1,
    /// The provided output storage is too small.
    OutputTooSmall = 2,
    /// ABI version, structure size, or semantic profile is unsupported.
    UnsupportedAbi = 3,
    /// The program binding is malformed or did not verify.
    InvalidBinding = 4,
    /// A structure pointer is not correctly aligned.
    MisalignedArgument = 5,
    /// A pointer range wrapped the target address space.
    PointerRangeInvalid = 6,
    /// The writable output overlaps an input range.
    OutputOverlapsInput = 7,
    /// The frame is shorter than its fixed header.
    TruncatedHeader = 100,
    /// The frame exceeds the hard 16 MiB bound.
    FrameTooLarge = 101,
    /// The frame magic is invalid.
    InvalidMagic = 102,
    /// The Lattice version is unsupported.
    UnsupportedFrameVersion = 103,
    /// Unknown flag bits are present.
    UnsupportedFlags = 104,
    /// Reserved header bits are nonzero.
    ReservedBits = 105,
    /// Declared lengths overflow or do not match the input.
    LengthMismatch = 106,
    /// The level-presence map is not canonical.
    NonCanonicalLevelMap = 107,
    /// A safe implementation invariant failed.
    InternalInvariant = 255,
}

impl JoanAbiStatusV1 {
    /// Stable numeric representation used by C callers.
    #[must_use]
    pub const fn code(self) -> u32 {
        self as u32
    }
}

impl From<FrameError> for JoanAbiStatusV1 {
    fn from(value: FrameError) -> Self {
        match value {
            FrameError::TruncatedHeader => Self::TruncatedHeader,
            FrameError::FrameTooLarge { .. } => Self::FrameTooLarge,
            FrameError::InvalidMagic => Self::InvalidMagic,
            FrameError::UnsupportedVersion(_) => Self::UnsupportedFrameVersion,
            FrameError::UnsupportedFlags(_) => Self::UnsupportedFlags,
            FrameError::ReservedBits => Self::ReservedBits,
            FrameError::LengthMismatch => Self::LengthMismatch,
            FrameError::NonCanonicalLevelMap => Self::NonCanonicalLevelMap,
        }
    }
}

/// Semantic identity supplied to the native boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct JoanProgramBindingV1 {
    /// Exact byte size of this binding structure.
    pub struct_size: u32,
    /// ABI version for this binding.
    pub abi_version: u16,
    /// One supported canonical AST semantic profile.
    pub semantic_profile: u16,
    /// Raw 32-byte canonical AST digest.
    pub semantic_root: [u8; SEMANTIC_ROOT_LEN_V1],
    /// Reserved for append-only compatibility; must remain zero.
    pub reserved: [u64; 3],
}

impl JoanProgramBindingV1 {
    /// Construct and validate one explicit native program binding.
    pub fn new(
        semantic_profile: u16,
        semantic_root: [u8; SEMANTIC_ROOT_LEN_V1],
    ) -> Result<Self, JoanAbiStatusV1> {
        let binding = Self {
            struct_size: u32::try_from(core::mem::size_of::<Self>())
                .map_err(|_| JoanAbiStatusV1::InternalInvariant)?,
            abi_version: ABI_VERSION_V1,
            semantic_profile,
            semantic_root,
            reserved: [0; 3],
        };
        validate_binding(&binding)?;
        Ok(binding)
    }
}

/// One relative span inside caller-owned input memory.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct JoanSpanV1 {
    /// Byte offset relative to the frame start.
    pub offset: u64,
    /// Number of bytes in the span.
    pub length: u64,
}

/// Fixed-layout result describing borrowed sections inside caller-owned memory.
///
/// The structure never owns or retains the input pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct JoanLatticeViewV1 {
    /// Exact byte size of this result structure.
    pub struct_size: u32,
    /// ABI version that produced the result.
    pub abi_version: u16,
    /// Validated JOAN Lattice wire version.
    pub lattice_version: u8,
    /// Validated Lattice frame flags.
    pub flags: u8,
    /// Exact validated frame length.
    pub frame_length: u64,
    /// Lattice schema digest copied from the fixed header.
    pub schema_digest: [u8; 32],
    /// Lattice intent digest copied from the fixed header.
    pub intent_digest: [u8; 32],
    /// Canonical AST semantic profile supplied by the verified caller.
    pub semantic_profile: u16,
    /// Always six for ABI v1.
    pub level_count: u16,
    /// Reserved for append-only compatibility; must remain zero.
    pub reserved0: u32,
    /// Program semantic root supplied by the verified native caller.
    pub semantic_root: [u8; SEMANTIC_ROOT_LEN_V1],
    /// Relative span for every Lattice level.
    pub levels: [JoanSpanV1; LEVEL_COUNT_V1],
    /// Reserved for append-only compatibility; must remain zero.
    pub reserved: [u64; 1],
}

fn semantic_profile_for(program: &BytecodeProgram) -> Result<u16, JoanAbiStatusV1> {
    match program.schema.as_str() {
        BYTECODE_PROGRAM_SCHEMA => Ok(SEMANTIC_PROFILE_LEGACY_V1),
        BYTECODE_PROGRAM_LINEAR_SCHEMA => Ok(SEMANTIC_PROFILE_LINEAR_V1),
        BYTECODE_PROGRAM_INFORMATION_SCHEMA => Ok(SEMANTIC_PROFILE_INFORMATION_V1),
        _ => Err(JoanAbiStatusV1::InvalidBinding),
    }
}

fn decode_semantic_root(value: &str) -> Result<[u8; SEMANTIC_ROOT_LEN_V1], JoanAbiStatusV1> {
    if value.len() != SEMANTIC_ROOT_LEN_V1 * 2
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(JoanAbiStatusV1::InvalidBinding);
    }
    let mut output = [0u8; SEMANTIC_ROOT_LEN_V1];
    for (index, byte) in output.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16)
            .map_err(|_| JoanAbiStatusV1::InvalidBinding)?;
    }
    Ok(output)
}

fn validate_binding(binding: &JoanProgramBindingV1) -> Result<(), JoanAbiStatusV1> {
    if usize::try_from(binding.struct_size).ok()
        != Some(core::mem::size_of::<JoanProgramBindingV1>())
        || binding.abi_version != ABI_VERSION_V1
        || !matches!(
            binding.semantic_profile,
            SEMANTIC_PROFILE_LEGACY_V1
                | SEMANTIC_PROFILE_LINEAR_V1
                | SEMANTIC_PROFILE_INFORMATION_V1
        )
    {
        return Err(JoanAbiStatusV1::UnsupportedAbi);
    }
    if binding.reserved != [0; 3] {
        return Err(JoanAbiStatusV1::InvalidBinding);
    }
    Ok(())
}

/// Verify exact bytecode and derive its typed native semantic binding.
///
/// This is a cold path and may allocate while independently verifying bytecode.
pub fn binding_from_verified_bytecode_v1(
    program: &BytecodeProgram,
) -> Result<JoanProgramBindingV1, JoanAbiStatusV1> {
    verify_bytecode(program).map_err(|_| JoanAbiStatusV1::InvalidBinding)?;
    let profile = semantic_profile_for(program)?;
    let semantic_root = decode_semantic_root(&program.semantic_identity.digest.value)?;
    if program.semantic_digest != program.semantic_identity.digest {
        return Err(JoanAbiStatusV1::InvalidBinding);
    }
    JoanProgramBindingV1::new(profile, semantic_root)
}

/// Validate a borrowed Lattice frame under an explicit program binding.
///
/// This hot path performs no allocation. Returned spans remain valid only while
/// `input` is alive and unchanged. Lattice digest bytes are structurally parsed,
/// not authenticated or recomputed by this function.
pub fn validate_borrowed_lattice_v1(
    input: &[u8],
    binding: &JoanProgramBindingV1,
) -> Result<JoanLatticeViewV1, JoanAbiStatusV1> {
    validate_binding(binding)?;
    let frame = decode(input).map_err(JoanAbiStatusV1::from)?;
    let base = input.as_ptr() as usize;
    let mut levels = [JoanSpanV1::default(); LEVEL_COUNT_V1];
    for (index, level) in LEVELS.into_iter().enumerate() {
        let bytes = frame.level(level);
        let offset = (bytes.as_ptr() as usize)
            .checked_sub(base)
            .ok_or(JoanAbiStatusV1::InternalInvariant)?;
        levels[index] = JoanSpanV1 {
            offset: u64::try_from(offset).map_err(|_| JoanAbiStatusV1::InternalInvariant)?,
            length: u64::try_from(bytes.len()).map_err(|_| JoanAbiStatusV1::InternalInvariant)?,
        };
    }

    let mut schema_digest = [0u8; 32];
    schema_digest.copy_from_slice(frame.schema_digest());
    let mut intent_digest = [0u8; 32];
    intent_digest.copy_from_slice(frame.intent_digest());

    Ok(JoanLatticeViewV1 {
        struct_size: u32::try_from(core::mem::size_of::<JoanLatticeViewV1>())
            .map_err(|_| JoanAbiStatusV1::InternalInvariant)?,
        abi_version: ABI_VERSION_V1,
        lattice_version: 0,
        flags: frame.flags(),
        frame_length: u64::try_from(input.len()).map_err(|_| JoanAbiStatusV1::InternalInvariant)?,
        schema_digest,
        intent_digest,
        semantic_profile: binding.semantic_profile,
        level_count: u16::try_from(LEVEL_COUNT_V1)
            .map_err(|_| JoanAbiStatusV1::InternalInvariant)?,
        reserved0: 0,
        semantic_root: binding.semantic_root,
        levels,
        reserved: [0; 1],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use joan_lattice::{FrameParts, encode};
    use proptest::prelude::*;

    #[test]
    fn stable_layout_matches_native_abi_v1() {
        assert_eq!(core::mem::size_of::<JoanSpanV1>(), 16);
        assert_eq!(core::mem::align_of::<JoanSpanV1>(), 8);
        assert_eq!(core::mem::offset_of!(JoanSpanV1, offset), 0);
        assert_eq!(core::mem::offset_of!(JoanSpanV1, length), 8);
        assert_eq!(core::mem::size_of::<JoanProgramBindingV1>(), 64);
        assert_eq!(core::mem::align_of::<JoanProgramBindingV1>(), 8);
        assert_eq!(core::mem::offset_of!(JoanProgramBindingV1, struct_size), 0);
        assert_eq!(core::mem::offset_of!(JoanProgramBindingV1, abi_version), 4);
        assert_eq!(
            core::mem::offset_of!(JoanProgramBindingV1, semantic_profile),
            6
        );
        assert_eq!(
            core::mem::offset_of!(JoanProgramBindingV1, semantic_root),
            8
        );
        assert_eq!(core::mem::offset_of!(JoanProgramBindingV1, reserved), 40);
        assert_eq!(core::mem::size_of::<JoanLatticeViewV1>(), 224);
        assert_eq!(core::mem::align_of::<JoanLatticeViewV1>(), 8);
        assert_eq!(core::mem::offset_of!(JoanLatticeViewV1, struct_size), 0);
        assert_eq!(core::mem::offset_of!(JoanLatticeViewV1, abi_version), 4);
        assert_eq!(core::mem::offset_of!(JoanLatticeViewV1, lattice_version), 6);
        assert_eq!(core::mem::offset_of!(JoanLatticeViewV1, flags), 7);
        assert_eq!(core::mem::offset_of!(JoanLatticeViewV1, frame_length), 8);
        assert_eq!(core::mem::offset_of!(JoanLatticeViewV1, schema_digest), 16);
        assert_eq!(core::mem::offset_of!(JoanLatticeViewV1, intent_digest), 48);
        assert_eq!(
            core::mem::offset_of!(JoanLatticeViewV1, semantic_profile),
            80
        );
        assert_eq!(core::mem::offset_of!(JoanLatticeViewV1, level_count), 82);
        assert_eq!(core::mem::offset_of!(JoanLatticeViewV1, reserved0), 84);
        assert_eq!(core::mem::offset_of!(JoanLatticeViewV1, semantic_root), 88);
        assert_eq!(core::mem::offset_of!(JoanLatticeViewV1, levels), 120);
        assert_eq!(core::mem::offset_of!(JoanLatticeViewV1, reserved), 216);
    }

    #[test]
    fn safe_view_binds_offsets_and_typed_semantic_root() -> Result<(), Box<dyn std::error::Error>> {
        let binding = JoanProgramBindingV1::new(SEMANTIC_PROFILE_INFORMATION_V1, [3u8; 32])
            .map_err(|status| format!("unexpected binding status: {status:?}"))?;
        let encoded = encode(&FrameParts {
            schema_digest: &[7u8; 32],
            intent_digest: &[9u8; 32],
            flags: 1,
            levels: [b"", b"shape", b"call", b"permit", b"evidence", b"result"],
        })?;
        let view = validate_borrowed_lattice_v1(&encoded, &binding)
            .map_err(|status| format!("unexpected ABI status: {status:?}"))?;
        assert_eq!(view.semantic_profile, SEMANTIC_PROFILE_INFORMATION_V1);
        assert_eq!(view.semantic_root, binding.semantic_root);
        assert_eq!(
            view.levels[1],
            JoanSpanV1 {
                offset: 96,
                length: 5
            }
        );
        assert_eq!(view.levels.map(|span| span.length), [0, 5, 4, 6, 8, 6]);
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4096))]

        #[test]
        fn arbitrary_bounded_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
            let binding = JoanProgramBindingV1::new(SEMANTIC_PROFILE_LEGACY_V1, [1u8; 32]);
            if let Ok(binding) = binding {
                let _ = validate_borrowed_lattice_v1(&bytes, &binding);
            }
        }
    }
}
