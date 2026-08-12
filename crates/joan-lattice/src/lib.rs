//! Bounded, canonical, borrowed-frame codec for JOAN Lattice M2M experiments.

use thiserror::Error;

/// Number of independently addressable Lattice levels.
pub const LEVEL_COUNT: usize = 6;
/// Fixed v0 frame header size.
pub const HEADER_LEN: usize = 96;
/// Maximum accepted complete frame size.
pub const MAX_FRAME_LEN: usize = 16 * 1_024 * 1_024;
/// Request an explicit receipt from the peer.
pub const FLAG_RECEIPT_REQUIRED: u8 = 0b0000_0001;

const MAGIC: &[u8; 4] = b"JNL0";
const VERSION: u8 = 0;
const KNOWN_FLAGS: u8 = FLAG_RECEIPT_REQUIRED;
const SCHEMA_OFFSET: usize = 8;
const INTENT_OFFSET: usize = 40;
const LENGTHS_OFFSET: usize = 72;

/// One Lattice information level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Level {
    /// L0 extension bytes beyond the fixed frame header.
    Frame = 0,
    /// L1 schema and type-shape knowledge difference.
    Shape = 1,
    /// L2 canonical intent.
    Intent = 2,
    /// L3 attenuated authority proof.
    Authority = 3,
    /// L4 evidence blocks or content references.
    Evidence = 4,
    /// L5 result or receipt body.
    Result = 5,
}

impl Level {
    const fn index(self) -> usize {
        self as usize
    }
}

/// Input view used to encode one frame in a single exact-size allocation.
#[derive(Clone, Copy, Debug)]
pub struct FrameParts<'a> {
    /// Versioned schema digest bytes.
    pub schema_digest: &'a [u8; 32],
    /// Canonical intent digest bytes.
    pub intent_digest: &'a [u8; 32],
    /// Supported v0 flags.
    pub flags: u8,
    /// Ordered level payloads. Empty levels consume no payload bytes.
    pub levels: [&'a [u8]; LEVEL_COUNT],
}

/// A validated frame whose variable sections borrow directly from input bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BorrowedFrame<'a> {
    flags: u8,
    schema_digest: &'a [u8],
    intent_digest: &'a [u8],
    levels: [&'a [u8]; LEVEL_COUNT],
}

impl<'a> BorrowedFrame<'a> {
    /// Supported frame flags.
    #[must_use]
    pub const fn flags(&self) -> u8 {
        self.flags
    }

    /// Borrow the exact 32 schema-digest bytes.
    #[must_use]
    pub const fn schema_digest(&self) -> &'a [u8] {
        self.schema_digest
    }

    /// Borrow the exact 32 intent-digest bytes.
    #[must_use]
    pub const fn intent_digest(&self) -> &'a [u8] {
        self.intent_digest
    }

    /// Borrow one level payload without copying it.
    #[must_use]
    pub const fn level(&self, level: Level) -> &'a [u8] {
        self.levels[level.index()]
    }
}

/// Strict Lattice frame rejection.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    /// Input is shorter than the fixed header.
    #[error("frame is shorter than the {HEADER_LEN}-byte header")]
    TruncatedHeader,
    /// Frame exceeds the hard byte bound.
    #[error("frame length {actual} exceeds {limit}")]
    FrameTooLarge {
        /// Observed bytes.
        actual: usize,
        /// Maximum bytes.
        limit: usize,
    },
    /// Magic bytes do not identify JOAN Lattice v0.
    #[error("invalid JOAN Lattice magic")]
    InvalidMagic,
    /// Version is unsupported.
    #[error("unsupported JOAN Lattice version {0}")]
    UnsupportedVersion(u8),
    /// Reserved or unknown flag bits are set.
    #[error("unsupported JOAN Lattice flags 0x{0:02x}")]
    UnsupportedFlags(u8),
    /// Reserved header bits are nonzero.
    #[error("reserved header bits must be zero")]
    ReservedBits,
    /// Declared section lengths overflow or do not match input length.
    #[error("declared level lengths do not match frame length")]
    LengthMismatch,
    /// Level-presence bits are not the canonical representation of lengths.
    #[error("level map is not canonical for declared lengths")]
    NonCanonicalLevelMap,
}

/// Encode one canonical Lattice frame using one exact-size output allocation.
pub fn encode(parts: &FrameParts<'_>) -> Result<Vec<u8>, FrameError> {
    if parts.flags & !KNOWN_FLAGS != 0 {
        return Err(FrameError::UnsupportedFlags(parts.flags));
    }
    let payload_len = parts.levels.iter().try_fold(0usize, |sum, level| {
        let length = u32::try_from(level.len()).map_err(|_| FrameError::FrameTooLarge {
            actual: level.len(),
            limit: u32::MAX as usize,
        })?;
        sum.checked_add(length as usize)
            .ok_or(FrameError::LengthMismatch)
    })?;
    let frame_len = HEADER_LEN
        .checked_add(payload_len)
        .ok_or(FrameError::LengthMismatch)?;
    if frame_len > MAX_FRAME_LEN {
        return Err(FrameError::FrameTooLarge {
            actual: frame_len,
            limit: MAX_FRAME_LEN,
        });
    }

    let mut level_map = 0u16;
    let mut output = Vec::with_capacity(frame_len);
    output.extend_from_slice(MAGIC);
    output.push(VERSION);
    output.push(parts.flags);
    output.extend_from_slice(&[0, 0]);
    output.extend_from_slice(parts.schema_digest);
    output.extend_from_slice(parts.intent_digest);
    for (index, level) in parts.levels.iter().enumerate() {
        if !level.is_empty() {
            level_map |= 1u16 << index;
        }
        let length = u32::try_from(level.len()).map_err(|_| FrameError::FrameTooLarge {
            actual: level.len(),
            limit: u32::MAX as usize,
        })?;
        output.extend_from_slice(&length.to_be_bytes());
    }
    output[6..8].copy_from_slice(&level_map.to_be_bytes());
    for level in parts.levels {
        output.extend_from_slice(level);
    }
    debug_assert_eq!(output.len(), frame_len);
    Ok(output)
}

/// Validate a complete canonical frame and borrow all variable sections.
pub fn decode(input: &[u8]) -> Result<BorrowedFrame<'_>, FrameError> {
    if input.len() < HEADER_LEN {
        return Err(FrameError::TruncatedHeader);
    }
    if input.len() > MAX_FRAME_LEN {
        return Err(FrameError::FrameTooLarge {
            actual: input.len(),
            limit: MAX_FRAME_LEN,
        });
    }
    if input.get(..4) != Some(MAGIC.as_slice()) {
        return Err(FrameError::InvalidMagic);
    }
    if input[4] != VERSION {
        return Err(FrameError::UnsupportedVersion(input[4]));
    }
    let flags = input[5];
    if flags & !KNOWN_FLAGS != 0 {
        return Err(FrameError::UnsupportedFlags(flags));
    }
    let level_map = u16::from_be_bytes([input[6], input[7]]);
    if level_map & !0b00_111111 != 0 {
        return Err(FrameError::ReservedBits);
    }

    let mut lengths = [0usize; LEVEL_COUNT];
    let mut payload_len = 0usize;
    let mut expected_map = 0u16;
    for (index, length) in lengths.iter_mut().enumerate() {
        let offset = LENGTHS_OFFSET + index * 4;
        *length = u32::from_be_bytes([
            input[offset],
            input[offset + 1],
            input[offset + 2],
            input[offset + 3],
        ]) as usize;
        payload_len = payload_len
            .checked_add(*length)
            .ok_or(FrameError::LengthMismatch)?;
        if *length > 0 {
            expected_map |= 1u16 << index;
        }
    }
    if level_map != expected_map {
        return Err(FrameError::NonCanonicalLevelMap);
    }
    if HEADER_LEN.checked_add(payload_len) != Some(input.len()) {
        return Err(FrameError::LengthMismatch);
    }

    let mut levels = [&input[HEADER_LEN..HEADER_LEN]; LEVEL_COUNT];
    let mut offset = HEADER_LEN;
    for (index, length) in lengths.into_iter().enumerate() {
        let end = offset
            .checked_add(length)
            .ok_or(FrameError::LengthMismatch)?;
        levels[index] = input.get(offset..end).ok_or(FrameError::LengthMismatch)?;
        offset = end;
    }
    Ok(BorrowedFrame {
        flags,
        schema_digest: &input[SCHEMA_OFFSET..SCHEMA_OFFSET + 32],
        intent_digest: &input[INTENT_OFFSET..INTENT_OFFSET + 32],
        levels,
    })
}
