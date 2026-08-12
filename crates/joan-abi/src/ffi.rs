//! The only raw-pointer boundary in `joan-abi`.

use crate::{
    ABI_VERSION_V1, JoanAbiStatusV1, JoanLatticeViewV1, JoanProgramBindingV1, MAX_BUFFER_LEN_V1,
    validate_borrowed_lattice_v1,
};
use core::mem::{align_of, size_of};

#[unsafe(no_mangle)]
/// Return the stable native ABI version.
pub extern "C" fn joan_abi_version_v1() -> u32 {
    u32::from(ABI_VERSION_V1)
}

#[unsafe(no_mangle)]
/// Return the maximum number of accepted input bytes.
pub extern "C" fn joan_abi_max_buffer_len_v1() -> u64 {
    MAX_BUFFER_LEN_V1
}

#[unsafe(no_mangle)]
/// Return the exact program-binding size expected by ABI v1.
pub extern "C" fn joan_abi_program_binding_size_v1() -> u32 {
    u32::try_from(size_of::<JoanProgramBindingV1>()).unwrap_or(u32::MAX)
}

#[unsafe(no_mangle)]
/// Return the exact result-view size expected by ABI v1.
pub extern "C" fn joan_abi_lattice_view_size_v1() -> u32 {
    u32::try_from(size_of::<JoanLatticeViewV1>()).unwrap_or(u32::MAX)
}

fn checked_end(start: usize, length: usize) -> Result<usize, JoanAbiStatusV1> {
    start
        .checked_add(length)
        .ok_or(JoanAbiStatusV1::PointerRangeInvalid)
}

fn overlaps(a_start: usize, a_end: usize, b_start: usize, b_end: usize) -> bool {
    a_start < b_end && b_start < a_end
}

/// Validate one complete Lattice frame in caller-owned memory without copying payloads.
///
/// # Safety
///
/// `frame..frame+frame_length` must lie inside one initialized contiguous
/// allocation, be readable, remain alive, and have no mutation (including
/// concurrent mutation) for the entire call. `binding` must point to one
/// initialized, aligned `JoanProgramBindingV1`. `out_view` must be aligned and
/// writable for at least `out_view_size` bytes. All ranges must remain valid for
/// the call, and the output must not overlap either input. JOAN checks nulls,
/// protocol bounds, arithmetic, structure alignment, and numeric overlap, but
/// raw C allocation provenance and lifetime cannot be proven in-process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn joan_lattice_validate_v1(
    frame: *const u8,
    frame_length: u64,
    binding: *const JoanProgramBindingV1,
    out_view: *mut JoanLatticeViewV1,
    out_view_size: u64,
) -> u32 {
    if frame.is_null() || binding.is_null() || out_view.is_null() {
        return JoanAbiStatusV1::NullArgument.code();
    }
    if out_view_size < size_of::<JoanLatticeViewV1>() as u64 {
        return JoanAbiStatusV1::OutputTooSmall.code();
    }
    if frame_length > MAX_BUFFER_LEN_V1 {
        return JoanAbiStatusV1::FrameTooLarge.code();
    }
    let Ok(frame_length_usize) = usize::try_from(frame_length) else {
        return JoanAbiStatusV1::FrameTooLarge.code();
    };

    let binding_start = binding as usize;
    let output_start = out_view as usize;
    if !binding_start.is_multiple_of(align_of::<JoanProgramBindingV1>())
        || !output_start.is_multiple_of(align_of::<JoanLatticeViewV1>())
    {
        return JoanAbiStatusV1::MisalignedArgument.code();
    }
    let frame_start = frame as usize;
    let frame_end = match checked_end(frame_start, frame_length_usize) {
        Ok(end) => end,
        Err(status) => return status.code(),
    };
    let binding_end = match checked_end(binding_start, size_of::<JoanProgramBindingV1>()) {
        Ok(end) => end,
        Err(status) => return status.code(),
    };
    let output_end = match checked_end(output_start, size_of::<JoanLatticeViewV1>()) {
        Ok(end) => end,
        Err(status) => return status.code(),
    };
    if overlaps(output_start, output_end, frame_start, frame_end)
        || overlaps(output_start, output_end, binding_start, binding_end)
    {
        return JoanAbiStatusV1::OutputOverlapsInput.code();
    }

    // SAFETY: the ABI contract requires an initialized, aligned, readable
    // binding. Null, alignment, range arithmetic, and output overlap were checked.
    let binding_value = unsafe { binding.read() };
    // SAFETY: the ABI contract requires a readable frame range. Null, the 16 MiB
    // bound, address arithmetic, and output overlap were checked first.
    let frame_slice = unsafe { core::slice::from_raw_parts(frame, frame_length_usize) };

    match validate_borrowed_lattice_v1(frame_slice, &binding_value) {
        Ok(view) => {
            // SAFETY: output is aligned, writable by contract, large enough, and
            // disjoint from both inputs. It is written only on success.
            unsafe { out_view.write(view) };
            JoanAbiStatusV1::Ok.code()
        }
        Err(status) => status.code(),
    }
}
