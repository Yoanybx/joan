//! Allocation-counting proof for successful, rejected, and maximum-size hot paths.

#![allow(unsafe_code)]

use joan_abi::{
    JoanAbiStatusV1, JoanLatticeViewV1, JoanProgramBindingV1, MAX_BUFFER_LEN_V1,
    SEMANTIC_PROFILE_LEGACY_V1, joan_lattice_validate_v1, validate_borrowed_lattice_v1,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct CountingAllocator;

static TRACKING: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if TRACKING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: this allocator delegates the original layout to System.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if TRACKING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: this allocator delegates the original layout to System.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the pointer and layout came from System through this allocator.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if TRACKING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: the pointer and layout came from System through this allocator.
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn binding() -> Result<JoanProgramBindingV1, JoanAbiStatusV1> {
    JoanProgramBindingV1::new(SEMANTIC_PROFILE_LEGACY_V1, [3u8; 32])
}

fn valid_frame(length: usize) -> Vec<u8> {
    let mut frame = vec![0u8; length];
    frame[..4].copy_from_slice(b"JNL0");
    if length > 96 {
        frame[7] = 1;
        let payload_length = u32::try_from(length - 96).unwrap_or(u32::MAX);
        frame[72..76].copy_from_slice(&payload_length.to_be_bytes());
    }
    frame
}

fn measured_allocations(operation: impl FnOnce()) -> usize {
    ALLOCATIONS.store(0, Ordering::SeqCst);
    TRACKING.store(true, Ordering::SeqCst);
    operation();
    TRACKING.store(false, Ordering::SeqCst);
    ALLOCATIONS.load(Ordering::SeqCst)
}

#[test]
fn hot_validation_allocates_zero_bytes() -> Result<(), JoanAbiStatusV1> {
    let binding = binding()?;
    let valid = valid_frame(100);
    let maximum = valid_frame(
        usize::try_from(MAX_BUFFER_LEN_V1).map_err(|_| JoanAbiStatusV1::InternalInvariant)?,
    );
    let truncated = [0u8; 95];
    let mut invalid_magic = [0u8; 96];
    invalid_magic[..4].copy_from_slice(b"XXXX");

    for input in [&valid[..], &maximum[..], &truncated, &invalid_magic] {
        let count = measured_allocations(|| {
            let _ = core::hint::black_box(validate_borrowed_lattice_v1(input, &binding));
        });
        assert_eq!(count, 0);

        let ffi_count = measured_allocations(|| {
            let mut output = MaybeUninit::<JoanLatticeViewV1>::uninit();
            // SAFETY: input, binding, and output are valid, aligned, bounded,
            // writable where required, and mutually disjoint for this call.
            let status = unsafe {
                joan_lattice_validate_v1(
                    input.as_ptr(),
                    u64::try_from(input.len()).unwrap_or(u64::MAX),
                    &raw const binding,
                    output.as_mut_ptr(),
                    u64::try_from(core::mem::size_of::<JoanLatticeViewV1>()).unwrap_or(u64::MAX),
                )
            };
            core::hint::black_box(status);
            core::hint::black_box(output);
        });
        assert_eq!(ffi_count, 0);
    }
    Ok(())
}
