//! Auditable unsafe boundary for finalized JIT code and executable-memory ownership.

use cranelift_jit::JITModule;
use cranelift_module::FuncId;
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};

/// Uniform host ABI emitted for every JOAN native wrapper.
type NativeEntrypointFn = unsafe extern "C" fn(*const i64, *mut u64, *mut i64) -> u32;

/// Typed handle that cannot be constructed from an arbitrary pointer outside this module.
#[derive(Clone, Copy)]
pub(crate) struct NativeEntrypoint(NativeEntrypointFn);

/// JIT module whose executable mappings are explicitly released on every exit path.
pub(crate) struct OwnedJitModule(ManuallyDrop<JITModule>);

impl OwnedJitModule {
    pub(crate) const fn new(module: JITModule) -> Self {
        Self(ManuallyDrop::new(module))
    }
}

impl Deref for OwnedJitModule {
    type Target = JITModule;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for OwnedJitModule {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for OwnedJitModule {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: this wrapper owns the module. Rust lifetimes prevent a prepared invocation
            // from outliving its NativeProgram, so no generated function can remain callable.
            ManuallyDrop::take(&mut self.0).free_memory();
        }
    }
}

/// Resolve one finalized Cranelift function to the exact private wrapper ABI.
pub(crate) fn finalized_entrypoint(module: &JITModule, function: FuncId) -> NativeEntrypoint {
    let pointer = module.get_finalized_function(function);
    unsafe {
        // SAFETY: this module only resolves finalized private wrappers emitted with the exact
        // NativeEntrypointFn signature. The untyped pointer never crosses this boundary.
        NativeEntrypoint(std::mem::transmute::<*const u8, NativeEntrypointFn>(
            pointer,
        ))
    }
}

/// Invoke one wrapper while typed borrowed host storage remains live.
pub(crate) fn invoke_entrypoint(
    entrypoint: NativeEntrypoint,
    arguments: &[i64],
    remaining: &mut u64,
    output: &mut i64,
) -> u32 {
    unsafe {
        // SAFETY: references provide aligned live storage for the call. NativeEntrypoint can only
        // be constructed above from a finalized wrapper, and its owning module remains borrowed.
        entrypoint.0(arguments.as_ptr(), remaining, output)
    }
}
