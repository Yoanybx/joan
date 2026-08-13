//! Configures the platform-specific dynamic-library identity for the JOAN ABI.

fn main() {
    #[cfg(target_os = "macos")]
    println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/libjoan_abi.dylib");
}
