//! Policy for the default Windows toolchain. Explicit CMake toolchain files
//! bypass this policy and own their compiler, assembler and CRT configuration.

pub(crate) fn needs_no_asm(host: &str, target_arch: &str) -> bool {
    // The vendored Windows x86/x64 assembly uses NASM, which recent CMake
    // Visual Studio generators support, including cross-architecture builds.
    // ARM64 uses preprocessed GNU-style .S files: neither cl.exe nor armasm64
    // can assemble these. Keep the compatibility fallback for that toolchain.
    host.contains("windows") && !matches!(target_arch, "x86" | "x86_64")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_and_cross_windows_x86_use_nasm() {
        for host in ["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"] {
            for arch in ["x86", "x86_64"] {
                assert!(!needs_no_asm(host, arch), "{host} -> {arch}");
            }
        }
    }

    #[test]
    fn default_arm64_keeps_compatibility_fallback() {
        for host in ["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"] {
            assert!(needs_no_asm(host, "aarch64"));
        }
    }

    #[test]
    fn non_windows_cross_toolchains_are_not_disabled() {
        for arch in ["x86", "x86_64", "aarch64"] {
            assert!(!needs_no_asm("x86_64-unknown-linux-gnu", arch));
        }
    }
}
