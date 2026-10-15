# Opt-in accelerated Windows ARM64 toolchain, for native or cross builds.
# Run in a Visual Studio ARM64 developer environment, with LLVM and Ninja on
# PATH. Select CMAKE_GENERATOR=Ninja and this file via CMAKE_TOOLCHAIN_FILE.
# NASM and Microsoft's armasm64 cannot assemble BoringSSL's ARM64 .S files.
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR ARM64)
set(CMAKE_C_COMPILER clang-cl)
set(CMAKE_CXX_COMPILER clang-cl)
set(CMAKE_C_COMPILER_TARGET aarch64-pc-windows-msvc)
set(CMAKE_CXX_COMPILER_TARGET aarch64-pc-windows-msvc)
set(CMAKE_ASM_COMPILER clang-cl)
# CMake uses the MSVC command-line dialect when C/CXX use clang-cl, so use
# that driver for .S too. Drop cmake-rs's C flags and target the integrated
# assembler explicitly (independent of the build host).
set(CMAKE_ASM_FLAGS "--target=aarch64-pc-windows-msvc" CACHE STRING "" FORCE)
set(OPENSSL_NO_ASM FALSE CACHE BOOL "" FORCE)

if("$ENV{CARGO_CFG_TARGET_FEATURE}" MATCHES "(^|,)crt-static(,|$)")
  set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreaded CACHE STRING "" FORCE)
else()
  set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreadedDLL CACHE STRING "" FORCE)
endif()
# Rust links the release CRT even for debug profiles.
set(CMAKE_C_FLAGS_DEBUG "/Zi /Ob0 /Od /RTC1" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS_DEBUG "/Zi /Ob0 /Od /RTC1" CACHE STRING "" FORCE)
