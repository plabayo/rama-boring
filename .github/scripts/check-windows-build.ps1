param(
    [Parameter(Mandatory)][string]$TargetDirectory,
    [ValidateSet('nasm', 'clang', 'none')][string]$Assembler = 'nasm',
    [ValidateSet('MultiThreaded', 'MultiThreadedDLL')][string]$Runtime = 'MultiThreadedDLL'
)
$ErrorActionPreference = 'Stop'
$caches = @(Get-ChildItem -LiteralPath $TargetDirectory -Filter CMakeCache.txt -Recurse)
if ($caches.Count -ne 1) { throw "Expected one clean BoringSSL build, found $($caches.Count)" }
$cache = Get-Content -LiteralPath $caches[0].FullName -Raw
if ($cache -notmatch 'CMAKE_CXX_FLAGS_RELWITHDEBINFO:[^=]+=.*[/\-]O2') {
    throw 'BoringSSL RelWithDebInfo lost native optimization'
}
if ($cache -notmatch 'CMAKE_CXX_FLAGS_RELWITHDEBINFO:[^=]+=.*[/\-]Zi') {
    throw 'BoringSSL RelWithDebInfo lost native debug symbols'
}
if ($cache -notmatch "(?m)^CMAKE_MSVC_RUNTIME_LIBRARY:[^=]+=$Runtime`r?$") {
    throw "Unexpected CRT; expected $Runtime"
}
if ($Assembler -eq 'none') {
    if ($cache -notmatch '(?m)^OPENSSL_NO_ASM:[^=]+=(TRUE|ON|1)\r?$') {
        throw 'Expected explicit unaccelerated compatibility fallback'
    }
} else {
    if ($cache -notmatch '(?m)^OPENSSL_NO_ASM:[^=]+=(FALSE|OFF|0)\r?$') {
        throw 'Assembly unexpectedly disabled'
    }
    $variable = if ($Assembler -eq 'nasm') { 'CMAKE_ASM_NASM_COMPILER' } else { 'CMAKE_ASM_COMPILER' }
    $compilerFile = if ($Assembler -eq 'nasm') { 'CMakeASM_NASMCompiler.cmake' } else { 'CMakeASMCompiler.cmake' }
    # A toolchain can set the compiler as a normal variable, not a cache entry.
    # CMake's generated compiler description records the actual selection.
    $compilerInfo = Get-ChildItem -LiteralPath $caches[0].DirectoryName -Recurse -Filter $compilerFile |
        ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }
    if (($compilerInfo -join "`n") -notmatch "set\($variable `"[^`"]*$Assembler[^`"]*`"\)") {
        throw "Expected assembler $Assembler"
    }
}
if ($cache -match '(?m)^CMAKE_GENERATOR:INTERNAL=Ninja' -and
    $cache -match '(?m)^CMAKE_GENERATOR_PLATFORM:[^=]+=\S+') {
    throw 'Ninja must not have a Visual Studio generator platform'
}
Write-Output "Verified $Assembler, optimized native code, symbols, and $Runtime in $($caches[0].FullName)"
