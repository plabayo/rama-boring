param(
    [Parameter(Mandatory)][string]$TargetDirectory,
    [ValidateSet('Release', 'RelWithDebInfo')][string]$BuildType = 'RelWithDebInfo',
    [ValidateSet('nasm', 'clang', 'none')][string]$Assembler = 'nasm',
    [ValidateSet('MultiThreaded', 'MultiThreadedDLL')][string]$Runtime = 'MultiThreadedDLL'
)
$ErrorActionPreference = 'Stop'
$caches = @(Get-ChildItem -LiteralPath $TargetDirectory -Filter CMakeCache.txt -Recurse)
if ($caches.Count -ne 1) { throw "Expected one clean BoringSSL build, found $($caches.Count)" }
$cache = Get-Content -LiteralPath $caches[0].FullName -Raw
function Get-CacheValue([string]$Name) {
    $entry = [regex]::Match($cache, "(?m)^$([regex]::Escape($Name)):[^=\r\n]+=([^\r\n]*)\r?$")
    if (!$entry.Success) { throw "Missing CMake setting $Name" }
    return $entry.Groups[1].Value
}
if ((Get-CacheValue 'CMAKE_BUILD_TYPE') -cne $BuildType) {
    throw "Unexpected native build profile; expected $BuildType"
}
foreach ($language in @('C', 'CXX')) {
    foreach ($configuration in @('RELEASE', 'RELWITHDEBINFO')) {
        $variable = "CMAKE_${language}_FLAGS_$configuration"
        # Profile flags follow the common flags. Check the last optimization
        # switch so an /Od or /O1 after /O2 cannot silently pass the guard.
        $flags = "$(Get-CacheValue "CMAKE_${language}_FLAGS") $(Get-CacheValue $variable)"
        $optimization = [regex]::Matches($flags, '(?:^|\s)[/\-]O([012dx])(?=\s|$)')
        if (!$optimization.Count -or $optimization[-1].Groups[1].Value -cne '2') {
            throw "BoringSSL $variable lost native optimization: $flags"
        }
        if ($configuration -eq 'RELWITHDEBINFO' -and $flags -cnotmatch '(?:^|\s)[/\-]Zi(?=\s|$)') {
            throw "BoringSSL $variable lost native debug symbols"
        }
    }
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
Write-Output "Verified $BuildType build, C/C++ Release and RelWithDebInfo flags, $Assembler, and $Runtime in $($caches[0].FullName)"
