$ErrorActionPreference = 'Stop'
$checker = Join-Path $PSScriptRoot 'check-windows-build.ps1'
$directory = Join-Path ([IO.Path]::GetTempPath()) "boring-build-check-$([guid]::NewGuid())"
New-Item -ItemType Directory -Path $directory | Out-Null
$cachePath = Join-Path $directory 'CMakeCache.txt'
$baseline = @'
CMAKE_BUILD_TYPE:STRING=RelWithDebInfo
CMAKE_C_FLAGS:STRING=-nologo -MD -Brepro -W0
CMAKE_CXX_FLAGS:STRING=-nologo -MD -Brepro -W0
CMAKE_C_FLAGS_RELEASE:STRING=/O2 /Ob2 /DNDEBUG
CMAKE_CXX_FLAGS_RELEASE:STRING=/O2 /Ob2 /DNDEBUG
CMAKE_C_FLAGS_RELWITHDEBINFO:STRING=/Zi /O2 /Ob1 /DNDEBUG
CMAKE_CXX_FLAGS_RELWITHDEBINFO:STRING=/Zi /O2 /Ob1 /DNDEBUG
CMAKE_MSVC_RUNTIME_LIBRARY:STRING=MultiThreadedDLL
OPENSSL_NO_ASM:BOOL=TRUE
CMAKE_GENERATOR:INTERNAL=Visual Studio 17 2022
'@

function Assert-Rejected([string]$Name, [string]$Contents, [string]$ExpectedMessage, [string]$BuildType = 'RelWithDebInfo') {
    Set-Content -LiteralPath $cachePath -Value $Contents
    try {
        & $checker -TargetDirectory $directory -BuildType $BuildType -Assembler none | Out-Null
    } catch {
        if (!$_.Exception.Message.Contains($ExpectedMessage)) { throw }
        Write-Output "Rejected $Name"
        return
    }
    throw "Build-settings checker accepted $Name"
}

try {
    foreach ($buildType in @('Release', 'RelWithDebInfo')) {
        Set-Content -LiteralPath $cachePath -Value ($baseline.Replace('CMAKE_BUILD_TYPE:STRING=RelWithDebInfo', "CMAKE_BUILD_TYPE:STRING=$buildType"))
        & $checker -TargetDirectory $directory -BuildType $buildType -Assembler none
    }
    foreach ($language in @('C', 'CXX')) {
        foreach ($buildType in @('RELEASE', 'RELWITHDEBINFO')) {
            $variable = "CMAKE_${language}_FLAGS_$buildType"
            $flags = if ($buildType -eq 'RELEASE') { '/O2 /Ob2 /DNDEBUG' } else { '/Zi /O2 /Ob1 /DNDEBUG' }
            $entry = "${variable}:STRING=$flags"
            Assert-Rejected "$variable without optimization" ($baseline.Replace($entry, "${variable}:STRING=-nologo -MD -Brepro -W0")) "$variable lost native optimization"
            Assert-Rejected "$variable with a later /Od" ($baseline.Replace($entry, "$entry /Od")) "$variable lost native optimization"
        }
        $variable = "CMAKE_${language}_FLAGS_RELWITHDEBINFO"
        Assert-Rejected "$variable without symbols" ($baseline.Replace("${variable}:STRING=/Zi", "${variable}:STRING=")) "$variable lost native debug symbols"
    }
    Assert-Rejected 'wrong active profile' $baseline 'Unexpected native build profile' 'Release'
    Assert-Rejected 'missing active profile' ($baseline.Replace('CMAKE_BUILD_TYPE:STRING=RelWithDebInfo', '')) 'Missing CMake setting CMAKE_BUILD_TYPE'
    Write-Output 'Windows build-settings regression checks passed'
} finally {
    Remove-Item -LiteralPath $directory -Recurse -Force
}
