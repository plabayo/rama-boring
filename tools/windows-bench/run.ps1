param(
    [Parameter(Mandatory)][string]$EndpointExe,
    [Parameter(Mandatory)][string]$RelayExe,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [int]$PayloadMiB = 256,
    [int]$Repeats = 3,
    [int]$OriginPort = 19443,
    [int]$RelayPort = 19444,
    [switch]$Profile,
    [string]$WprProfile = "$PSScriptRoot\cpu-sampling.wprp!BoringCpu"
)
$ErrorActionPreference = 'Stop'
$EndpointExe = (Resolve-Path -LiteralPath $EndpointExe).Path
$RelayExe = (Resolve-Path -LiteralPath $RelayExe).Path
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
if (-not ('WindowsBenchArchitecture' -as [type])) {
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class WindowsBenchArchitecture {
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine);
}
'@
}

function PeMachine([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $reader = [IO.BinaryReader]::new($stream)
    try {
        $stream.Position = 0x3c
        $offset = $reader.ReadInt32()
        $stream.Position = $offset + 4
        return ('0x{0:x4}' -f $reader.ReadUInt16())
    } finally { $reader.Dispose(); $stream.Dispose() }
}

function WaitReady($Process, [string]$Log) {
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($Process.HasExited) { throw "Server exited: $(Get-Content -LiteralPath $Log -Raw)" }
        if ((Test-Path -LiteralPath $Log) -and (Select-String -LiteralPath $Log -Pattern 'ready ' -Quiet)) { return }
        Start-Sleep -Milliseconds 100
    }
    throw "Server readiness timeout: $Log"
}

$cpu = Get-CimInstance Win32_Processor
$os = Get-CimInstance Win32_OperatingSystem
[ordered]@{
    os = $os.Caption; osVersion = $os.Version; osArchitecture = $os.OSArchitecture
    cpu = $cpu.Name; cpuArchitecture = $cpu.Architecture
    logicalProcessors = $cpu.NumberOfLogicalProcessors
    endpoint = $EndpointExe; endpointMachine = (PeMachine $EndpointExe)
    endpointHash = (Get-FileHash -LiteralPath $EndpointExe).Hash
    relay = $RelayExe; relayMachine = (PeMachine $RelayExe)
    relayHash = (Get-FileHash -LiteralPath $RelayExe).Hash
    payloadMiB = $PayloadMiB; repeats = $Repeats
    httpLogging = 'off'; cipher = 'ECDHE-RSA-AES128-GCM-SHA256'; tls = '1.2'
    wprProfile = $(if ($Profile) { $WprProfile } else { $null })
} | ConvertTo-Json | Set-Content -LiteralPath "$OutputDirectory\environment.json"

$origin = $null
$relay = $null
$recording = $false
try {
    if ($Profile) {
        # Do not stop someone else's WPR session. A conflicting start fails.
        wpr -start $WprProfile -filemode
        if ($LASTEXITCODE -ne 0) { throw 'WPR could not start CPU recording' }
        $recording = $true
    }
    $origin = Start-Process -FilePath $EndpointExe -ArgumentList "origin $OriginPort $PayloadMiB" -PassThru -WindowStyle Hidden -RedirectStandardError "$OutputDirectory\origin.log" -RedirectStandardOutput "$OutputDirectory\origin.out"
    WaitReady $origin "$OutputDirectory\origin.log"
    $relay = Start-Process -FilePath $RelayExe -ArgumentList "relay $RelayPort $OriginPort" -PassThru -WindowStyle Hidden -RedirectStandardError "$OutputDirectory\relay.log" -RedirectStandardOutput "$OutputDirectory\relay.out"
    WaitReady $relay "$OutputDirectory\relay.log"
    "relayPid=$($relay.Id)" | Set-Content -LiteralPath "$OutputDirectory\pids.txt"
    [ushort]$processMachine = 0
    [ushort]$nativeMachine = 0
    if (![WindowsBenchArchitecture]::IsWow64Process2($relay.Handle, [ref]$processMachine, [ref]$nativeMachine)) {
        throw 'IsWow64Process2 failed'
    }
    [ordered]@{
        pid = $relay.Id; processMachine = ('0x{0:x4}' -f $processMachine)
        nativeMachine = ('0x{0:x4}' -f $nativeMachine)
        wow64 = ($processMachine -ne 0)
        # x86 on AMD64 uses the processor's compatibility mode. WOW64 alone
        # does not imply the x64-on-ARM64 CPU emulation relevant to this issue.
        emulated = ($nativeMachine -eq 0xaa64 -and $processMachine -in @(0x8664, 0x014c))
    } | ConvertTo-Json | Set-Content -LiteralPath "$OutputDirectory\process-architecture.json"
    $rows = @()
    foreach ($mode in @('direct', 'proxy')) {
        for ($iteration = 1; $iteration -le $Repeats; $iteration++) {
            $relay.Refresh()
            $cpuBefore = $relay.TotalProcessorTime.TotalSeconds
            $timer = [Diagnostics.Stopwatch]::StartNew()
            $result = if ($mode -eq 'proxy') {
                & $EndpointExe download $RelayPort proxy 2>> "$OutputDirectory\client.log"
            } else {
                & $EndpointExe download $OriginPort 2>> "$OutputDirectory\client.log"
            }
            if ($LASTEXITCODE -ne 0) { throw "Download failed: $result" }
            $timer.Stop()
            $relay.Refresh()
            $cpuSeconds = $relay.TotalProcessorTime.TotalSeconds - $cpuBefore
            $parts = $result.Split(',')
            $row = [pscustomobject]@{
                mode = $mode; iteration = $iteration; bytes = [long]$parts[1]
                seconds = [double]::Parse($parts[2], [Globalization.CultureInfo]::InvariantCulture)
                mbps = [double]::Parse($parts[3], [Globalization.CultureInfo]::InvariantCulture)
                relayCpuSeconds = $cpuSeconds
                relayCpuPercentOfOneCore = 100 * $cpuSeconds / $timer.Elapsed.TotalSeconds
            }
            $rows += $row
            $row | ConvertTo-Json -Compress
        }
    }
    $rows | ConvertTo-Json | Set-Content -LiteralPath "$OutputDirectory\downloads.json"
    $rows | ForEach-Object {
        $fields = [ordered]@{}
        foreach ($property in $_.PSObject.Properties) {
            $value = $property.Value
            $fields[$property.Name] = if ($value -is [IFormattable]) {
                $value.ToString($null, [Globalization.CultureInfo]::InvariantCulture)
            } else { $value }
        }
        [pscustomobject]$fields
    } | Export-Csv -LiteralPath "$OutputDirectory\downloads.csv" -NoTypeInformation
} finally {
    foreach ($process in @($relay, $origin)) {
        if ($null -ne $process -and !$process.HasExited) { Stop-Process -Id $process.Id }
    }
    if ($recording) {
        wpr -stop "$OutputDirectory\cpu.etl"
        if ($LASTEXITCODE -ne 0) { Write-Error 'WPR could not save the CPU trace' }
    }
}
