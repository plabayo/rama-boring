param(
    [Parameter(Mandatory)][string]$OutputDirectory,
    [string]$Xperf = 'xperf',
    [string]$SymbolPath
)
$ErrorActionPreference = 'Stop'
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$metadata = Get-Content -LiteralPath "$OutputDirectory\environment.json" -Raw | ConvertFrom-Json
$relayProcessId = [int]((Get-Content -LiteralPath "$OutputDirectory\pids.txt") -replace '^relayPid=', '')
$oldSymbols = $env:_NT_SYMBOL_PATH
$oldCache = $env:_NT_SYMCACHE_PATH
try {
    $env:_NT_SYMBOL_PATH = if ($SymbolPath) { $SymbolPath } else {
        @((Split-Path $metadata.relay), (Split-Path $metadata.endpoint)) -join ';'
    }
    if (!$env:_NT_SYMCACHE_PATH) {
        $env:_NT_SYMCACHE_PATH = "$OutputDirectory\symcache"
    }
    New-Item -ItemType Directory -Force -Path $env:_NT_SYMCACHE_PATH | Out-Null
    & $Xperf -i "$OutputDirectory\cpu.etl" -symbols -o "$OutputDirectory\samples.csv" -a profile -detail
    if ($LASTEXITCODE -ne 0) { throw 'xperf leaf analysis failed' }
    & $Xperf -i "$OutputDirectory\cpu.etl" -symbols -o "$OutputDirectory\stacks.html" -a stack -butterfly 10 -pid $relayProcessId -event 'Sampled Profile'
    if ($LASTEXITCODE -ne 0) { throw 'xperf stack analysis failed' }
    & $Xperf -i "$OutputDirectory\cpu.etl" -o "$OutputDirectory\trace-stats.txt" -a tracestats
    if ($LASTEXITCODE -ne 0) { throw 'xperf trace statistics failed' }

    # xperf's Usage % is relative to the whole trace/machine. Normalize only
    # this relay's weighted CPU samples, including work in kernel modules.
    $name = [regex]::Escape([IO.Path]::GetFileName($metadata.relay))
    $pattern = "^$name \($relayProcessId\),\s*(\d+),\s*[\d.]+,\s*(.*)$"
    $samples = @(Get-Content -LiteralPath "$OutputDirectory\samples.csv" | ForEach-Object {
        if ($_ -match $pattern) {
            [pscustomobject]@{ weightMicroseconds = [long]$Matches[1]; symbol = $Matches[2] }
        }
    })
    if (!$samples.Count) { throw "No CPU samples found for relay PID $relayProcessId" }
    $total = ($samples | Measure-Object weightMicroseconds -Sum).Sum
    $samples | Sort-Object weightMicroseconds -Descending | ForEach-Object {
        [pscustomobject]@{
            weightMicroseconds = $_.weightMicroseconds
            percentOfRelay = (100 * $_.weightMicroseconds / $total).ToString('F6', [Globalization.CultureInfo]::InvariantCulture)
            symbol = $_.symbol
        }
    } | Export-Csv -LiteralPath "$OutputDirectory\relay-leaves.csv" -NoTypeInformation

    # xperf emits HTML with unescaped Rust generic names, so XML parsing is
    # inappropriate. Extract only its table/cell/link tags, preserving symbols.
    $html = Get-Content -LiteralPath "$OutputDirectory\stacks.html" -Raw
    $tables = [regex]::Matches($html, '(?s)<table\b[^>]*>(.*?)</table>')
    if ($tables.Count -ne 6) { throw 'Unexpected xperf stack report structure' }
    [regex]::Matches($tables[3].Groups[1].Value, '(?s)<tr\b[^>]*>(.*?)</tr>') | ForEach-Object {
        $cells = @([regex]::Matches($_.Groups[1].Value, '(?s)<td\b[^>]*>(.*?)</td>') | ForEach-Object {
            [Net.WebUtility]::HtmlDecode(($_.Groups[1].Value -replace '</?a\b[^>]*>|</?p>|<br\s*/?>', ''))
        })
        if ($cells.Count -eq 7) {
            [pscustomobject]@{
                symbol = $cells[0]; inclusiveHits = [long]$cells[1]
                percentOfRelayStacks = $cells[2].TrimEnd('%'); exclusiveHits = [long]$cells[3]
            }
        }
    } | Export-Csv -LiteralPath "$OutputDirectory\relay-inclusive.csv" -NoTypeInformation
    "Relay PID $relayProcessId`: $total microseconds of weighted CPU samples. Check trace-stats.txt for event loss."
} finally {
    $env:_NT_SYMBOL_PATH = $oldSymbols
    $env:_NT_SYMCACHE_PATH = $oldCache
}
