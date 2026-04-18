<#
.SYNOPSIS
    JMemoryAnalyser - production SOC/IR case triage engine.

.DESCRIPTION
    Creates a structured case folder, runs the full analysis stack against
    one or more .DMP files, and produces a case_summary.json.

    Analysis pipeline per dump:
      1. Basic scan  - strings, keywords, URL/IP, risk tier
      2. Minidump    - native MDMP header parse (no external deps)
      3. CDB plugins - OS version, PEB, threads, handles, modules,
                       exception, memory map, RWX regions, network IOCs
      4. YARA scan   - optional; requires -WithYara and rules under rules\vendor\yara

.PARAMETER CaseName
    Short identifier for the case (e.g. "incident01"). Used in folder name.

.PARAMETER Dumps
    One or more paths to .DMP files. Accepts an array or a comma-separated string.

.PARAMETER MaxMbScan
    Max megabytes to scan per dump in basic mode (default 512).

.PARAMETER UpdateRules
    Fetch / update YARA rules from upstream before scanning.

.PARAMETER WithYara
    Enable YARA scanning. Requires rules under rules\vendor\yara
    (run Update-JMA-Rules.ps1 first).

.PARAMETER RulesDir
    Path to YARA rules directory (default: .\rules\vendor\yara).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\Invoke-JMA-CaseTriage.ps1 `
        -CaseName "incident01" `
        -Dumps "C:\dumps\notepad.DMP","C:\dumps\chrome.DMP" `
        -WithYara

.EXAMPLE
    # Single dump, update rules first
    powershell -ExecutionPolicy Bypass -File .\scripts\Invoke-JMA-CaseTriage.ps1 `
        -CaseName "malware_triage" `
        -Dumps "C:\evidence\suspicious.DMP" `
        -UpdateRules -WithYara -MaxMbScan 1024
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$CaseName,

    [Parameter(Mandatory=$true)]
    [object]$Dumps,

    [int]$MaxMbScan   = 512,
    [switch]$UpdateRules,
    [switch]$WithYara,
    [string]$RulesDir = ".\rules\vendor\yara"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Normalize-Dumps([object]$x) {
    if ($null -eq $x) { return @() }
    $out = @()
    $items = if ($x -is [System.Array]) { $x } else { @([string]$x) }
    foreach ($e in $items) {
        if ($null -eq $e) { continue }
        $s = [string]$e
        if ($s -match ",") {
            $out += $s.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        } else {
            if ($s.Trim()) { $out += $s.Trim() }
        }
    }
    return $out
}

function New-CaseFolder([string]$name) {
    $stamp    = Get-Date -Format "yyyyMMdd_HHmmss"
    $casesDir = Join-Path $ProjectRoot "cases"
    New-Item -ItemType Directory -Force -Path $casesDir | Out-Null
    $casePath = Join-Path $casesDir ("{0}_{1}" -f $name, $stamp)
    New-Item -ItemType Directory -Force -Path (Join-Path $casePath "inputs")  | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $casePath "outputs") | Out-Null
    return $casePath
}

function Find-VenvPython {
    $venvPy = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $venvPy) {
        return (Resolve-Path -LiteralPath $venvPy).Path
    }
    throw "venv not found at $venvPy - run: powershell -ExecutionPolicy Bypass -File .\scripts\Install-JMA.ps1"
}

function Write-Section([string]$msg) {
    Write-Host ""
    Write-Host "------------------------------------------------------------"
    Write-Host " $msg"
    Write-Host "------------------------------------------------------------"
}

# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$dumpList    = Normalize-Dumps $Dumps

if ($dumpList.Count -lt 1) { throw "No dump paths provided." }

$casePath   = New-CaseFolder $CaseName
$inputsDir  = Join-Path $casePath "inputs"
$outputsDir = Join-Path $casePath "outputs"
$venvPy     = Find-VenvPython
$cliPy      = Join-Path $ProjectRoot "python\jma\cli.py"

Write-Host ""
Write-Host "============================================================"
Write-Host " JMemoryAnalyser - Case Triage"
Write-Host "============================================================"
Write-Host "Case    : $casePath"
Write-Host "Dumps   : $($dumpList.Count) file(s)"
Write-Host "YARA    : $(if ($WithYara) { 'enabled' } else { 'disabled' })"
Write-Host "Python  : $venvPy"
Write-Host ""

# Optional rule update
if ($UpdateRules) {
    Write-Section "Updating YARA rules from GitHub"
    $updateScript = Join-Path $ProjectRoot "scripts\Update-JMA-Rules.ps1"
    powershell -ExecutionPolicy Bypass -File $updateScript
}

# Resolve RulesDir to absolute path
if (-not [System.IO.Path]::IsPathRooted($RulesDir)) {
    $RulesDir = Join-Path $ProjectRoot $RulesDir
}

# ---------------------------------------------------------------------------
# Copy dumps into case inputs
# ---------------------------------------------------------------------------

$dumpTargets = @()
foreach ($d in $dumpList) {
    if (-not (Test-Path -LiteralPath $d)) {
        Write-Warning "Dump not found, skipping: $d"
        continue
    }
    $src = (Resolve-Path -LiteralPath $d).Path
    $dst = Join-Path $inputsDir ([System.IO.Path]::GetFileName($src))
    Copy-Item -Force -LiteralPath $src -Destination $dst
    $dumpTargets += $dst
    Write-Host "[+] Copied: $([System.IO.Path]::GetFileName($src))"
}

if ($dumpTargets.Count -lt 1) { throw "No valid dump files to process." }

# ---------------------------------------------------------------------------
# Analysis loop
# ---------------------------------------------------------------------------

$pluginPack  = @("osver","procinfo","threads","handles","modules","exception","memmap","rwx","netfind")
$familyTally = @{}

foreach ($dmp in $dumpTargets) {
    $base    = [System.IO.Path]::GetFileNameWithoutExtension($dmp)
    $outRoot = Join-Path $outputsDir $base
    $outBasic   = Join-Path $outRoot "basic"
    $outMinidump= Join-Path $outRoot "minidump"
    $outPlugins = Join-Path $outRoot "plugins"
    $outTriage  = Join-Path $outRoot "triage"

    foreach ($d in @($outBasic,$outMinidump,$outPlugins,$outTriage)) {
        New-Item -ItemType Directory -Force -Path $d | Out-Null
    }

    Write-Section "Processing: $([System.IO.Path]::GetFileName($dmp))"
    Write-Host "  Output: $outRoot"

    # 1) Basic scan
    Write-Host "[*] Basic scan..."
    & $venvPy $cliPy run --input $dmp --mode basic --out $outBasic --max-mb-scan $MaxMbScan
    Write-Host ""

    # 2) Native minidump parse (no external deps)
    Write-Host "[*] Minidump parse..."
    & $venvPy $cliPy run --input $dmp --mode minidump --out $outMinidump
    Write-Host ""

    # 3) CDB plugins (individual)
    foreach ($p in $pluginPack) {
        $pOut = Join-Path $outPlugins $p
        New-Item -ItemType Directory -Force -Path $pOut | Out-Null
        Write-Host "[*] Plugin: $p"
        & $venvPy $cliPy plugin --input $dmp --out $pOut --name $p
    }

    # 4) Combined triage pack
    Write-Host ""
    Write-Host "[*] Triage pack (combined)..."
    if ($WithYara) {
        & $venvPy $cliPy triage --input $dmp --out $outTriage `
            --max-mb-scan $MaxMbScan --with-yara --rules-dir $RulesDir
    } else {
        & $venvPy $cliPy triage --input $dmp --out $outTriage --max-mb-scan $MaxMbScan
    }

    # Aggregate YARA family labels from triage report
    $tri = Get-ChildItem -LiteralPath $outTriage -Filter "*_triage_*.json" -ErrorAction SilentlyContinue |
           Sort-Object LastWriteTime -Descending |
           Select-Object -First 1

    if ($tri) {
        try {
            $j  = Get-Content -LiteralPath $tri.FullName -Raw | ConvertFrom-Json
            $tf = $j.result.yara.top_family_labels
            if ($tf) {
                foreach ($x in $tf) {
                    $label = [string]$x.label
                    $cnt   = [int]$x.count
                    if (-not $familyTally.ContainsKey($label)) { $familyTally[$label] = 0 }
                    $familyTally[$label] += $cnt
                }
            }
        } catch { <# non-fatal: YARA may not have run #> }
    }
}

# ---------------------------------------------------------------------------
# Case summary
# ---------------------------------------------------------------------------

$familyList = @()
foreach ($k in $familyTally.Keys) {
    $familyList += [pscustomobject]@{ family = $k; score = $familyTally[$k] }
}
$familyList = $familyList | Sort-Object score -Descending

$summary = @{
    tool          = "JMemoryAnalyser"
    version       = "1.0.0"
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    case          = $casePath
    dumps         = $dumpTargets
    with_yara     = [bool]$WithYara
    rules_dir     = if (Test-Path -LiteralPath $RulesDir -ErrorAction SilentlyContinue) {
                        (Resolve-Path -LiteralPath $RulesDir).Path
                    } else { $RulesDir }
    top_families  = ($familyList | Select-Object -First 25)
    notes         = "Family scoring is based on YARA meta labels; heuristic and depends on rule quality."
}

$summaryPath = Join-Path $outputsDir "case_summary.json"
($summary | ConvertTo-Json -Depth 6) | Set-Content -Encoding UTF8 -LiteralPath $summaryPath

Write-Host ""
Write-Host "============================================================"
Write-Host " Case complete."
Write-Host "============================================================"
Write-Host "[+] Summary : $summaryPath"
Write-Host ""
Write-Host "Open outputs:"
Write-Host "  explorer `"$outputsDir`""
