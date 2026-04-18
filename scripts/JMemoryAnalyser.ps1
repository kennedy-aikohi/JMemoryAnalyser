<#
.SYNOPSIS
    JMemoryAnalyser - simple single-dump launcher.

.DESCRIPTION
    Runs a single analyser mode against one .DMP file and writes a JSON report.
    For production SOC/IR workflows use Invoke-JMA-CaseTriage.ps1 instead.

.PARAMETER InputPath
    Path to the .DMP file (required).

.PARAMETER Mode
    Analyser mode: basic | minidump | volatility (default: basic)
    - basic      : String extraction, keyword scanning, URL/IP harvest. No external deps.
    - minidump   : Native MDMP header parse (streams, modules, threads, exception). No external deps.
    - volatility : Volatility3 hooks. Best for full RAM images, not Task Manager dumps.

.PARAMETER OutDir
    Output directory for the JSON report (default: .\reports)

.PARAMETER MaxMbScan
    Maximum megabytes to scan for strings in basic mode (default: 256)

.PARAMETER OpenReport
    Open the generated JSON report automatically after analysis.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\JMemoryAnalyser.ps1 `
        -InputPath "C:\cases\notepad.DMP" -Mode basic

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\JMemoryAnalyser.ps1 `
        -InputPath "C:\cases\notepad.DMP" -Mode minidump -OutDir "C:\cases\out"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$InputPath,

    [Parameter(Mandatory=$false)]
    [ValidateSet("basic","minidump","volatility")]
    [string]$Mode = "basic",

    [Parameter(Mandatory=$false)]
    [string]$OutDir = "",

    [Parameter(Mandatory=$false)]
    [int]$MaxMbScan = 256,

    [Parameter(Mandatory=$false)]
    [switch]$OpenReport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Resolve script location robustly
if ($PSCommandPath) {
    $ScriptDir = Split-Path -Parent $PSCommandPath
} elseif ($MyInvocation.MyCommand.Path) {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
} else {
    $ScriptDir = (Resolve-Path ".\scripts").Path
}
$ProjectRoot = (Resolve-Path (Join-Path $ScriptDir "..")).Path

# ---- Helpers ---------------------------------------------------------------

function Find-VenvPython {
    $venvPy = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $venvPy) {
        return (Resolve-Path -LiteralPath $venvPy).Path
    }
    throw "venv not found. Run first: powershell -ExecutionPolicy Bypass -File .\scripts\Install-JMA.ps1"
}

function Ensure-Dir([string]$dir) {
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    return (Resolve-Path -LiteralPath $dir).Path
}

function Write-Header([string]$title) {
    Write-Host ""
    Write-Host "============================================================"
    Write-Host " JMemoryAnalyser - $title"
    Write-Host "============================================================"
    Write-Host ""
}

# ---- Main ------------------------------------------------------------------

$absInput = (Resolve-Path -LiteralPath $InputPath -ErrorAction Stop).Path
if (-not $OutDir) {
    $OutDir = Join-Path $ProjectRoot "reports"
}
$absOut   = Ensure-Dir $OutDir
$venvPy   = Find-VenvPython
$cliPy    = Join-Path $ProjectRoot "python\jma\cli.py"

if (-not (Test-Path -LiteralPath $cliPy)) {
    throw "cli.py not found: $cliPy. Ensure the project structure is intact."
}

Write-Header "Single Dump Analysis"
Write-Host "Input  : $absInput"
Write-Host "Mode   : $Mode"
Write-Host "Out    : $absOut"
Write-Host "Python : $venvPy"
Write-Host ""

# BUG FIX: original script passed --input/--mode directly (no subcommand).
# cli.py requires the 'run' subcommand before the flags.
& $venvPy $cliPy run `
    --input  "$absInput" `
    --mode   $Mode `
    --out    "$absOut" `
    --max-mb-scan $MaxMbScan

$exitCode = $LASTEXITCODE

$lastReport = Get-ChildItem -LiteralPath $absOut -Filter "*.json" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if ($lastReport) {
    Write-Host ""
    Write-Host "[+] Latest report: $($lastReport.FullName)"
    if ($OpenReport) {
        Invoke-Item -LiteralPath $lastReport.FullName
    }
} else {
    Write-Warning "No JSON report was produced in $absOut"
}

exit $exitCode
