<#
.SYNOPSIS
    JMemoryAnalyser environment installer.

.DESCRIPTION
    Creates a Python virtual environment and installs all required
    and optional dependencies for JMemoryAnalyser including the GUI.

.PARAMETER WithMinidump
    Install the 'minidump' package for extra MDMP parser coverage.

.PARAMETER WithVolatility
    Install 'volatility3' for full memory image analysis.

.PARAMETER WithYara
    Install 'yara-python' for YARA scanning.
    NOTE: Requires Visual C++ build tools on Windows.
    If pip install fails, download a pre-built wheel from:
    https://github.com/VirusTotal/yara-python/releases

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\Install-JMA.ps1

    powershell -ExecutionPolicy Bypass -File .\scripts\Install-JMA.ps1 -WithYara -WithVolatility

    powershell -ExecutionPolicy Bypass -File .\scripts\Install-JMA.ps1 -WithYara -WithMinidump -WithVolatility
#>

[CmdletBinding()]
param(
    [switch]$WithMinidump,
    [switch]$WithVolatility,
    [switch]$WithYara
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$venvPath    = Join-Path $projectRoot ".venv"

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    throw "Python not found in PATH. Install Python 3.10+ and restart PowerShell."
}

$verStr = & $python.Source --version 2>&1
Write-Host "Python : $verStr"
Write-Host "Project: $projectRoot"

if (-not (Test-Path -LiteralPath $venvPath)) {
    Write-Host "[*] Creating venv at $venvPath ..."
    & $python.Source -m venv $venvPath
} else {
    Write-Host "[*] venv already exists at $venvPath"
}

$venvPy = Join-Path $venvPath "Scripts\python.exe"
if (-not (Test-Path -LiteralPath $venvPy)) {
    throw "venv python not found: $venvPy"
}

Write-Host ""
Write-Host "[*] Upgrading pip..."
& $venvPy -m pip install --upgrade pip --quiet

Write-Host "[*] Installing baseline dependencies..."
& $venvPy -m pip install pefile --quiet

Write-Host "[*] Installing Flask (required for GUI)..."
& $venvPy -m pip install flask --quiet

if ($WithMinidump) {
    Write-Host "[*] Installing minidump parser..."
    & $venvPy -m pip install minidump --quiet
}

if ($WithYara) {
    Write-Host "[*] Installing yara-python..."
    Write-Host "    (Requires Visual C++ build tools)"
    & $venvPy -m pip install yara-python
}

if ($WithVolatility) {
    Write-Host "[*] Installing volatility3..."
    & $venvPy -m pip install volatility3 --quiet
}

Write-Host "[*] Installing JMemoryAnalyser package (editable)..."
& $venvPy -m pip install -e $projectRoot --quiet

Write-Host ""
Write-Host "============================================================"
Write-Host " Install complete."
Write-Host "============================================================"
Write-Host ""
Write-Host "Launch the GUI:"
Write-Host "  powershell -ExecutionPolicy Bypass -File .\scripts\Launch-JMA-GUI.ps1"
Write-Host ""
Write-Host "CLI modes:"
Write-Host "  Basic scan   : jma run --input file.DMP --mode basic --out .\reports"
Write-Host "  MDMP parse   : jma run --input file.DMP --mode minidump --out .\reports"
Write-Host "  Volatility   : jma run --input image.raw --mode volatility --out .\reports"
Write-Host "  Vol plugins  : jma vol --input image.raw --plugins windows.pslist,windows.malfind --out .\reports"
Write-Host "  Full triage  : jma triage --input image.raw --with-vol --with-yara --out .\reports"
Write-Host ""
