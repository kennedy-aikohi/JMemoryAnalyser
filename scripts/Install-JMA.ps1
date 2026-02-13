[CmdletBinding()]
param(
  [switch]$WithMinidump,
  [switch]$WithVolatility
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$venvPath    = Join-Path $projectRoot ".venv"
$python      = Get-Command python -ErrorAction Stop

Write-Host "Project: $projectRoot"
Write-Host "Python : $($python.Source)"

if (-not (Test-Path $venvPath)) {
  Write-Host "Creating venv at $venvPath"
  & $python.Source -m venv $venvPath
}

$venvPython = Join-Path $venvPath "Scripts\python.exe"
if (-not (Test-Path $venvPython)) { throw "venv python not found: $venvPython" }

Write-Host "Upgrading pip..."
& $venvPython -m pip install --upgrade pip

# Baseline: no heavy deps required, but install "pefile" for optional parsing helpers
Write-Host "Installing baseline deps..."
& $venvPython -m pip install pefile

if ($WithMinidump) {
  Write-Host "Installing minidump parser..."
  & $venvPython -m pip install minidump
}

if ($WithVolatility) {
  Write-Host "Installing volatility3..."
  & $venvPython -m pip install volatility3
}

Write-Host ""
Write-Host "Done."
Write-Host "Use venv python by running:"
Write-Host "  $venvPython"
Write-Host ""
Write-Host "Or run JMemoryAnalyser with:"
Write-Host "  powershell -ExecutionPolicy Bypass -File .\scripts\JMemoryAnalyser.ps1 -InputPath <dumpfile> -Mode basic"
