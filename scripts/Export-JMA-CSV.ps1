<#
.SYNOPSIS
    Convert all JMemoryAnalyser JSON outputs in a case to CSV.

.DESCRIPTION
    Walks the case outputs directory, converts every *.json report to one
    or more analyst-friendly CSVs, and writes them under a _csv subfolder
    (or the path specified by -OutDir).

.PARAMETER CaseOutputsDir
    Path to the case outputs directory (e.g. .\cases\incident01_20250101\outputs).

.PARAMETER OutDir
    Destination directory for CSV files (default: <CaseOutputsDir>\_csv).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\Export-JMA-CSV.ps1 `
        -CaseOutputsDir ".\cases\incident01_20250101_120000\outputs"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$CaseOutputsDir,

    [string]$OutDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

$venvPy = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $venvPy)) {
    throw "venv python not found: $venvPy - run: powershell -ExecutionPolicy Bypass -File .\scripts\Install-JMA.ps1"
}
$venvPy = (Resolve-Path -LiteralPath $venvPy).Path

$inDir = (Resolve-Path -LiteralPath $CaseOutputsDir -ErrorAction Stop).Path

if (-not $OutDir) {
    $OutDir = Join-Path $inDir "_csv"
}
$outDirAbs = (New-Item -ItemType Directory -Force -Path $OutDir).FullName

# BUG FIX: original called export_csv.py as a script directly, which fails when
# the jma package is not on sys.path. Use 'python -m jma.export_csv' instead so
# the package import chain resolves correctly via the installed editable package.
Write-Host "[*] Input : $inDir"
Write-Host "[*] Output: $outDirAbs"
Write-Host ""

& $venvPy -m jma.export_csv --in $inDir --out $outDirAbs

Write-Host ""
Write-Host "[+] CSV export complete."
Write-Host "    Files written to: $outDirAbs"
