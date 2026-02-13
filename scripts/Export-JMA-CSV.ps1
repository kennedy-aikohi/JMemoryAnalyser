param(
  [Parameter(Mandatory=$true)]
  [string]$CaseOutputsDir,

  [string]$OutDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path ".").Path
$venvPy = Join-Path $projectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $venvPy)) { throw "venv python not found: $venvPy (run scripts\Install-JMA.ps1)" }
$venvPy = (Resolve-Path -LiteralPath $venvPy).Path

$inDir = (Resolve-Path -LiteralPath $CaseOutputsDir).Path
if (-not $OutDir) {
  $OutDir = Join-Path $inDir "_csv"
}
$outDirAbs = (New-Item -ItemType Directory -Force -Path $OutDir).FullName

$exporter = Join-Path $projectRoot "python\jma\export_csv.py"
if (-not (Test-Path -LiteralPath $exporter)) { throw "Missing exporter: $exporter" }

Write-Host "[*] Input : $inDir"
Write-Host "[*] Output: $outDirAbs"
& $venvPy $exporter --in $inDir --out $outDirAbs
Write-Host "[+] Done."
