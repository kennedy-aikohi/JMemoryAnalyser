[CmdletBinding()]
param(
  [Parameter(Mandatory=$true, Position=0)]
  [string]$InputPath,

  [Parameter(Mandatory=$false)]
  [ValidateSet("basic","minidump","volatility")]
  [string]$Mode = "basic",

  [Parameter(Mandatory=$false)]
  [string]$OutDir = (Join-Path $ScriptDir "..\reports"),

  [Parameter(Mandatory=$false)]
  [switch]$OpenReport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ScriptPath = $null
if ($PSCommandPath) { $ScriptPath = $PSCommandPath }
elseif ($MyInvocation -and $MyInvocation.MyCommand -and $MyInvocation.MyCommand.Path) { $ScriptPath = $MyInvocation.MyCommand.Path }
if (-not $ScriptPath) { $ScriptPath = (Resolve-Path -LiteralPath ".\scripts\JMemoryAnalyser.ps1").Path }
$ScriptDir = Split-Path -Parent $ScriptPath
if (-not $ScriptDir) { throw "Could not resolve script directory (ScriptDir is null). ScriptPath=$ScriptPath" }

function Resolve-AbsolutePath([string]$p) {
  $item = Get-Item -LiteralPath $p -ErrorAction Stop
  return $item.FullName
}

function Ensure-Python {
  $py = Get-Command python -ErrorAction SilentlyContinue
  if (-not $py) { throw "Python not found in PATH. Install Python 3.10+ and restart PowerShell." }
  return $py.Source
}

function Ensure-OutDir([string]$dir) {
  if (-not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
  }
  return (Get-Item -LiteralPath $dir).FullName
}

function Write-Header {
  param([string]$Title)
  Write-Host ""
  Write-Host "===================================================="
  Write-Host " JMemoryAnalyser - $Title"
  Write-Host "===================================================="
  Write-Host ""
}

$absInput = Resolve-AbsolutePath $InputPath
$absOut   = Ensure-OutDir (Resolve-Path -LiteralPath $OutDir).Path
$python   = Ensure-Python

$pyEntry = Join-Path $ScriptDir "..\python\jma\cli.py"
$pyEntry = (Resolve-Path -LiteralPath $pyEntry).Path

Write-Header "Run"
Write-Host "Input : $absInput"
Write-Host "Mode  : $Mode"
Write-Host "Out   : $absOut"
Write-Host "Python: $python"
Write-Host ""

& $python $pyEntry --input "$absInput" --mode $Mode --out "$absOut"

$lastReport = Get-ChildItem -LiteralPath $absOut -Filter "*.json" |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1

if ($lastReport) {
  Write-Host ""
  Write-Host "Latest report: $($lastReport.FullName)"
  if ($OpenReport) {
    Invoke-Item -LiteralPath $lastReport.FullName
  }
} else {
  Write-Warning "No report produced."
}

