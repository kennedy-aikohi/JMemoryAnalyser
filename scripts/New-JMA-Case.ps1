<#
.SYNOPSIS
    Create a new JMemoryAnalyser case folder structure.

.DESCRIPTION
    Scaffolds a timestamped case directory under .\cases\ with
    inputs/ and outputs/ subdirectories and a blank profile.json.
    Use this before manually running individual analyses, or let
    Invoke-JMA-CaseTriage.ps1 create cases automatically.

.PARAMETER Name
    Case identifier (e.g. "incident01", "phishing_triage").

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\New-JMA-Case.ps1 -Name incident01
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Name
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$casesDir    = Join-Path $ProjectRoot "cases"
$stamp       = Get-Date -Format "yyyyMMdd_HHmmss"
$casePath    = Join-Path $casesDir ("{0}_{1}" -f $Name, $stamp)

New-Item -ItemType Directory -Force -Path (Join-Path $casePath "inputs")  | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $casePath "outputs") | Out-Null

# BUG FIX: original tried to copy from cases\_templates\triage\profile.json
# which never existed in the repo - causing a hard failure every time.
# Instead, generate a minimal profile.json inline.
$profile = [ordered]@{
    case_name     = $Name
    created_utc   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    analyst       = $env:USERNAME
    description   = ""
    dumps         = @()
    tags          = @()
    notes         = ""
}

$profilePath = Join-Path $casePath "profile.json"
($profile | ConvertTo-Json -Depth 4) | Set-Content -Encoding UTF8 -LiteralPath $profilePath

Write-Host ""
Write-Host "[+] Case created : $casePath"
Write-Host "[+] Profile      : $profilePath"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Copy dump(s) to : $casePath\inputs\"
Write-Host "  2. Run triage      :"
Write-Host "     powershell -ExecutionPolicy Bypass -File .\scripts\Invoke-JMA-CaseTriage.ps1 \"
Write-Host "       -CaseName $Name -Dumps '$casePath\inputs\your.DMP'"
