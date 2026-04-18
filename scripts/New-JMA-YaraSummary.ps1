<#
.SYNOPSIS
    Generate a human-readable YARA summary from a case's triage JSON output.

.DESCRIPTION
    Reads all *_triage_*.json files in a case outputs directory,
    extracts YARA match data, and writes a consolidated yara_summary.json.

.PARAMETER CaseOutputsDir
    Path to the case outputs directory.

.PARAMETER OutFile
    Output path for yara_summary.json (default: <CaseOutputsDir>\yara_summary.json).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\New-JMA-YaraSummary.ps1 `
        -CaseOutputsDir ".\cases\incident01_20250101_120000\outputs"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$CaseOutputsDir,

    [string]$OutFile = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$inDir = (Resolve-Path -LiteralPath $CaseOutputsDir -ErrorAction Stop).Path
if (-not $OutFile) {
    $OutFile = Join-Path $inDir "yara_summary.json"
}

$allMatches   = @()
$allFamilies  = @{}
$filesScanned = 0
$triageFiles  = Get-ChildItem -LiteralPath $inDir -Recurse -Filter "*_triage_*.json" -ErrorAction SilentlyContinue

foreach ($tf in $triageFiles) {
    try {
        $j    = Get-Content -LiteralPath $tf.FullName -Raw | ConvertFrom-Json
        $yara = $j.result.yara
        if (-not $yara) { continue }

        $filesScanned++
        $dump = $j.input

        foreach ($m in $yara.matches) {
            $allMatches += [pscustomobject]@{
                dump        = $dump
                rule        = $m.rule
                namespace   = $m.namespace
                tags        = ($m.tags -join ",")
                family      = ($m.meta.family -or $m.meta.malware -or $m.meta.threat -or "")
                description = ($m.meta.description -or "")
                source_file = $m.source_file
            }
        }

        foreach ($fam in $yara.top_family_labels) {
            $label = [string]$fam.label
            if (-not $allFamilies.ContainsKey($label)) { $allFamilies[$label] = 0 }
            $allFamilies[$label] += [int]$fam.count
        }
    } catch {
        Write-Warning "Could not parse: $($tf.FullName): $_"
    }
}

$topFamilies = @()
foreach ($k in ($allFamilies.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 25)) {
    $topFamilies += [pscustomobject]@{ family = $k.Name; score = $k.Value }
}

$summary = @{
    tool              = "JMemoryAnalyser"
    generated_utc     = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    triage_files_read = $filesScanned
    total_matches     = $allMatches.Count
    top_families      = $topFamilies
    matches           = $allMatches
}

($summary | ConvertTo-Json -Depth 8) | Set-Content -Encoding UTF8 -LiteralPath $OutFile

Write-Host "[+] YARA summary written: $OutFile"
Write-Host "    Triage files read : $filesScanned"
Write-Host "    Total YARA matches: $($allMatches.Count)"
Write-Host "    Unique families   : $($allFamilies.Count)"
