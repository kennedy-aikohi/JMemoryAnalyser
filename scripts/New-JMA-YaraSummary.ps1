param(
  [Parameter(Mandatory=$true)]
  [string]$YaraOutDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$dir = (Resolve-Path -LiteralPath $YaraOutDir).Path

# Find latest YARA plugin json in that folder
$latest = Get-ChildItem -LiteralPath $dir -Filter "*plugin_yara_*.json" -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1

if (-not $latest) {
  throw "No YARA plugin JSON found in: $dir (expected *plugin_yara_*.json)"
}

# Copy/rename to yara_matches.json for consistent naming
$matchesPath = Join-Path $dir "yara_matches.json"
Copy-Item -Force -LiteralPath $latest.FullName -Destination $matchesPath

# Read JSON
$j = Get-Content -LiteralPath $matchesPath -Raw | ConvertFrom-Json

# Matches array location may differ; try common shapes
$matches =
  $j.result.matches,
  $j.result.data.matches,
  $j.matches |
  Where-Object { $_ } |
  Select-Object -First 1

if (-not $matches) { $matches = @() }

# Summarize: families + apis + capabilities
$families = @{}
$apis = New-Object System.Collections.Generic.HashSet[string]
$caps = New-Object System.Collections.Generic.HashSet[string]

foreach ($m in $matches) {
  $meta = $m.meta
  if (-not $meta) { $meta = @{} }

  $fam = $meta.family
  if (-not $fam) { $fam = $meta.malware }
  if (-not $fam) { $fam = "unknown" }

  if (-not $families.ContainsKey($fam)) { $families[$fam] = 0 }
  $families[$fam]++

  $metaApis = $meta.apis
  if ($metaApis) {
    foreach ($a in ([string]$metaApis).Split(",")) {
      $t = $a.Trim()
      if ($t) { $null = $apis.Add($t) }
    }
  }

  $metaCap = $meta.capability
  if ($metaCap) {
    foreach ($c in ([string]$metaCap).Split(",")) {
      $t = $c.Trim()
      if ($t) { $null = $caps.Add($t) }
    }
  }
}

$topFamily = "unknown"
$score = 0
if ($families.Keys.Count -gt 0) {
  $top = $families.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1
  $topFamily = [string]$top.Key
  $score = [int]$top.Value
}

$confidence = "LOW"
if ($score -ge 5) { $confidence = "HIGH" }
elseif ($score -ge 2) { $confidence = "MEDIUM" }

$summary = [ordered]@{
  malware_family = $topFamily
  confidence     = $confidence
  matched_rules  = $score
  capabilities   = @($caps) | Sort-Object
  apis_detected  = @($apis) | Sort-Object
  notes          = "Family scoring is based on YARA rule metadata (meta.family/meta.malware/meta.apis/meta.capability)."
}

# Write yara_summary.json
$summaryJson = Join-Path $dir "yara_summary.json"
($summary | ConvertTo-Json -Depth 6) | Set-Content -Encoding UTF8 -LiteralPath $summaryJson

# Write yara_summary.csv (SOC-friendly)
$csvPath = Join-Path $dir "yara_summary.csv"
$csvObj = [pscustomobject]@{
  family       = $topFamily
  confidence   = $confidence
  apis_detected= (($summary.apis_detected -join "|"))
  capabilities = (($summary.capabilities -join "|"))
  matched_rules= $score
}
$csvObj | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath $csvPath

Write-Host "[+] Wrote: $matchesPath"
Write-Host "[+] Wrote: $summaryJson"
Write-Host "[+] Wrote: $csvPath"
