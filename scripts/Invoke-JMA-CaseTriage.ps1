param(
  [Parameter(Mandatory=$true)]
  [string]$CaseName,

  [Parameter(Mandatory=$true)]
  [object]$Dumps,

  [int]$MaxMbScan = 512,

  [switch]$UpdateRules,
  [switch]$WithYara,
  [string]$RulesDir = ".\rules\vendor\yara"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Normalize-Dumps([object]$x) {
  if ($null -eq $x) { return @() }

  if ($x -is [System.Array]) {
    $out = @()
    foreach ($e in $x) {
      if ($null -eq $e) { continue }
      $s = [string]$e
      if ($s -match ",") {
        $out += $s.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
      } else {
        $out += $s
      }
    }
    return $out
  }

  $s = [string]$x
  if ($s -match ",") {
    return @($s.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  }
  return @($s)
}

function New-CaseFolder([string]$name) {
  $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
  $casesRoot = Join-Path (Resolve-Path .\cases).Path ""
  $case = Join-Path $casesRoot ("{0}_{1}" -f $name, $stamp)

  New-Item -ItemType Directory -Force -Path $case | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $case "inputs") | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $case "outputs") | Out-Null
  return $case
}

function Find-VenvPython([string]$projectRoot) {
  $venvPy = Join-Path $projectRoot ".venv\Scripts\python.exe"
  if (Test-Path -LiteralPath $venvPy) { return (Resolve-Path -LiteralPath $venvPy).Path }
  throw "venv python not found: $venvPy (run scripts\Install-JMA.ps1 first)"
}

# ---- main ----
$dumpList = Normalize-Dumps $Dumps
if ($dumpList.Count -lt 1) { throw "No dump paths were provided." }

$projectRoot = (Resolve-Path -LiteralPath ".").Path
$casePath = New-CaseFolder $CaseName
$inputs   = Join-Path $casePath "inputs"
$outputs  = Join-Path $casePath "outputs"

$venvPy = Find-VenvPython $projectRoot
$cli    = Join-Path $projectRoot "python\jma\cli.py"

Write-Host ""
Write-Host "===================================================="
Write-Host " JMemoryAnalyser Case Triage"
Write-Host "===================================================="
Write-Host "Case   : $casePath"
Write-Host "Inputs : $inputs"
Write-Host "Outputs: $outputs"
Write-Host "Python : $venvPy"
Write-Host "YARA   : " -NoNewline
if ($WithYara) { Write-Host "enabled" } else { Write-Host "disabled" }
Write-Host ""

if ($UpdateRules) {
  Write-Host "[*] Updating rules from GitHub..."
  powershell -ExecutionPolicy Bypass -File (Join-Path $projectRoot "scripts\Update-JMA-Rules.ps1")
  Write-Host ""
}

# Copy dumps into inputs
$dumpTargets = @()
foreach ($d in $dumpList) {
  $src = (Resolve-Path -LiteralPath $d).Path
  $dst = Join-Path $inputs ([System.IO.Path]::GetFileName($src))
  Copy-Item -Force -LiteralPath $src -Destination $dst
  $dumpTargets += $dst
  Write-Host "[+] Copied: $src -> $dst"
}

# Plugins to run separately (each goes into its own folder)
$pluginPack = @("osver","procinfo","threads","handles","modules","exception","memmap","rwx","netfind")

# Aggregate family labels across dumps
$familyTally = @{}

foreach ($dmp in $dumpTargets) {
  $base    = [System.IO.Path]::GetFileNameWithoutExtension($dmp)
  $outRoot = Join-Path $outputs $base

  # Stage folders
  $outBasic   = Join-Path $outRoot "basic"
  $outPlugins = Join-Path $outRoot "plugins"
  $outTriage  = Join-Path $outRoot "triage"

  New-Item -ItemType Directory -Force -Path $outBasic   | Out-Null
  New-Item -ItemType Directory -Force -Path $outPlugins | Out-Null
  New-Item -ItemType Directory -Force -Path $outTriage  | Out-Null

  Write-Host ""
  Write-Host "---- Dump: $dmp"
  Write-Host "     Out:  $outRoot"

  # 1) basic (strings scan etc.)
  Write-Host "[*] basic scan..."
  & $venvPy $cli run --input $dmp --mode basic --out $outBasic --max-mb-scan $MaxMbScan

  # 2) plugins (each to its own folder)
  foreach ($p in $pluginPack) {
    $pOut = Join-Path $outPlugins $p
    New-Item -ItemType Directory -Force -Path $pOut | Out-Null
    Write-Host "[*] plugin $p..."
    & $venvPy $cli plugin --input $dmp --out $pOut --name $p
  }

  # 3) triage (combined pack + optional yara)
  Write-Host "[*] triage pack..."
  if ($WithYara) {
    & $venvPy $cli triage --input $dmp --out $outTriage --max-mb-scan $MaxMbScan --with-yara --rules-dir $RulesDir
  } else {
    & $venvPy $cli triage --input $dmp --out $outTriage --max-mb-scan $MaxMbScan
  }

  # Aggregate family labels from latest triage json (if yara ran)
  $tri = Get-ChildItem -LiteralPath $outTriage -Filter "*_triage_*.json" -ErrorAction SilentlyContinue |
         Sort-Object LastWriteTime -Descending |
         Select-Object -First 1

  if ($tri) {
    try {
      $j = Get-Content -LiteralPath $tri.FullName -Raw | ConvertFrom-Json
      $tf = $j.result.yara.top_family_labels
      if ($tf) {
        foreach ($x in $tf) {
          $label = [string]$x.label
          $cnt = [int]$x.count
          if (-not $familyTally.ContainsKey($label)) { $familyTally[$label] = 0 }
          $familyTally[$label] += $cnt
        }
      }
    } catch {}
  }
}

# Build case_summary.json
$familyList = @()
foreach ($k in $familyTally.Keys) {
  $familyList += [pscustomobject]@{ family = $k; score = $familyTally[$k] }
}
$familyList = $familyList | Sort-Object score -Descending

$summary = @{
  tool = "JMemoryAnalyser"
  timestamp_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
  case = $casePath
  dumps = $dumpTargets
  with_yara = [bool]$WithYara
  rules_dir = (Resolve-Path -LiteralPath $RulesDir -ErrorAction SilentlyContinue).Path
  top_families = $familyList | Select-Object -First 25
  notes = "Family scoring is based on YARA meta labels; heuristic and depends on rule quality."
}

$summaryPath = Join-Path $outputs "case_summary.json"
($summary | ConvertTo-Json -Depth 6) | Set-Content -Encoding UTF8 -LiteralPath $summaryPath

Write-Host ""
Write-Host "[+] Case complete."
Write-Host "[+] Case summary: $summaryPath"
Write-Host ""
Write-Host "To browse outputs:"
Write-Host "  explorer `"$outputs`""
