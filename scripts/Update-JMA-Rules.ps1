param(
  [string]$Config = ".\rules\rules_sources.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Config)) { throw "Config not found: $Config" }
$cfg = Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
  throw "git not found. Install git and ensure it is on PATH."
}

$root = (Resolve-Path .).Path
$vendor = Join-Path $root "rules\vendor"
New-Item -ItemType Directory -Force -Path $vendor | Out-Null

function Sync-Repo([string]$dest, [string]$giturl, [string]$branch) {
  if (-not (Test-Path -LiteralPath $dest)) {
    git clone --depth 1 --branch $branch $giturl $dest | Out-Host
  } else {
    pushd $dest | Out-Null
    git fetch --depth 1 origin $branch | Out-Host
    git checkout $branch | Out-Host
    git pull --ff-only origin $branch | Out-Host
    popd | Out-Null
  }
}

function Copy-Paths([string]$repoDir, [string[]]$paths, [string]$outDir) {
  New-Item -ItemType Directory -Force -Path $outDir | Out-Null
  foreach ($p in $paths) {
    $src = Join-Path $repoDir $p
    if (Test-Path -LiteralPath $src) {
      Copy-Item -Recurse -Force -LiteralPath $src -Destination (Join-Path $outDir $p)
    }
  }
}

# YARA
$yaraOut = Join-Path $vendor "yara"
New-Item -ItemType Directory -Force -Path $yaraOut | Out-Null

foreach ($s in $cfg.yara_sources) {
  $repoDir = Join-Path $vendor ("_repos\yara\" + $s.name)
  $destOut = Join-Path $yaraOut $s.name
  Write-Host "`n[+] Updating YARA source: $($s.name)"
  Sync-Repo $repoDir $s.git $s.branch

  if (Test-Path -LiteralPath $destOut) { Remove-Item -Recurse -Force -LiteralPath $destOut }
  Copy-Paths $repoDir $s.paths $destOut
  Write-Host "    -> staged to: $destOut"
}

# Sigma (stored for future; not used by dump scanning)
$sigmaOut = Join-Path $vendor "sigma"
New-Item -ItemType Directory -Force -Path $sigmaOut | Out-Null

foreach ($s in $cfg.sigma_sources) {
  $repoDir = Join-Path $vendor ("_repos\sigma\" + $s.name)
  $destOut = Join-Path $sigmaOut $s.name
  Write-Host "`n[+] Updating Sigma source: $($s.name)"
  Sync-Repo $repoDir $s.git $s.branch

  if (Test-Path -LiteralPath $destOut) { Remove-Item -Recurse -Force -LiteralPath $destOut }
  Copy-Paths $repoDir $s.paths $destOut
  Write-Host "    -> staged to: $destOut"
}

Write-Host "`nDone."
Write-Host "YARA rules staged under: rules\vendor\yara"
Write-Host "Sigma rules staged under: rules\vendor\sigma"
