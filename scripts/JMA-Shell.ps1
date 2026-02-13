param(
  [Parameter(Mandatory=$true)]
  [string]$Image,

  [string]$OutDir="..\reports"
)

$projectRoot = (Resolve-Path -LiteralPath (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "..")).Path
$venvPy = Join-Path $projectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) { throw "venv python not found. Run Install-JMA.ps1 first." }

$cli = Join-Path $projectRoot "python\jma\cli.py"

Write-Host "JMemoryAnalyser shell"
Write-Host "image: $Image"
Write-Host "commands:"
Write-Host "  info | pslist | cmdline"
Write-Host "  threads <pid> | handles <pid> | malfind [pid] | netscan"
Write-Host "  sherlock [malware=update.exe] [pipehint=MSSE-]"
Write-Host "  quit"
Write-Host ""

while ($true) {
  $line = Read-Host "jma"
  if (-not $line) { continue }
  if ($line -match '^(quit|exit)$') { break }

  $parts = $line.Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)
  $cmd = $parts[0].ToLower()

  if ($cmd -eq "sherlock") {
    $mal = "update.exe"
    $pipe = "MSSE-"
    foreach ($p in $parts[1..($parts.Count-1)]) {
      if ($p -like "malware=*") { $mal = $p.Split("=")[1] }
      if ($p -like "pipehint=*") { $pipe = $p.Split("=")[1] }
    }
    & $venvPy $cli sherlock --input $Image --out $OutDir --malware $mal --pipehint $pipe
    continue
  }

  if ($cmd -in @("info","pslist","cmdline","netscan")) {
    & $venvPy $cli cmd --input $Image --out $OutDir --do $cmd
    continue
  }

  if ($cmd -in @("threads","handles")) {
    if ($parts.Count -lt 2) { Write-Host "usage: $cmd <pid>"; continue }
    & $venvPy $cli cmd --input $Image --out $OutDir --do $cmd --pid ([int]$parts[1])
    continue
  }

  if ($cmd -eq "malfind") {
    if ($parts.Count -ge 2) {
      & $venvPy $cli cmd --input $Image --out $OutDir --do malfind --pid ([int]$parts[1])
    } else {
      & $venvPy $cli cmd --input $Image --out $OutDir --do malfind
    }
    continue
  }

  Write-Host "Unknown command: $cmd"
}
