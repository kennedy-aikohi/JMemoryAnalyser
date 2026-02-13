param(
  [Parameter(Mandatory=$true)][string]$Name
)
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$case = Join-Path (Resolve-Path .\cases).Path ("{0}_{1}" -f $Name, $stamp)

New-Item -ItemType Directory -Force -Path $case | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $case "inputs") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $case "outputs") | Out-Null
Copy-Item -Force .\cases\_templates\triage\profile.json (Join-Path $case "profile.json")

"Case created: $case"
"Put dumps in:  $case\inputs"
"Reports go to: $case\outputs"
