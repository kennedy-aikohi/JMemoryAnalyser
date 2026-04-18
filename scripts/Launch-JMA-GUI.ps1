<#
.SYNOPSIS
    Launch the JMemoryAnalyser browser-based GUI workbench.

.DESCRIPTION
    Starts the Flask backend and opens the forensics workbench in your browser.

    Panels:
      - API Inspector  : Every API in memory, categorised and risk-scored
      - Memory Map     : Virtual address space, RWX anomaly detection
      - IOC Hunter     : IPs, URLs, domains, named pipes, YARA hits
      - Command Output : WinDbg-style kd> command engine (routes to cdb.exe)
      - Strings        : ASCII + UTF-16 extraction
      - Modules/Threads: Parsed from MDMP structure
      - Risk Score     : Per-category threat scoring
      - Author         : Kennedy Aikohi - kennedy-aikohi.com

.PARAMETER Port
    HTTP port (default 5891).

.PARAMETER NoBrowser
    Start server without auto-opening browser.

.PARAMETER DumpPath
    Optionally pre-load a .DMP file on startup.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\Launch-JMA-GUI.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\Launch-JMA-GUI.ps1 `
        -Port 8080 -DumpPath "C:\evidence\notepad.DMP"
#>

[CmdletBinding()]
param(
    [int]   $Port      = 5891,
    [switch]$NoBrowser,
    [string]$DumpPath  = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$venvPy      = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $venvPy)) {
    throw "venv not found. Run first: powershell -ExecutionPolicy Bypass -File .\scripts\Install-JMA.ps1"
}
$venvPy = (Resolve-Path -LiteralPath $venvPy).Path

Write-Host ""
Write-Host "  ================================================================"
Write-Host "   JMemoryAnalyser GUI Workbench  -  v1.0.0"
Write-Host "   Author  : Kennedy Aikohi"
Write-Host "   Website : https://kennedy-aikohi.com"
Write-Host "   GitHub  : https://github.com/kennedy-aikohi"
Write-Host "   LinkedIn: https://linkedin.com/in/aikohikennedy"
Write-Host "  ================================================================"
Write-Host ""
Write-Host "  Starting server on http://127.0.0.1:$Port ..."
Write-Host "  Press Ctrl+C to stop."
Write-Host ""

$guiArgs = @("-m", "jma.gui", "--port", $Port)
if ($NoBrowser) { $guiArgs += "--no-browser" }

if ($DumpPath -and (Test-Path -LiteralPath $DumpPath)) {
    $env:JMA_PRELOAD_DUMP = (Resolve-Path -LiteralPath $DumpPath).Path
    Write-Host "  Pre-loading: $($env:JMA_PRELOAD_DUMP)"
    Write-Host ""
}

$env:PYTHONPATH = Join-Path $ProjectRoot "python"

& $venvPy @guiArgs
