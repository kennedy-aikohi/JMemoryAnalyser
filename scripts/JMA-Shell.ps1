<#
.SYNOPSIS
    JMemoryAnalyser interactive shell.

.DESCRIPTION
    Drops into an interactive loop where you can run JMA CLI subcommands
    without typing the full python invocation each time.

    Built-in commands:
      help           Show available commands
      plugins        List registered plugins
      run            Run basic/minidump/volatility on a dump
      plugin         Run a named plugin
      triage         Full triage pack
      exit / quit    Exit the shell

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\JMA-Shell.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"   # interactive - don't abort on non-fatal errors

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

$venvPy = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $venvPy)) {
    throw "venv not found. Run: powershell -ExecutionPolicy Bypass -File .\scripts\Install-JMA.ps1"
}
$venvPy = (Resolve-Path -LiteralPath $venvPy).Path
$cliPy  = Join-Path $ProjectRoot "python\jma\cli.py"

Write-Host ""
Write-Host "  JMemoryAnalyser Interactive Shell"
Write-Host "  Type 'help' for commands, 'exit' to quit."
Write-Host ""

function Show-Help {
    Write-Host ""
    Write-Host "  Commands:"
    Write-Host "    plugins                          List all available plugins"
    Write-Host "    run <dump> [mode] [out] [mb]     Run analyser (basic|minidump|volatility)"
    Write-Host "    plugin <dump> <name> [out]       Run a named plugin"
    Write-Host "    triage <dump> [out] [--yara]     Full triage pack"
    Write-Host "    exit / quit                      Exit the shell"
    Write-Host ""
}

while ($true) {
    $input_line = Read-Host "JMA>"
    $tokens = ($input_line.Trim() -split "\s+")
    $cmd    = $tokens[0].ToLower()

    switch ($cmd) {
        "exit"    { Write-Host "Bye."; return }
        "quit"    { Write-Host "Bye."; return }
        "help"    { Show-Help }

        "plugins" {
            & $venvPy $cliPy plugins
        }

        "run" {
            # run <dump> [mode=basic] [out=.\reports] [max_mb=256]
            $dmp  = if ($tokens.Count -gt 1) { $tokens[1] } else { Read-Host "  Dump path" }
            $mode = if ($tokens.Count -gt 2) { $tokens[2] } else { "basic" }
            $out  = if ($tokens.Count -gt 3) { $tokens[3] } else { Join-Path $ProjectRoot "reports" }
            $mb   = if ($tokens.Count -gt 4) { $tokens[4] } else { "256" }
            New-Item -ItemType Directory -Force -Path $out | Out-Null
            & $venvPy $cliPy run --input $dmp --mode $mode --out $out --max-mb-scan $mb
        }

        "plugin" {
            $dmp  = if ($tokens.Count -gt 1) { $tokens[1] } else { Read-Host "  Dump path" }
            $name = if ($tokens.Count -gt 2) { $tokens[2] } else { Read-Host "  Plugin name" }
            $out  = if ($tokens.Count -gt 3) { $tokens[3] } else { Join-Path $ProjectRoot "reports" }
            New-Item -ItemType Directory -Force -Path $out | Out-Null
            & $venvPy $cliPy plugin --input $dmp --name $name --out $out
        }

        "triage" {
            $dmp   = if ($tokens.Count -gt 1) { $tokens[1] } else { Read-Host "  Dump path" }
            $out   = if ($tokens.Count -gt 2) { $tokens[2] } else { Join-Path $ProjectRoot "reports" }
            $yara  = $tokens -contains "--yara"
            New-Item -ItemType Directory -Force -Path $out | Out-Null
            if ($yara) {
                & $venvPy $cliPy triage --input $dmp --out $out --with-yara
            } else {
                & $venvPy $cliPy triage --input $dmp --out $out
            }
        }

        "" { <# empty line #> }

        default {
            Write-Host "  Unknown command: $cmd  (type 'help')"
        }
    }
}
