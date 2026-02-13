# JMemoryAnalyser

PowerShell launcher + Python analyzers for memory dumps.

## Folder layout

- scripts/
  - JMemoryAnalyser.ps1  (launcher)
  - Install-JMA.ps1      (venv + optional deps)
- python/jma/
  - cli.py               (entry point)
  - analyzers/
    - basic.py           (hash/metadata/strings)
    - minidump_analyzer.py (optional minidump parsing)
    - volatility_analyzer.py (optional volatility3 hooks)
- reports/               (JSON outputs)
- samples/               (your test dumps)

## Quick start

1) Install Python 3.10+ (make sure `python` works in PowerShell).

2) Create venv and baseline deps:
   powershell -ExecutionPolicy Bypass -File .\scripts\Install-JMA.ps1

3) Run basic analysis:
   powershell -ExecutionPolicy Bypass -File .\scripts\JMemoryAnalyser.ps1 -InputPath "C:\path\file.dmp" -Mode basic

4) Optional: minidump parsing
   powershell -ExecutionPolicy Bypass -File .\scripts\Install-JMA.ps1 -WithMinidump
   powershell -ExecutionPolicy Bypass -File .\scripts\JMemoryAnalyser.ps1 -InputPath "C:\path\file.dmp" -Mode minidump

5) Optional: volatility hooks (best for full memory images)
   powershell -ExecutionPolicy Bypass -File .\scripts\Install-JMA.ps1 -WithVolatility
   powershell -ExecutionPolicy Bypass -File .\scripts\JMemoryAnalyser.ps1 -InputPath "C:\path\mem.raw" -Mode volatility
