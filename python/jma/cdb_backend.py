from __future__ import annotations
import os
import re
import subprocess
from dataclasses import dataclass
from typing import Optional

@dataclass
class CdbResult:
    ok: bool
    stdout: str
    stderr: str
    returncode: int

def find_cdb() -> Optional[str]:
    # 1) if user set env var
    p = os.environ.get("JMA_CDB")
    if p and os.path.exists(p):
        return p

    # 2) try PATH
    from shutil import which
    w = which("cdb.exe") or which("cdb")
    if w:
        return w

    return None

def run_cdb(dmp_path: str, commands: list[str], cdb_path: Optional[str] = None, timeout: int = 180) -> CdbResult:
    cdb_path = cdb_path or find_cdb()
    if not cdb_path:
        return CdbResult(False, "", "cdb.exe not found. Install Debugging Tools or add cdb.exe to PATH.", 127)

    # -z <dump> opens dump
    # -c "<cmds>;q" runs commands and quits
    cmdline = "; ".join(commands + ["q"])
    cmd = [cdb_path, "-z", dmp_path, "-c", cmdline]

    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    ok = (p.returncode == 0) or ("quit:" in (p.stdout or "").lower())
    return CdbResult(ok, p.stdout or "", p.stderr or "", p.returncode)

def parse_peb_imagepath(cdb_out: str) -> tuple[Optional[str], Optional[str]]:
    # !peb output often includes:
    # ProcessParameters: ... ImagePathName: 'C:\...\update.exe'
    # CommandLine: '"C:\...\update.exe" ...'
    img = None
    cmd = None
    m = re.search(r"ImagePathName:\s*'([^']+)'", cdb_out)
    if m:
        img = m.group(1)
    m = re.search(r"CommandLine:\s*'([^']+)'", cdb_out)
    if m:
        cmd = m.group(1)
    return img, cmd

def count_threads_from_tilde(cdb_out: str) -> int:
    # "~" lists threads. Lines often start with "  0  Id: ...."
    # We count lines that look like thread entries.
    n = 0
    for line in cdb_out.splitlines():
        if re.match(r"^\s*\d+\s+Id:\s+[0-9a-fA-F.]+", line):
            n += 1
    return n

def find_named_pipes(cdb_out: str) -> list[str]:
    pipes = set()
    for line in cdb_out.splitlines():
        # Look for \Device\NamedPipe\XYZ
        if "\\Device\\NamedPipe\\" in line:
            idx = line.find("\\Device\\NamedPipe\\")
            pipes.add(line[idx:].strip())
    return sorted(pipes)

def find_ipv4_strings(cdb_out: str) -> list[str]:
    ips = set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", cdb_out))
    return sorted(ips)
