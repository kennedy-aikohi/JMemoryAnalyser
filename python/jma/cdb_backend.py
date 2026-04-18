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
    """
    Locate cdb.exe in order of preference:
      1. JMA_CDB environment variable
      2. PATH lookup
      3. Well-known WinDbg install locations
    """
    p = os.environ.get("JMA_CDB")
    if p and os.path.isfile(p):
        return p

    from shutil import which
    w = which("cdb.exe") or which("cdb")
    if w:
        return w

    # Common WinDbg installation paths (x64 and x86)
    candidates = [
        r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
        r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe",
        r"C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe",
        r"C:\Program Files\Windows Kits\10\Debuggers\x86\cdb.exe",
        r"C:\Debuggers\cdb.exe",
        r"C:\WinDbg\cdb.exe",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c

    return None


def run_cdb(
    dmp_path: str,
    commands: list[str],
    cdb_path: Optional[str] = None,
    timeout: int = 180,
) -> CdbResult:
    """
    Run CDB against a dump file, execute commands, then quit.
    Returns a CdbResult regardless of exit code so callers
    can always inspect stdout/stderr.
    """
    cdb_path = cdb_path or find_cdb()
    if not cdb_path:
        return CdbResult(
            False,
            "",
            (
                "cdb.exe not found. Install 'Debugging Tools for Windows' "
                "(Windows SDK) and ensure cdb.exe is on PATH, "
                "or set the JMA_CDB environment variable to the full path."
            ),
            127,
        )

    # Build the command string for -c: join with semicolons, terminate with q
    cmdline_str = "; ".join(commands + ["q"])
    cmd = [cdb_path, "-z", dmp_path, "-c", cmdline_str]

    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return CdbResult(False, "", f"CDB timed out after {timeout}s", -1)
    except FileNotFoundError:
        return CdbResult(False, "", f"cdb.exe not found at: {cdb_path}", 127)
    except Exception as e:
        return CdbResult(False, "", str(e), -1)

    # CDB exits 0 on success OR on a controlled quit; also check for "quit:" in output
    ok = p.returncode == 0 or "quit:" in (p.stdout or "").lower()
    return CdbResult(ok, p.stdout or "", p.stderr or "", p.returncode)


def parse_peb_imagepath(cdb_out: str) -> tuple[Optional[str], Optional[str]]:
    """
    Extract ImagePathName and CommandLine from !peb output.

    CDB can format these as:
      ImagePathName:  'C:\\path\\to\\exe'        (single-quoted)
      ImagePathName:  C:\\path\\to\\exe           (unquoted)
      ImagePathName:  "C:\\path\\to\\exe"         (double-quoted)
    """
    img = None
    cmd_line = None

    # Single-quoted (most common)
    m = re.search(r"ImagePathName:\s+'([^']+)'", cdb_out)
    if m:
        img = m.group(1).strip()
    # Double-quoted
    if not img:
        m = re.search(r'ImagePathName:\s+"([^"]+)"', cdb_out)
        if m:
            img = m.group(1).strip()
    # Unquoted: capture until EOL, stop at whitespace blobs
    if not img:
        m = re.search(r"ImagePathName:\s+(\S+(?:\\[^\s]+)*)", cdb_out)
        if m:
            img = m.group(1).strip().rstrip("\\")

    # CommandLine - same three variants
    m = re.search(r"CommandLine:\s+'([^']+)'", cdb_out)
    if m:
        cmd_line = m.group(1).strip()
    if not cmd_line:
        m = re.search(r'CommandLine:\s+"([^"]+)"', cdb_out)
        if m:
            cmd_line = m.group(1).strip()
    if not cmd_line:
        m = re.search(r"CommandLine:\s+(.+)", cdb_out)
        if m:
            cmd_line = m.group(1).strip()

    return img, cmd_line


def count_threads_from_tilde(cdb_out: str) -> int:
    """
    Count threads from ~ output.
    Thread lines start with whitespace then a decimal thread ID, then " Id:".
    Example:  "   0  Id: 1234.5678 Suspend: 0 Teb: ..."
    """
    n = 0
    for line in (cdb_out or "").splitlines():
        if re.match(r"^\s*\d+\s+Id:\s+[0-9a-fA-F.]+", line):
            n += 1
    return n


def find_named_pipes(cdb_out: str) -> list[str]:
    """
    Extract NamedPipe paths from CDB output.
    Handles both \\Device\\NamedPipe and \\PIPE\\ variants.
    """
    pipes: set[str] = set()
    for line in (cdb_out or "").splitlines():
        # \\Device\\NamedPipe\\...
        m = re.search(r"(\\Device\\NamedPipe\\[^\s,;\"']+)", line, re.IGNORECASE)
        if m:
            pipes.add(m.group(1).rstrip("."))
        # \\PIPE\\...
        m = re.search(r"(\\PIPE\\[^\s,;\"']+)", line, re.IGNORECASE)
        if m:
            pipes.add(m.group(1).rstrip("."))
    return sorted(pipes)


def find_ipv4_strings(cdb_out: str) -> list[str]:
    """
    Extract IPv4 addresses from CDB output, filtering out obvious
    non-addresses (e.g. version strings with four dotted numbers).
    """
    ips: set[str] = set()
    for m in re.finditer(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b", cdb_out or ""):
        octets = [int(m.group(i)) for i in range(1, 5)]
        if all(0 <= o <= 255 for o in octets):
            # Filter loopback (127.x), unroutable (0.0.0.0)
            if octets[0] not in (0, 127):
                ips.add(m.group(0))
    return sorted(ips)
