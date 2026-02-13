from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Optional
import re

from .cdb_backend import run_cdb, parse_peb_imagepath, count_threads_from_tilde, find_named_pipes, find_ipv4_strings

@dataclass
class CmdResult:
    ok: bool
    summary: str
    data: Any

def _tail(s: str, n: int = 20000) -> str:
    return (s or "")[-n:]

def cmd_peb(dmp: str) -> CmdResult:
    r = run_cdb(dmp, [".symfix", ".reload", "!peb"])
    img, cmd = parse_peb_imagepath(r.stdout)
    return CmdResult(r.ok, "peb", {"image_path": img, "command_line": cmd, "raw_tail": _tail(r.stdout)})

def cmd_threads(dmp: str) -> CmdResult:
    r = run_cdb(dmp, ["~"])
    n = count_threads_from_tilde(r.stdout)
    return CmdResult(r.ok, "threads", {"thread_count": n, "raw_tail": _tail(r.stdout)})

def cmd_handles(dmp: str) -> CmdResult:
    r = run_cdb(dmp, [".symfix", ".reload", "!handle 0 3"])
    pipes = find_named_pipes(r.stdout)
    return CmdResult(r.ok, "handles", {"named_pipes": pipes, "raw_tail": _tail(r.stdout)})

def cmd_modules(dmp: str) -> CmdResult:
    # lm = list loaded modules
    r = run_cdb(dmp, ["lm"])
    return CmdResult(r.ok, "modules", {"raw_tail": _tail(r.stdout)})

def cmd_exception(dmp: str) -> CmdResult:
    # !analyze -v gives crash/exception summary for many dumps
    r = run_cdb(dmp, [".symfix", ".reload", "!analyze -v"], timeout=300)
    return CmdResult(r.ok, "exception", {"raw_tail": _tail(r.stdout)})

def cmd_osver(dmp: str) -> CmdResult:
    # vertarget often prints OS version/target
    r = run_cdb(dmp, ["vertarget"])
    # Try to extract a version-like token
    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", r.stdout or "")
    ver = m.group(1) if m else None
    return CmdResult(r.ok, "osver", {"os_version": ver, "raw_tail": _tail(r.stdout)})

def cmd_memmap(dmp: str) -> CmdResult:
    # !address summarizes the process VA layout; useful in user-mode dumps
    r = run_cdb(dmp, ["!address"], timeout=300)
    return CmdResult(r.ok, "memmap", {"raw_tail": _tail(r.stdout)})

def cmd_rwx(dmp: str) -> CmdResult:
    # Best-effort: parse !address output and look for RWX-ish regions.
    r = run_cdb(dmp, ["!address"], timeout=300)
    text = r.stdout or ""
    hits = []
    for line in text.splitlines():
        u = line.upper()
        # crude heuristics: look for "EXECUTE" and "WRITE"
        if ("EXECUTE" in u and "WRITE" in u) or ("PAGE_EXECUTE_READWRITE" in u):
            hits.append(line.strip())
    return CmdResult(r.ok, "rwx", {"hits": hits[:200], "raw_tail": _tail(r.stdout)})

def cmd_iocs(dmp: str) -> CmdResult:
    # Pull IOCs out of CDB text outputs we already know how to get:
    # !peb, !handle, !analyze -v (short tail)
    peb = run_cdb(dmp, [".symfix", ".reload", "!peb"])
    hnd = run_cdb(dmp, [".symfix", ".reload", "!handle 0 3"])
    anl = run_cdb(dmp, [".symfix", ".reload", "!analyze -v"], timeout=300)

    blob = (peb.stdout or "") + "\n" + (hnd.stdout or "") + "\n" + (anl.stdout or "")
    ips = sorted(set(find_ipv4_strings(blob)))
    pipes = sorted(set(find_named_pipes(blob)))

    # URLs/domains (best-effort from text blobs)
    urls = sorted(set(re.findall(r"(https?://[^\s'\"<>]+)", blob, flags=re.IGNORECASE)))
    domains = set()
    for u in urls:
        m = re.search(r"https?://([^/:]+)", u, flags=re.IGNORECASE)
        if m:
            domains.add(m.group(1).lower())
    domains = sorted(domains)

    return CmdResult(True, "iocs", {
        "ips": ips[:200],
        "urls": urls[:200],
        "domains": domains[:200],
        "named_pipes": pipes[:200],
        "raw_tail": _tail(blob, 30000)
    })

def cmd_sherlock(dmp: str, malware_name: str = "update.exe", pipe_hint: str = "MSSE-") -> CmdResult:
    osr = cmd_osver(dmp).data
    peb = cmd_peb(dmp).data
    thr = cmd_threads(dmp).data
    hnd = cmd_handles(dmp).data
    exc = cmd_exception(dmp).data

    pipe_hits = [p for p in (hnd.get("named_pipes") or []) if pipe_hint.lower() in p.lower()]
    ips = sorted(set(find_ipv4_strings((hnd.get("raw_tail","") + "\n" + exc.get("raw_tail","") + "\n" + peb.get("raw_tail","")))))

    answers = {
        "os_version": osr.get("os_version"),
        "malware_full_path": peb.get("image_path"),
        "malware_command_line": peb.get("command_line"),
        "thread_count": thr.get("thread_count"),
        "named_pipes": pipe_hits if pipe_hits else hnd.get("named_pipes"),
        "c2_ip_candidates": ips[:50],
        "c2_framework_guess": "Cobalt Strike (heuristic)" if pipe_hits else None,

        # These are usually not solvable from only a single user-mode process dump:
        "injected_pid": None,
        "last_thread_time_utc": None,
        "shellcode_base": None,
    }

    return CmdResult(True, "sherlock", {
        "answers": answers,
        "evidence": {
            "osver_tail": osr.get("raw_tail"),
            "peb_tail": peb.get("raw_tail"),
            "threads_tail": thr.get("raw_tail"),
            "handles_tail": hnd.get("raw_tail"),
            "exception_tail": exc.get("raw_tail"),
        }
    })
