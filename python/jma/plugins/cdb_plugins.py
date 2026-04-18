from __future__ import annotations

import re
from typing import Any, Dict

from jma.cdb_backend import (
    run_cdb,
    parse_peb_imagepath,
    count_threads_from_tilde,
    find_named_pipes,
    find_ipv4_strings,
)
from .registry import Plugin, register


def _tail(s: str, n: int = 30_000) -> str:
    return (s or "")[-n:]


# ---------------------------------------------------------------------------
# Individual plugin runners
# ---------------------------------------------------------------------------

def p_osver(dmp: str, **kwargs) -> Dict[str, Any]:
    r = run_cdb(dmp, ["vertarget"])
    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", r.stdout or "")
    return {
        "ok":         r.ok,
        "os_version": m.group(1) if m else None,
        "raw_tail":   _tail(r.stdout),
        "stderr":     r.stderr[:2000] if not r.ok else "",
    }


def p_procinfo(dmp: str, **kwargs) -> Dict[str, Any]:
    r = run_cdb(dmp, [".symfix", ".reload", "!peb"])
    img, cmd = parse_peb_imagepath(r.stdout)
    return {
        "ok":           r.ok,
        "image_path":   img,
        "command_line": cmd,
        "raw_tail":     _tail(r.stdout),
        "stderr":       r.stderr[:2000] if not r.ok else "",
    }


def p_threads(dmp: str, **kwargs) -> Dict[str, Any]:
    r = run_cdb(dmp, ["~"])
    return {
        "ok":           r.ok,
        "thread_count": count_threads_from_tilde(r.stdout),
        "raw_tail":     _tail(r.stdout),
    }


def p_handles(dmp: str, **kwargs) -> Dict[str, Any]:
    r = run_cdb(dmp, [".symfix", ".reload", "!handle 0 3"])
    pipes = find_named_pipes(r.stdout)
    return {
        "ok":          r.ok,
        "named_pipes": pipes,
        "pipe_count":  len(pipes),
        "raw_tail":    _tail(r.stdout),
    }


def p_modules(dmp: str, **kwargs) -> Dict[str, Any]:
    r = run_cdb(dmp, ["lm"])
    # Parse module lines: "start end  module_name ..."
    lines  = (r.stdout or "").splitlines()
    mods   = []
    for line in lines:
        m = re.match(r"^([0-9a-fA-F`]+)\s+([0-9a-fA-F`]+)\s+(\S+)", line)
        if m:
            mods.append({
                "start":  m.group(1),
                "end":    m.group(2),
                "module": m.group(3),
            })
    return {
        "ok":           r.ok,
        "module_count": len(mods),
        "modules":      mods[:300],
        "raw_tail":     _tail(r.stdout),
    }


def p_exception(dmp: str, **kwargs) -> Dict[str, Any]:
    r = run_cdb(dmp, [".symfix", ".reload", "!analyze -v"], timeout=300)
    # Extract exception code from output
    exc_code = None
    m = re.search(r"ExceptionCode:\s+(0x[0-9a-fA-F]+)", r.stdout or "", re.IGNORECASE)
    if m:
        exc_code = m.group(1)
    return {
        "ok":             r.ok,
        "exception_code": exc_code,
        "raw_tail":       _tail(r.stdout),
    }


def p_memmap(dmp: str, **kwargs) -> Dict[str, Any]:
    r = run_cdb(dmp, ["!address"], timeout=300)
    return {
        "ok":      r.ok,
        "raw_tail": _tail(r.stdout),
    }


def p_rwx(dmp: str, **kwargs) -> Dict[str, Any]:
    r = run_cdb(dmp, ["!address"], timeout=300)
    hits = []
    for line in (r.stdout or "").splitlines():
        u = line.upper()
        if ("EXECUTE" in u and "WRITE" in u) or "PAGE_EXECUTE_READWRITE" in u:
            hits.append(line.strip())
    return {
        "ok":        r.ok,
        "hit_count": len(hits),
        "hits":      hits[:300],
        "raw_tail":  _tail(r.stdout),
    }


def p_netfind(dmp: str, **kwargs) -> Dict[str, Any]:
    """
    Heuristic network IOC extraction from process dump.
    Aggregates output from !peb, !handle, and !analyze into one blob,
    then extracts IPs, URLs, domains, and named pipes.
    """
    blob = ""
    for cmds in ([".symfix", ".reload", "!peb"],
                 [".symfix", ".reload", "!handle 0 3"],
                 [".symfix", ".reload", "!analyze -v"]):
        r = run_cdb(dmp, cmds, timeout=300)
        blob += "\n" + (r.stdout or "")

    ips     = sorted(set(find_ipv4_strings(blob)))
    urls    = sorted(set(re.findall(r"(https?://[^\s'\"<>]+)", blob, re.IGNORECASE)))
    domains = sorted({
        re.search(r"https?://([^/:]+)", u, re.IGNORECASE).group(1).lower()
        for u in urls
        if re.search(r"https?://([^/:]+)", u, re.IGNORECASE)
    })
    pipes   = sorted(set(find_named_pipes(blob)))

    return {
        "ok":                True,
        "ip_candidates":     ips[:300],
        "url_candidates":    urls[:300],
        "domain_candidates": domains[:300],
        "named_pipes_seen":  pipes[:300],
        "note": (
            "Process-dump netfind is heuristic; "
            "for full network state use Volatility windows.netscan on a complete memory image."
        ),
    }


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_all() -> None:
    register(Plugin("osver",     "Target OS version via vertarget.",                   "cdb", p_osver))
    register(Plugin("procinfo",  "Process image path + command line via !peb.",        "cdb", p_procinfo))
    register(Plugin("threads",   "Thread enumeration and count via ~.",                "cdb", p_threads))
    register(Plugin("handles",   "Handle enumeration incl. named pipes via !handle.", "cdb", p_handles))
    register(Plugin("modules",   "Loaded module list via lm.",                         "cdb", p_modules))
    register(Plugin("exception", "Exception/crash analysis via !analyze -v.",          "cdb", p_exception))
    register(Plugin("memmap",    "Virtual address space map via !address.",             "cdb", p_memmap))
    register(Plugin("rwx",       "RWX memory regions (heuristic from !address).",      "cdb", p_rwx))
    register(Plugin("netfind",   "Network IOC extraction from process dump (heuristic).","cdb", p_netfind))
