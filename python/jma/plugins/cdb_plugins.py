from __future__ import annotations
import re
from typing import Any, Dict

from jma.cdb_backend import run_cdb, parse_peb_imagepath, count_threads_from_tilde, find_named_pipes, find_ipv4_strings
from .registry import Plugin, register

def _tail(s: str, n: int = 30000) -> str:
    return (s or "")[-n:]

def p_procinfo(dmp: str, **kwargs) -> Dict[str, Any]:
    r = run_cdb(dmp, [".symfix", ".reload", "!peb"])
    img, cmd = parse_peb_imagepath(r.stdout)
    return {
        "ok": r.ok,
        "image_path": img,
        "command_line": cmd,
        "raw_tail": _tail(r.stdout),
    }

def p_threads(dmp: str, **kwargs) -> Dict[str, Any]:
    r = run_cdb(dmp, ["~"])
    return {
        "ok": r.ok,
        "thread_count": count_threads_from_tilde(r.stdout),
        "raw_tail": _tail(r.stdout),
    }

def p_handles(dmp: str, **kwargs) -> Dict[str, Any]:
    r = run_cdb(dmp, [".symfix", ".reload", "!handle 0 3"])
    pipes = find_named_pipes(r.stdout)
    return {
        "ok": r.ok,
        "named_pipes": pipes,
        "raw_tail": _tail(r.stdout),
    }

def p_modules(dmp: str, **kwargs) -> Dict[str, Any]:
    r = run_cdb(dmp, ["lm"])
    return {"ok": r.ok, "raw_tail": _tail(r.stdout)}

def p_exception(dmp: str, **kwargs) -> Dict[str, Any]:
    r = run_cdb(dmp, [".symfix", ".reload", "!analyze -v"], timeout=300)
    return {"ok": r.ok, "raw_tail": _tail(r.stdout)}

def p_memmap(dmp: str, **kwargs) -> Dict[str, Any]:
    r = run_cdb(dmp, ["!address"], timeout=300)
    return {"ok": r.ok, "raw_tail": _tail(r.stdout)}

def p_rwx(dmp: str, **kwargs) -> Dict[str, Any]:
    r = run_cdb(dmp, ["!address"], timeout=300)
    hits = []
    for line in (r.stdout or "").splitlines():
        u = line.upper()
        if ("EXECUTE" in u and "WRITE" in u) or ("PAGE_EXECUTE_READWRITE" in u):
            hits.append(line.strip())
    return {"ok": r.ok, "hits": hits[:300], "raw_tail": _tail(r.stdout)}

def p_osver(dmp: str, **kwargs) -> Dict[str, Any]:
    r = run_cdb(dmp, ["vertarget"])
    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", r.stdout or "")
    return {"ok": r.ok, "os_version": (m.group(1) if m else None), "raw_tail": _tail(r.stdout)}

def p_netfind(dmp: str, **kwargs) -> Dict[str, Any]:
    # "netscan-like" for process dumps: best-effort extraction from debugger text
    # and (optionally) other plugin tails.
    blob = ""
    for cmd in (["!peb"], ["!handle 0 3"], ["!analyze -v"]):
        r = run_cdb(dmp, [".symfix", ".reload"] + cmd, timeout=300)
        blob += "\n" + (r.stdout or "")
    ips = sorted(set(find_ipv4_strings(blob)))
    urls = sorted(set(re.findall(r"(https?://[^\s'\"<>]+)", blob, flags=re.IGNORECASE)))
    domains = sorted({re.search(r"https?://([^/:]+)", u, flags=re.IGNORECASE).group(1).lower()
                      for u in urls if re.search(r"https?://([^/:]+)", u, flags=re.IGNORECASE)})
    pipes = sorted(set(find_named_pipes(blob)))
    return {
        "ok": True,
        "ip_candidates": ips[:300],
        "url_candidates": urls[:300],
        "domain_candidates": domains[:300],
        "named_pipes_seen": pipes[:300],
        "note": "Process-dump netfind is heuristic; for full memory use Volatility netscan.",
    }

def register_all() -> None:
    register(Plugin("osver",     "Target OS version (best-effort via vertarget).", "cdb", p_osver))
    register(Plugin("procinfo",  "Process PEB info: full path + command line.", "cdb", p_procinfo))
    register(Plugin("threads",   "Thread enumeration and count (~).", "cdb", p_threads))
    register(Plugin("handles",   "Handle enumeration incl named pipes (!handle).", "cdb", p_handles))
    register(Plugin("modules",   "Loaded modules (lm).", "cdb", p_modules))
    register(Plugin("exception", "Exception/crash analysis (!analyze -v).", "cdb", p_exception))
    register(Plugin("memmap",    "Virtual address map (!address).", "cdb", p_memmap))
    register(Plugin("rwx",       "Suspicious RWX regions (heuristic from !address).", "cdb", p_rwx))
    register(Plugin("netfind",   "Netscan-like IOC extraction from process dump (heuristic).", "cdb", p_netfind))
