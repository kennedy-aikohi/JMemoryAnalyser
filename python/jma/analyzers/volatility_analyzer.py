"""
JMemoryAnalyser - Volatility 3 Integration Layer
Runs Volatility plugins against full memory images and normalises
output into the same AnalysisResult structure used by all JMA analyzers.

Supported plugins (auto-selected based on OS detection):
  windows.info, windows.pslist, windows.psscan, windows.cmdline,
  windows.dlllist, windows.malfind, windows.netscan, windows.netstat,
  windows.handles, windows.filescan, windows.registry.hivelist,
  windows.registry.printkey, windows.svcscan, windows.driverirp,
  windows.ssdt, windows.modules, windows.modscan,
  windows.memmap, windows.vadinfo, windows.privileges,
  windows.hashdump (if memory permits), windows.lsadump

Callable via:
  python -m jma.cli run --input image.raw --mode volatility
  python -m jma.cli vol --input image.raw --plugins pslist,malfind,netscan
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .common import AnalysisResult
from ..utils import get_file_info, probe_dmp_format


# ---------------------------------------------------------------------------
# Volatility plugin catalogue
# ---------------------------------------------------------------------------

@dataclass
class VolPlugin:
    name: str           # volatility plugin name e.g. "windows.pslist"
    label: str          # human label
    category: str       # pslist | injection | network | registry | creds | kernel | misc
    risk_weight: int    # how much a positive hit contributes to risk (0-3)
    timeout: int = 120
    extra_args: list[str] = field(default_factory=list)
    description: str = ""


PLUGIN_CATALOGUE: list[VolPlugin] = [
    # -- System info ----------------------------------------------------------
    VolPlugin("windows.info",      "System Info",       "misc",     0, 60,
              description="OS version, kernel base, DTB, CPU architecture"),

    # -- Process enumeration --------------------------------------------------
    VolPlugin("windows.pslist",    "Process List",      "pslist",   0, 120,
              description="Walk PsActiveProcessHead doubly-linked list"),
    VolPlugin("windows.psscan",    "Process Scan",      "pslist",   1, 180,
              description="Pool-tag scan for EPROCESS - finds hidden/unlinked processes"),
    VolPlugin("windows.cmdline",   "Command Lines",     "pslist",   1, 120,
              description="Process command line arguments from PEB"),
    VolPlugin("windows.dlllist",   "DLL List",          "pslist",   1, 180,
              description="Loaded DLLs per process from PEB InMemoryOrderModuleList"),

    # -- Injection / suspicious memory ----------------------------------------
    VolPlugin("windows.malfind",   "Malfind",           "injection",3, 300,
              description="VAD regions with executable+write protection and MZ header - "
                          "classic shellcode/reflective loader indicator"),
    VolPlugin("windows.vadinfo",   "VAD Info",          "injection",1, 180,
              description="Virtual Address Descriptor tree - full process memory layout"),
    VolPlugin("windows.memmap",    "Memory Map",        "injection",0, 120,
              description="Process memory map with protection flags"),

    # -- Network --------------------------------------------------------------
    VolPlugin("windows.netscan",   "Network Scan",      "network",  2, 180,
              description="Pool-tag scan for TCP/UDP endpoints and connections"),
    VolPlugin("windows.netstat",   "Network State",     "network",  2, 120,
              description="Active network connections from kernel structures"),

    # -- Handles / files ------------------------------------------------------
    VolPlugin("windows.handles",   "Handle Table",      "misc",     1, 300,
              description="Process handle tables - files, registry, events, mutants"),
    VolPlugin("windows.filescan",  "File Scan",         "misc",     0, 300,
              description="Pool-tag scan for FILE_OBJECT structures"),
    VolPlugin("windows.modules",   "Kernel Modules",    "kernel",   1, 120,
              description="Loaded kernel modules from PsLoadedModuleList"),
    VolPlugin("windows.modscan",   "Module Scan",       "kernel",   2, 180,
              description="Pool-tag scan for LDR_DATA_TABLE_ENTRY - finds hidden drivers"),

    # -- Services / drivers ---------------------------------------------------
    VolPlugin("windows.svcscan",   "Service Scan",      "kernel",   1, 180,
              description="Windows services from SCM database in memory"),
    VolPlugin("windows.driverirp", "Driver IRP",        "kernel",   2, 180,
              description="IRP handler addresses per driver - detects DKOM hooks"),
    VolPlugin("windows.ssdt",      "SSDT Hooks",        "kernel",   3, 120,
              description="System Service Descriptor Table - rootkit hook detection"),

    # -- Registry -------------------------------------------------------------
    VolPlugin("windows.registry.hivelist",  "Registry Hives",   "registry", 0, 120,
              description="Registry hive list from kernel"),
    VolPlugin("windows.registry.printkey",  "Registry Keys",    "registry", 1, 120,
              extra_args=["--key", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"],
              description="Autorun registry key - persistence indicator"),

    # -- Credentials ----------------------------------------------------------
    VolPlugin("windows.hashdump",  "Hash Dump",         "creds",    3, 120,
              description="SAM database password hashes (requires SYSTEM hive in memory)"),
    VolPlugin("windows.lsadump",   "LSA Dump",          "creds",    3, 120,
              description="LSA secrets from registry (cached domain creds, service passwords)"),
    VolPlugin("windows.privileges","Privileges",        "misc",     1, 120,
              description="Process token privileges - SeDebugPrivilege is a key indicator"),
]

# Fast triage set - run these first for a quick verdict
TRIAGE_PLUGINS = [
    "windows.info",
    "windows.pslist",
    "windows.psscan",
    "windows.cmdline",
    "windows.malfind",
    "windows.netscan",
    "windows.svcscan",
    "windows.ssdt",
]

# Full deep-dive set
FULL_PLUGINS = [p.name for p in PLUGIN_CATALOGUE]


# ---------------------------------------------------------------------------
# Volatility runner
# ---------------------------------------------------------------------------

def _find_vol() -> str | None:
    """Locate the Volatility 3 entry point."""
    # 1. Installed as module in current venv
    try:
        import volatility3  # noqa
        return "module"
    except ImportError:
        pass
    # 2. vol.py / vol3.py on PATH
    from shutil import which
    for name in ("vol", "vol3", "volatility", "volatility3"):
        p = which(name + ".py") or which(name)
        if p:
            return p
    return None


def _run_plugin(
    image_path: str,
    plugin: VolPlugin,
    output_format: str = "json",
    extra_env: dict | None = None,
) -> dict[str, Any]:
    """
    Execute a single Volatility plugin and return structured output.
    Always uses sys.executable (the current venv Python).
    """
    if output_format == "json":
        cmd = [sys.executable, "-m", "volatility3",
               "-r", "json", "-f", image_path, plugin.name] + plugin.extra_args
    else:
        cmd = [sys.executable, "-m", "volatility3",
               "-f", image_path, plugin.name] + plugin.extra_args

    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)

    started = datetime.utcnow()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=plugin.timeout,
            env=env,
        )
        elapsed = (datetime.utcnow() - started).total_seconds()

        if proc.returncode != 0 and not proc.stdout.strip():
            return {
                "ok": False,
                "plugin": plugin.name,
                "error": proc.stderr[-3000:].strip() or f"Exit code {proc.returncode}",
                "elapsed_s": round(elapsed, 2),
                "rows": [],
            }

        # Parse JSON output
        rows = []
        raw_stdout = proc.stdout.strip()
        if output_format == "json" and raw_stdout:
            try:
                data = json.loads(raw_stdout)
                # Volatility JSON can be: list of rows, or {"rows": [...], "columns": [...]}
                if isinstance(data, list):
                    rows = data
                elif isinstance(data, dict):
                    rows = data.get("rows", data.get("data", data.get("result", [])))
                    if not isinstance(rows, list):
                        rows = [data]
            except json.JSONDecodeError:
                # Fall back to raw text if JSON parse fails
                rows = [{"raw_line": ln} for ln in raw_stdout.splitlines() if ln.strip()]

        return {
            "ok": True,
            "plugin": plugin.name,
            "label": plugin.label,
            "category": plugin.category,
            "row_count": len(rows),
            "rows": rows,
            "stderr_tail": proc.stderr[-1000:].strip() if proc.stderr else "",
            "elapsed_s": round(elapsed, 2),
        }

    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "plugin": plugin.name,
            "error": f"Timed out after {plugin.timeout}s",
            "elapsed_s": plugin.timeout,
            "rows": [],
        }
    except Exception as e:
        return {
            "ok": False,
            "plugin": plugin.name,
            "error": str(e),
            "elapsed_s": 0,
            "rows": [],
        }


# ---------------------------------------------------------------------------
# Intelligence extraction from plugin rows
# ---------------------------------------------------------------------------

def _extract_pslist_intel(rows: list[dict]) -> dict[str, Any]:
    """Normalise pslist/psscan rows into analyst-friendly fields."""
    processes = []
    for r in rows:
        # Volatility column names vary by version - try common variants
        pid  = r.get("PID") or r.get("Pid") or r.get("pid")
        ppid = r.get("PPID") or r.get("PPid") or r.get("ppid")
        name = r.get("ImageFileName") or r.get("Name") or r.get("name") or ""
        exit_time = r.get("ExitTime") or r.get("Exit") or ""
        processes.append({
            "pid":  pid,
            "ppid": ppid,
            "name": name,
            "exit_time": exit_time,
        })
    return {"processes": processes, "count": len(processes)}


def _extract_malfind_intel(rows: list[dict]) -> dict[str, Any]:
    """Extract injection indicators from malfind output."""
    hits = []
    for r in rows:
        pid  = r.get("PID") or r.get("Pid") or r.get("pid")
        proc = r.get("Process") or r.get("ImageFileName") or r.get("name") or ""
        base = r.get("Start")  or r.get("StartVPN") or r.get("Address") or r.get("address") or ""
        prot = r.get("Protection") or r.get("Protect") or ""
        tag  = r.get("Tag") or ""
        hexdump = r.get("Hexdump") or r.get("hexdump") or ""
        disasm  = r.get("Disasm")  or r.get("disasm")  or ""

        # MZ header = PE in memory = reflective loader / injected DLL
        has_mz = "4d5a" in str(hexdump).lower() or "MZ" in str(hexdump)

        hits.append({
            "pid":           pid,
            "process":       proc,
            "base_address":  base if isinstance(base, str) else hex(base) if isinstance(base, int) else str(base),
            "protection":    prot,
            "tag":           tag,
            "has_mz_header": has_mz,
            "hexdump_head":  str(hexdump)[:120],
            "disasm_head":   str(disasm)[:200],
        })
    return {"hits": hits, "count": len(hits), "pe_injections": sum(1 for h in hits if h["has_mz_header"])}


def _extract_network_intel(rows: list[dict]) -> dict[str, Any]:
    """Extract C2/network artefacts from netscan/netstat output."""
    connections = []
    c2_candidates = []
    for r in rows:
        proto      = r.get("Proto") or r.get("proto") or r.get("Protocol") or ""
        local_addr = r.get("LocalAddr") or r.get("local_address") or r.get("LocalAddress") or ""
        local_port = r.get("LocalPort") or r.get("local_port") or ""
        foreign    = r.get("ForeignAddr") or r.get("RemoteAddr") or r.get("remote_address") or ""
        fport      = r.get("ForeignPort") or r.get("RemotePort") or r.get("remote_port") or ""
        state      = r.get("State") or r.get("state") or ""
        pid        = r.get("PID") or r.get("Pid") or r.get("pid") or ""
        proc       = r.get("Owner") or r.get("Process") or r.get("name") or ""

        conn = {
            "proto": str(proto), "local": f"{local_addr}:{local_port}",
            "foreign": f"{foreign}:{fport}", "state": str(state),
            "pid": pid, "process": str(proc),
        }
        connections.append(conn)

        # Flag non-loopback, non-LAN external connections as C2 candidates
        faddr = str(foreign)
        is_external = (
            faddr and
            not faddr.startswith("0.0.0.0") and
            not faddr.startswith("127.") and
            not faddr.startswith("::") and
            not faddr.startswith("10.") and
            not re.match(r"^192\.168\.", faddr) and
            not re.match(r"^172\.(1[6-9]|2\d|3[01])\.", faddr)
        )
        if is_external and str(state).upper() in ("ESTABLISHED", "CLOSE_WAIT", ""):
            c2_candidates.append(conn)

    return {
        "connections": connections,
        "count": len(connections),
        "c2_candidates": c2_candidates,
        "external_count": len(c2_candidates),
    }


def _extract_ssdt_intel(rows: list[dict]) -> dict[str, Any]:
    """Detect SSDT hooks - non-ntoskrnl handlers = rootkit indicator."""
    hooks = []
    for r in rows:
        sym    = r.get("Symbol") or r.get("symbol") or r.get("FunctionName") or ""
        module = r.get("Module") or r.get("module") or ""
        addr   = r.get("Address") or r.get("address") or ""
        idx    = r.get("Index") or r.get("index") or ""
        # Hook = handler not in ntoskrnl or win32k
        is_hooked = module and not any(
            m in str(module).lower()
            for m in ("ntoskrnl", "win32k", "ntkrnl")
        )
        if is_hooked:
            hooks.append({"index": idx, "symbol": sym, "module": module, "address": addr})
    return {"hooks": hooks, "hook_count": len(hooks)}


def _hidden_process_diff(pslist_rows: list[dict], psscan_rows: list[dict]) -> list[dict]:
    """
    Cross-reference pslist vs psscan.
    Processes in psscan but NOT pslist = potentially hidden (DKOM unlink).
    """
    def get_pid(r: dict) -> int | None:
        v = r.get("PID") or r.get("Pid") or r.get("pid")
        try:
            return int(v)
        except (TypeError, ValueError):
            return None

    listed_pids = {get_pid(r) for r in pslist_rows if get_pid(r) is not None}
    hidden = []
    for r in psscan_rows:
        pid = get_pid(r)
        if pid and pid not in listed_pids:
            name = r.get("ImageFileName") or r.get("Name") or r.get("name") or ""
            hidden.append({"pid": pid, "name": name, "reason": "In psscan but not pslist - possible DKOM unlink"})
    return hidden


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def _compute_risk(results: dict[str, dict]) -> dict[str, Any]:
    """Aggregate risk score from all plugin results."""
    score = 0
    findings = []

    malfind = results.get("windows.malfind", {})
    if malfind.get("ok"):
        intel = malfind.get("_intel", {})
        count = intel.get("count", 0)
        pe_inj = intel.get("pe_injections", 0)
        if pe_inj > 0:
            score += 30
            findings.append(f"Malfind: {pe_inj} PE injection(s) detected (MZ header in RWX region)")
        elif count > 0:
            score += 15
            findings.append(f"Malfind: {count} suspicious RWX region(s)")

    netscan = results.get("windows.netscan") or results.get("windows.netstat", {})
    if netscan and netscan.get("ok"):
        intel = netscan.get("_intel", {})
        ext = intel.get("external_count", 0)
        if ext > 0:
            score += min(ext * 5, 20)
            findings.append(f"Network: {ext} external C2 candidate connection(s)")

    ssdt = results.get("windows.ssdt", {})
    if ssdt.get("ok"):
        intel = ssdt.get("_intel", {})
        hooks = intel.get("hook_count", 0)
        if hooks > 0:
            score += 25
            findings.append(f"SSDT: {hooks} hook(s) detected - rootkit indicator")

    hidden = results.get("_hidden_processes", [])
    if hidden:
        score += len(hidden) * 10
        findings.append(f"Hidden processes: {len(hidden)} process(es) unlinked from pslist")

    svcscan = results.get("windows.svcscan", {})
    if svcscan.get("ok") and svcscan.get("row_count", 0) > 0:
        for r in svcscan.get("rows", [])[:]:
            svc_name = str(r.get("Name") or r.get("name") or "").lower()
            bin_path = str(r.get("Binary") or r.get("binary") or r.get("ImagePath") or "").lower()
            if any(k in bin_path for k in ["temp", "appdata", "programdata", "\\users\\"]):
                score += 10
                findings.append(f"Suspicious service path: {bin_path[:80]}")
                break

    tier = "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW" if score > 0 else "CLEAN"
    return {"score": min(score, 100), "tier": tier, "findings": findings}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_volatility(
    path: str,
    plugins: list[str] | None = None,
    mode: str = "triage",   # "triage" | "full" | "custom"
    pid_filter: int | None = None,
) -> AnalysisResult:
    """
    Run Volatility 3 against a memory image and return a structured AnalysisResult.

    Args:
        path:        Path to memory image (.raw, .lime, .avml, .vmem, .dmp)
        plugins:     Specific plugin names to run (overrides mode)
        mode:        "triage" = fast essential set, "full" = everything, "custom" = use plugins arg
        pid_filter:  Filter process-specific plugins to this PID
    """
    info = get_file_info(path)
    fmt  = probe_dmp_format(path)
    warnings: list[str] = []

    # Warn if this is an MDMP (Task Manager dump) - Volatility has limited support
    if fmt.is_minidump:
        warnings.append(
            "MDMP (Task Manager dump) detected. Volatility has limited support for MDMP format. "
            "Most plugins work best with full memory images (raw, lime, avml, vmem). "
            "Use JMA 'basic' and 'minidump' modes for full MDMP coverage."
        )

    # Check Volatility availability
    vol_loc = _find_vol()
    if vol_loc is None:
        return AnalysisResult(
            analyzer="volatility",
            ok=False,
            summary="Volatility 3 not installed. Run: pip install volatility3",
            details={"file": info.__dict__, "format": fmt.__dict__},
            warnings=warnings,
        )

    # Select plugins
    if plugins:
        selected_names = plugins
    elif mode == "full":
        selected_names = FULL_PLUGINS
    else:
        selected_names = TRIAGE_PLUGINS

    # Build plugin objects
    cat_map = {p.name: p for p in PLUGIN_CATALOGUE}
    selected_plugins = []
    for name in selected_names:
        if name in cat_map:
            selected_plugins.append(cat_map[name])
        else:
            # Unknown plugin - create a generic entry
            selected_plugins.append(VolPlugin(name, name, "misc", 0, 180))

    # Apply PID filter where relevant
    if pid_filter:
        for p in selected_plugins:
            if p.name in ("windows.dlllist", "windows.handles", "windows.memmap", "windows.vadinfo"):
                p.extra_args = p.extra_args + ["--pid", str(pid_filter)]

    # Run all plugins
    results: dict[str, Any] = {}
    total = len(selected_plugins)

    for i, plug in enumerate(selected_plugins, 1):
        result = _run_plugin(path, plug)

        # Attach intelligence extraction
        if result.get("ok") and result.get("rows"):
            if plug.name in ("windows.pslist", "windows.psscan"):
                result["_intel"] = _extract_pslist_intel(result["rows"])
            elif plug.name == "windows.malfind":
                result["_intel"] = _extract_malfind_intel(result["rows"])
            elif plug.name in ("windows.netscan", "windows.netstat"):
                result["_intel"] = _extract_network_intel(result["rows"])
            elif plug.name == "windows.ssdt":
                result["_intel"] = _extract_ssdt_intel(result["rows"])

        results[plug.name] = result

    # Hidden process diff (pslist vs psscan)
    pslist_rows = results.get("windows.pslist", {}).get("rows", [])
    psscan_rows = results.get("windows.psscan", {}).get("rows", [])
    if pslist_rows and psscan_rows:
        results["_hidden_processes"] = _hidden_process_diff(pslist_rows, psscan_rows)

    # Risk scoring
    risk = _compute_risk(results)

    # Build summary
    ok_count   = sum(1 for r in results.values() if isinstance(r, dict) and r.get("ok"))
    fail_count = sum(1 for r in results.values() if isinstance(r, dict) and not r.get("ok"))
    proc_count = results.get("windows.pslist", {}).get("_intel", {}).get("count", 0)
    mf_count   = results.get("windows.malfind", {}).get("_intel", {}).get("count", 0)
    net_ext    = (results.get("windows.netscan") or results.get("windows.netstat") or {}).get("_intel", {}).get("external_count", 0)
    hidden     = len(results.get("_hidden_processes", []))

    summary = (
        f"[{risk['tier']}] Volatility triage complete. "
        f"Plugins: {ok_count} ok / {fail_count} failed. "
        f"Processes: {proc_count}, Hidden: {hidden}, "
        f"Malfind hits: {mf_count}, External C2 candidates: {net_ext}."
    )

    if risk["findings"]:
        warnings.extend(risk["findings"])

    details: dict[str, Any] = {
        "file":            {**info.__dict__, "format": fmt.__dict__},
        "volatility_mode": mode,
        "plugins_run":     selected_names,
        "risk":            risk,
        "results":         results,
        "hidden_processes": results.get("_hidden_processes", []),
    }

    return AnalysisResult(
        analyzer="volatility",
        ok=(ok_count > 0),
        summary=summary,
        details=details,
        warnings=warnings,
    )
