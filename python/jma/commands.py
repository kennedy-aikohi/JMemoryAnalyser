from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Any

from .volrun import vol_json

@dataclass
class CmdResult:
    ok: bool
    summary: str
    data: Any

def _rows(doc: Any) -> list[dict]:
    """
    Vol3 JSON output varies by version; normalize to a list of row dicts if possible.
    """
    if doc is None:
        return []
    if isinstance(doc, list):
        # already a list of row dicts
        return [r for r in doc if isinstance(r, dict)]
    if isinstance(doc, dict):
        # Some renderers wrap as {"rows":[...]} or similar
        for k in ("rows", "data", "result", "elements"):
            v = doc.get(k)
            if isinstance(v, list):
                return [r for r in v if isinstance(r, dict)]
    return []

def cmd_info(image: str) -> CmdResult:
    doc = vol_json(image, "windows.info")
    return CmdResult(True, "windows.info", doc)

def cmd_pslist(image: str) -> CmdResult:
    doc = vol_json(image, "windows.pslist")
    return CmdResult(True, "windows.pslist", doc)

def cmd_cmdline(image: str) -> CmdResult:
    doc = vol_json(image, "windows.cmdline")
    return CmdResult(True, "windows.cmdline", doc)

def cmd_threads(image: str, pid: int) -> CmdResult:
    # Volatility 3 threads plugin exists as windows.threads on many builds
    doc = vol_json(image, "windows.threads", ["--pid", str(pid)])
    return CmdResult(True, f"windows.threads pid={pid}", doc)

def cmd_handles(image: str, pid: int) -> CmdResult:
    doc = vol_json(image, "windows.handles", ["--pid", str(pid)])
    return CmdResult(True, f"windows.handles pid={pid}", doc)

def cmd_malfind(image: str, pid: int | None = None) -> CmdResult:
    extra = []
    if pid is not None:
        extra = ["--pid", str(pid)]
    doc = vol_json(image, "windows.malfind", extra, timeout=600)
    return CmdResult(True, f"windows.malfind{'' if pid is None else f' pid={pid}'}", doc)

def cmd_netscan(image: str) -> CmdResult:
    doc = vol_json(image, "windows.netscan")
    return CmdResult(True, "windows.netscan", doc)

def find_pid_by_image(ps_rows: list[dict], image_name: str) -> list[int]:
    hits = []
    img = image_name.lower()
    for r in ps_rows:
        for k in ("ImageFileName", "ImageFile", "image", "Name", "Process"):
            v = r.get(k)
            if isinstance(v, str) and v.lower() == img:
                for pk in ("PID", "Pid", "pid"):
                    pv = r.get(pk)
                    if isinstance(pv, int):
                        hits.append(pv)
    return sorted(set(hits))

def extract_os_version(info_doc: Any) -> str | None:
    # Try common keys
    if isinstance(info_doc, dict):
        for k in ("Version", "version", "NtMajorVersion", "MajorVersion"):
            if k in info_doc and isinstance(info_doc[k], str):
                return info_doc[k]
    # Sometimes it?s a list of dict rows
    rows = _rows(info_doc)
    for r in rows:
        for k in ("NtBuildLab", "Kernel Base", "Build", "NtVersion", "Version"):
            v = r.get(k)
            if isinstance(v, str) and re.search(r"\d+\.\d+\.\d+\.\d+", v):
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)", v)
                if m:
                    return m.group(1)
    return None

def extract_cmdline_path(cmd_doc: Any, pid: int) -> str | None:
    rows = _rows(cmd_doc)
    for r in rows:
        p = r.get("PID") or r.get("Pid") or r.get("pid")
        if p == pid:
            for k in ("CommandLine", "CmdLine", "command_line", "Args"):
                v = r.get(k)
                if isinstance(v, str) and v.strip():
                    return v.strip()
    return None

def count_threads(threads_doc: Any) -> int:
    rows = _rows(threads_doc)
    return len(rows)

def find_named_pipes_in_handles(handles_doc: Any) -> list[str]:
    rows = _rows(handles_doc)
    pipes = set()
    for r in rows:
        name = None
        for k in ("Name", "ObjectName", "FullName", "name"):
            v = r.get(k)
            if isinstance(v, str):
                name = v
                break
        if not name:
            continue
        # Typical pipe path: \Device\NamedPipe\XYZ
        if "\\Device\\NamedPipe\\" in name or "\\PIPE\\" in name.upper():
            pipes.add(name)
    return sorted(pipes)

def find_last_thread_create_time(threads_doc: Any) -> str | None:
    rows = _rows(threads_doc)
    # keys vary; try common time field names
    candidates = []
    for r in rows:
        for k in ("CreateTime", "create_time", "Created", "StartTime", "start_time"):
            v = r.get(k)
            if isinstance(v, str) and v.strip():
                candidates.append(v.strip())
                break
    # Not always sortable; return max lexicographically as a best-effort (many are ISO-ish)
    return max(candidates) if candidates else None

def find_malfind_base_and_pid(malfind_doc: Any) -> list[dict]:
    rows = _rows(malfind_doc)
    hits = []
    for r in rows:
        pid = r.get("PID") or r.get("Pid") or r.get("pid")
        base = None
        for k in ("Start", "StartAddress", "Base", "Address", "VAD_Start", "VadStart"):
            v = r.get(k)
            if isinstance(v, str):
                base = v
                break
            if isinstance(v, int):
                base = hex(v)
                break
        if pid and base:
            hits.append({"pid": pid, "base": base, "row": r})
    return hits

def find_c2_ips(netscan_doc: Any) -> list[str]:
    rows = _rows(netscan_doc)
    ips = set()
    for r in rows:
        for k in ("ForeignAddr", "ForeignAddress", "RemoteAddr", "RemoteAddress"):
            v = r.get(k)
            if isinstance(v, str) and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v):
                ips.add(v)
    return sorted(ips)
