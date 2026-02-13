from __future__ import annotations
import os
from typing import Any
from .common import AnalysisResult
from ..utils import get_file_info, extract_ascii_strings, iter_file_chunks

DEFAULT_KEYWORDS = [
    "EXCEPTION", "STACK", "MODULE", "KERNEL32", "ntdll", "ucrtbase", "fault", "access violation",
    "0xC0000005", "BugCheck", "PAGE_FAULT", "IRQL", "win32k", "dxgkrnl", "WHEA",
]

def run_basic(path: str, max_mb_scan: int = 256) -> AnalysisResult:
    info = get_file_info(path)

    # Read only up to max_mb_scan for string scanning (avoid huge RAM usage)
    max_bytes = max_mb_scan * 1024 * 1024
    read_bytes = 0
    strings: list[str] = []

    for chunk in iter_file_chunks(path):
        if read_bytes >= max_bytes:
            break
        take = chunk if (read_bytes + len(chunk)) <= max_bytes else chunk[: max_bytes - read_bytes]
        read_bytes += len(take)
        strings.extend(extract_ascii_strings(take, min_len=7))

    # De-dupe while preserving order
    seen = set()
    uniq_strings = []
    for s in strings:
        if s not in seen:
            seen.add(s)
            uniq_strings.append(s)

    # Keyword hits
    hits: dict[str, int] = {}
    lower = [s.lower() for s in uniq_strings]
    for kw in DEFAULT_KEYWORDS:
        k = kw.lower()
        hits[kw] = sum(1 for s in lower if k in s)

    # Short preview set for the report
    preview = uniq_strings[:500]

    details: dict[str, Any] = {
        "file": info.__dict__,
        "scan": {
            "max_mb_scan": max_mb_scan,
            "bytes_scanned": read_bytes,
            "strings_found": len(uniq_strings),
            "strings_preview_count": len(preview),
            "keyword_hits": hits,
        },
        "strings_preview": preview,
    }

    return AnalysisResult(
        analyzer="basic",
        ok=True,
        summary=f"Scanned {read_bytes} bytes, extracted {len(uniq_strings)} strings.",
        details=details,
        warnings=[] if info.size <= max_bytes else [f"File larger than scan limit; scanned first {max_mb_scan} MB only."],
    )
