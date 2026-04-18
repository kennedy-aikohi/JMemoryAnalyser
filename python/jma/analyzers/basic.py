from __future__ import annotations

import os
from typing import Any

from .common import AnalysisResult
from ..utils import get_file_info, probe_dmp_format, extract_ascii_strings, extract_unicode_strings, iter_file_chunks

# ---------------------------------------------------------------------------
# Keyword taxonomy - expanded for production DMP triage
# ---------------------------------------------------------------------------
_KEYWORDS: dict[str, list[str]] = {
    # Crash / exception signals present in Windows minidumps
    "crash_signals": [
        "EXCEPTION_ACCESS_VIOLATION", "0xC0000005", "0xC0000409",
        "0x80000003", "STACK_OVERFLOW", "STATUS_HEAP_CORRUPTION",
        "EXCEPTION_BREAKPOINT", "CRITICAL_PROCESS_DIED",
        "INVALID_HANDLE", "fault", "access violation",
        "BugCheck", "PAGE_FAULT", "IRQL",
    ],
    # OS & loader artefacts
    "os_loader": [
        "KERNEL32", "ntdll", "ucrtbase", "KERNELBASE", "wow64",
        "ntoskrnl", "win32k", "dxgkrnl", "WHEA",
        "msvcrt", "clr.dll", "mscorlib",
    ],
    # Credential / LSASS exposure
    "credential_exposure": [
        "lsass", "sekurlsa", "wdigest", "kerberos", "SAMKey",
        "NtlmHash", "LMHash", "mimikatz", "WCE", "pwdump",
    ],
    # Common C2 / RAT strings
    "c2_indicators": [
        "cmd.exe", "powershell", "wscript", "cscript",
        "mshta", "regsvr32", "rundll32", "schtasks",
        "beacon", "implant", "stager", "shellcode",
        "Cobalt Strike", "Metasploit", "meterpreter",
        "MSSE-", "msagent_", "postex",
    ],
    # Network / IOC strings
    "network_ioc": [
        "http://", "https://", "ftp://",
        "CreateSocket", "WSAConnect", "InternetOpenUrl",
        "WinHttpOpen", "URLDownloadToFile",
        "CONNECT ", "User-Agent:", "X-Forwarded",
    ],
    # Process injection / hollowing
    "injection": [
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "RtlCreateUserThread",
        "SetThreadContext", "QueueUserAPC",
        "NtUnmapViewOfSection", "ZwMapViewOfSection",
        "ProcessHollowing", "reflective",
    ],
    # Persistence artefacts
    "persistence": [
        "CurrentVersion\\Run", "CurrentVersion\\RunOnce",
        "HKCU\\Software\\Microsoft",
        "Startup", "schtasks /create", "sc create",
        "AppData\\Roaming", "AppData\\Local\\Temp",
    ],
    # Ransomware indicators
    "ransomware": [
        "CryptEncrypt", "CryptGenKey", "BCryptEncrypt",
        "DeleteShadowCopy", "vssadmin delete",
        "wbadmin delete", ".locked", ".encrypted",
        "README_HOW_TO_DECRYPT",
    ],
}

# Flat keyword list for quick scanning
_ALL_KEYWORDS: list[str] = [kw for lst in _KEYWORDS.values() for kw in lst]


def _keyword_scan(strings: list[str]) -> dict[str, dict[str, int]]:
    """Return hit counts per category and per keyword."""
    lower_strings = [s.lower() for s in strings]
    by_category: dict[str, dict[str, int]] = {}
    for category, keywords in _KEYWORDS.items():
        hits: dict[str, int] = {}
        for kw in keywords:
            kl = kw.lower()
            count = sum(1 for s in lower_strings if kl in s)
            if count:
                hits[kw] = count
        if hits:
            by_category[category] = hits
    return by_category


def run_basic(path: str, max_mb_scan: int = 256) -> AnalysisResult:
    info = get_file_info(path)
    fmt = probe_dmp_format(path)

    warnings: list[str] = []
    if fmt.format == "UNKNOWN":
        warnings.append(f"DMP format check FAILED: {fmt.note}")
    elif fmt.is_full_dump:
        warnings.append(
            f"Detected full memory dump ({fmt.format}). "
            "Basic scanner works but Volatility is strongly recommended for full images."
        )

    max_bytes = max_mb_scan * 1024 * 1024
    read_bytes = 0
    ascii_strings: list[str] = []
    unicode_strings: list[str] = []

    for chunk in iter_file_chunks(path):
        if read_bytes >= max_bytes:
            break
        take = chunk if (read_bytes + len(chunk)) <= max_bytes else chunk[: max_bytes - read_bytes]
        read_bytes += len(take)
        ascii_strings.extend(extract_ascii_strings(take, min_len=6))
        unicode_strings.extend(extract_unicode_strings(take, min_len=6))

    # De-duplicate ASCII while preserving order
    seen: set[str] = set()
    uniq_ascii: list[str] = []
    for s in ascii_strings:
        if s not in seen:
            seen.add(s)
            uniq_ascii.append(s)

    # De-duplicate Unicode
    seen_u: set[str] = set()
    uniq_unicode: list[str] = []
    for s in unicode_strings:
        if s not in seen_u and s not in seen:   # don't repeat ASCII-also strings
            seen_u.add(s)
            uniq_unicode.append(s)

    all_strings = uniq_ascii + uniq_unicode

    # Keyword scan across combined string set
    keyword_hits_by_category = _keyword_scan(all_strings)

    # Flat summary for backwards compat
    flat_hits: dict[str, int] = {}
    for cat_hits in keyword_hits_by_category.values():
        flat_hits.update(cat_hits)

    # Determine overall risk tier
    total_hits = sum(flat_hits.values())
    high_categories = {"c2_indicators", "injection", "credential_exposure", "ransomware"}
    high_hit_categories = [c for c in keyword_hits_by_category if c in high_categories]
    if high_hit_categories:
        risk_tier = "HIGH"
    elif total_hits > 5:
        risk_tier = "MEDIUM"
    elif total_hits > 0:
        risk_tier = "LOW"
    else:
        risk_tier = "CLEAN"

    # URL and IP extraction from strings
    import re
    url_pattern = re.compile(r"https?://[^\s'\"<>{}\[\]\\]{4,}", re.IGNORECASE)
    ip_pattern  = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    extracted_urls: list[str] = sorted({m.group() for s in all_strings for m in url_pattern.finditer(s)})
    extracted_ips:  list[str] = sorted({m.group() for s in all_strings for m in ip_pattern.finditer(s)})

    # Preview strings
    preview_ascii   = uniq_ascii[:300]
    preview_unicode = uniq_unicode[:200]

    if info.size > max_bytes:
        warnings.append(f"File larger than scan limit ({max_mb_scan} MB); only first {max_mb_scan} MB scanned.")

    details: dict[str, Any] = {
        "file": {**info.__dict__, "format": fmt.__dict__},
        "scan": {
            "max_mb_scan": max_mb_scan,
            "bytes_scanned": read_bytes,
            "ascii_strings_found": len(uniq_ascii),
            "unicode_strings_found": len(uniq_unicode),
            "total_unique_strings": len(all_strings),
            "keyword_hits_by_category": keyword_hits_by_category,
            "keyword_hits_flat": flat_hits,
            "risk_tier": risk_tier,
            "high_risk_categories": high_hit_categories,
            "extracted_urls": extracted_urls[:200],
            "extracted_ips": extracted_ips[:200],
        },
        "strings_preview_ascii":   preview_ascii,
        "strings_preview_unicode": preview_unicode,
    }

    summary = (
        f"[{risk_tier}] Scanned {read_bytes:,} bytes - "
        f"{len(uniq_ascii)} ASCII + {len(uniq_unicode)} Unicode strings. "
        f"Keyword hits: {total_hits} across {len(keyword_hits_by_category)} categories. "
        f"URLs: {len(extracted_urls)}, IPs: {len(extracted_ips)}."
    )

    return AnalysisResult(
        analyzer="basic",
        ok=True,
        summary=summary,
        details=details,
        warnings=warnings,
    )
