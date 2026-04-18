from __future__ import annotations

import hashlib
import os
import re
import struct
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

# ---------------------------------------------------------------------------
# Windows Minidump magic bytes
# MDMP header: "MDMP" (4D 44 4D 50) at offset 0
# Full memory dump (WinPmem/hiberfil style): "PAGEDUMP" or "FDMP"
# Task Manager dumps are standard MDMP minidumps.
# ---------------------------------------------------------------------------
_DMP_MAGIC_MDMP   = b"MDMP"
_DMP_MAGIC_PAGED  = b"PAGEDUMP"
_DMP_MAGIC_FDMP   = b"FDMP"


@dataclass
class FileInfo:
    path: str
    size: int
    mtime_utc: str
    sha256: str


@dataclass
class DmpFormatInfo:
    format: str           # "MDMP" | "FULL_PAGEDUMP" | "FULL_FDMP" | "UNKNOWN"
    is_minidump: bool
    is_full_dump: bool
    magic_hex: str
    note: str


def sha256_file(path: str, chunk_size: int = 4 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def get_file_info(path: str) -> FileInfo:
    st = os.stat(path)
    mtime = datetime.utcfromtimestamp(st.st_mtime).isoformat() + "Z"
    return FileInfo(
        path=os.path.abspath(path),
        size=st.st_size,
        mtime_utc=mtime,
        sha256=sha256_file(path),
    )


def probe_dmp_format(path: str) -> DmpFormatInfo:
    """
    Read the first 16 bytes of the file and classify the dump format.
    Task Manager .DMP files are always MDMP (Windows Minidump).
    """
    try:
        with open(path, "rb") as f:
            header = f.read(16)
    except OSError as e:
        return DmpFormatInfo(
            format="UNKNOWN", is_minidump=False, is_full_dump=False,
            magic_hex="", note=f"Cannot read file: {e}"
        )

    if len(header) < 4:
        return DmpFormatInfo(
            format="UNKNOWN", is_minidump=False, is_full_dump=False,
            magic_hex=header.hex(), note="File too small to be a valid dump"
        )

    magic_hex = header[:8].hex().upper()

    if header[:4] == _DMP_MAGIC_MDMP:
        return DmpFormatInfo(
            format="MDMP",
            is_minidump=True,
            is_full_dump=False,
            magic_hex=magic_hex,
            note="Windows Minidump (MDMP) - standard Task Manager / WER format",
        )
    if header[:8] == _DMP_MAGIC_PAGED:
        return DmpFormatInfo(
            format="FULL_PAGEDUMP",
            is_minidump=False,
            is_full_dump=True,
            magic_hex=magic_hex,
            note="Windows full memory / kernel dump (PAGEDUMP signature)",
        )
    if header[:4] == _DMP_MAGIC_FDMP:
        return DmpFormatInfo(
            format="FULL_FDMP",
            is_minidump=False,
            is_full_dump=True,
            magic_hex=magic_hex,
            note="Windows full dump (FDMP signature)",
        )

    return DmpFormatInfo(
        format="UNKNOWN",
        is_minidump=False,
        is_full_dump=False,
        magic_hex=magic_hex,
        note=(
            "Unknown format. File may be corrupt, not a dump, or a RAW memory image. "
            "CDB / minidump parser may fail. Use Volatility for RAW images."
        ),
    )


def extract_ascii_strings(data: bytes, min_len: int = 6) -> list[str]:
    """Extract printable ASCII strings from a bytes buffer."""
    pattern = rb"[ -~]{%d,}" % min_len
    return [m.group(0).decode("ascii", errors="ignore") for m in re.finditer(pattern, data)]


def extract_unicode_strings(data: bytes, min_len: int = 6) -> list[str]:
    """
    Extract UTF-16LE strings from a bytes buffer.
    Windows process dumps store many critical strings (module paths, registry keys,
    command lines, URLs, etc.) as UTF-16LE rather than ASCII. Missing these is a
    significant gap in basic DMP analysis.
    """
    results: list[str] = []
    i = 0
    n = len(data)
    current: list[int] = []

    while i < n - 1:
        lo = data[i]
        hi = data[i + 1]
        # Printable ASCII code point in UTF-16LE: hi byte == 0, lo in [0x20..0x7E]
        if hi == 0 and 0x20 <= lo <= 0x7E:
            current.append(lo)
            i += 2
        else:
            if len(current) >= min_len:
                try:
                    results.append(bytes(current).decode("ascii"))
                except Exception:
                    pass
            current = []
            i += 1

    if len(current) >= min_len:
        try:
            results.append(bytes(current).decode("ascii"))
        except Exception:
            pass

    return results


def iter_file_chunks(path: str, chunk_size: int = 8 * 1024 * 1024) -> Iterable[bytes]:
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            yield b
