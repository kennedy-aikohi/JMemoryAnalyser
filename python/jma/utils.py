from __future__ import annotations
import hashlib
import os
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

@dataclass
class FileInfo:
    path: str
    size: int
    mtime_utc: str
    sha256: str

def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
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

def extract_ascii_strings(data: bytes, min_len: int = 6) -> list[str]:
    # Extract ASCII-ish strings safely
    pattern = rb"[ -~]{%d,}" % min_len
    return [m.group(0).decode("ascii", errors="ignore") for m in re.finditer(pattern, data)]

def iter_file_chunks(path: str, chunk_size: int = 8 * 1024 * 1024) -> Iterable[bytes]:
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            yield b
