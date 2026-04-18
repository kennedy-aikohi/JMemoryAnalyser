from __future__ import annotations
from dataclasses import dataclass
from typing import Any

@dataclass
class AnalysisResult:
    analyzer: str
    ok: bool
    summary: str
    details: dict[str, Any]
    warnings: list[str]
