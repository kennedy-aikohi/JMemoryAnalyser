from __future__ import annotations
import subprocess
from typing import Any
from .common import AnalysisResult
from ..utils import get_file_info

def run_volatility(path: str) -> AnalysisResult:
    """
    Hook for Volatility 3.
    Note: Volatility generally expects full memory images (raw, lime, avml, etc.).
    Many Windows .dmp formats won't work directly.
    """
    info = get_file_info(path)

    try:
        import volatility3  # noqa: F401  # type: ignore
    except Exception as e:
        return AnalysisResult(
            analyzer="volatility",
            ok=False,
            summary="volatility3 not installed. Install via: pip install volatility3",
            details={"file": info.__dict__, "error": str(e)},
            warnings=[],
        )

    # We call volatility3 as a module to keep it simple.
    # User can change plugin list later.
    plugins = [
        ("windows.info", []),
        ("windows.pslist", []),
    ]

    outputs: dict[str, Any] = {"file": info.__dict__, "runs": []}
    warnings = [
        "Volatility works best with full memory images; many .dmp files may fail or give partial results."
    ]

    for plugin, args in plugins:
        cmd = ["python", "-m", "volatility3", "-f", path, plugin] + args
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            outputs["runs"].append({
                "plugin": plugin,
                "cmd": cmd,
                "returncode": p.returncode,
                "stdout": p.stdout[-20000:],  # keep tail
                "stderr": p.stderr[-20000:],
            })
        except Exception as e:
            outputs["runs"].append({
                "plugin": plugin,
                "cmd": cmd,
                "error": str(e),
            })

    ok = any(r.get("returncode", 1) == 0 for r in outputs["runs"])
    summary = "Volatility plugins executed." if ok else "Volatility execution failed (likely incompatible dump format)."

    return AnalysisResult(
        analyzer="volatility",
        ok=ok,
        summary=summary,
        details=outputs,
        warnings=warnings,
    )
