from __future__ import annotations
import json
import subprocess
import sys
from typing import Any

def vol_json(image_path: str, plugin: str, extra: list[str] | None = None, timeout: int = 300) -> Any:
    """
    Run Volatility3 plugin with JSON renderer and return parsed JSON.
    Uses the current interpreter (venv) for reliability.
    """
    extra = extra or []
    cmd = [sys.executable, "-m", "volatility3", "-r", "json", "-f", image_path, plugin] + extra
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    if p.returncode != 0:
        raise RuntimeError(
            f"Volatility failed ({plugin}) rc={p.returncode}\nSTDERR:\n{p.stderr[-4000:]}\nSTDOUT:\n{p.stdout[-4000:]}"
        )

    out = p.stdout.strip()
    if not out:
        return None

    # Volatility JSON renderer typically outputs a single JSON document.
    return json.loads(out)
