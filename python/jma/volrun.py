"""
Low-level Volatility 3 subprocess runner.
Used by volatility_analyzer.py and the GUI backend.
Always uses sys.executable so we stay in the active venv.
"""
from __future__ import annotations

import json
import subprocess
import sys
from typing import Any


def vol_json(
    image_path: str,
    plugin: str,
    extra: list[str] | None = None,
    timeout: int = 300,
) -> Any:
    """
    Run a Volatility 3 plugin with the JSON renderer.
    Returns parsed JSON output or None if stdout is empty.
    Raises RuntimeError on non-zero exit with no output.
    """
    extra = extra or []
    cmd = [sys.executable, "-m", "volatility3",
           "-r", "json", "-f", image_path, plugin] + extra

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Volatility timed out after {timeout}s (plugin={plugin})")
    except FileNotFoundError:
        raise RuntimeError("Python interpreter not found - cannot run Volatility")

    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(
            f"Volatility failed (plugin={plugin}, rc={proc.returncode})\n"
            f"STDERR:\n{proc.stderr[-3000:]}\n"
            f"STDOUT:\n{proc.stdout[-1000:]}"
        )

    out = proc.stdout.strip()
    if not out:
        return None

    return json.loads(out)


def vol_text(
    image_path: str,
    plugin: str,
    extra: list[str] | None = None,
    timeout: int = 300,
) -> str:
    """
    Run a Volatility plugin with the default text renderer.
    Returns stdout as a string.
    """
    extra = extra or []
    cmd = [sys.executable, "-m", "volatility3",
           "-f", image_path, plugin] + extra

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return proc.stdout or ""
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT after {timeout}s]"
    except Exception as e:
        return f"[ERROR: {e}]"
