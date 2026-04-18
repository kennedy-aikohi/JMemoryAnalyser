from __future__ import annotations

import os
from typing import Any, Dict, List

from .registry import Plugin, register


def _collect_rule_files(rules_dir: str) -> List[str]:
    out = []
    for root, _, files in os.walk(rules_dir):
        for f in files:
            lf = f.lower()
            if lf.endswith(".yar") or lf.endswith(".yara"):
                out.append(os.path.join(root, f))
    return sorted(out)


def p_yara(dmp: str, rules_dir: str = r"rules\vendor\yara", **kwargs) -> Dict[str, Any]:
    # Normalise path separators - works on both Windows and Linux
    rules_dir = os.path.abspath(rules_dir.replace("\\", os.sep).replace("/", os.sep))

    try:
        import yara  # type: ignore
    except ImportError:
        return {
            "ok": False,
            "error": (
                "yara-python not installed. "
                "Run: powershell -ExecutionPolicy Bypass -File .\\scripts\\Install-JMA.ps1 -WithYara"
            ),
        }

    if not os.path.isdir(rules_dir):
        return {
            "ok": False,
            "error": (
                f"Rules directory not found: {rules_dir}. "
                "Run: powershell -ExecutionPolicy Bypass -File .\\scripts\\Update-JMA-Rules.ps1"
            ),
        }

    files = _collect_rule_files(rules_dir)
    if not files:
        return {
            "ok": False,
            "error": f"No .yar/.yara files found under: {rules_dir}",
        }

    compiled_ok = 0
    failed: List[Dict[str, str]] = []
    match_hits: List[Dict[str, Any]] = []

    for path in files:
        try:
            rules = yara.compile(filepath=path)
            compiled_ok += 1
        except Exception as e:
            failed.append({"file": path, "error": str(e)})
            continue

        try:
            ms = rules.match(dmp, timeout=60)
            for m in ms:
                match_hits.append({
                    "rule":        m.rule,
                    "namespace":   m.namespace,
                    "tags":        list(m.tags),
                    "meta":        dict(m.meta),
                    "source_file": path,
                })
        except Exception as e:
            failed.append({"file": path, "error": f"match_error: {e}"})

    # Family label extraction
    families: Dict[str, int] = {}
    for h in match_hits:
        meta = h.get("meta") or {}
        fam  = meta.get("family") or meta.get("malware") or meta.get("threat") or meta.get("description")
        if isinstance(fam, str) and fam.strip():
            key = fam.strip()
            families[key] = families.get(key, 0) + 1

    top_families = sorted(
        [{"label": k, "count": v} for k, v in families.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:20]

    return {
        "ok":                True,
        "rules_dir":         rules_dir,
        "files_found":       len(files),
        "compiled_ok":       compiled_ok,
        "failed_count":      len(failed),
        "match_count":       len(match_hits),
        "top_family_labels": top_families,
        "matches":           match_hits[:500],
        "failures":          failed[:100],
        "note": (
            "Rule repos vary in style/variables; compile failures are expected and skipped. "
            "Run Update-JMA-Rules.ps1 to refresh rule sets."
        ),
    }


def register_all() -> None:
    register(Plugin(
        name    = "yara",
        help    = "Scan dump with YARA rules (rules\\vendor\\yara). Run Update-JMA-Rules.ps1 first.",
        backend = "hybrid",
        runner  = p_yara,
    ))
