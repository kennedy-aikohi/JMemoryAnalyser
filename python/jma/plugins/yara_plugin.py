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

def p_yara(dmp: str, rules_dir: str = "rules\\vendor\\yara", **kwargs) -> Dict[str, Any]:
    try:
        import yara
    except Exception as e:
        return {"ok": False, "error": f"yara-python not installed: {e}. Install with: python -m pip install yara-python"}

    rules_dir = os.path.abspath(rules_dir)
    if not os.path.isdir(rules_dir):
        return {"ok": False, "error": f"Rules dir not found: {rules_dir}"}

    files = _collect_rule_files(rules_dir)
    if not files:
        return {"ok": False, "error": f"No .yar/.yara files found under: {rules_dir}"}

    compiled = 0
    failed = []
    match_hits = []

    # Compile each file individually so one bad file doesn't break everything.
    for path in files:
        try:
            rules = yara.compile(filepath=path)
            compiled += 1
        except Exception as e:
            failed.append({"file": path, "error": str(e)})
            continue

        try:
            ms = rules.match(dmp, timeout=60)
            for m in ms:
                match_hits.append({
                    "rule": m.rule,
                    "namespace": m.namespace,
                    "tags": list(m.tags),
                    "meta": dict(m.meta),
                    "source_file": path,
                })
        except Exception as e:
            failed.append({"file": path, "error": f"match_error: {e}"})
            continue

    # Heuristic family label: prefer meta.family / meta.malware / meta.threat if present
    families = {}
    for h in match_hits:
        meta = h.get("meta") or {}
        fam = meta.get("family") or meta.get("malware") or meta.get("threat") or meta.get("description")
        if isinstance(fam, str) and fam.strip():
            families[fam.strip()] = families.get(fam.strip(), 0) + 1

    top_families = sorted([{"label": k, "count": v} for k, v in families.items()], key=lambda x: x["count"], reverse=True)[:20]

    return {
        "ok": True,
        "rules_dir": rules_dir,
        "files_found": len(files),
        "compiled_ok": compiled,
        "failed_count": len(failed),
        "match_count": len(match_hits),
        "top_family_labels": top_families,
        "matches": match_hits[:500],
        "failures": failed[:200],
        "note": "Rule repos vary in style/variables; failures are expected and are skipped."
    }

def register_all() -> None:
    register(Plugin("yara", "Scan the dump with YARA rules under rules\\vendor\\yara (auto-fetched).", "hybrid", p_yara))
