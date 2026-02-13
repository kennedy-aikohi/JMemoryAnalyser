from __future__ import annotations

import csv
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


def _safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s)


def _flatten(obj: Any, prefix: str = "") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                out.update(_flatten(v, key))
            elif isinstance(v, list):
                # small scalar lists -> join; big/complex -> count
                if len(v) <= 10 and all(not isinstance(x, (dict, list)) for x in v):
                    out[key] = "|".join(str(x) for x in v)
                else:
                    out[key] = len(v)
            else:
                out[key] = v
    else:
        out[prefix or "value"] = obj
    return out


def _write_rows_csv(path: Path, fieldnames: List[str], rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def export_one(json_path: Path, out_dir: Path | None = None) -> List[Path]:
    """
    Convert one JMA JSON report -> one or more CSVs.
    Returns list of written CSV paths.
    """
    with json_path.open("r", encoding="utf-8-sig") as f:
        j = json.load(f)

    written: List[Path] = []
    out_dir = out_dir or json_path.parent
    base = json_path.stem

    sub = j.get("subcommand") or ""
    mode = j.get("mode") or ""
    plugin = (j.get("plugin") or {}).get("name") if isinstance(j.get("plugin"), dict) else None
    result = j.get("result") or {}

    # Common meta
    meta = {
        "tool": j.get("tool"),
        "version": j.get("version"),
        "timestamp_utc": j.get("timestamp_utc"),
        "author": j.get("author"),
        "github": j.get("github"),
        "linkedin": j.get("linkedin"),
        "subcommand": sub,
        "mode": mode,
        "plugin": plugin,
        "source_json": str(json_path),
    }

    # ---- Specialized outputs for analyst-friendly CSV ----
    # RWX: one row per hit
    if sub == "plugin" and plugin == "rwx":
        hits = result.get("hits") or []
        rows = [{**meta, "hit": h} for h in hits] or [{**meta, "hit": ""}]
        out = out_dir / f"{base}_rwx_hits.csv"
        _write_rows_csv(out, fieldnames=list(rows[0].keys()), rows=rows)
        written.append(out)
        return written

    # netfind: one row per IOC
    if sub == "plugin" and plugin == "netfind":
        rows: List[Dict[str, Any]] = []
        for ip in result.get("ip_candidates") or []:
            rows.append({**meta, "type": "ip", "value": ip})
        for url in result.get("url_candidates") or []:
            rows.append({**meta, "type": "url", "value": url})
        for dom in result.get("domain_candidates") or []:
            rows.append({**meta, "type": "domain", "value": dom})
        for pipe in result.get("named_pipes_seen") or []:
            rows.append({**meta, "type": "pipe", "value": pipe})
        if not rows:
            rows = [{**meta, "type": "", "value": ""}]
        out = out_dir / f"{base}_netfind_iocs.csv"
        _write_rows_csv(out, fieldnames=list(rows[0].keys()), rows=rows)
        written.append(out)
        return written

    # handles: named pipes list -> one row per pipe (if your plugin populates it)
    if sub == "plugin" and plugin == "handles":
        pipes = result.get("named_pipes") or []
        rows = [{**meta, "named_pipe": p} for p in pipes] or [{**meta, "named_pipe": ""}]
        out = out_dir / f"{base}_handles_namedpipes.csv"
        _write_rows_csv(out, fieldnames=list(rows[0].keys()), rows=rows)
        written.append(out)
        # plus a compact summary csv
        summary = {**meta, **_flatten({k: v for k, v in result.items() if k != "raw_tail"}, "result")}
        out2 = out_dir / f"{base}_summary.csv"
        _write_rows_csv(out2, fieldnames=list(summary.keys()), rows=[summary])
        written.append(out2)
        return written

    # basic run: keep summary CSV (don’t dump 75k strings into csv)
    if sub == "run" and mode == "basic":
        summary = {**meta, **_flatten(j.get("result") or {}, "result")}
        out = out_dir / f"{base}_summary.csv"
        _write_rows_csv(out, fieldnames=list(summary.keys()), rows=[summary])
        written.append(out)

        # optional: save strings_preview into a text file for grep
        sp = ((j.get("result") or {}).get("details") or {}).get("strings_preview") or []
        if sp:
            txt = out_dir / f"{base}_strings_preview.txt"
            txt.write_text("\n".join(str(x) for x in sp), encoding="utf-8-sig")
            written.append(txt)
        return written

    # ---- Generic: one-row CSV (exclude raw_tail to keep it clean) ----
    if isinstance(result, dict) and "raw_tail" in result:
        result = {k: v for k, v in result.items() if k != "raw_tail"}

    row = {**meta, **_flatten(result, "result")}
    out = out_dir / f"{base}_summary.csv"
    _write_rows_csv(out, fieldnames=list(row.keys()), rows=[row])
    written.append(out)
    return written


def export_tree(in_dir: Path, out_dir: Path) -> List[Path]:
    """
    Convert all *.json under in_dir to CSV under out_dir (mirrors structure).
    """
    written: List[Path] = []
    for jp in sorted(in_dir.rglob("*.json")):
        rel = jp.relative_to(in_dir)
        target_dir = out_dir / rel.parent
        written.extend(export_one(jp, target_dir))
    return written


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Export JMemoryAnalyser JSON reports to CSV.")
    ap.add_argument("--in", dest="in_path", required=True, help="Input JSON file OR folder")
    ap.add_argument("--out", dest="out_path", required=True, help="Output folder")
    args = ap.parse_args()

    inp = Path(args.in_path)
    outp = Path(args.out_path)

    if inp.is_file():
        export_one(inp, outp)
    else:
        export_tree(inp, outp)

    print(f"[+] CSV export complete -> {outp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


