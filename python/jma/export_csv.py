"""
JMemoryAnalyser - JSON report -> CSV exporter.

Callable as:
  python -m jma.export_csv --in <dir_or_file> --out <dir>

Or imported:
  from jma.export_csv import export_one, export_tree
"""
from __future__ import annotations

import csv
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List


def _safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.\-]+", "_", s)


def _flatten(obj: Any, prefix: str = "") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                out.update(_flatten(v, key))
            elif isinstance(v, list):
                if len(v) <= 10 and all(not isinstance(x, (dict, list)) for x in v):
                    out[key] = "|".join(str(x) for x in v)
                else:
                    out[key] = len(v)
            else:
                out[key] = v
    else:
        out[prefix or "value"] = obj
    return out


def _write_csv(path: Path, fieldnames: List[str], rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def export_one(json_path: Path, out_dir: Path | None = None) -> List[Path]:
    """Convert one JMA JSON report to one or more CSVs. Returns list of written paths."""
    with json_path.open("r", encoding="utf-8-sig") as f:
        j = json.load(f)

    written: List[Path] = []
    out_dir = out_dir or json_path.parent
    base    = json_path.stem

    sub    = j.get("subcommand") or ""
    mode   = j.get("mode") or ""
    plugin = (j.get("plugin") or {}).get("name") if isinstance(j.get("plugin"), dict) else None
    result = j.get("result") or {}

    meta = {
        "tool":          j.get("tool"),
        "version":       j.get("version"),
        "timestamp_utc": j.get("timestamp_utc"),
        "author":        j.get("author"),
        "input":         j.get("input"),
        "subcommand":    sub,
        "mode":          mode,
        "plugin":        plugin,
        "source_json":   str(json_path),
    }

    # ---- Specialised per-plugin outputs ------------------------------------

    if sub == "plugin" and plugin == "rwx":
        hits = result.get("hits") or []
        rows = [{**meta, "rwx_region": h} for h in hits] or [{**meta, "rwx_region": ""}]
        out  = out_dir / f"{base}_rwx_regions.csv"
        _write_csv(out, list(rows[0].keys()), rows)
        written.append(out)
        return written

    if sub == "plugin" and plugin == "netfind":
        rows: List[Dict[str, Any]] = []
        for ip  in result.get("ip_candidates")  or []: rows.append({**meta, "ioc_type": "ip",     "value": ip})
        for url in result.get("url_candidates")  or []: rows.append({**meta, "ioc_type": "url",    "value": url})
        for dom in result.get("domain_candidates") or []: rows.append({**meta, "ioc_type": "domain","value": dom})
        for p   in result.get("named_pipes_seen") or []: rows.append({**meta, "ioc_type": "pipe",  "value": p})
        if not rows:
            rows = [{**meta, "ioc_type": "", "value": ""}]
        out = out_dir / f"{base}_network_iocs.csv"
        _write_csv(out, list(rows[0].keys()), rows)
        written.append(out)
        return written

    if sub == "plugin" and plugin == "handles":
        pipes = result.get("named_pipes") or []
        rows  = [{**meta, "named_pipe": p} for p in pipes] or [{**meta, "named_pipe": ""}]
        out   = out_dir / f"{base}_named_pipes.csv"
        _write_csv(out, list(rows[0].keys()), rows)
        written.append(out)

    # ---- Basic run: extract meaningful scan fields -------------------------

    if sub == "run" and mode == "basic":
        # Top-level summary row
        scan    = ((result.get("details") or {}).get("scan") or {})
        file_d  = ((result.get("details") or {}).get("file") or {})
        fmt_d   = (file_d.get("format") or {})
        summary_row = {
            **meta,
            "ok":                result.get("ok"),
            "risk_tier":         scan.get("risk_tier"),
            "bytes_scanned":     scan.get("bytes_scanned"),
            "ascii_strings":     scan.get("ascii_strings_found"),
            "unicode_strings":   scan.get("unicode_strings_found"),
            "total_strings":     scan.get("total_unique_strings"),
            "urls_found":        len(scan.get("extracted_urls") or []),
            "ips_found":         len(scan.get("extracted_ips") or []),
            "dmp_format":        fmt_d.get("format"),
            "sha256":            file_d.get("sha256"),
            "file_size_bytes":   file_d.get("size"),
            "warnings":          "|".join(result.get("warnings") or []),
            "summary":           result.get("summary"),
        }
        # Add per-category hit counts
        by_cat = scan.get("keyword_hits_by_category") or {}
        for cat, hits in by_cat.items():
            summary_row[f"hits_{cat}"] = sum(hits.values())

        out = out_dir / f"{base}_basic_summary.csv"
        _write_csv(out, list(summary_row.keys()), [summary_row])
        written.append(out)

        # URL list
        urls = scan.get("extracted_urls") or []
        if urls:
            url_rows = [{**meta, "url": u} for u in urls]
            out2 = out_dir / f"{base}_urls.csv"
            _write_csv(out2, list(url_rows[0].keys()), url_rows)
            written.append(out2)

        # IP list
        ips = scan.get("extracted_ips") or []
        if ips:
            ip_rows = [{**meta, "ip": ip} for ip in ips]
            out3 = out_dir / f"{base}_ips.csv"
            _write_csv(out3, list(ip_rows[0].keys()), ip_rows)
            written.append(out3)

        # String preview as plain text (not CSV - too wide)
        preview = (result.get("details") or {}).get("strings_preview_ascii") or []
        if preview:
            txt = out_dir / f"{base}_strings_ascii.txt"
            txt.write_text("\n".join(str(s) for s in preview), encoding="utf-8-sig")
            written.append(txt)

        return written

    # ---- Minidump run: modules + threads -----------------------------------

    if sub == "run" and mode == "minidump":
        det = result.get("details") or {}
        mods = (det.get("modules") or {}).get("modules") or []
        if mods:
            mod_rows = [{
                **meta,
                "module_name":    m.get("name"),
                "base_address":   m.get("base_address"),
                "size":           m.get("size"),
                "checksum":       m.get("checksum_hex"),
                "timestamp_unix": m.get("timestamp_unix"),
            } for m in mods]
            out = out_dir / f"{base}_modules.csv"
            _write_csv(out, list(mod_rows[0].keys()), mod_rows)
            written.append(out)

        threads = (det.get("threads") or {}).get("threads") or []
        if threads:
            thr_rows = [{**meta, **t} for t in threads]
            out2 = out_dir / f"{base}_threads.csv"
            _write_csv(out2, list(thr_rows[0].keys()), thr_rows)
            written.append(out2)

        exc = det.get("exception")
        if exc:
            exc_row = {**meta, **{k: v for k, v in exc.items()}}
            out3 = out_dir / f"{base}_exception.csv"
            _write_csv(out3, list(exc_row.keys()), [exc_row])
            written.append(out3)

        return written

    # ---- YARA matches (from triage) ----------------------------------------

    if sub == "triage":
        yara_data = result.get("yara") or {}
        matches   = yara_data.get("matches") or []
        if matches:
            yara_rows = [{
                **meta,
                "rule":        m.get("rule"),
                "namespace":   m.get("namespace"),
                "tags":        "|".join(m.get("tags") or []),
                "family":      (m.get("meta") or {}).get("family") or (m.get("meta") or {}).get("malware") or "",
                "description": (m.get("meta") or {}).get("description") or "",
                "source_file": m.get("source_file"),
            } for m in matches]
            out = out_dir / f"{base}_yara_matches.csv"
            _write_csv(out, list(yara_rows[0].keys()), yara_rows)
            written.append(out)

    # ---- Generic fallback: one flat summary row ----------------------------

    clean_result = result
    if isinstance(result, dict):
        clean_result = {k: v for k, v in result.items() if k != "raw_tail"}

    row  = {**meta, **_flatten(clean_result, "result")}
    out  = out_dir / f"{base}_summary.csv"
    _write_csv(out, list(row.keys()), [row])
    written.append(out)
    return written


def export_tree(in_dir: Path, out_dir: Path) -> List[Path]:
    """Convert all *.json under in_dir to CSV under out_dir (mirrors directory structure)."""
    written: List[Path] = []
    for jp in sorted(in_dir.rglob("*.json")):
        rel        = jp.relative_to(in_dir)
        target_dir = out_dir / rel.parent
        written.extend(export_one(jp, target_dir))
    return written


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Export JMemoryAnalyser JSON reports to CSV.")
    ap.add_argument("--in",  dest="in_path",  required=True, help="Input JSON file or folder")
    ap.add_argument("--out", dest="out_path", required=True, help="Output folder")
    args = ap.parse_args()

    inp  = Path(args.in_path)
    outp = Path(args.out_path)

    if inp.is_file():
        paths = export_one(inp, outp)
    elif inp.is_dir():
        paths = export_tree(inp, outp)
    else:
        print(f"[ERROR] Input not found: {inp}")
        return 1

    for p in paths:
        print(f"[+] {p}")
    print(f"\n[+] CSV export complete -> {outp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
