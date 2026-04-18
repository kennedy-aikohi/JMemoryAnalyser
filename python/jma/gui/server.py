"""
JMemoryAnalyser GUI Server
Flask backend that powers the browser-based forensics workbench.

Run with:
    python -m jma.gui
    or
    python -m jma.gui --port 5000 --host 127.0.0.1 --no-browser
"""
from __future__ import annotations

import json
import os
import sys
import threading
import webbrowser
from pathlib import Path
from datetime import datetime
from typing import Any

try:
    from flask import Flask, request, jsonify, send_from_directory, render_template_string
except ImportError:
    print("[ERROR] Flask not installed. Run: pip install flask")
    sys.exit(1)

# ---- resolve project root ------------------------------------------------
_HERE       = Path(__file__).parent
_STATIC     = _HERE / "static"
_TEMPLATES  = _HERE / "templates"
_PROJ_ROOT  = _HERE.parent.parent.parent   # python/jma/gui -> python/jma -> python -> project root

sys.path.insert(0, str(_PROJ_ROOT / "python"))

from jma.utils          import get_file_info, probe_dmp_format
from jma.analyzers.basic         import run_basic
from jma.analyzers.minidump_analyzer import run_minidump
from jma.cdb_backend    import run_cdb, find_cdb, parse_peb_imagepath, count_threads_from_tilde, find_named_pipes, find_ipv4_strings
from jma.plugins        import init_plugins
from jma.plugins.registry import get_plugin
from jma.export_csv     import export_one

AUTHOR   = "Kennedy Aikohi"
GITHUB   = "https://github.com/kennedy-aikohi"
LINKEDIN = "https://linkedin.com/in/aikohikennedy"
WEBSITE  = "https://kennedy-aikohi.com"
VERSION  = "1.0.0"

app = Flask(__name__, static_folder=str(_STATIC), template_folder=str(_TEMPLATES))
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024 * 1024  # 2 GB

# ---- in-memory session state (single dump per session) -------------------
_SESSION: dict[str, Any] = {
    "dump_path":    None,
    "file_info":    None,
    "fmt_info":     None,
    "basic_result": None,
    "mdmp_result":  None,
    "cdb_cache":    {},
    "loaded_at":    None,
}


def _fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# =========================================================================
# Static / index
# =========================================================================

@app.route("/")
def index():
    html_path = _TEMPLATES / "index.html"
    return html_path.read_text(encoding="utf-8")


@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory(str(_STATIC), filename)


# =========================================================================
# API: meta
# =========================================================================

@app.route("/api/meta")
def api_meta():
    return jsonify({
        "tool":     "JMemoryAnalyser",
        "version":  VERSION,
        "author":   AUTHOR,
        "github":   GITHUB,
        "linkedin": LINKEDIN,
        "website":  WEBSITE,
        "cdb_available": find_cdb() is not None,
        "cdb_path":      find_cdb(),
    })


# =========================================================================
# API: load dump
# =========================================================================

@app.route("/api/load", methods=["POST"])
def api_load():
    """Accept a .DMP path (JSON body) or a file upload."""
    data = request.get_json(silent=True) or {}
    path = data.get("path", "").strip()

    # File upload fallback
    if not path and "file" in request.files:
        f   = request.files["file"]
        dst = _PROJ_ROOT / "samples" / f.filename
        dst.parent.mkdir(exist_ok=True)
        f.save(str(dst))
        path = str(dst)

    if not path or not os.path.isfile(path):
        return jsonify({"ok": False, "error": f"File not found: {path}"}), 400

    try:
        fi   = get_file_info(path)
        fmt  = probe_dmp_format(path)
        _SESSION.update({
            "dump_path":    path,
            "file_info":    fi.__dict__,
            "fmt_info":     fmt.__dict__,
            "basic_result": None,
            "mdmp_result":  None,
            "cdb_cache":    {},
            "loaded_at":    datetime.utcnow().isoformat() + "Z",
        })
        return jsonify({
            "ok":       True,
            "path":     path,
            "filename": os.path.basename(path),
            "size":     _fmt_size(fi.size),
            "size_bytes": fi.size,
            "sha256":   fi.sha256,
            "mtime":    fi.mtime_utc,
            "format":   fmt.format,
            "is_minidump": fmt.is_minidump,
            "note":     fmt.note,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# =========================================================================
# API: basic scan
# =========================================================================

@app.route("/api/scan/basic", methods=["POST"])
def api_basic():
    path = _SESSION.get("dump_path")
    if not path:
        return jsonify({"ok": False, "error": "No dump loaded"}), 400

    data    = request.get_json(silent=True) or {}
    max_mb  = int(data.get("max_mb", 256))

    try:
        r = run_basic(path, max_mb_scan=max_mb)
        _SESSION["basic_result"] = r
        scan = r.details.get("scan", {})
        return jsonify({
            "ok":           r.ok,
            "summary":      r.summary,
            "risk_tier":    scan.get("risk_tier", "UNKNOWN"),
            "warnings":     r.warnings,
            "ascii_count":  scan.get("ascii_strings_found", 0),
            "unicode_count":scan.get("unicode_strings_found", 0),
            "total_strings":scan.get("total_unique_strings", 0),
            "urls":         scan.get("extracted_urls", []),
            "ips":          scan.get("extracted_ips", []),
            "keyword_hits": scan.get("keyword_hits_by_category", {}),
            "risk_flat":    scan.get("keyword_hits_flat", {}),
            "strings_ascii":   r.details.get("strings_preview_ascii", [])[:500],
            "strings_unicode": r.details.get("strings_preview_unicode", [])[:300],
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# =========================================================================
# API: minidump parse
# =========================================================================

@app.route("/api/scan/minidump", methods=["POST"])
def api_minidump():
    path = _SESSION.get("dump_path")
    if not path:
        return jsonify({"ok": False, "error": "No dump loaded"}), 400
    try:
        r = run_minidump(path)
        _SESSION["mdmp_result"] = r
        det = r.details
        return jsonify({
            "ok":       r.ok,
            "summary":  r.summary,
            "warnings": r.warnings,
            "header":   det.get("header", {}),
            "streams":  det.get("stream_directory", []),
            "system_info": det.get("system_info", {}),
            "exception":   det.get("exception", {}),
            "modules":     det.get("modules", {}),
            "threads":     det.get("threads", {}),
            "misc_info":   det.get("misc_info", {}),
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# =========================================================================
# API: CDB command
# =========================================================================

@app.route("/api/cdb/run", methods=["POST"])
def api_cdb():
    path = _SESSION.get("dump_path")
    if not path:
        return jsonify({"ok": False, "error": "No dump loaded"}), 400

    data     = request.get_json(silent=True) or {}
    command  = data.get("command", "").strip()
    if not command:
        return jsonify({"ok": False, "error": "No command provided"}), 400

    # Reject obviously dangerous shell injection attempts
    BLOCKED = [";", "&&", "||", "|", ">", "<", "`", "$", "rm ", "del ", "format"]
    for b in BLOCKED:
        if b in command and b not in ["||"]:
            return jsonify({"ok": False, "error": f"Blocked character in command: {b}"}), 400

    # Cache identical commands within the same session
    cache_key = command.lower()
    if cache_key in _SESSION["cdb_cache"]:
        cached = _SESSION["cdb_cache"][cache_key]
        cached["cached"] = True
        return jsonify(cached)

    if not find_cdb():
        return jsonify({
            "ok":    False,
            "error": "cdb.exe not found. Install Debugging Tools for Windows or set JMA_CDB env var.",
            "stdout": "",
        }), 200

    # Map shorthand to CDB command sequences
    CDB_PRESETS: dict[str, list[str]] = {
        "!peb":       [".symfix", ".reload", "!peb"],
        "lm":         ["lm"],
        "~":          ["~"],
        "!analyze -v":[".symfix", ".reload", "!analyze -v"],
        "!address":   ["!address"],
        "!handle 0 3":[".symfix", ".reload", "!handle 0 3"],
        "!iat":       [".symfix", ".reload", "dps poi(poi(fs:30)+0xc)+0x10 L80"],
        "vertarget":  ["vertarget"],
        "dt nt!_peb": [".symfix", ".reload", "dt nt!_PEB"],
        "!teb":       [".symfix", ".reload", "!teb"],
        "u eip":      [".symfix", ".reload", "u @eip"],
        "k":          [".symfix", ".reload", "k"],
        "!dh -f":     [".symfix", ".reload", "!dh -f"],
    }
    cmds = CDB_PRESETS.get(command.lower(), [command])

    try:
        r   = run_cdb(path, cmds, timeout=120)
        out = {
            "ok":         r.ok,
            "command":    command,
            "stdout":     r.stdout,
            "stderr":     r.stderr,
            "returncode": r.returncode,
            "cached":     False,
        }
        _SESSION["cdb_cache"][cache_key] = out
        return jsonify(out)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "stdout": ""}), 500


# =========================================================================
# API: plugin run
# =========================================================================

@app.route("/api/plugin/<name>", methods=["POST"])
def api_plugin(name: str):
    path = _SESSION.get("dump_path")
    if not path:
        return jsonify({"ok": False, "error": "No dump loaded"}), 400

    init_plugins()
    plug = get_plugin(name)
    if not plug:
        return jsonify({"ok": False, "error": f"Unknown plugin: {name}"}), 404

    data   = request.get_json(silent=True) or {}
    kwargs = {}
    if name == "yara":
        rd = data.get("rules_dir", str(_PROJ_ROOT / "rules" / "vendor" / "yara"))
        kwargs["rules_dir"] = rd

    try:
        result = plug.runner(path, **kwargs)
        return jsonify(result)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# =========================================================================
# API: export
# =========================================================================

@app.route("/api/export", methods=["POST"])
def api_export():
    path = _SESSION.get("dump_path")
    if not path:
        return jsonify({"ok": False, "error": "No dump loaded"}), 400

    data     = request.get_json(silent=True) or {}
    out_dir  = data.get("out_dir") or str(_PROJ_ROOT / "reports")
    fmt      = data.get("format", "json")   # "json" | "csv"

    os.makedirs(out_dir, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%SZ")
    base      = os.path.splitext(os.path.basename(path))[0]

    written = []

    if fmt in ("json", "both"):
        import json as _json
        payload = {
            "tool":      "JMemoryAnalyser",
            "version":   VERSION,
            "author":    AUTHOR,
            "github":    GITHUB,
            "linkedin":  LINKEDIN,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "dump_path": path,
            "file_info": _SESSION.get("file_info"),
            "fmt_info":  _SESSION.get("fmt_info"),
        }
        if _SESSION.get("basic_result"):
            br = _SESSION["basic_result"]
            payload["basic"] = {"summary": br.summary, "details": br.details, "warnings": br.warnings}
        if _SESSION.get("mdmp_result"):
            mr = _SESSION["mdmp_result"]
            payload["minidump"] = {"summary": mr.summary, "details": mr.details, "warnings": mr.warnings}

        out_path = os.path.join(out_dir, f"{base}_jma_{timestamp}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            _json.dump(payload, f, indent=2, default=str)
        written.append(out_path)

    if fmt in ("csv", "both") and written:
        from pathlib import Path as _Path
        csv_paths = export_one(_Path(written[0]), _Path(out_dir))
        written.extend([str(p) for p in csv_paths])

    return jsonify({"ok": True, "files": written})


# =========================================================================
# API: session state
# =========================================================================

@app.route("/api/session")
def api_session():
    return jsonify({
        "loaded":     _SESSION["dump_path"] is not None,
        "dump_path":  _SESSION["dump_path"],
        "file_info":  _SESSION["file_info"],
        "fmt_info":   _SESSION["fmt_info"],
        "loaded_at":  _SESSION["loaded_at"],
    })


# =========================================================================
# Entry point
# =========================================================================

def run(host: str = "127.0.0.1", port: int = 5891, open_browser: bool = True):
    init_plugins()
    url = f"http://{host}:{port}"
    print(f"\n  JMemoryAnalyser GUI - {url}")
    print(f"  Author  : {AUTHOR}")
    print(f"  GitHub  : {GITHUB}")
    print(f"  Stop    : Ctrl+C\n")

    if open_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()

    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    run()


# =========================================================================
# API: Volatility endpoints
# =========================================================================

@app.route("/api/vol/plugins")
def api_vol_plugins():
    """Return the full plugin catalogue."""
    from jma.analyzers.volatility_analyzer import PLUGIN_CATALOGUE, TRIAGE_PLUGINS, FULL_PLUGINS
    return jsonify({
        "plugins": [
            {
                "name":        p.name,
                "label":       p.label,
                "category":    p.category,
                "risk_weight": p.risk_weight,
                "timeout":     p.timeout,
                "description": p.description,
            }
            for p in PLUGIN_CATALOGUE
        ],
        "triage_set": TRIAGE_PLUGINS,
        "full_set":   FULL_PLUGINS,
    })


@app.route("/api/vol/run", methods=["POST"])
def api_vol_run():
    """
    Run Volatility against the loaded image.
    Body: { "mode": "triage"|"full"|"custom", "plugins": ["windows.pslist",...], "pid": null }
    """
    path = _SESSION.get("dump_path")
    if not path:
        return jsonify({"ok": False, "error": "No dump loaded"}), 400

    from jma.analyzers.volatility_analyzer import run_volatility, TRIAGE_PLUGINS, FULL_PLUGINS

    data    = request.get_json(silent=True) or {}
    mode    = data.get("mode", "triage")
    plugins = data.get("plugins") or None
    pid     = data.get("pid")

    if plugins and isinstance(plugins, str):
        plugins = [p.strip() for p in plugins.split(",") if p.strip()]

    try:
        result = run_volatility(path, plugins=plugins, mode=mode,
                                pid_filter=int(pid) if pid else None)
        _SESSION["vol_result"] = result

        # Extract key intel for the GUI panels
        det  = result.details
        risk = det.get("risk", {})
        res  = det.get("results", {})

        pslist_intel  = res.get("windows.pslist",  {}).get("_intel", {})
        psscan_intel  = res.get("windows.psscan",  {}).get("_intel", {})
        malfind_intel = res.get("windows.malfind", {}).get("_intel", {})
        net_intel     = (res.get("windows.netscan") or res.get("windows.netstat") or {}).get("_intel", {})
        ssdt_intel    = res.get("windows.ssdt",    {}).get("_intel", {})

        return jsonify({
            "ok":      result.ok,
            "summary": result.summary,
            "warnings": result.warnings,
            "risk":    risk,
            "hidden_processes": det.get("hidden_processes", []),
            "pslist":  pslist_intel,
            "psscan":  psscan_intel,
            "malfind": malfind_intel,
            "network": net_intel,
            "ssdt":    ssdt_intel,
            "plugin_status": {
                k: {"ok": v.get("ok"), "row_count": v.get("row_count", 0),
                    "elapsed_s": v.get("elapsed_s", 0), "error": v.get("error")}
                for k, v in res.items()
                if isinstance(v, dict)
            },
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/vol/plugin/<plugin_name>", methods=["POST"])
def api_vol_single_plugin(plugin_name: str):
    """Run a single Volatility plugin and return raw rows."""
    path = _SESSION.get("dump_path")
    if not path:
        return jsonify({"ok": False, "error": "No dump loaded"}), 400

    from jma.analyzers.volatility_analyzer import VolPlugin, _run_plugin

    data    = request.get_json(silent=True) or {}
    extra   = data.get("extra_args", [])
    timeout = int(data.get("timeout", 180))

    plug = VolPlugin(
        name=plugin_name, label=plugin_name, category="misc",
        risk_weight=0, timeout=timeout, extra_args=extra
    )
    try:
        result = _run_plugin(path, plug)
        return jsonify(result)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
