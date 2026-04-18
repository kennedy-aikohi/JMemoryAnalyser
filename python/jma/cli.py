"""
JMemoryAnalyser CLI entry point.

Subcommands:
  run       - Run a single analyser (basic | minidump | volatility)
  vol       - Run specific Volatility plugins with full control
  plugin    - Run a single JMA plugin (cdb-based or yara)
  triage    - Full triage: basic + minidump + all CDB plugins + optional YARA
  plugins   - List registered plugins
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime

from jma.analyzers.basic             import run_basic
from jma.analyzers.minidump_analyzer import run_minidump
from jma.analyzers.volatility_analyzer import run_volatility, TRIAGE_PLUGINS, FULL_PLUGINS, PLUGIN_CATALOGUE
from jma.plugins                     import init_plugins
from jma.plugins.registry            import list_plugins, get_plugin

TOOL_NAME = "JMemoryAnalyser"
AUTHOR    = "Kennedy Aikohi"
GITHUB    = "https://github.com/kennedy-aikohi"
LINKEDIN  = "https://linkedin.com/in/aikohikennedy"
WEBSITE   = "https://kennedy-aikohi.com"
VERSION   = "1.0.0"


def _supports_ansi() -> bool:
    if os.getenv("JMA_NO_COLOR") or os.getenv("NO_COLOR"):
        return False
    if os.name != "nt":
        return True
    if os.getenv("WT_SESSION") or os.getenv("TERM") or os.getenv("ANSICON"):
        return True
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(ctypes.windll.kernel32.GetStdHandle(-11), 7)
        return True
    except Exception:
        return False


def _sty(no_color: bool) -> tuple[str, str, str, str]:
    if no_color or not _supports_ansi():
        return "", "", "", ""
    return "\x1b[1m", "\x1b[32m", "\x1b[36m", "\x1b[0m"


def banner(no_color: bool = False) -> str:
    B, G, C, R = _sty(no_color)
    art = r"""
   _ __  __                                      _
  | |  \/  | ___ _ __ ___   ___  _ __ _   _    / \   _ __   __ _| |_   _ ___  ___ _ __
  | | |\/| |/ _ \ '_ ` _ \ / _ \| '__| | | |  / _ \ | '_ \ / _` | | | | |/ _ \/ _ \ '__|
 _| | |  | |  __/ | | | | | (_) | |  | |_| | / ___ \| | | | (_| | | |_| |  __/  __/ |
|___|_|  |_|\___|_| |_| |_|\___/|_|   \__, |/_/   \_\_| |_|\__,_|_|\__, |\___|\___|_|
                                       |___/                          |___/
"""
    return (
        f"{B}{G}{art}{R}\n"
        f"  {C}{'=' * 60}{R}\n"
        f"  {B}Tool    :{R} {TOOL_NAME} v{VERSION}\n"
        f"  {B}Author  :{R} {AUTHOR}\n"
        f"  {B}Website :{R} {WEBSITE}\n"
        f"  {B}GitHub  :{R} {GITHUB}\n"
        f"  {B}LinkedIn:{R} {LINKEDIN}\n"
        f"  {C}{'=' * 60}{R}\n"
    )


def now_stamp() -> str:
    return datetime.utcnow().strftime("%Y%m%d_%H%M%SZ")


def write_report(out_dir: str, base: str, tag: str, payload: dict) -> str:
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{base}_{tag}_{now_stamp()}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    return out_path


def _validate_input(path: str) -> None:
    if not os.path.exists(path):
        raise SystemExit(f"[ERROR] Input not found: {path}")
    if not os.path.isfile(path):
        raise SystemExit(f"[ERROR] Not a file: {path}")
    if os.path.getsize(path) == 0:
        raise SystemExit(f"[ERROR] File is empty: {path}")


def _build_meta() -> dict:
    return {
        "tool":          TOOL_NAME,
        "version":       VERSION,
        "author":        AUTHOR,
        "github":        GITHUB,
        "linkedin":      LINKEDIN,
        "website":       WEBSITE,
        "timestamp_utc": datetime.utcnow().isoformat() + "Z",
    }


def main() -> int:
    init_plugins()

    ap = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=f"{TOOL_NAME} v{VERSION} - {AUTHOR} - {WEBSITE}",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--version",  action="version", version=f"{TOOL_NAME} {VERSION}")
    sub = ap.add_subparsers(dest="subcmd", required=True)

    # -- run ------------------------------------------------------------------
    p_run = sub.add_parser("run", help="Run a single analyser (basic|minidump|volatility)")
    p_run.add_argument("--input",        required=True,  metavar="PATH")
    p_run.add_argument("--mode",         default="basic",
                       choices=["basic", "minidump", "volatility"])
    p_run.add_argument("--out",          required=True,  metavar="DIR")
    p_run.add_argument("--max-mb-scan",  type=int, default=256, metavar="MB")
    p_run.add_argument("--vol-mode",     default="triage",
                       choices=["triage", "full"],
                       help="Volatility plugin set (triage=fast, full=all plugins)")

    # -- vol ------------------------------------------------------------------
    p_vol = sub.add_parser("vol", help="Run Volatility plugins with precise control")
    p_vol.add_argument("--input",        required=True, metavar="PATH")
    p_vol.add_argument("--out",          required=True, metavar="DIR")
    p_vol.add_argument("--plugins",      default="",
                       metavar="PLUGINS",
                       help="Comma-separated plugin names, e.g. windows.pslist,windows.malfind\n"
                            "Omit to use triage set. Use 'all' for every plugin.")
    p_vol.add_argument("--pid",          type=int, default=None, metavar="PID",
                       help="Filter process-specific plugins to this PID")
    p_vol.add_argument("--list-plugins", action="store_true",
                       help="List all available Volatility plugins and exit")

    # -- plugins --------------------------------------------------------------
    sub.add_parser("plugins", help="List all registered JMA plugins")

    # -- plugin ---------------------------------------------------------------
    p_pl = sub.add_parser("plugin", help="Run a single JMA plugin")
    p_pl.add_argument("--input",     required=True, metavar="PATH")
    p_pl.add_argument("--out",       required=True, metavar="DIR")
    p_pl.add_argument("--name",      required=True, help="Plugin name (see: plugins)")
    p_pl.add_argument("--rules-dir", default=r"rules\vendor\yara")

    # -- triage ---------------------------------------------------------------
    p_tr = sub.add_parser("triage",
                           help="Full triage: basic + minidump + CDB plugins + optional YARA + optional Volatility")
    p_tr.add_argument("--input",        required=True, metavar="PATH")
    p_tr.add_argument("--out",          required=True, metavar="DIR")
    p_tr.add_argument("--max-mb-scan",  type=int, default=512, metavar="MB")
    p_tr.add_argument("--with-yara",    action="store_true")
    p_tr.add_argument("--with-vol",     action="store_true",
                       help="Include Volatility triage pass (requires full memory image for best results)")
    p_tr.add_argument("--vol-mode",     default="triage", choices=["triage", "full"])
    p_tr.add_argument("--rules-dir",    default=r"rules\vendor\yara")

    args = ap.parse_args()
    no_color = bool(getattr(args, "no_color", False))

    if not any(a in ("-h", "--help", "--version") for a in sys.argv[1:]):
        print(banner(no_color=no_color))

    meta = _build_meta()

    # =========================================================================
    # plugins (list JMA plugins)
    # =========================================================================
    if args.subcmd == "plugins":
        plugs = list_plugins()
        if not plugs:
            print("[!] No plugins registered.")
        else:
            print(f"{'NAME':<14} {'BACKEND':<10} DESCRIPTION")
            print("-" * 70)
            for p in plugs:
                print(f"{p.name:<14} [{p.backend:<6}]  {p.help}")
        return 0

    # =========================================================================
    # vol --list-plugins
    # =========================================================================
    if args.subcmd == "vol" and args.list_plugins:
        print(f"{'PLUGIN':<45} {'CATEGORY':<12} {'RISK':<6} DESCRIPTION")
        print("-" * 100)
        for p in PLUGIN_CATALOGUE:
            print(f"{p.name:<45} {p.category:<12} {p.risk_weight:<6} {p.description[:50]}")
        print(f"\nTriage set ({len(TRIAGE_PLUGINS)}):", ", ".join(TRIAGE_PLUGINS))
        print(f"Full set   ({len(FULL_PLUGINS)}):", ", ".join(FULL_PLUGINS[:5]), "...")
        return 0

    # =========================================================================
    # Common input validation
    # =========================================================================
    in_path = os.path.abspath(args.input)
    out_dir = os.path.abspath(args.out)
    _validate_input(in_path)
    base = os.path.splitext(os.path.basename(in_path))[0]

    # =========================================================================
    # run
    # =========================================================================
    if args.subcmd == "run":
        mode = args.mode
        if mode == "basic":
            result = run_basic(in_path, max_mb_scan=args.max_mb_scan)
        elif mode == "minidump":
            result = run_minidump(in_path)
        else:
            result = run_volatility(in_path, mode=args.vol_mode)

        report = {
            **meta, "subcommand": "run", "mode": mode, "input": in_path,
            "result": {
                "analyzer": result.analyzer,
                "ok":       result.ok,
                "summary":  result.summary,
                "warnings": result.warnings,
                "details":  result.details,
            },
        }
        out_path = write_report(out_dir, base, mode, report)
        print(f"[+] Report  : {out_path}")
        print(f"[+] Summary : {result.summary}")
        for w in result.warnings:
            print(f"[!] {w}")
        return 0 if result.ok else 2

    # =========================================================================
    # vol
    # =========================================================================
    if args.subcmd == "vol":
        if args.plugins.lower() == "all":
            plugins_list = FULL_PLUGINS
            vol_mode = "full"
        elif args.plugins:
            plugins_list = [p.strip() for p in args.plugins.split(",") if p.strip()]
            vol_mode = "custom"
        else:
            plugins_list = None
            vol_mode = "triage"

        print(f"[*] Volatility mode : {vol_mode}")
        print(f"[*] Image           : {in_path}")
        if plugins_list:
            print(f"[*] Plugins         : {', '.join(plugins_list)}")

        result = run_volatility(
            in_path,
            plugins=plugins_list,
            mode=vol_mode,
            pid_filter=args.pid,
        )

        report = {
            **meta, "subcommand": "vol", "input": in_path,
            "result": {
                "analyzer": result.analyzer,
                "ok":       result.ok,
                "summary":  result.summary,
                "warnings": result.warnings,
                "details":  result.details,
            },
        }
        out_path = write_report(out_dir, base, "vol", report)
        print(f"[+] Report  : {out_path}")
        print(f"[+] Summary : {result.summary}")
        for w in result.warnings:
            print(f"[!] {w}")

        # Print key findings inline
        risk = result.details.get("risk", {})
        if risk.get("findings"):
            print(f"\n[!] Key findings ({risk.get('tier','?')}):")
            for f in risk["findings"]:
                print(f"    - {f}")

        hidden = result.details.get("hidden_processes", [])
        if hidden:
            print(f"\n[!] Hidden processes ({len(hidden)}):")
            for h in hidden:
                print(f"    PID {h['pid']} ({h['name']}) - {h['reason']}")

        return 0 if result.ok else 2

    # =========================================================================
    # plugin
    # =========================================================================
    if args.subcmd == "plugin":
        plug = get_plugin(args.name)
        if not plug:
            raise SystemExit(f"[ERROR] Unknown plugin '{args.name}'. Run: {TOOL_NAME} plugins")

        kwargs: dict = {}
        if args.name == "yara":
            kwargs["rules_dir"] = args.rules_dir

        data = plug.runner(in_path, **kwargs)
        report = {
            **meta, "subcommand": "plugin", "input": in_path,
            "plugin": {"name": plug.name, "backend": plug.backend, "help": plug.help},
            "result": data,
        }
        out_path = write_report(out_dir, base, f"plugin_{plug.name}", report)
        print(f"[+] Report : {out_path}")
        if not data.get("ok"):
            print(f"[!] {data.get('error', 'plugin failed')}")
        return 0 if data.get("ok") else 2

    # =========================================================================
    # triage
    # =========================================================================
    if args.subcmd == "triage":
        PLUGIN_PACK = ["osver", "procinfo", "threads", "handles",
                       "modules", "exception", "memmap", "rwx", "netfind"]
        triage_results: dict = {}

        print(f"[*] Basic scan ({args.max_mb_scan} MB)...")
        basic = run_basic(in_path, max_mb_scan=args.max_mb_scan)
        triage_results["basic"] = {
            "ok": basic.ok, "summary": basic.summary,
            "warnings": basic.warnings, "details": basic.details,
        }
        print(f"    {basic.summary}")

        print("[*] Minidump parse...")
        mdmp = run_minidump(in_path)
        triage_results["minidump"] = {
            "ok": mdmp.ok, "summary": mdmp.summary,
            "warnings": mdmp.warnings, "details": mdmp.details,
        }
        print(f"    {mdmp.summary}")

        for name in PLUGIN_PACK:
            plug = get_plugin(name)
            if not plug:
                triage_results[name] = {"ok": False, "error": "plugin_not_registered"}
                continue
            print(f"[*] Plugin: {name}...")
            try:
                triage_results[name] = plug.runner(in_path)
            except Exception as e:
                triage_results[name] = {"ok": False, "error": str(e)}

        if args.with_yara:
            print(f"[*] YARA scan...")
            yara_plug = get_plugin("yara")
            if yara_plug:
                try:
                    yara_data = yara_plug.runner(in_path, rules_dir=args.rules_dir)
                    triage_results["yara"] = yara_data
                    print(f"    YARA matches: {yara_data.get('match_count', 0)}")
                except Exception as e:
                    triage_results["yara"] = {"ok": False, "error": str(e)}

        if args.with_vol:
            print(f"[*] Volatility triage ({args.vol_mode})...")
            vol_result = run_volatility(in_path, mode=args.vol_mode)
            triage_results["volatility"] = {
                "ok":       vol_result.ok,
                "summary":  vol_result.summary,
                "warnings": vol_result.warnings,
                "risk":     vol_result.details.get("risk", {}),
                "hidden_processes": vol_result.details.get("hidden_processes", []),
                "plugins":  {
                    k: {"ok": v.get("ok"), "row_count": v.get("row_count", 0)}
                    for k, v in vol_result.details.get("results", {}).items()
                    if isinstance(v, dict)
                },
            }
            print(f"    {vol_result.summary}")

        report = {
            **meta, "subcommand": "triage", "input": in_path,
            "plugin_pack": PLUGIN_PACK,
            "with_yara": args.with_yara,
            "with_vol":  args.with_vol,
            "result": triage_results,
        }
        out_path = write_report(out_dir, base, "triage", report)
        print(f"[+] Report : {out_path}")
        return 0 if triage_results.get("basic", {}).get("ok") else 2

    raise SystemExit("[ERROR] Unknown subcommand")


if __name__ == "__main__":
    raise SystemExit(main())
