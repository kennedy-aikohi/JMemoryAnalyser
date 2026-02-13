from __future__ import annotations

import argparse
import json
import os
from datetime import datetime

from jma.analyzers.basic import run_basic
from jma.analyzers.minidump_analyzer import run_minidump
from jma.analyzers.volatility_analyzer import run_volatility

from jma.plugins import init_plugins
from jma.plugins.registry import list_plugins, get_plugin


TOOL_NAME = "JMemoryAnalyser"
AUTHOR = "KENNEDY AIKOHI"
GITHUB = "https://github.com/kennedy-aikohi"
LINKEDIN = "https://linkedin.com/in/aikohikennedy"
VERSION = "0.6.3"


def _supports_ansi() -> bool:
    """
    Best-effort ANSI detection for Windows.
    Windows Terminal: WT_SESSION is set.
    Legacy conhost often shows raw ESC sequences.
    """
    if os.getenv("JMA_NO_COLOR") is not None or os.getenv("NO_COLOR") is not None:
        return False
    if os.name != "nt":
        return True
    # Windows Terminal
    if os.getenv("WT_SESSION") is not None:
        return True
    # Some other ANSI-capable hosts set TERM / ANSICON
    if os.getenv("TERM") is not None or os.getenv("ANSICON") is not None:
        return True
    return False


def _sty(no_color: bool) -> tuple[str, str, str]:
    if no_color or not _supports_ansi():
        return "", "", ""
    B = "\x1b[1m"   # bold
    G = "\x1b[32m"  # green
    R = "\x1b[0m"   # reset
    return B, G, R


def banner(no_color: bool = False) -> str:
    B, G, R = _sty(no_color)

    art = r"""
     ██╗ ███╗   ███╗ ███████╗ ███╗   ███╗ ██████╗ ██████╗ ██╗   ██╗
     ██║ ████╗ ████║ ██╔════╝ ████╗ ████║ ██╔══██╗██╔══██╗╚██╗ ██╔╝
     ██║ ██╔████╔██║ █████╗   ██╔████╔██║ ██║  ██║██████╔╝ ╚████╔╝
██   ██║ ██║╚██╔╝██║ ██╔══╝   ██║╚██╔╝██║ ██║  ██║██╔══██╗  ╚██╔╝
╚█████╔╝ ██║ ╚═╝ ██║ ███████╗ ██║ ╚═╝ ██║ ██████╔╝██║  ██║   ██║
 ╚════╝  ╚═╝     ╚═╝ ╚══════╝ ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝

                    █████╗ ███╗   ██╗ █████╗ ██╗      ██╗   ██╗ ███████╗ ██████╗
                   ██╔══██╗████╗  ██║██╔══██╗██║      ╚██╗ ██╔╝ ╚══███╔╝██╔════╝
                   ███████║██╔██╗ ██║███████║██║       ╚████╔╝    ███╔╝ █████╗
                   ██╔══██║██║╚██╗██║██╔══██║██║        ╚██╔╝    ███╔╝  ██╔══╝
                   ██║  ██║██║ ╚████║██║  ██║███████╗    ██║    ███████╗███████╗
                   ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝    ╚═╝    ╚══════╝╚══════╝
"""

    return (
        f"{B}{G}Welcome to JMemoryAnalyzer v{VERSION}{R}\n\n"
        f"{B}{G}{art}{R}\n"
        f"{B}{G}Author  :{R} {AUTHOR}\n"
        f"{B}{G}GitHub  :{R} {GITHUB}\n"
        f"{B}{G}LinkedIn:{R} {LINKEDIN}\n"
        f"{B}{G}Logo    :{R} ✡ ✡ ✡\n"
    )



def now_stamp() -> str:
    return datetime.utcnow().strftime("%Y%m%d_%H%M%SZ")


def write_report(out_dir: str, base: str, tag: str, payload: dict) -> str:
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{base}_{tag}_{now_stamp()}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return out_path


def main() -> int:
    init_plugins()

    ap = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Memory dump analyzer for Task Manager process dumps (.DMP) + optional YARA enrichment.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colors in output (and hide ESC codes).")

    sub = ap.add_subparsers(dest="subcmd", required=True)

    # Core analyzers
    p_run = sub.add_parser("run", help="Run analyzers (basic/minidump/volatility)")
    p_run.add_argument("--input", required=True)
    p_run.add_argument("--mode", default="basic", choices=["basic", "minidump", "volatility"])
    p_run.add_argument("--out", required=True)
    p_run.add_argument("--max-mb-scan", type=int, default=256)

    # Plugin list
    sub.add_parser("plugins", help="List available plugins")

    # Plugin run
    p_pr = sub.add_parser("plugin", help="Run a plugin against a dump")
    p_pr.add_argument("--input", required=True)
    p_pr.add_argument("--out", required=True)
    p_pr.add_argument("--name", required=True, help="Plugin name (see: plugins)")
    p_pr.add_argument("--rules-dir", default="rules\\vendor\\yara", help="For yara plugin only")

    # Triage pack
    p_tr = sub.add_parser("triage", help="Run full triage pack (plugins + basic + optional YARA)")
    p_tr.add_argument("--input", required=True)
    p_tr.add_argument("--out", required=True)
    p_tr.add_argument("--max-mb-scan", type=int, default=512)
    p_tr.add_argument("--with-yara", action="store_true")
    p_tr.add_argument("--rules-dir", default="rules\\vendor\\yara")

    args = ap.parse_args()

    # Only show splash when not asking for help
    if not any(a in ("-h", "--help") for a in os.sys.argv[1:]):
        print(banner(no_color=bool(args.no_color)))

    in_path = os.path.abspath(args.input) if hasattr(args, "input") else None
    out_dir = os.path.abspath(args.out) if hasattr(args, "out") else None
    base = os.path.splitext(os.path.basename(in_path))[0] if in_path else "report"

    meta = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "timestamp_utc": datetime.utcnow().isoformat() + "Z",
        "author": AUTHOR,
        "github": GITHUB,
        "linkedin": LINKEDIN,
    }

    if args.subcmd == "plugins":
        for p in list_plugins():
            print(f"- {p.name:10s} [{p.backend}] {p.help}")
        return 0

    if args.subcmd == "run":
        if args.mode == "basic":
            result = run_basic(in_path, max_mb_scan=args.max_mb_scan)
        elif args.mode == "minidump":
            result = run_minidump(in_path)
        else:
            result = run_volatility(in_path)

        report = {
            **meta,
            "subcommand": "run",
            "mode": args.mode,
            "result": {
                "analyzer": result.analyzer,
                "ok": result.ok,
                "summary": result.summary,
                "warnings": result.warnings,
                "details": result.details,
            },
        }
        out_path = write_report(out_dir, base, args.mode, report)
        print(f"[+] Report written: {out_path}")
        print(f"[+] Summary: {result.summary}")
        return 0 if result.ok else 2

    if args.subcmd == "plugin":
        plug = get_plugin(args.name)
        if not plug:
            raise SystemExit(f"Unknown plugin: {args.name}. Use: {TOOL_NAME} plugins")

        kwargs = {}
        if args.name == "yara":
            kwargs["rules_dir"] = args.rules_dir

        data = plug.runner(in_path, **kwargs)
        report = {
            **meta,
            "subcommand": "plugin",
            "plugin": {"name": plug.name, "backend": plug.backend, "help": plug.help},
            "result": data,
        }
        out_path = write_report(out_dir, base, f"plugin_{plug.name}", report)
        print(f"[+] Report written: {out_path}")
        return 0 if data.get("ok") else 2

    if args.subcmd == "triage":
        pack = ["osver", "procinfo", "threads", "handles", "modules", "exception", "memmap", "rwx", "netfind"]
        results = {}

        basic = run_basic(in_path, max_mb_scan=args.max_mb_scan)
        results["basic"] = {
            "ok": basic.ok,
            "summary": basic.summary,
            "warnings": basic.warnings,
            "details": basic.details,
        }

        for name in pack:
            plug = get_plugin(name)
            if not plug:
                results[name] = {"ok": False, "error": "plugin_missing"}
                continue
            results[name] = plug.runner(in_path)

        if args.with_yara:
            plug = get_plugin("yara")
            if plug:
                results["yara"] = plug.runner(in_path, rules_dir=args.rules_dir)
            else:
                results["yara"] = {"ok": False, "error": "plugin_missing"}

        report = {**meta, "subcommand": "triage", "pack": pack, "result": results}
        out_path = write_report(out_dir, base, "triage", report)
        print(f"[+] Report written: {out_path}")
        return 0 if results.get("basic", {}).get("ok") else 2

    raise SystemExit("Unknown subcommand")


if __name__ == "__main__":
    raise SystemExit(main())

