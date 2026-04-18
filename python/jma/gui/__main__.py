"""python -m jma.gui entry point"""
from __future__ import annotations
import argparse

def main():
    ap = argparse.ArgumentParser(
        prog="jma.gui",
        description="JMemoryAnalyser - browser-based forensics workbench"
    )
    ap.add_argument("--host",       default="127.0.0.1", help="Bind host (default 127.0.0.1)")
    ap.add_argument("--port",       default=5891, type=int, help="Port (default 5891)")
    ap.add_argument("--no-browser", action="store_true",   help="Do not auto-open browser")
    args = ap.parse_args()

    from jma.gui.server import run
    run(host=args.host, port=args.port, open_browser=not args.no_browser)

if __name__ == "__main__":
    main()
