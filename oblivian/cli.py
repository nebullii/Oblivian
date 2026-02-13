from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import uvicorn

from .scanner import scan_markdown_to_dict
from .server import create_app


def _cmd_scan(args: argparse.Namespace) -> int:
    path = Path(args.path)
    text = path.read_text(encoding="utf-8")
    result = scan_markdown_to_dict(text)
    print(json.dumps(result, indent=2, ensure_ascii=True))
    if args.fail_on_high:
        if any(f["severity"] == "high" for f in result["findings"]):
            return 2
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    uvicorn.run(
        "oblivian.server:create_app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        factory=True,
    )
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="oblivian")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan Markdown for risky patterns")
    scan.add_argument("path", help="Path to Markdown file")
    scan.add_argument("--fail-on-high", action="store_true")
    scan.set_defaults(func=_cmd_scan)

    serve = sub.add_parser("serve", help="Run the sidecar service")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--reload", action="store_true")
    serve.set_defaults(func=_cmd_serve)

    args = parser.parse_args()
    sys.exit(args.func(args))
