"""Command line interface."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .demo import write_demo_project
from .models import SEVERITY_ORDER
from .report import FORMATS, to_text
from .rules import rule_catalog
from .scanner import scan


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hardenagent",
        description="Audit a self-hosted AI agent project for risky settings. Local files only.",
    )
    parser.add_argument("--version", action="version", version=f"hardenagent {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan_cmd = sub.add_parser("scan", help="scan a folder or file")
    scan_cmd.add_argument("path", nargs="?", default=".", help="folder or file to scan (default: .)")
    scan_cmd.add_argument("--format", choices=["text", "json", "markdown", "sarif"], default="text")
    scan_cmd.add_argument("--fail-on", choices=list(SEVERITY_ORDER) + ["never"], default="high",
                          help="exit with code 1 if a finding at or above this level exists (default: high)")
    scan_cmd.add_argument("--ignore", action="append", default=[], metavar="RULE_ID",
                          help="rule id to skip (repeatable)")
    scan_cmd.add_argument("--output", "-o", help="write the report to this file")
    scan_cmd.add_argument("--no-color", action="store_true", help="disable colored output")

    sub.add_parser("rules", help="list every rule")
    sub.add_parser("demo", help="scan a deliberately insecure sample project")
    return parser


def _emit(text: str, output: Optional[str]) -> None:
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


def _run_scan(path: str, fmt: str, fail_on: str, ignore: List[str],
              output: Optional[str], no_color: bool) -> int:
    target = Path(path)
    if not target.exists():
        print(f"hardenagent: path not found: {path}", file=sys.stderr)
        return 2
    result = scan(path, ignore=ignore)
    if fmt == "text":
        color = (not no_color and not output and sys.stdout.isatty()
                 and "NO_COLOR" not in os.environ)
        _emit(to_text(result, color=color), output)
    else:
        _emit(FORMATS[fmt](result), output)
    if fail_on == "never":
        return 0
    return 1 if result.worst() >= SEVERITY_ORDER[fail_on] else 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan(args.path, args.format, args.fail_on, args.ignore,
                         args.output, args.no_color)
    if args.command == "rules":
        for rule_id, severity, title in rule_catalog():
            print(f"{rule_id:<11} {severity:<9} {title}")
        return 0
    if args.command == "demo":
        folder = write_demo_project()
        print(f"Demo project written to {folder}\n")
        return _run_scan(folder, "text", "never", [], None, False)
    parser.print_help()
    return 2
