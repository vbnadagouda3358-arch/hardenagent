"""Turn a ScanResult into text, JSON, Markdown or SARIF."""

from __future__ import annotations

import json
from typing import Dict

from . import __version__
from .models import ScanResult
from .rules import rule_catalog

COLORS = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[90m",
}
RESET = "\033[0m"
BOLD = "\033[1m"


def _summary_line(result: ScanResult) -> str:
    counts = result.counts()
    return (f"{counts['critical']} critical, {counts['high']} high, "
            f"{counts['medium']} medium, {counts['low']} low")


def to_text(result: ScanResult, color: bool = False) -> str:
    def paint(text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if color else text

    out = []
    out.append(paint(f"hardenagent {__version__}", BOLD)
               + f" - scanned {result.files_scanned} files in {result.root}")
    out.append(f"Hardening score: {result.score()}/100 (quick heuristic, not a certification)")
    out.append("")
    if not result.findings:
        out.append("No findings. Nice work. Re-run after every config change.")
        return "\n".join(out)
    for finding in result.findings:
        label = paint(f"{finding.severity.upper():<8}", COLORS[finding.severity])
        out.append(f"{label} {finding.rule_id}  {finding.title}")
        out.append(f"         {finding.file}:{finding.line}")
        out.append(f"         > {finding.evidence}")
        out.append(f"         Fix: {finding.fix}")
        out.append("")
    out.append("Summary: " + _summary_line(result))
    out.append("Only scan systems you own or are authorised to test.")
    return "\n".join(out)


def to_json(result: ScanResult) -> str:
    payload: Dict[str, object] = {
        "tool": "hardenagent",
        "version": __version__,
        "root": result.root,
        "files_scanned": result.files_scanned,
        "score": result.score(),
        "counts": result.counts(),
        "findings": [f.to_dict() for f in result.findings],
    }
    return json.dumps(payload, indent=2)


def to_markdown(result: ScanResult) -> str:
    out = [
        "# Agent hardening report",
        "",
        f"- Scanned: `{result.root}` ({result.files_scanned} files)",
        f"- Hardening score: **{result.score()}/100** (quick heuristic, not a certification)",
        f"- Findings: {_summary_line(result)}",
        "",
    ]
    if not result.findings:
        out.append("No findings.")
        return "\n".join(out)
    out += ["| Severity | Rule | Location | Issue |", "|---|---|---|---|"]
    for f in result.findings:
        out.append(f"| {f.severity} | {f.rule_id} | `{f.file}:{f.line}` | {f.title} |")
    out += ["", "## Fixes", ""]
    for f in result.findings:
        out.append(f"- **{f.rule_id}** `{f.file}:{f.line}` - {f.fix}")
    return "\n".join(out)


def to_sarif(result: ScanResult) -> str:
    level = {"critical": "error", "high": "error", "medium": "warning",
             "low": "note", "info": "note"}
    rules = [
        {"id": rid, "shortDescription": {"text": title},
         "properties": {"severity": sev}}
        for rid, sev, title in rule_catalog()
    ]
    results = [
        {
            "ruleId": f.rule_id,
            "level": level[f.severity],
            "message": {"text": f"{f.title}. {f.fix}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": f.line},
                }
            }],
        }
        for f in result.findings
    ]
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "hardenagent", "version": __version__, "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


FORMATS = {"json": to_json, "markdown": to_markdown, "sarif": to_sarif}
