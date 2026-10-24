"""Data models shared by the scanner and the reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List

SEVERITY_ORDER: Dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Points removed from the 100-point hardening score per finding.
SEVERITY_WEIGHT: Dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 4,
    "high": 10,
    "critical": 25,
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    file: str
    line: int
    evidence: str
    fix: str

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class ScanResult:
    root: str
    files_scanned: int = 0
    findings: List[Finding] = field(default_factory=list)

    def counts(self) -> Dict[str, int]:
        out = {level: 0 for level in SEVERITY_ORDER}
        for finding in self.findings:
            out[finding.severity] += 1
        return out

    def score(self) -> int:
        """Heuristic 0-100 score. Not a certification, just a quick signal."""
        penalty = sum(SEVERITY_WEIGHT[f.severity] for f in self.findings)
        return max(0, 100 - penalty)

    def worst(self) -> int:
        if not self.findings:
            return -1
        return max(SEVERITY_ORDER[f.severity] for f in self.findings)
