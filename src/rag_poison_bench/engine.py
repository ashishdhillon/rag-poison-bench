from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Sequence

from .detectors.base import BaseDetector, DetectionFinding, Severity, ThreatCategory
from .detectors.unicode_stealth import UnicodeStealthDetector
from .detectors.instruction_override import InstructionOverrideDetector
from .detectors.exfiltration import ExfiltrationDetector
from .detectors.delimiter_hijack import DelimiterHijackDetector

SEVERITY_WEIGHTS = {
    Severity.LOW: 0.25,
    Severity.MEDIUM: 0.55,
    Severity.HIGH: 0.85,
    Severity.CRITICAL: 1.0,
}


@dataclass
class ScanResult:
    text: str
    is_poisoned: bool
    score: float
    max_severity: Severity | None
    findings: list[DetectionFinding] = field(default_factory=list)
    categories_detected: list[ThreatCategory] = field(default_factory=list)
    scan_time_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "is_poisoned": self.is_poisoned,
            "score": round(self.score, 4),
            "max_severity": self.max_severity.value if self.max_severity else None,
            "categories_detected": [c.value for c in self.categories_detected],
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "scan_time_ms": round(self.scan_time_ms, 3),
        }


class ScanEngine:
    """Orchestrates detectors to scan text chunks for indirect prompt injection."""

    def __init__(
        self,
        detectors: Sequence[BaseDetector] | None = None,
        threshold: float = 0.5,
    ):
        if detectors is None:
            self.detectors: list[BaseDetector] = [
                UnicodeStealthDetector(),
                InstructionOverrideDetector(),
                ExfiltrationDetector(),
                DelimiterHijackDetector(),
            ]
        else:
            self.detectors = list(detectors)
        self.threshold = threshold

    def scan(self, text: str) -> ScanResult:
        t0 = time.perf_counter()
        all_findings: list[DetectionFinding] = []

        for detector in self.detectors:
            findings = detector.detect(text)
            all_findings.extend(findings)

        scan_time_ms = (time.perf_counter() - t0) * 1000.0

        if not all_findings:
            return ScanResult(
                text=text,
                is_poisoned=False,
                score=0.0,
                max_severity=None,
                findings=[],
                categories_detected=[],
                scan_time_ms=scan_time_ms,
            )

        # Determine highest severity and compute cumulative score
        severity_rank = {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        max_sev = max(all_findings, key=lambda f: severity_rank[f.severity]).severity

        # Combined threat score: max finding weight + logarithmic dampening of multiple findings
        max_weight = SEVERITY_WEIGHTS[max_sev]
        extra_weight = min(0.3, 0.05 * (len(all_findings) - 1))
        score = min(1.0, max_weight + extra_weight)

        categories = sorted(list({f.category for f in all_findings}), key=lambda c: c.value)
        is_poisoned = score >= self.threshold

        return ScanResult(
            text=text,
            is_poisoned=is_poisoned,
            score=score,
            max_severity=max_sev,
            findings=all_findings,
            categories_detected=categories,
            scan_time_ms=scan_time_ms,
        )
