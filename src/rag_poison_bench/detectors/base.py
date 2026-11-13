from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Tuple


class ThreatCategory(str, Enum):
    UNICODE_STEALTH = "unicode_stealth"
    INSTRUCTION_OVERRIDE = "instruction_override"
    EXFILTRATION = "exfiltration"
    DELIMITER_HIJACK = "delimiter_hijack"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class DetectionFinding:
    category: ThreatCategory
    detector: str
    severity: Severity
    description: str
    matched_text: str
    char_span: Tuple[int, int]
    remediation: str

    def to_dict(self) -> dict:
        return {
            "category": self.category.value,
            "detector": self.detector,
            "severity": self.severity.value,
            "description": self.description,
            "matched_text": self.matched_text,
            "char_span": list(self.char_span),
            "remediation": self.remediation,
        }


class BaseDetector:
    name: str = "base_detector"
    category: ThreatCategory = ThreatCategory.INSTRUCTION_OVERRIDE

    def detect(self, text: str) -> list[DetectionFinding]:
        raise NotImplementedError
