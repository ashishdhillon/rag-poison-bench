from __future__ import annotations

import re
from .base import BaseDetector, DetectionFinding, Severity, ThreatCategory

# Exfiltration patterns targeting rendering frontends (e.g. Markdown image beacons)
EXFIL_PATTERNS = [
    # Markdown image containing query params designed for exfiltration
    (
        r"!\[([^\]]*)\]\((https?://[^\s)]+?[?&](?:q|leak|token|data|secret|key|exfil|cookie|user|prompt)=[^)]*)\)",
        Severity.CRITICAL,
        "Markdown image beacon with tracking query parameters (potential data exfiltration)",
    ),
    # Direct instruction to render a markdown image with user data or context
    (
        r"(?i)(?:render|output|display|show)\s+(?:an?\s+)?image\s+(?:markdown\s+)?(?:tag\s+)?(?:like\s+)?!\[.*?\]\(https?://",
        Severity.HIGH,
        "Instruction instructing the model to render an external tracking image",
    ),
    # Hidden HTML image beacon
    (
        r"""<img\s+[^>]*?src=["']https?://[^"']*?[?&](?:leak|data|token|q|exfil)=[^"']*?["'][^>]*>""",
        Severity.CRITICAL,
        "HTML img beacon with dynamic query parameter payload",
    ),
    # Zero-sized or hidden HTML beacon
    (
        r"""<img\s+[^>]*?(?:width=["']0["']|height=["']0["']|display:\s*none|visibility:\s*hidden)[^>]*>""",
        Severity.HIGH,
        "Hidden zero-dimension HTML image element",
    ),
    # Exfiltration instruction via curl / webhook disguised in RAG context
    (
        r"(?i)(?:send|exfiltrate|transmit|post)\s+(?:all\s+)?(?:context|conversation|secrets?|keys?|user\s+data)(?:\s+(?:and|or|,)\s+(?:context|conversation|secrets?|keys?|user\s+data))*\s+to\s+https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        Severity.HIGH,
        "Direct instruction to exfiltrate context or secrets to external host",
    ),
]


class ExfiltrationDetector(BaseDetector):
    name = "exfiltration"
    category = ThreatCategory.EXFILTRATION

    def detect(self, text: str) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        if not text:
            return findings

        for pattern, severity, description in EXFIL_PATTERNS:
            for match in re.finditer(pattern, text):
                findings.append(
                    DetectionFinding(
                        category=self.category,
                        detector=self.name,
                        severity=severity,
                        description=description,
                        matched_text=match.group(),
                        char_span=(match.start(), match.end()),
                        remediation="Defang markdown image tags and block external image rendering in UI.",
                    )
                )

        return findings
