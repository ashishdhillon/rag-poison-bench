from __future__ import annotations

import re
from .base import BaseDetector, DetectionFinding, Severity, ThreatCategory

DELIMITER_PATTERNS = [
    # ChatML tokens
    (
        r"<\|(?:im_start|im_end|endoftext|system|user|assistant)\|>",
        Severity.CRITICAL,
        "ChatML control token breakout (<|im_start|>, <|im_end|>, etc.)",
    ),
    # Llama / Mistral instruction tags
    (
        r"\[\/?(?:INST|SYS)\]|<<\/?SYS>>",
        Severity.CRITICAL,
        "Llama / Mistral model instruction delimiter breakout ([INST], <<SYS>>)",
    ),
    # Common RAG boundary closures paired with injected system blocks
    (
        r"(?i)<\/(?:context|retrieved_documents?|docs|documents?|knowledge_base)>\s*<(?:system|instructions?|prompt|override)>",
        Severity.CRITICAL,
        "RAG context closure paired with injected system tag breakout",
    ),
    # Standalone fake system boundary tags inside chunk
    (
        r"(?i)<\/?(?:system_instructions?|developer_directive|system_message)>",
        Severity.HIGH,
        "Structural XML/HTML tag spoofing system instruction boundaries",
    ),
    # Markdown separator spoofing system roles
    (
        r"(?im)^(?:\-{3,}|={3,}|#{2,})\s*(?:BEGIN\s+SYSTEM(?:\s+PROMPT)?|SYSTEM\s+PROMPT|ADMIN\s+OVERRIDE|END\s+OF\s+CONTEXT)\s*(?:\-{3,}|={3,}|#{2,})?$",
        Severity.HIGH,
        "Forged text boundary simulating system prompt section headers",
    ),
    # Human / Assistant conversation turn spoofing inside chunk
    (
        r"(?im)^(?:Human|User|Assistant|System)\s*:\s*(?:Ignore|Override|Forget|Now|Disregard)\b",
        Severity.MEDIUM,
        "Simulated dialog turn spoofing assistant or user role",
    ),
]


class DelimiterHijackDetector(BaseDetector):
    name = "delimiter_hijack"
    category = ThreatCategory.DELIMITER_HIJACK

    def detect(self, text: str) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        if not text:
            return findings

        for pattern, severity, description in DELIMITER_PATTERNS:
            for match in re.finditer(pattern, text):
                findings.append(
                    DetectionFinding(
                        category=self.category,
                        detector=self.name,
                        severity=severity,
                        description=description,
                        matched_text=match.group(),
                        char_span=(match.start(), match.end()),
                        remediation="Escape XML/markdown delimiter sequences before injecting into prompt templates.",
                    )
                )

        return findings
