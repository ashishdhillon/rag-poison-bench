from __future__ import annotations

import re
from .base import BaseDetector, DetectionFinding, Severity, ThreatCategory

# Compiled patterns representing common indirect prompt injection vectors
INSTRUCTION_PATTERNS = [
    (
        r"(?i)\b(?:ignore|disregard|forget|bypass|override)\s+(?:all\s+)?(?:(?:previous|prior|above|existing|earlier)\s+)?(?:instructions|prompts|directives|rules|constraints|context)\b",
        Severity.CRITICAL,
        "Direct instruction cancellation ('ignore previous instructions')",
    ),
    (
        r"(?i)\b(?:disregard|ignore)\s+(?:the\s+)?(?:system\s+prompt|developer\s+mode|safety\s+guidelines?)\b",
        Severity.CRITICAL,
        "System prompt or safety guideline override attempt",
    ),
    (
        r"(?i)\b(?:you\s+are\s+now|operating\s+as)\s+(?:in\s+)?(?:unrestricted|jailbreak(?:ed)?|developer\s+mode|dan\s+mode|root\s+mode)\b",
        Severity.CRITICAL,
        "Persona hijacking / jailbreak mode switch",
    ),
    (
        r"(?i)\b(?:important|urgent|critical)\s+(?:system\s+)?(?:notice|directive|instruction|override)\s*:\s*(?:ignore|do\s+not|override|instead|bypass)\b",
        Severity.HIGH,
        "High-priority imperative system spoofing",
    ),
    (
        r"(?i)\b(?:stop\s+following|abandon)\s+(?:prior|previous|all)\s+instructions\b",
        Severity.CRITICAL,
        "Instruction abandonment directive",
    ),
    (
        r"(?i)\binstead\s+of\s+(?:answering|summarizing|processing)\s+(?:the\s+)?(?:user(?:'s)?(?:\s+question)?|query|question|document),\s*(?:you\s+must|print|output|say|execute)\b",
        Severity.HIGH,
        "Workflow diversion instruction targeting RAG response",
    ),
    (
        r"(?i)\bdo\s+not\s+(?:answer|respond\s+to)\s+the\s+user(?:'s)?\s+question[;,]\s*(?:instead|print|output)\b",
        Severity.HIGH,
        "Response redirection imperative",
    ),
    (
        r"(?i)\b(?:new|updated)\s+system\s+(?:directive|instruction)\s*:\s*(?:disregard|override|reveal|exfiltrate)\b",
        Severity.CRITICAL,
        "Fake system directive update",
    ),
    (
        r"(?i)\bfrom\s+now\s+on,\s*(?:you\s+(?:will|must)|respond\s+only\s+with|ignore)\b",
        Severity.MEDIUM,
        "Conversational scope override ('from now on...')",
    ),
]


class InstructionOverrideDetector(BaseDetector):
    name = "instruction_override"
    category = ThreatCategory.INSTRUCTION_OVERRIDE

    def detect(self, text: str) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        if not text:
            return findings

        for pattern, severity, description in INSTRUCTION_PATTERNS:
            for match in re.finditer(pattern, text):
                findings.append(
                    DetectionFinding(
                        category=self.category,
                        detector=self.name,
                        severity=severity,
                        description=description,
                        matched_text=match.group(),
                        char_span=(match.start(), match.end()),
                        remediation="Quarantine or rewrite chunk; isolate retrieved context in strict quotes.",
                    )
                )

        return findings
