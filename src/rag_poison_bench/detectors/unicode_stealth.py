from __future__ import annotations

import re
import unicodedata
from .base import BaseDetector, DetectionFinding, Severity, ThreatCategory

# Invisible & zero-width code points often used to conceal prompt injection
ZERO_WIDTH_CHARS = {
    "\u200b": "Zero Width Space (U+200B)",
    "\ufeff": "Byte Order Mark / Zero Width No-Break Space (U+FEFF)",
    "\u2060": "Word Joiner (U+2060)",
    "\u180e": "Mongolian Vowel Separator (U+180E)",
    "\u200e": "Left-to-Right Mark (U+200E)",
    "\u200f": "Right-to-Left Mark (U+200F)",
}

# BiDi override characters commonly used to reorder or disguise tokens
BIDI_OVERRIDES = {
    "\u202a": "Left-to-Right Embedding (U+202A)",
    "\u202b": "Right-to-Left Embedding (U+202B)",
    "\u202c": "Pop Directional Formatting (U+202C)",
    "\u202d": "Left-to-Right Override (U+202D)",
    "\u202e": "Right-to-Left Override (U+202E)",
    "\u2066": "Left-to-Right Isolate (U+2066)",
    "\u2067": "Right-to-Left Isolate (U+2067)",
    "\u2068": "First Strong Isolate (U+2068)",
    "\u2069": "Pop Directional Isolate (U+2069)",
}


class UnicodeStealthDetector(BaseDetector):
    name = "unicode_stealth"
    category = ThreatCategory.UNICODE_STEALTH

    def detect(self, text: str) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        if not text:
            return findings

        # 1. Zero-width and invisible control characters
        for idx, char in enumerate(text):
            if idx == 0 and char == "\ufeff":
                # Valid file-level UTF-8 BOM at the very start
                continue
            if char in ZERO_WIDTH_CHARS:
                findings.append(
                    DetectionFinding(
                        category=self.category,
                        detector=self.name,
                        severity=Severity.HIGH,
                        description=f"Hidden zero-width character detected: {ZERO_WIDTH_CHARS[char]}",
                        matched_text=repr(char),
                        char_span=(idx, idx + 1),
                        remediation="Strip zero-width characters before passing chunk to the LLM.",
                    )
                )

        # 2. Tag characters (U+E0001 to U+E007F) used for ASCII smuggling
        for match in re.finditer(r"[\U000e0001-\U000e007f]+", text):
            findings.append(
                DetectionFinding(
                    category=self.category,
                    detector=self.name,
                    severity=Severity.CRITICAL,
                    description=f"Unicode tag characters detected ({len(match.group())} code points, possible ASCII smuggling)",
                    matched_text=repr(match.group()),
                    char_span=(match.start(), match.end()),
                    remediation="Strip all Unicode tag block characters (U+E0000..U+E007F).",
                )
            )

        # 3. BiDi override characters
        for idx, char in enumerate(text):
            if char in BIDI_OVERRIDES:
                findings.append(
                    DetectionFinding(
                        category=self.category,
                        detector=self.name,
                        severity=Severity.MEDIUM,
                        description=f"Directional override character detected: {BIDI_OVERRIDES[char]}",
                        matched_text=repr(char),
                        char_span=(idx, idx + 1),
                        remediation="Sanitize bidirectional control characters to avoid visual-semantic mismatch.",
                    )
                )

        # 4. Soft hyphens inside words (e.g. "i\xadg\xadn\xado\xadr\xade")
        for match in re.finditer(r"\b\w*(?:\u00ad\w+)+\b", text):
            findings.append(
                DetectionFinding(
                    category=self.category,
                    detector=self.name,
                    severity=Severity.MEDIUM,
                    description="Soft hyphen word fragmentation detected (evasion technique)",
                    matched_text=match.group(),
                    char_span=(match.start(), match.end()),
                    remediation="Remove soft hyphens from document tokens.",
                )
            )

        # 5. Suspicious ZWJ/ZWNJ usage in Latin text
        for match in re.finditer(r"[A-Za-z0-9][\u200c\u200d]+[A-Za-z0-9]", text):
            findings.append(
                DetectionFinding(
                    category=self.category,
                    detector=self.name,
                    severity=Severity.HIGH,
                    description="Zero-width joiner embedded inside Latin alphanumeric token",
                    matched_text=repr(match.group()),
                    char_span=(match.start(), match.end()),
                    remediation="Normalize text to remove non-printing joiners in Latin tokens.",
                )
            )

        return findings
