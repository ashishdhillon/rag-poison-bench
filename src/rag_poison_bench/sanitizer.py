from __future__ import annotations

import re
from typing import Tuple

ZERO_WIDTH_RE = re.compile(r"[\u200b\u2060\u180e\u200e\u200f]")
TAG_CHARS_RE = re.compile(r"[\U000e0001-\U000e007f]")
BIDI_RE = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
SOFT_HYPHEN_RE = re.compile(r"\u00ad")
CHATML_TOKEN_RE = re.compile(r"<\|(im_start|im_end|endoftext|system|user|assistant)\|>")
LLAMA_TOKEN_RE = re.compile(r"\[(\/?(?:INST|SYS))\]|<<(\/?SYS)>>")
MD_IMAGE_RE = re.compile(r"!\[([^\]]*)\]\((https?://[^\s)]+)\)")
RAG_TAG_RE = re.compile(r"<\/?(context|retrieved_documents?|docs|system_instructions?|instructions?)>")


class Sanitizer:
    """Sanitizes text chunks to neutralize indirect prompt injection payloads."""

    def __init__(
        self,
        strip_unicode: bool = True,
        defang_images: bool = True,
        defang_delimiters: bool = True,
    ):
        self.strip_unicode = strip_unicode
        self.defang_images = defang_images
        self.defang_delimiters = defang_delimiters

    def sanitize(self, text: str) -> Tuple[str, list[str]]:
        """Returns (sanitized_text, list_of_modifications)."""
        if not text:
            return "", []

        modifications: list[str] = []
        cleaned = text

        # 1. Unicode stealth stripping
        if self.strip_unicode:
            if ZERO_WIDTH_RE.search(cleaned):
                cleaned = ZERO_WIDTH_RE.sub("", cleaned)
                modifications.append("Stripped zero-width and invisible control characters")

            # BOM: remove if occurs after the first byte
            if len(cleaned) > 1 and "\ufeff" in cleaned[1:]:
                cleaned = cleaned[0] + cleaned[1:].replace("\ufeff", "")
                modifications.append("Stripped embedded byte-order marks (U+FEFF)")

            if TAG_CHARS_RE.search(cleaned):
                cleaned = TAG_CHARS_RE.sub("", cleaned)
                modifications.append("Stripped ASCII-smuggling Unicode tag characters")

            if BIDI_RE.search(cleaned):
                cleaned = BIDI_RE.sub("", cleaned)
                modifications.append("Stripped bidirectional override control characters")

            if SOFT_HYPHEN_RE.search(cleaned):
                cleaned = SOFT_HYPHEN_RE.sub("", cleaned)
                modifications.append("Stripped soft hyphen word fragmentations")

        # 2. Defang markdown image exfiltration
        if self.defang_images:
            if MD_IMAGE_RE.search(cleaned):
                cleaned = MD_IMAGE_RE.sub(r"[image-defanged: \1 (\2)]", cleaned)
                modifications.append("Defanged markdown image embed tags to plain text reference")

        # 3. Defang model control tokens and RAG boundary tags
        if self.defang_delimiters:
            if CHATML_TOKEN_RE.search(cleaned):
                cleaned = CHATML_TOKEN_RE.sub(r"[control-token:\1]", cleaned)
                modifications.append("Defanged ChatML delimiter tokens")

            if LLAMA_TOKEN_RE.search(cleaned):
                cleaned = LLAMA_TOKEN_RE.sub(r"[delimiter:\1\2]", cleaned)
                modifications.append("Defanged Llama instruction delimiter tokens")

            if RAG_TAG_RE.search(cleaned):
                cleaned = RAG_TAG_RE.sub(r"[tag:\1]", cleaned)
                modifications.append("Defanged structural RAG context XML/HTML tags")

        return cleaned, modifications
