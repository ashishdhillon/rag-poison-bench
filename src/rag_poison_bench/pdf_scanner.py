from __future__ import annotations

import re
import zlib
from pathlib import Path
from typing import List
from .engine import ScanEngine, ScanResult


def extract_text_from_pdf_stream(pdf_bytes: bytes) -> str:
    """Extracts text streams and literal text operators from a PDF file using standard library only."""
    text_parts: List[str] = []

    # 1. Search for FlateDecode compressed streams
    stream_re = re.compile(b"stream[\r\n]+(.*?)[\r\n]+endstream", re.DOTALL)
    for match in stream_re.finditer(pdf_bytes):
        stream_data = match.group(1)
        try:
            decompressed = zlib.decompress(stream_data)
        except Exception:
            decompressed = stream_data

        # Look for PDF text show operators: (text) Tj or [(t)(e)(x)(t)] TJ
        tj_matches = re.findall(rb"\((.*?)\)\s*Tj", decompressed)
        for tj in tj_matches:
            try:
                decoded = tj.decode("utf-8", errors="replace")
                text_parts.append(decoded)
            except Exception:
                pass

        tj_array = re.findall(rb"\[(.*?)\]\s*TJ", decompressed, re.DOTALL)
        for arr in tj_array:
            inner_texts = re.findall(rb"\((.*?)\)", arr)
            line = "".join(t.decode("utf-8", errors="replace") for t in inner_texts)
            if line:
                text_parts.append(line)

    # 2. Extract literal text from uncompressed PDF structures
    uncompressed_tj = re.findall(rb"\((.*?)\)\s*Tj", pdf_bytes)
    for u in uncompressed_tj:
        try:
            text_parts.append(u.decode("utf-8", errors="replace"))
        except Exception:
            pass

    return "\n".join(text_parts)


def scan_pdf_file(pdf_path: Path | str, engine: ScanEngine | None = None) -> ScanResult:
    """Extracts text from a PDF document and scans it for indirect prompt injection."""
    p = Path(pdf_path)
    if not p.is_file():
        raise FileNotFoundError(f"PDF file not found: {pdf_path}")

    pdf_bytes = p.read_bytes()
    extracted_text = extract_text_from_pdf_stream(pdf_bytes)

    eng = engine or ScanEngine()
    return eng.scan(extracted_text)
