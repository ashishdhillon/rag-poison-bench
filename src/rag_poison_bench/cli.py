from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Sequence

from .benchmark import BenchmarkRunner, format_markdown, format_table
from .engine import ScanEngine
from .html_report import generate_html_report
from .pdf_scanner import extract_text_from_pdf_stream, scan_pdf_file
from .sanitizer import Sanitizer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rag-poison-bench",
        description="Deterministic scanner and reproducible benchmark for indirect prompt injection in RAG pipelines.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan
    scan_parser = subparsers.add_parser("scan", help="Scan document(s) or text chunks for indirect prompt injection")
    scan_parser.add_argument("target", help="File path, directory path, or '-' for stdin")
    scan_parser.add_argument("--threshold", type=float, default=0.5, help="Threat score threshold (0.0 to 1.0, default: 0.5)")
    scan_parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

    # bench
    bench_parser = subparsers.add_parser("bench", help="Run the indirect prompt injection evaluation benchmark")
    bench_parser.add_argument("--bootstrap", type=int, default=1000, help="Number of bootstrap iterations for 95%% CI (default: 1000)")
    bench_parser.add_argument("--format", choices=["table", "markdown", "json", "html"], default="table", help="Output format")
    bench_parser.add_argument("-o", "--output", help="Save benchmark report to file")

    # sanitize
    san_parser = subparsers.add_parser("sanitize", help="Neutralize and defang prompt injection payloads in a file")
    san_parser.add_argument("target", help="File path to sanitize")
    san_parser.add_argument("--in-place", action="store_true", help="Modify the target file in-place")
    san_parser.add_argument("--output", "-o", help="Output file path (default: stdout)")

    # inspect
    inspect_parser = subparsers.add_parser("inspect", help="Deeply inspect a single string chunk")
    inspect_parser.add_argument("text", help="Text to inspect")

    return parser


def handle_scan(args: argparse.Namespace) -> int:
    engine = ScanEngine(threshold=args.threshold)
    files_to_scan: list[Path] = []

    if args.target == "-":
        content = sys.stdin.read()
        res = engine.scan(content)
        if args.format == "json":
            print(json.dumps(res.to_dict(), indent=2))
        else:
            status = "🚨 POISONED" if res.is_poisoned else "✅ CLEAN"
            print(f"Status: {status} (Score: {res.score:.2f}, Severity: {res.max_severity})")
            for f in res.findings:
                print(f"  [{f.severity.value.upper()}] {f.detector}: {f.description}")
        return 1 if res.is_poisoned else 0

    p = Path(args.target)
    if not p.exists():
        print(f"Error: Target path '{args.target}' does not exist.", file=sys.stderr)
        return 2

    if p.is_file():
        files_to_scan.append(p)
    else:
        for ext in ("*.txt", "*.md", "*.markdown", "*.json", "*.html", "*.pdf"):
            files_to_scan.extend(p.rglob(ext))

    if not files_to_scan:
        print(f"No text documents found in '{args.target}'.", file=sys.stderr)
        return 0

    any_poisoned = False
    all_results = []

    for file_path in files_to_scan:
        if file_path.suffix.lower() == ".pdf":
            try:
                content = extract_text_from_pdf_stream(file_path.read_bytes())
            except Exception as e:
                print(f"Failed to read PDF {file_path}: {e}", file=sys.stderr)
                continue
        else:
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                print(f"Failed to read {file_path}: {e}", file=sys.stderr)
                continue

        res = engine.scan(content)
        if res.is_poisoned:
            any_poisoned = True

        all_results.append({
            "path": str(file_path),
            **res.to_dict(),
        })

    if args.format == "json":
        print(json.dumps(all_results, indent=2))
    else:
        print(f"Scanned {len(files_to_scan)} files:")
        for r in all_results:
            status = "🚨 POISONED" if r["is_poisoned"] else "✅ CLEAN"
            print(f"  {r['path']}: {status} (Score: {r['score']:.2f})")
            for f in r["findings"]:
                print(f"    • [{f['severity'].upper()}] {f['description']}")

    return 1 if any_poisoned else 0


def handle_bench(args: argparse.Namespace) -> int:
    runner = BenchmarkRunner()
    summary = runner.run(bootstrap_iterations=args.bootstrap)

    if args.format == "html":
        out = generate_html_report(summary, runner.last_results)
    elif args.format == "json":
        out = json.dumps(summary.to_dict(), indent=2)
    elif args.format == "markdown":
        out = format_markdown(summary)
    else:
        out = format_table(summary)

    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        print(f"Benchmark report written to {args.output}")
    else:
        print(out)
    return 0


def handle_sanitize(args: argparse.Namespace) -> int:
    sanitizer = Sanitizer()
    p = Path(args.target)
    if not p.is_file():
        print(f"Error: Target '{args.target}' is not a valid file.", file=sys.stderr)
        return 2

    content = p.read_text(encoding="utf-8", errors="replace")
    cleaned, mods = sanitizer.sanitize(content)

    if args.in_place:
        p.write_text(cleaned, encoding="utf-8")
        print(f"Sanitized '{args.target}' in-place ({len(mods)} modifications applied).")
    elif args.output:
        Path(args.output).write_text(cleaned, encoding="utf-8")
        print(f"Wrote sanitized content to '{args.output}' ({len(mods)} modifications applied).")
    else:
        sys.stdout.write(cleaned)

    return 0


def handle_inspect(args: argparse.Namespace) -> int:
    engine = ScanEngine()
    res = engine.scan(args.text)
    print(f"Threat Score: {res.score:.2f} | Status: {'POISONED' if res.is_poisoned else 'CLEAN'}")
    print(f"Max Severity: {res.max_severity.value if res.max_severity else 'none'}")
    print(f"Scan Duration: {res.scan_time_ms:.3f} ms")
    if res.findings:
        print("\nFindings:")
        for idx, f in enumerate(res.findings, 1):
            print(f" {idx}. [{f.severity.value.upper()}] {f.detector} ({f.category.value})")
            print(f"    Description: {f.description}")
            print(f"    Span: {f.char_span} -> {repr(f.matched_text)}")
            print(f"    Remediation: {f.remediation}")
    else:
        print("No threats detected.")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return handle_scan(args)
    elif args.command == "bench":
        return handle_bench(args)
    elif args.command == "sanitize":
        return handle_sanitize(args)
    elif args.command == "inspect":
        return handle_inspect(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
