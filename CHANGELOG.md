# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-14

### Added
- **Interactive HTML Visual Report:** Added `--format html` output to `rag-poison-bench bench`, generating a standalone visual security scorecard with KPI cards and interactive highlighted chunk inspection.
- **Pure-Python PDF Scanner:** Added `extract_text_from_pdf_stream` and `scan_pdf_file` using standard library `zlib` to inspect raw PDF binary streams and text operators without third-party C-dependencies.
- **Dataset Expansion:** Expanded benchmark dataset to 60 enterprise samples with Jira ticket injections, code review comments, and diverse clean technical documents.
- **Enhanced Override Detection:** Added support for `"override previous constraints"` and un-prefixed system directive cancellation patterns.

---

## [0.1.0] - 2026-11-13

### Added
- Initial release of deterministic scanner and reproducible benchmark for indirect prompt injection in RAG pipelines.
- Multi-vector detection: Unicode stealth & ASCII smuggling, instruction override, markdown image exfiltration, and delimiter breakouts.
- Defensive sanitizer (`rag-poison-bench sanitize`).
- Reproducible benchmark runner with 95% bootstrap confidence intervals.
