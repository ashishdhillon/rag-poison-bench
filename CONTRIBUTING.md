# Contributing to rag-poison-bench

Thank you for contributing to `rag-poison-bench`!

We welcome contributions to expand detection vectors, add document formats, and introduce new benchmark samples.

---

## Development Setup

`rag-poison-bench` has **zero external runtime dependencies** (Pure Python 3.9+ standard library).

```bash
git clone https://github.com/ashishdhillon/rag-poison-bench.git
cd rag-poison-bench
pip install -e .
```

### Running Tests

Run the test suite using standard library `unittest`:

```bash
python -m unittest discover -s tests -v
```

### Running the Benchmark

```bash
rag-poison-bench bench --format markdown
```

---

## Guidelines for New Detectors & Rules

1. New detectors should inherit from `BaseDetector` in `src/rag_poison_bench/detectors/base.py`.
2. Ensure you calculate exact character spans `(start, end)` for findings so the HTML visual report can highlight the affected substring.
3. Keep the core runtime dependency-free.
4. Add corresponding poisoned and benign test vectors to `src/rag_poison_bench/data/benchmark_dataset.py` to ensure the False Positive Rate (FPR) remains 0.0%.
