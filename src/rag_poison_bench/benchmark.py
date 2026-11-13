from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .data.benchmark_dataset import BenchmarkSample, load_benchmark_dataset
from .detectors.base import ThreatCategory
from .engine import ScanEngine, ScanResult


@dataclass
class MetricSummary:
    total: int
    poisoned_count: int
    benign_count: int
    tp: int
    fp: int
    tn: int
    fn: int
    recall: float
    precision: float
    fpr: float
    f1: float
    accuracy: float
    recall_ci95: Tuple[float, float]
    fpr_ci95: Tuple[float, float]
    category_recall: Dict[str, float]
    scan_throughput_cps: float  # chunks per second
    throughput_kb_s: float
    elapsed_seconds: float

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "poisoned_count": self.poisoned_count,
            "benign_count": self.benign_count,
            "confusion_matrix": {
                "tp": self.tp,
                "fp": self.fp,
                "tn": self.tn,
                "fn": self.fn,
            },
            "metrics": {
                "recall": round(self.recall, 4),
                "precision": round(self.precision, 4),
                "fpr": round(self.fpr, 4),
                "f1": round(self.f1, 4),
                "accuracy": round(self.accuracy, 4),
                "recall_ci95": [round(x, 4) for x in self.recall_ci95],
                "fpr_ci95": [round(x, 4) for x in self.fpr_ci95],
            },
            "category_recall": {k: round(v, 4) for k, v in self.category_recall.items()},
            "performance": {
                "throughput_chunks_per_sec": round(self.scan_throughput_cps, 1),
                "throughput_kb_per_sec": round(self.throughput_kb_s, 2),
                "elapsed_seconds": round(self.elapsed_seconds, 4),
            },
        }


class BenchmarkRunner:
    """Evaluates ScanEngine against curated benchmark datasets."""

    def __init__(self, engine: Optional[ScanEngine] = None):
        self.engine = engine or ScanEngine()

    def run(
        self,
        samples: Optional[List[BenchmarkSample]] = None,
        bootstrap_iterations: int = 1000,
        seed: int = 42,
    ) -> MetricSummary:
        dataset = samples if samples is not None else load_benchmark_dataset()

        t0 = time.perf_counter()
        results: List[Tuple[BenchmarkSample, ScanResult]] = []
        total_bytes = 0

        for sample in dataset:
            total_bytes += len(sample.text.encode("utf-8"))
            scan_res = self.engine.scan(sample.text)
            results.append((sample, scan_res))

        elapsed = time.perf_counter() - t0
        elapsed = max(elapsed, 1e-6)

        tp = sum(1 for s, r in results if s.is_poisoned and r.is_poisoned)
        fp = sum(1 for s, r in results if not s.is_poisoned and r.is_poisoned)
        tn = sum(1 for s, r in results if not s.is_poisoned and not r.is_poisoned)
        fn = sum(1 for s, r in results if s.is_poisoned and not r.is_poisoned)

        poisoned_count = sum(1 for s, _ in results if s.is_poisoned)
        benign_count = sum(1 for s, _ in results if not s.is_poisoned)

        recall = tp / poisoned_count if poisoned_count > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        fpr = fp / benign_count if benign_count > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / len(results) if results else 0.0

        # Per category recall
        category_stats: Dict[str, Dict[str, int]] = {}
        for s, r in results:
            if s.is_poisoned and s.expected_category:
                cat_name = s.expected_category.value
                stats = category_stats.setdefault(cat_name, {"total": 0, "detected": 0})
                stats["total"] += 1
                if r.is_poisoned:
                    stats["detected"] += 1

        cat_recall = {
            k: (v["detected"] / v["total"] if v["total"] > 0 else 0.0)
            for k, v in category_stats.items()
        }

        # Bootstrap confidence intervals
        recall_ci, fpr_ci = self._bootstrap_ci(results, iterations=bootstrap_iterations, seed=seed)

        cps = len(results) / elapsed
        kb_s = (total_bytes / 1024.0) / elapsed

        return MetricSummary(
            total=len(results),
            poisoned_count=poisoned_count,
            benign_count=benign_count,
            tp=tp,
            fp=fp,
            tn=tn,
            fn=fn,
            recall=recall,
            precision=precision,
            fpr=fpr,
            f1=f1,
            accuracy=accuracy,
            recall_ci95=recall_ci,
            fpr_ci95=fpr_ci,
            category_recall=cat_recall,
            scan_throughput_cps=cps,
            throughput_kb_s=kb_s,
            elapsed_seconds=elapsed,
        )

    def _bootstrap_ci(
        self,
        results: List[Tuple[BenchmarkSample, ScanResult]],
        iterations: int = 1000,
        seed: int = 42,
    ) -> Tuple[Tuple[float, float], Tuple[float, float]]:
        if iterations <= 0 or not results:
            return ((0.0, 0.0), (0.0, 0.0))

        rng = random.Random(seed)
        n = len(results)
        recalls: List[float] = []
        fprs: List[float] = []

        for _ in range(iterations):
            sampled = rng.choices(results, k=n)
            p_total = sum(1 for s, _ in sampled if s.is_poisoned)
            b_total = sum(1 for s, _ in sampled if not s.is_poisoned)

            if p_total > 0:
                tp_s = sum(1 for s, r in sampled if s.is_poisoned and r.is_poisoned)
                recalls.append(tp_s / p_total)
            if b_total > 0:
                fp_s = sum(1 for s, r in sampled if not s.is_poisoned and r.is_poisoned)
                fprs.append(fp_s / b_total)

        def percentile(vals: List[float], q: float) -> float:
            if not vals:
                return 0.0
            vals_sorted = sorted(vals)
            idx = int(q * (len(vals_sorted) - 1))
            return vals_sorted[idx]

        recall_ci = (percentile(recalls, 0.025), percentile(recalls, 0.975))
        fpr_ci = (percentile(fprs, 0.025), percentile(fprs, 0.975))
        return recall_ci, fpr_ci


def format_markdown(summary: MetricSummary) -> str:
    lines = [
        "## RAG Poison Bench Evaluation Results",
        "",
        f"- **Total Chunks Evaluated:** {summary.total} ({summary.poisoned_count} Poisoned, {summary.benign_count} Benign)",
        f"- **Throughput:** {summary.scan_throughput_cps:,.1f} chunks/sec ({summary.throughput_kb_s:,.1f} KB/s)",
        "",
        "### Global Performance Metrics",
        "",
        "| Metric | Value | 95% Confidence Interval |",
        "| :--- | :--- | :--- |",
        f"| **Recall (TPR)** | `{summary.recall * 100:.1f}%` | `[{summary.recall_ci95[0] * 100:.1f}%, {summary.recall_ci95[1] * 100:.1f}%]` |",
        f"| **Precision** | `{summary.precision * 100:.1f}%` | - |",
        f"| **FPR (False Alarm)** | `{summary.fpr * 100:.1f}%` | `[{summary.fpr_ci95[0] * 100:.1f}%, {summary.fpr_ci95[1] * 100:.1f}%]` |",
        f"| **F1 Score** | `{summary.f1:.4f}` | - |",
        f"| **Accuracy** | `{summary.accuracy * 100:.1f}%` | - |",
        "",
        "### Recall by Attack Category",
        "",
        "| Attack Vector Category | Recall | Status |",
        "| :--- | :--- | :--- |",
    ]
    for cat, rec in sorted(summary.category_recall.items()):
        status = "PASSED" if rec >= 0.90 else "WARNING"
        lines.append(f"| `{cat}` | `{rec * 100:.1f}%` | {status} |")

    lines.extend([
        "",
        "### Confusion Matrix",
        "",
        f"- **True Positives (TP):** {summary.tp}",
        f"- **False Positives (FP):** {summary.fp}",
        f"- **True Negatives (TN):** {summary.tn}",
        f"- **False Negatives (FN):** {summary.fn}",
    ])
    return "\n".join(lines)


def format_table(summary: MetricSummary) -> str:
    r_ci = f"[{summary.recall_ci95[0]*100:.1f}%, {summary.recall_ci95[1]*100:.1f}%]"
    f_ci = f"[{summary.fpr_ci95[0]*100:.1f}%, {summary.fpr_ci95[1]*100:.1f}%]"

    out = []
    out.append("┌────────────────────────────────────────────────────────┐")
    out.append("│              RAG POISON BENCH RESULTS                  │")
    out.append("├────────────────────────────────────────────────────────┤")
    out.append(f"│ Total Evaluated: {summary.total:<5} (Poisoned: {summary.poisoned_count:<3} | Benign: {summary.benign_count:<3})   │")
    out.append(f"│ Scan Throughput: {summary.scan_throughput_cps:>8.1f} chunks/s ({summary.throughput_kb_s:>7.1f} KB/s) │")
    out.append("├──────────────────────┬──────────┬──────────────────────┤")
    out.append("│ Metric               │ Value    │ 95% CI               │")
    out.append("├──────────────────────┼──────────┼──────────────────────┤")
    out.append(f"│ Recall (TPR)         │ {summary.recall*100:>6.1f}%  │ {r_ci:<20} │")
    out.append(f"│ False Positive (FPR) │ {summary.fpr*100:>6.1f}%  │ {f_ci:<20} │")
    out.append(f"│ Precision            │ {summary.precision*100:>6.1f}%  │ -                    │")
    out.append(f"│ F1 Score             │ {summary.f1:>7.4f}  │ -                    │")
    out.append(f"│ Overall Accuracy     │ {summary.accuracy*100:>6.1f}%  │ -                    │")
    out.append("├──────────────────────┴──────────┴──────────────────────┤")
    out.append("│ Recall by Category:                                    │")
    for cat, rec in sorted(summary.category_recall.items()):
        out.append(f"│  • {cat:<24} {rec*100:>5.1f}%                  │")
    out.append("└────────────────────────────────────────────────────────┘")
    return "\n".join(out)
