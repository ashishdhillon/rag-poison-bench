"""RAG Poison Bench: Deterministic scanner and reproducible benchmark for indirect prompt injection."""

from .detectors.base import (
    BaseDetector,
    DetectionFinding,
    Severity,
    ThreatCategory,
)
from .engine import ScanEngine, ScanResult
from .sanitizer import Sanitizer
from .benchmark import BenchmarkRunner, MetricSummary
from .data.benchmark_dataset import BenchmarkSample, load_benchmark_dataset

__version__ = "0.1.0"

__all__ = [
    "BaseDetector",
    "DetectionFinding",
    "Severity",
    "ThreatCategory",
    "ScanEngine",
    "ScanResult",
    "Sanitizer",
    "BenchmarkRunner",
    "MetricSummary",
    "BenchmarkSample",
    "load_benchmark_dataset",
]
