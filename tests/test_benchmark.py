import unittest
from rag_poison_bench.benchmark import BenchmarkRunner, format_markdown, format_table


class TestBenchmark(unittest.TestCase):
    def test_benchmark_runner(self):
        runner = BenchmarkRunner()
        summary = runner.run(bootstrap_iterations=50)

        self.assertGreaterEqual(summary.total, 30)
        self.assertGreater(summary.poisoned_count, 0)
        self.assertGreater(summary.benign_count, 0)
        self.assertGreaterEqual(summary.recall, 0.95)
        self.assertLessEqual(summary.fpr, 0.05)
        self.assertGreaterEqual(summary.f1, 0.95)
        self.assertGreater(summary.scan_throughput_cps, 100)

        # Ensure formatters run without error
        tbl = format_table(summary)
        self.assertIn("RAG POISON BENCH RESULTS", tbl)

        md = format_markdown(summary)
        self.assertIn("RAG Poison Bench Evaluation Results", md)

        d = summary.to_dict()
        self.assertIn("confusion_matrix", d)
        self.assertIn("recall_ci95", d["metrics"])


if __name__ == "__main__":
    unittest.main()
