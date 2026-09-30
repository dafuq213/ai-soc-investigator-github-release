import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.generic_benchmark import run_generic_benchmark


class GenericBenchmarkTests(unittest.TestCase):
    def test_manifest_checks_expected_outcome_without_truth_accuracy_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"name": "test", "cases": [{"id": "a", "artifact": "data/a.json", "category": "generic", "expected_outcome": "accepted"}]}), encoding="utf-8")
            with patch("src.generic_benchmark.evaluate_generic_artifact", return_value={"outcome": "accepted", "passed": True, "issues": []}):
                result = run_generic_benchmark(manifest)
        self.assertTrue(result["contract_gate_passed"])
        self.assertFalse(result["analyst_accuracy_measured"])
        self.assertTrue(result["results"][0]["expectation_met"])

    def test_manifest_rejects_unknown_expected_outcome(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.json"
            manifest.write_text(json.dumps({"cases": [{"id": "a", "artifact": "x", "expected_outcome": "malicious"}]}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "valid expected_outcome"):
                run_generic_benchmark(manifest)


if __name__ == "__main__":
    unittest.main()
