import json
import tempfile
import unittest
from pathlib import Path

from src.post_benchmark_evaluator import evaluate_post_benchmark


class PostBenchmarkEvaluatorTests(unittest.TestCase):
    def _setup(self, root, agreement="agree", confidence=55):
        artifact = root / "data" / "investigations" / "case.json"
        artifact.parent.mkdir(parents=True)
        artifact.write_text(json.dumps({"model_execution": {"invoked": True}, "assessment": {"verdict": "inconclusive", "confidence": confidence}}), encoding="utf-8")
        manifest = root / "benchmarks" / "reviews.json"
        manifest.parent.mkdir()
        manifest.write_text(json.dumps({"cases": [{"case_id": "case", "artifact": "data/investigations/case.json", "alert_family": "authentication", "final_disposition": "insufficient_evidence", "analyst_conclusion": "Insufficient context.", "model_assessment_agreement": agreement, "evidence_citations_verified": True, "unsupported_claims": 0, "unsafe_response": False}]}), encoding="utf-8")
        return manifest

    def test_reports_agreement_metrics_without_claiming_small_sample_calibration(self):
        with tempfile.TemporaryDirectory() as directory:
            outcome = evaluate_post_benchmark(self._setup(Path(directory)), thresholds={"minimum_valid_cases": 1, "minimum_alert_families": 1, "minimum_accepted_assessment_coverage": 1.0, "minimum_weighted_agreement": 1.0, "maximum_disagreement_rate": 0.0, "maximum_high_confidence_disagreements": 0})
        self.assertTrue(outcome["post_benchmark_gate_passed"])
        self.assertEqual(outcome["weighted_analyst_agreement"], 1.0)
        self.assertFalse(outcome["confidence_alignment"]["evaluable"])

    def test_high_confidence_disagreement_blocks_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            outcome = evaluate_post_benchmark(self._setup(Path(directory), agreement="disagree", confidence=80), thresholds={"minimum_valid_cases": 1, "minimum_alert_families": 1, "minimum_accepted_assessment_coverage": 1.0, "minimum_weighted_agreement": 0.0, "maximum_disagreement_rate": 1.0, "maximum_high_confidence_disagreements": 0})
        self.assertFalse(outcome["checks"]["no_high_confidence_disagreement"])
        self.assertEqual(outcome["high_confidence_disagreements"], ["case"])
