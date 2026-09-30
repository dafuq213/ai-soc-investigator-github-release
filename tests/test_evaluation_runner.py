import json
import tempfile
import unittest
from pathlib import Path

from src.evaluation_runner import run_evaluation


class EvaluationRunnerTests(unittest.TestCase):
    def test_scores_recorded_cases_and_keeps_release_gate_closed_under_minimum(self):
        fixture = [{
            "case_id": "eval-1", "expected_verdict": "inconclusive", "prohibited_claim_types": [],
            "seed_result": {"ok": True, "data": [{"alert_id": "a-1", "event": {}, "rule": {}}]},
            "model_output": {"verdict": "inconclusive", "llm_confidence": 0.0, "claims": [], "benign_alternatives": [], "unknowns": ["No additional evidence."], "recommended_actions": []},
        }]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cases.json"
            path.write_text(json.dumps(fixture), encoding="utf-8")
            outcome = run_evaluation(path, minimum_cases=30)
        self.assertEqual(outcome["metrics"]["verdict_accuracy"], 1.0)
        self.assertFalse(outcome["release_gates"]["corpus_minimum_met"])
        self.assertFalse(outcome["release_ready"])


if __name__ == "__main__":
    unittest.main()
