import json
import tempfile
import unittest
from pathlib import Path

from src.truth_label_evaluation import evaluate_truth_labels


class TruthLabelEvaluationTests(unittest.TestCase):
    def test_scores_only_assessed_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            labels = root / "labels.json"
            labels.write_text(json.dumps({"cases": [{"fixture": "fixture-a.json", "allowed_verdicts": ["inconclusive"], "must_not_recommend": ["consider_response"], "required_unknown_keywords": ["parent"]}]}), encoding="utf-8")
            corpus = root / "corpus"
            corpus.mkdir()
            (corpus / "FIXTURE-A.json").write_text(json.dumps({"assessment": {"verdict": "inconclusive", "recommended_actions": ["preserve_evidence"], "unknowns": ["The parent origin is unavailable."]}}), encoding="utf-8")
            result = evaluate_truth_labels(labels, corpus)
        self.assertTrue(result["truth_label_gate_passed"])
        self.assertEqual(result["scored_cases"], 1)

    def test_evidence_only_artifact_is_pending_not_scored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            labels = root / "labels.json"
            labels.write_text(json.dumps({"cases": [{"fixture": "fixture-a.json", "allowed_verdicts": ["inconclusive"]}]}), encoding="utf-8")
            corpus = root / "corpus"
            corpus.mkdir()
            (corpus / "FIXTURE-A.json").write_text(json.dumps({"assessment": None}), encoding="utf-8")
            result = evaluate_truth_labels(labels, corpus)
        self.assertEqual(result["pending_cases"], 1)
        self.assertFalse(result["truth_label_gate_passed"])

    def test_rejected_model_output_is_not_reported_as_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            labels = root / "labels.json"
            labels.write_text(json.dumps({"cases": [{"fixture": "fixture-a.json", "allowed_verdicts": ["inconclusive"]}]}), encoding="utf-8")
            corpus = root / "corpus"
            corpus.mkdir()
            (corpus / "FIXTURE-A.json").write_text(json.dumps({"assessment": None, "assessment_error": "invalid schema"}), encoding="utf-8")
            result = evaluate_truth_labels(labels, corpus)
        self.assertEqual(result["pending_cases"], 0)
        self.assertEqual(result["rejected_model_outputs"], 1)
        self.assertEqual(result["results"][0]["state"], "rejected_model_output")


if __name__ == "__main__":
    unittest.main()
