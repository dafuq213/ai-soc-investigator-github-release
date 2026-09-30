import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.v1_release_gate import evaluate_reviewed_cases, run_v1_release_gate


class V1ReleaseGateTests(unittest.TestCase):
    def _write_manifest(self, root, cases):
        benchmarks = root / "benchmarks"
        benchmarks.mkdir()
        path = benchmarks / "reviews.json"
        path.write_text(json.dumps({"cases": cases}), encoding="utf-8")
        return path

    def test_empty_review_manifest_is_not_release_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_manifest(Path(directory), [])
            outcome = evaluate_reviewed_cases(path, minimum_cases=1)
        self.assertFalse(outcome["review_gate_passed"])
        self.assertFalse(outcome["minimum_cases_met"])

    def test_safe_reviewed_record_passes_when_minimum_is_one(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "data" / "investigations" / "case.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("{}", encoding="utf-8")
            record = {"case_id": "case-1", "artifact": "data/investigations/case.json", "alert_family": "authentication", "final_disposition": "insufficient_evidence", "analyst_conclusion": "The artifact lacks the initiating process.", "model_assessment_agreement": "agree", "evidence_citations_verified": True, "unsupported_claims": 0, "unsafe_response": False}
            outcome = evaluate_reviewed_cases(self._write_manifest(root, [record]), minimum_cases=1, minimum_families=1)
        self.assertTrue(outcome["review_gate_passed"])

    def test_contract_and_review_status_are_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            review = self._write_manifest(root, [])
            with patch("src.v1_release_gate.run_generic_benchmark", return_value={"contract_gate_passed": True}), patch("src.v1_release_gate.verify_baseline_lock", return_value={"baseline_verified": True}):
                outcome = run_v1_release_gate("unused.json", review, minimum_cases=1)
        self.assertTrue(outcome["v1_candidate_ready"])
        self.assertFalse(outcome["production_reliability_claim_allowed"])
