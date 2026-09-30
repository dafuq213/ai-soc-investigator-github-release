import json
import tempfile
import unittest
from pathlib import Path

from src.local_truth_benchmark import assess_corpus_artifact


class _Provider:
    model = "local-test"
    def assess_prompt(self, prompt):
        return json.dumps({
            "verdict": "inconclusive", "confidence": 40,
            "what_happened": [{"evidence_ids": ["E01"], "text": "The cited record shows a controlled process event on the monitored endpoint."}],
            "alert_claim_assessment": {"status": "not_assessable", "evidence_ids": ["E01"], "text": "The cited record does not establish the full alert claim."},
            "hypotheses": [], "unknowns": ["Authorization for the process is not established by the packet."],
            "recommended_actions": [{"category": "preserve_evidence", "action": "Preserve the cited process record before the retention period expires.", "reason": "The cited alert is the primary record available for subsequent analyst review.", "evidence_ids": ["E01"], "target": None, "priority": "medium"}], "analyst_question": "Can the observed process be associated with an approved test?",
        })


class LocalTruthBenchmarkTests(unittest.TestCase):
    def test_persists_one_local_assessment_and_audit(self):
        artifact = {"evidence_packet": {"schema_version": "evidence_packet_v1", "alert": {"alert_id": "a", "title": "Alert", "source": {}}, "evidence": [{"id": "E01", "relationship": "seed_alert", "source": {"alert_id": "a"}, "summary": "Observed.", "fields": {}}], "collection": {}}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "CASE.json"
            path.write_text(json.dumps(artifact), encoding="utf-8")
            result = assess_corpus_artifact(_Provider(), path, root / "audits")
            updated = json.loads(path.read_text(encoding="utf-8"))
            response_exists = Path(updated["prompt_audit"]["response_path"]).exists()
        self.assertEqual(result["assessment_status"], "accepted")
        self.assertEqual(updated["model_execution"]["provider"], "ollama")
        self.assertTrue(response_exists)


if __name__ == "__main__":
    unittest.main()
