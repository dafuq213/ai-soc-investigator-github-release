import tempfile
import unittest
from pathlib import Path

from src.investigate_generic import AssessmentOutputError, assess_packet, new_case_id, run_generic_investigation


class _Tools:
    def get_alert_by_id(self, alert_id):
        return {"ok": True, "data": [{"wazuh_alert_id": alert_id, "alert_id": "doc", "timestamp": "2026-09-04T10:00:00Z", "agent": {"id": "001", "name": "WS-01"}, "rule": {"description": "Observed command", "level": 7}, "event": {"data": {"win": {"system": {"eventID": "1"}, "eventdata": {"Image": "C:\\Windows\\System32\\cmd.exe", "ProcessGuid": "{x}"}}}}}]}
    def get_entity_activity(self, **kwargs):
        return {"ok": True, "data": [], "meta": {}, "error": None}
    def get_authentication_activity(self, **kwargs):
        return {"ok": True, "data": [], "meta": {}, "error": None}


class _Provider:
    provider_name = "test"
    model = "test-model"
    def assess_prompt(self, prompt):
        return '{"verdict":"inconclusive","confidence":40,"what_happened":[{"evidence_ids":["E01"],"text":"The cited alert records a command process on the monitored endpoint."}],"alert_claim_assessment":{"status":"not_assessable","evidence_ids":["E01"],"text":"The cited record establishes an alert but does not establish the detection claim."},"hypotheses":[],"unknowns":["No additional related records were returned in the bounded collection."],"recommended_actions":[{"category":"preserve_evidence","action":"Preserve the cited process record before the retention period expires.","reason":"The cited alert is the primary record available for subsequent analyst review.","evidence_ids":["E01"],"target":null,"priority":"medium"}],"analyst_question":"Can the process activity be associated with an approved administrative task?"}'


class GenericInvestigationTests(unittest.TestCase):
    def test_generated_case_ids_do_not_collide_within_one_second(self):
        from datetime import datetime, timezone
        instant = datetime(2026, 9, 15, 5, 58, 24, tzinfo=timezone.utc)
        first = new_case_id(instant)
        second = new_case_id(instant)
        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith("GENERIC-20260915-055824-000000-"))

    def test_collects_generic_packet_without_model(self):
        normalized, packet = run_generic_investigation(_Tools(), "alert-1")
        self.assertEqual(normalized["alert_id"], "alert-1")
        self.assertEqual(packet["evidence"][0]["id"], "E01")

    def test_assessment_is_audited_and_contract_validated(self):
        _, packet = run_generic_investigation(_Tools(), "alert-1")
        with tempfile.TemporaryDirectory() as directory:
            assessment, audit = assess_packet(_Provider(), packet, "CASE-1", Path(directory))
            self.assertEqual(assessment["verdict"], "inconclusive")
            self.assertEqual(audit["contract_version"], "generic_assessment_v3")
            self.assertTrue(Path(audit["response_path"]).exists())

    def test_invalid_model_output_preserves_prompt_and_response_audits(self):
        class BadProvider(_Provider):
            def assess_prompt(self, prompt): return '{"broken"'
        _, packet = run_generic_investigation(_Tools(), "alert-1")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(AssessmentOutputError) as raised:
                assess_packet(BadProvider(), packet, "CASE-2", Path(directory))
            self.assertTrue(Path(raised.exception.audit["path"]).exists())
            self.assertTrue(Path(raised.exception.response_audit).exists())


if __name__ == "__main__":
    unittest.main()
