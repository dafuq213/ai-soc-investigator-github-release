import unittest

from src.investigate_case import run_case_investigation


class StubTools:
    def get_alert_by_id(self, alert_id):
        return {"ok": True, "data": [{"alert_id": alert_id, "timestamp": "2026-08-10T10:00:00Z", "host": "WS-001", "rule": {}, "event": {}}]}


class CaseEntrypointTests(unittest.TestCase):
    def test_entrypoint_creates_evidence_only_case_without_reasoning(self):
        case, assessment = run_case_investigation(StubTools(), "seed-1", None)
        self.assertEqual(case.case_id[:5], "CASE-")
        self.assertEqual(case.evidence[0].evidence_id, "E001")
        self.assertEqual(assessment.status, "evidence_only")
        self.assertEqual(assessment.verdict, "inconclusive")


if __name__ == "__main__":
    unittest.main()
