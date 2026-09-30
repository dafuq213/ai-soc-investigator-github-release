import unittest

from src.case_models import CaseBuilder
from src.correlation import attach_deterministic_correlations
from src.evidence_reduction import build_activity_cards
from src.reasoning_narrative import verify_narrative


def _record(alert_id, event_id, fields):
    return {
        "alert_id": alert_id, "timestamp": "2026-08-20T10:00:00Z", "host": "WS-01", "agent_id": "001", "rule": {"groups": ["sysmon"]},
        "event": {"data": {"win": {"system": {"eventID": str(event_id)}, "eventdata": fields}}},
    }


class EvidenceReductionTests(unittest.TestCase):
    def _case(self):
        seed = _record("seed", 1, {"processGuid": "{actor}", "image": "powershell.exe", "commandLine": "powershell.exe -File c:\\lab.ps1"})
        case = CaseBuilder.from_seed_result("CASE-REDUCE", {"ok": True, "data": [seed]})
        for item in (
            _record("dns-a", 22, {"processGuid": "{actor}", "queryName": "example.com"}),
            _record("dns-b", 22, {"processGuid": "{actor}", "queryName": "example.com"}),
        ):
            case.add_alert_evidence(item, {"backend": "telemetry", "index": "archives"})
        attach_deterministic_correlations(case)
        return case

    def test_reducer_groups_repeated_same_object_events(self):
        cards = build_activity_cards(self._case())
        dns = [item for item in cards if item["kind"] == "DNS query"]
        self.assertEqual(len(dns), 1)
        self.assertEqual(dns[0]["observed"]["occurrences"], 2)
        self.assertEqual(len(dns[0]["evidence_ids"]), 2)

    def test_narrative_rejects_uncited_specific_values(self):
        case = self._case()
        with self.assertRaises(ValueError):
            verify_narrative(case, [{"card_ids": ["R01"], "text": "The process contacted 8.8.8.8, indicating compromise."}])

    def test_narrative_accepts_cited_cautious_reasoning(self):
        case = self._case()
        value = verify_narrative(case, [{"card_ids": ["R01", "R02"], "text": "The collected cards show a process and DNS activity; the evidence does not establish intent."}])
        self.assertEqual(len(value), 1)

    def test_narrative_accepts_observed_parent_image_on_seed_card(self):
        seed = _record("seed-parent", 1, {
            "processGuid": "{actor}", "image": "C:\\Windows\\System32\\reg.exe",
            "parentImage": "C:\\Windows\\System32\\svchost.exe",
            "commandLine": "reg.exe add HKLM\\Software\\Vendor /v value /d 1",
        })
        case = CaseBuilder.from_seed_result("CASE-PARENT-NARRATIVE", {"ok": True, "data": [seed]})
        value = verify_narrative(case, [{
            "card_ids": ["R01"],
            "text": "The cited card shows reg.exe launched by svchost.exe; this observed launch context does not establish intent.",
        }])
        self.assertEqual(len(value), 1)


if __name__ == "__main__":
    unittest.main()
