import unittest

from src.case_models import InvestigationCase
from src.correlation import attach_deterministic_correlations, build_process_tree, correlate_authentication_windows


def process_alert(alert_id, guid, parent_guid, image, timestamp):
    return {"alert_id": alert_id, "timestamp": timestamp, "host": "WS-001", "rule": {"groups": ["sysmon"]}, "event": {"data": {"win": {"system": {"eventID": "1"}, "eventdata": {"processGuid": guid, "parentProcessGuid": parent_guid, "image": image, "user": "ACME\\user"}}}}}


def auth_alert(alert_id, timestamp, description):
    return {"alert_id": alert_id, "timestamp": timestamp, "host": "DC-001", "rule": {"description": description, "groups": ["authentication"]}, "event": {"data": {"win": {"eventdata": {"targetUserName": "jsmith", "ipAddress": "203.0.113.10", "workstationName": "DC-001", "logonType": "3"}}}}}


class CorrelationTests(unittest.TestCase):
    def test_process_tree_requires_observed_process_guids(self):
        case = InvestigationCase("CASE-PROC", "seed")
        case.add_alert_evidence(process_alert("a1", "{word}", None, "WINWORD.EXE", "2026-08-10T10:00:00Z"))
        case.add_alert_evidence(process_alert("a2", "{ps}", "{word}", "powershell.exe", "2026-08-10T10:00:01Z"))
        case.add_alert_evidence(process_alert("a3", "{cmd}", "{missing}", "cmd.exe", "2026-08-10T10:00:02Z"))
        tree = build_process_tree(case)
        self.assertEqual(tree.roots, ["{cmd}", "{word}"])
        self.assertEqual(tree.nodes["{word}"].child_process_guids, ["{ps}"])
        self.assertEqual(tree.unresolved_parent_guids, ["{missing}"])

    def test_authentication_correlation_uses_key_and_bounded_window(self):
        case = InvestigationCase("CASE-AUTH", "seed")
        case.add_alert_evidence(auth_alert("a1", "2026-08-10T10:00:00Z", "Failed login"))
        case.add_alert_evidence(auth_alert("a2", "2026-08-10T10:01:00Z", "Failed login"))
        case.add_alert_evidence(auth_alert("a3", "2026-08-10T10:02:00Z", "Successful login"))
        case.add_alert_evidence(auth_alert("a4", "2026-08-10T10:20:00Z", "Failed login"))
        windows = correlate_authentication_windows(case)
        self.assertEqual(len(windows), 2)
        self.assertEqual((windows[0].failures, windows[0].successes), (2, 1))
        self.assertEqual(windows[0].evidence_ids, ["E001", "E002", "E003"])
        self.assertEqual((windows[1].failures, windows[1].successes), (1, 0))

    def test_correlation_output_is_persisted_on_case(self):
        case = InvestigationCase("CASE-CORR", "seed")
        case.add_alert_evidence(process_alert("a1", "{word}", None, "WINWORD.EXE", "2026-08-10T10:00:00Z"))
        attach_deterministic_correlations(case)
        self.assertIn("process_tree", case.correlations)
        self.assertIn("authentication_windows", case.correlations)

    def test_contextual_siblings_are_excluded_from_direct_process_tree(self):
        case = InvestigationCase("CASE-CONTEXT", "seed")
        direct = case.add_alert_evidence(process_alert("a1", "{seed}", "{parent}", "powershell.exe", "2026-08-10T10:00:00Z"))
        sibling = case.add_alert_evidence(process_alert("a2", "{sibling}", "{parent}", "cmd.exe", "2026-08-10T10:00:01Z"))
        case.contextual_evidence_ids.add(sibling.evidence_id)
        tree = build_process_tree(case)
        self.assertIn("{seed}", tree.nodes)
        self.assertNotIn("{sibling}", tree.nodes)


if __name__ == "__main__":
    unittest.main()
