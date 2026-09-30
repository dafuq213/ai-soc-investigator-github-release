import unittest

from src.case_models import CaseBuilder
from src.correlation import attach_deterministic_correlations
from src.telemetry_profiles import SysmonProfileCollector, select_telemetry_profiles


def _record(alert_id, event_id, fields):
    return {
        "alert_id": alert_id, "timestamp": "2026-08-19T12:00:00Z", "host": "WS-01", "agent_id": "001",
        "rule": {"groups": ["sysmon"]},
        "event": {"data": {"win": {"system": {"eventID": str(event_id), "providerName": "Microsoft-Windows-Sysmon"}, "eventdata": fields}}},
    }


class _Tools:
    def __init__(self, records):
        self.records, self.calls = records, []

    def get_sysmon_profile_events(self, **kwargs):
        self.calls.append(kwargs)
        requested = set(kwargs["event_ids"])
        if kwargs["relationship"] == "access":
            data = [item for item in self.records if str(item["event"]["data"]["win"]["system"]["eventID"]) == "10"]
        elif kwargs["relationship"] == "child":
            data = [item for item in self.records if item["event"]["data"]["win"]["eventdata"].get("parentProcessGuid") == kwargs["process_guid"]]
        else:
            data = [item for item in self.records if item["event"]["data"]["win"]["eventdata"].get("processGuid") == kwargs["process_guid"] and str(item["event"]["data"]["win"]["system"]["eventID"]) in requested]
        limit = kwargs.get("limit", len(data))
        returned = data[:limit]
        return {"ok": True, "data": returned, "meta": {"source": "telemetry", "index": "wazuh-archives-*", "count": len(returned), "total": len(data), "truncated": len(data) > len(returned)}, "error": None}


class TelemetryProfileTests(unittest.TestCase):
    def test_process_access_collects_source_and_target_creation_records(self):
        source = _record("source", 1, {"processGuid": "{source}", "image": "tool.exe"})
        target = _record("target", 1, {"processGuid": "{target}", "image": "lsass.exe"})
        seed = _record("access", 10, {"sourceProcessGUID": "{source}", "sourceImage": "tool.exe", "targetProcessGUID": "{target}", "targetImage": "lsass.exe", "grantedAccess": "0x1010"})
        case = CaseBuilder.from_seed_result("CASE-ACCESS", {"ok": True, "data": [seed]})
        tools = _Tools([source, target])
        SysmonProfileCollector(tools).collect(case)
        attach_deterministic_correlations(case)
        self.assertEqual(select_telemetry_profiles(case), ["windows_sysmon_process_access"])
        self.assertEqual({call["process_guid"] for call in tools.calls}, {"{source}", "{target}"})
        relation = case.correlations["sysmon_relationships"][0]
        self.assertEqual(relation["relationship"], "process_access")
        self.assertEqual(relation["status"], "resolved")

    def test_same_seed_guid_is_a_valid_link_when_process_create_is_not_collected(self):
        seed = _record("registry", 13, {"processGuid": "{seed}", "image": "powershell.exe", "targetObject": "HKCU\\Software\\AiSocLab"})
        related = _record("registry-create", 12, {"processGuid": "{seed}", "image": "powershell.exe", "targetObject": "HKCU\\Software\\AiSocLab"})
        case = CaseBuilder.from_seed_result("CASE-SAME-SEED", {"ok": True, "data": [seed]})
        case.add_alert_evidence(related)
        attach_deterministic_correlations(case)
        relation = next(item for item in case.correlations["sysmon_relationships"] if item["evidence_id"] != case.evidence[0].evidence_id)
        self.assertEqual(relation["status"], "same_seed_process")
        self.assertEqual(relation["process_creation_status"], "unavailable")
        self.assertEqual(relation["process_image"], "powershell.exe")

    def test_process_access_source_can_be_exact_seed_without_source_process_create(self):
        seed = _record("registry", 13, {"processGuid": "{seed}", "image": "powershell.exe", "targetObject": "HKCU\\Software\\AiSocLab"})
        target = _record("target", 1, {"processGuid": "{target}", "image": "csc.exe"})
        access = _record("access", 10, {"sourceProcessGUID": "{seed}", "sourceImage": "powershell.exe", "targetProcessGUID": "{target}", "targetImage": "csc.exe", "grantedAccess": "0x1fffff"})
        case = CaseBuilder.from_seed_result("CASE-SEED-ACCESS", {"ok": True, "data": [seed]})
        case.add_alert_evidence(target)
        case.add_alert_evidence(access)
        attach_deterministic_correlations(case)
        relation = next(item for item in case.correlations["sysmon_relationships"] if item["relationship"] == "process_access")
        self.assertEqual(relation["source_relationship"], "same_seed_process")
        self.assertEqual(relation["target_relationship"], "process_creation_observed")
        self.assertEqual(relation["source_process_image"], "powershell.exe")

    def test_process_seed_collects_exact_actor_child_and_access_event_families(self):
        seed = _record("process", 1, {"processGuid": "{child}", "parentProcessGuid": "{parent}", "image": "cmd.exe"})
        case = CaseBuilder.from_seed_result("CASE-PROCESS", {"ok": True, "data": [seed]})
        tools = _Tools([])
        SysmonProfileCollector(tools).collect(case)
        calls = {(call["relationship"], tuple(call["event_ids"])) for call in tools.calls}
        self.assertIn(("actor", ("1",)), calls)
        self.assertIn(("child", ("1",)), calls)
        self.assertIn(("actor", ("3", "7", "11", "12", "13", "14", "22")), calls)
        self.assertIn(("access", ("10",)), calls)

    def test_process_seed_collects_direct_child_activity_by_exact_guid(self):
        seed = _record("process", 1, {"processGuid": "{parent}", "image": "powershell.exe"})
        child = _record("child", 1, {"processGuid": "{curl}", "parentProcessGuid": "{parent}", "image": "curl.exe"})
        network = _record("network", 3, {"processGuid": "{curl}", "destinationIp": "93.184.216.34"})
        case = CaseBuilder.from_seed_result("CASE-CHILD-ACTIVITY", {"ok": True, "data": [seed]})
        tools = _Tools([child, network])
        SysmonProfileCollector(tools).collect(case)
        attach_deterministic_correlations(case)
        self.assertIn({"process_guid": "{curl}", "agent_id": "001", "start_time": "2026-08-18T12:00:00Z", "end_time": "2026-08-19T12:05:00Z", "event_ids": ["3", "7", "11", "12", "13", "14", "22"], "relationship": "actor", "limit": 5}, tools.calls)
        self.assertEqual(case.correlations["sysmon_relationships"][0]["process_guid"], "{curl}")

    def test_profile_collection_never_adds_more_than_eight_related_records(self):
        seed = _record("dns", 22, {"processGuid": "{actor}", "queryName": "example.com"})
        related = [_record(f"r{index}", 3, {"processGuid": "{actor}", "destinationIp": f"203.0.113.{index}"}) for index in range(1, 30)]
        case = CaseBuilder.from_seed_result("CASE-CAP", {"ok": True, "data": [seed]})
        SysmonProfileCollector(_Tools(related)).collect(case, limit=5)
        self.assertLessEqual(len(case.evidence) - 1, 8)

    def test_zero_sysmon_process_guid_fails_closed_for_process_linked_profile(self):
        seed = _record("network", 3, {
            "processGuid": "{00000000-0000-0000-0000-000000000000}",
            "image": "<unknown process>", "destinationIp": "1.1.1.1", "destinationPort": "443",
        })
        case = CaseBuilder.from_seed_result("CASE-ZERO-GUID", {"ok": True, "data": [seed]})
        tools = _Tools([])
        SysmonProfileCollector(tools).collect(case)
        self.assertEqual(tools.calls, [])
        self.assertEqual(case.correlations["telemetry_profiles"][0]["status"], "unavailable_missing_process_guid")

    def test_non_sysmon_seed_does_not_select_profile(self):
        seed = _record("security", 10, {"sourceProcessGuid": "{a}", "targetProcessGuid": "{b}"})
        seed["rule"] = {"groups": ["windows"]}
        seed["event"]["data"]["win"]["system"]["providerName"] = "Microsoft-Windows-Security-Auditing"
        case = CaseBuilder.from_seed_result("CASE-NON-SYSMON", {"ok": True, "data": [seed]})
        self.assertEqual(select_telemetry_profiles(case), [])

    def test_supported_sysmon_event_families_select_their_own_profile(self):
        expected = {
            "3": "windows_sysmon_network", "7": "windows_sysmon_image_load",
            "11": "windows_sysmon_file", "12": "windows_sysmon_registry",
            "13": "windows_sysmon_registry", "14": "windows_sysmon_registry",
            "22": "windows_sysmon_dns",
        }
        for event_id, profile in expected.items():
            with self.subTest(event_id=event_id):
                case = CaseBuilder.from_seed_result(f"CASE-{event_id}", {"ok": True, "data": [_record(event_id, event_id, {"processGuid": "{actor}"})]})
                self.assertEqual(select_telemetry_profiles(case), [profile])


if __name__ == "__main__":
    unittest.main()
