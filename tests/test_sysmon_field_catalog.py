import unittest

from src.sysmon_field_catalog import build_catalog


class Tools:
    def get_sysmon_profile_coverage(self, agent_id, start_time, end_time, event_ids, limit):
        event_id = event_ids[0]
        fields = {"processGuid": "{p}", "image": "C:\\Windows\\System32\\cmd.exe"}
        if event_id == "10":
            fields = {"sourceProcessGUID": "{source}", "targetProcessGUID": "{target}", "grantedAccess": "0x1000", "callTrace": "raw"}
        return {"ok": True, "data": [{"event": {"data": {"win": {"eventdata": fields}}}}]}


class SysmonFieldCatalogTests(unittest.TestCase):
    def test_catalog_classifies_observed_fields_without_hiding_raw_only_fields(self):
        catalog = build_catalog(Tools(), "001", "2026-08-19T00:00:00Z", "2026-08-20T00:00:00Z")
        access = next(item for item in catalog["profiles"] if item["event_id"] == "10")
        roles = {item["field"]: item["role"] for item in access["fields"]}
        self.assertEqual(roles["data.win.eventdata.sourceProcessGUID"], "correlation_key")
        self.assertEqual(roles["data.win.eventdata.grantedAccess"], "dossier_candidate")
        self.assertEqual(roles["data.win.eventdata.callTrace"], "raw_only")


if __name__ == "__main__":
    unittest.main()
