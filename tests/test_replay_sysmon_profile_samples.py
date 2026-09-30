import unittest

from src.replay_sysmon_profile_samples import replay_samples


def _record(event_id, fields):
    return {"alert_id": f"archive-{event_id}", "timestamp": "2026-08-19T12:00:00Z", "host": "WS-01", "agent_id": "001", "rule": {"groups": ["sysmon"]}, "event": {"data": {"win": {
        "system": {"eventID": event_id, "providerName": "Microsoft-Windows-Sysmon"}, "eventdata": fields,
    }}}}


class Tools:
    def get_sysmon_profile_coverage(self, agent_id, start_time, end_time, event_ids, limit):
        event_id = event_ids[0]
        fields = {"processGuid": "{p}", "image": "cmd.exe"}
        if event_id == "10":
            fields = {"sourceProcessGUID": "{source}", "targetProcessGUID": "{target}", "sourceImage": "powershell.exe", "targetImage": "notepad.exe", "grantedAccess": "0x1000"}
        return {"ok": True, "data": [_record(event_id, fields)], "meta": {"source": "telemetry", "index": "wazuh-archives-*"}}

    def get_sysmon_profile_events(self, **kwargs):
        return {"ok": True, "data": [], "meta": {"source": "telemetry", "index": "wazuh-archives-*", "count": 0}}


class ReplaySysmonProfileSamplesTests(unittest.TestCase):
    def test_replays_every_contract_as_archive_not_alert(self):
        replays = replay_samples(Tools(), "001", "2026-08-19T00:00:00Z", "2026-08-20T00:00:00Z")
        self.assertEqual(len(replays), 9)
        self.assertTrue(all(item["status"] == "replayed" for item in replays))
        event_10 = next(item for item in replays if item["event_id"] == "10")
        self.assertEqual(event_10["source_kind"], "wazuh_archive_sample_not_alert")
        self.assertEqual(event_10["profile_observation"]["fields"]["source_image"], "powershell.exe")


if __name__ == "__main__":
    unittest.main()
