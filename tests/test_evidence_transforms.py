import unittest

from src.case_models import CaseBuilder
from src.evidence_transforms import decode_powershell_commands


class EvidenceTransformTests(unittest.TestCase):
    def test_decodes_observed_command_into_traceable_derived_evidence(self):
        case = CaseBuilder.from_seed_result("CASE-DECODE", {"ok": True, "data": [{
            "alert_id": "a1", "rule": {}, "event": {"data": {"win": {"eventdata": {
                "image": "powershell.exe", "commandLine": "powershell.exe -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAHQAZQBzAHQAJwA="
            }}}}
        }]})
        decode_powershell_commands(case)
        self.assertEqual(case.evidence[1].source, "deterministic_transform")
        self.assertEqual(case.evidence[1].record["source_evidence_id"], "E001")
        self.assertEqual(case.evidence[1].record["decoded_command"], "Write-Output 'test'")
        self.assertEqual(case.evidence[1].record["observed_behavior"], ["Writes a text string to standard output."])

    def test_describes_only_observed_process_and_identity_query_tokens(self):
        case = CaseBuilder.from_seed_result("CASE-BEHAVIOR", {"ok": True, "data": [{
            "alert_id": "a2", "rule": {}, "event": {"data": {"win": {"eventdata": {
                "image": "powershell.exe", "commandLine": "powershell.exe -EncodedCommand UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAGMAbQBkAC4AZQB4AGUAIAAtAEEAcgBnAHUAbQBlAG4AdABMAGkAcwB0ACAAJwAvAGMAIAB3AGgAbwBhAG0AaQAnAA=="
            }}}}
        }]})
        decode_powershell_commands(case)
        self.assertEqual(case.evidence[1].record["observed_behavior"], [
            "Starts cmd.exe as a child process.",
            "Runs whoami, which prints the current Windows identity.",
        ])
