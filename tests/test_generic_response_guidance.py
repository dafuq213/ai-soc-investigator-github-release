import unittest

from src.generic_response_guidance import build_response_proposals


class GenericResponseGuidanceTests(unittest.TestCase):
    def test_general_actions_are_explained_and_approval_only(self):
        packet = {"observed_entities": {"host": "WS-01"}}
        assessment = {"verdict": "suspicious_requires_review", "confidence": 60, "recommended_actions": [{"category": "investigate", "action": "Review subsequent child process activity.", "reason": "The cited process requires additional scoping.", "evidence_ids": ["E01"], "target": "WS-01", "priority": "high"}]}
        proposals = build_response_proposals(packet, assessment)
        self.assertEqual(proposals[0]["action"], "Review subsequent child process activity.")
        self.assertFalse(proposals[0]["requires_human_approval"])
        self.assertFalse(proposals[0]["executed"])

    def test_containment_requires_strong_verdict_and_observed_host(self):
        packet = {"observed_entities": {"host": "WS-01"}}
        strong = {"verdict": "likely_malicious", "confidence": 70, "recommended_actions": [{"category": "consider_response", "action": "Consider isolating WS-01 after human approval.", "reason": "The cited activity supports containment consideration.", "evidence_ids": ["E01"], "target": "WS-01", "priority": "high"}]}
        proposal = build_response_proposals(packet, strong)[0]
        self.assertEqual(proposal["action"], "Consider isolating WS-01 after human approval.")
        self.assertEqual(proposal["target"], "WS-01")
        self.assertTrue(proposal["requires_human_approval"])
