import unittest

from src.assessment import VerifiedAssessment
from src.confidence import calculate_confidence
from src.evaluation import EvaluationExpectation, score
from src.reasoning_contract import AtomicClaim
from src.response_advisor import advise


def accepted(claims, verdict="suspicious_requires_review"):
    return VerifiedAssessment("accepted", verdict, 0.9, claims, [], [], ["Change context unavailable"], [], None)


class ConfidenceResponseEvaluationTests(unittest.TestCase):
    def test_confidence_and_isolation_guidance_require_verified_network_evidence(self):
        assessment = accepted([AtomicClaim("process_parent", ["E001"], "p", "q"), AtomicClaim("encoded_powershell", ["E001"]), AtomicClaim("network_connection", ["E002"], "p", "203.0.113.20")])
        confidence = calculate_confidence(assessment)
        self.assertGreaterEqual(confidence.score, 0.7)
        self.assertIn("isolate_host", [item.action for item in advise(assessment, confidence)])

    def test_metrics_expose_prohibited_claims(self):
        assessment = accepted([AtomicClaim("encoded_powershell", ["E001"])], "inconclusive")
        metrics = score([EvaluationExpectation("C1", "inconclusive", {"encoded_powershell"})], {"C1": assessment})
        self.assertEqual(metrics["verdict_accuracy"], 1.0)
        self.assertEqual(metrics["unsupported_claim_rate"], 1.0)


if __name__ == "__main__":
    unittest.main()
