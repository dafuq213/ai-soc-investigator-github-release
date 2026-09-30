import tempfile
import unittest
from pathlib import Path

from src.assessment import AssessmentPipeline
from src.assessment_prompt import assessment_prompt
from src.case_models import CaseBuilder
from src.report_quality import assess_l3_readiness
from src.verified_reporting import write_verified_report


def build_case():
    return CaseBuilder.from_seed_result("JUDGMENT-CASE", {"ok": True, "data": [{
        "alert_id": "alert-1", "host": "WS-01",
        "rule": {"id": "10001", "level": 8, "description": "Example Wazuh detection"},
        "event": {"data": {"win": {"system": {"eventID": "1"}, "eventdata": {
            "image": "C:\\Windows\\System32\\reg.exe",
            "parentImage": "C:\\Windows\\System32\\svchost.exe",
            "user": "NT AUTHORITY\\SYSTEM",
            "commandLine": "reg.exe add HKLM\\Software\\Vendor /v Enabled /t REG_DWORD /d 1",
        }}}},
    }]})


def valid_payload():
    return {
        "verdict": "likely_benign", "confidence": 60, "claim_verification_id": "V01",
        "what_happened": [{"refs": ["D02"], "text": "The cited command records reg.exe adding a registry value under the Vendor key."}],
        "alert_claim_assessment": [{"refs": ["R01"], "text": "The Wazuh title is a detection trigger; the cited process record provides the available evidence for review."}],
        "reassuring_factors": [{"refs": ["R01"], "text": "The cited process record shows reg.exe launched by svchost.exe as SYSTEM, which is a possible maintenance context."}],
        "concern_factors": [],
        "competing_hypotheses": [{"refs": ["D02"], "text": "The same registry modification could require further review because the alert match itself is not independently visible."}],
        "evidence_gap_ids": ["U08"], "next_check_id": "N01", "action_ids": ["A01"],
    }


class JudgmentContractTests(unittest.TestCase):
    def test_prompt_advertises_required_generic_narrative_sections(self):
        prompt = assessment_prompt(build_case())
        self.assertIn("judgment_v2", prompt)
        self.assertIn('"what_happened"', prompt)
        self.assertIn('"reassuring_factors"', prompt)
        self.assertNotIn("full_log", prompt)

    def test_accepts_cited_likely_benign_judgment_with_capped_confidence(self):
        assessment = AssessmentPipeline().evaluate(build_case(), valid_payload())
        self.assertEqual(assessment.status, "accepted")
        self.assertEqual(assessment.verdict, "likely_benign")
        self.assertEqual(assessment.confidence, 0.6)
        self.assertEqual(assessment.investigation_guidance["contract_version"], "judgment_v2")
        quality = assess_l3_readiness(build_case(), assessment)
        self.assertTrue(quality.checks["reasoning_cites_activity"])
        self.assertTrue(quality.checks["proportionate_next_step"])

    def test_rejects_confidence_above_unverified_claim_cap(self):
        payload = valid_payload()
        payload["confidence"] = 80
        assessment = AssessmentPipeline().evaluate(build_case(), payload)
        self.assertEqual(assessment.status, "rejected")
        self.assertIn("evidence cap", assessment.error)

    def test_rejects_likely_malicious_without_independent_concern_references(self):
        payload = valid_payload()
        payload["verdict"] = "likely_malicious"
        payload["confidence"] = 65
        payload["reassuring_factors"] = []
        payload["concern_factors"] = [{"refs": ["D02"], "text": "The cited command changed a registry value that warrants investigation."}]
        assessment = AssessmentPipeline().evaluate(build_case(), payload)
        self.assertEqual(assessment.status, "rejected")
        self.assertIn("two independent", assessment.error)

    def test_rejects_evidence_gap_identifier_as_a_narrative_reference(self):
        payload = valid_payload()
        payload["concern_factors"] = [{
            "refs": ["U08"],
            "text": "The cited evidence gap means authorization cannot be determined from the collected telemetry.",
        }]
        assessment = AssessmentPipeline().evaluate(build_case(), payload)
        self.assertEqual(assessment.status, "rejected")
        self.assertIn("unknown evidence", assessment.error)

    def test_rejects_a_copied_prompt_example(self):
        payload = valid_payload()
        payload["what_happened"] = [{
            "refs": ["D02"],
            "text": "The cited observation records activity; it does not establish intent or outcome.",
        }]
        assessment = AssessmentPipeline().evaluate(build_case(), payload)
        self.assertEqual(assessment.status, "rejected")
        self.assertIn("copies the prompt example", assessment.error)

    def test_report_renders_all_judgment_sections_with_references(self):
        case = build_case()
        assessment = AssessmentPipeline().evaluate(case, valid_payload())
        with tempfile.TemporaryDirectory() as directory:
            report = Path(write_verified_report(case, assessment, Path(directory) / "report.md")).read_text(encoding="utf-8")
        for heading in ("## What happened", "## Wazuh claim versus confirmed evidence", "## Why it may be legitimate", "## Why it may be suspicious"):
            self.assertIn(heading, report)
        self.assertIn("The cited command records reg.exe adding a registry value", report)
        self.assertIn("Evidence: D02", report)
        self.assertIn("Model confidence: 60%", report)


if __name__ == "__main__":
    unittest.main()
