import tempfile
import unittest
from pathlib import Path

from src.assessment import AssessmentPipeline
from src.case_models import CaseBuilder
from src.evidence_interpretation import interpretation_prompt, verify_interpretation
from src.verified_reporting import write_verified_report


def _case():
    return CaseBuilder.from_seed_result("CASE-INTERPRET", {"ok": True, "data": [{
        "alert_id": "a1", "host": "WS-01", "rule": {},
        "event": {"data": {"win": {"eventdata": {
            "image": "cmd.exe", "processGuid": "{p}", "parentProcessGuid": "{parent}",
            "commandLine": "cmd.exe /c whoami /all",
        }}}},
    }]})


class EvidenceInterpretationTests(unittest.TestCase):
    def test_accepts_a_known_explanation_citing_an_observed_fact(self):
        case = _case()
        prompt = interpretation_prompt(case)
        result = verify_interpretation(case, {
            "interpretation_ids": ["I01"],
        })
        self.assertIn("OPTIONS", prompt)
        self.assertEqual(result.status, "accepted")
        self.assertEqual(result.items[0]["evidence_id"], "E001")

    def test_rejects_unknown_id_or_extra_field(self):
        case = _case()
        unknown = verify_interpretation(case, {"interpretation_ids": ["I99"]})
        extra = verify_interpretation(case, {"interpretation_ids": ["I01"], "host": "invented"})
        self.assertEqual(unknown.status, "rejected")
        self.assertEqual(extra.status, "rejected")

    def test_report_labels_interpretation_and_cites_source(self):
        case = _case()
        assessment = AssessmentPipeline.evidence_only()
        interpretation = verify_interpretation(case, {"interpretation_ids": ["I01"]})
        with tempfile.TemporaryDirectory() as directory:
            text = Path(write_verified_report(case, assessment, Path(directory) / "report.md", interpretation)).read_text(encoding="utf-8")
        self.assertIn("## Assessment", text)
        self.assertIn("not proof of intent", text)
        self.assertIn("Source: E001", text)


if __name__ == "__main__":
    unittest.main()
