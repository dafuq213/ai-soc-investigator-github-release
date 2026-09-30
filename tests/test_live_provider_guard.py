import tempfile
import unittest
from pathlib import Path

from src.case_models import CaseBuilder
from src.investigate_wazuh import _tracked_call
from src.llm_usage import BudgetExceeded, ModelPricing, UsageLedger


class _UnmeteredRemote:
    provider_name = "gemini"
    model = "test"
    pricing = None
    max_output_tokens = 100
    last_usage = None


class _BillableFailure:
    provider_name = "anthropic"
    model = "test"
    pricing = ModelPricing(2, 10)
    max_output_tokens = 100
    last_usage = None


class LiveProviderGuardTests(unittest.TestCase):
    def test_rejects_a_remote_provider_before_call_without_a_usage_ledger(self):
        called = False

        def call(*_):
            nonlocal called
            called = True
            return "{}"

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(BudgetExceeded):
                _tracked_call(_UnmeteredRemote(), "CASE", "assessment", UsageLedger(Path(directory) / "usage.jsonl", 1.0), [], [], call, object())
        self.assertFalse(called)

    def test_records_returned_usage_when_billable_provider_raises(self):
        provider = _BillableFailure()
        records = []

        def call(*_):
            provider.last_usage = {"input_tokens": 10, "output_tokens": 20}
            raise RuntimeError("response parse failed")

        with tempfile.TemporaryDirectory() as directory:
            ledger = UsageLedger(Path(directory) / "usage.jsonl", 1.0)
            case = CaseBuilder.from_seed_result("CASE", {"ok": True, "data": [{"alert_id": "a-1", "event": {}, "rule": {}}]})
            with self.assertRaisesRegex(RuntimeError, "response parse failed"):
                _tracked_call(provider, "CASE", "assessment", ledger, records, [], call, case, audit_dir=Path(directory) / "audits")
            self.assertEqual(len(records), 1)
            self.assertAlmostEqual(ledger.total_usd(), 0.00022)


if __name__ == "__main__":
    unittest.main()
