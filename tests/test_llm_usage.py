import os
import tempfile
import unittest
from pathlib import Path

from src.llm_usage import BudgetExceeded, ModelPricing, UsageLedger, conservative_request_estimate, ensure_request_within_cap, request_cap_from_env


class UsageLedgerTests(unittest.TestCase):
    def test_records_actual_tokens_and_enforces_total_ceiling(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = UsageLedger(Path(directory) / "usage.jsonl", 0.01)
            record = ledger.append("CASE-1", "assessment", "anthropic", "claude-test", 2_000, 500, ModelPricing(2, 10))
            self.assertEqual(record.estimated_usd, 0.009)
            self.assertAlmostEqual(ledger.total_usd(), 0.009)
            ledger.ensure_can_start()
            ledger.append("CASE-2", "qa", "anthropic", "claude-test", 1_000, 100, ModelPricing(1, 5))
            with self.assertRaises(BudgetExceeded):
                ledger.ensure_can_start()

    def test_requires_complete_stage_pricing(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = UsageLedger(Path(directory) / "usage.jsonl", 1.0)
            with self.assertRaises(ValueError):
                ledger.append("CASE-1", "unknown", "anthropic", "claude", 1, 1, ModelPricing(1, 1))

    def test_preflight_reserves_conservative_cost_before_a_call(self):
        pricing = ModelPricing(2, 10)
        estimate = conservative_request_estimate("x" * 3_000, 350, pricing)
        self.assertGreater(estimate, pricing.estimate(1_000, 350))
        with tempfile.TemporaryDirectory() as directory:
            ledger = UsageLedger(Path(directory) / "usage.jsonl", estimate - 0.000001)
            with self.assertRaises(BudgetExceeded):
                ledger.ensure_can_start(estimate)

    def test_per_request_cap_blocks_an_unusually_large_estimate(self):
        with self.assertRaises(BudgetExceeded):
            ensure_request_within_cap(0.11, 0.10, "assessment")
        previous = os.environ.get("QA_MAX_REQUEST_USD")
        os.environ["QA_MAX_REQUEST_USD"] = "0.03"
        try:
            self.assertEqual(request_cap_from_env("QA", 0.10), 0.03)
        finally:
            if previous is None:
                os.environ.pop("QA_MAX_REQUEST_USD", None)
            else:
                os.environ["QA_MAX_REQUEST_USD"] = previous


if __name__ == "__main__":
    unittest.main()
