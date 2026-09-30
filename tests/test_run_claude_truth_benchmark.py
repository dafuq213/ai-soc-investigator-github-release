import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.run_claude_truth_benchmark import prepare_controlled_claude_run


class _Anthropic:
    provider_name = "anthropic"
    model = "test"


class ClaudeTruthBenchmarkTests(unittest.TestCase):
    def test_requires_anthropic_and_uses_precollected_packet(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "packet.json"
            artifact.write_text(json.dumps({"evidence_packet": {"evidence": [{"id": "E01"}]}}), encoding="utf-8")
            old = os.environ.get("LLM_PROVIDER")
            try:
                os.environ["LLM_PROVIDER"] = "anthropic"
                with patch("src.run_claude_truth_benchmark.provider_from_env", return_value=_Anthropic()):
                    packet, provider = prepare_controlled_claude_run(artifact)
            finally:
                if old is None:
                    os.environ.pop("LLM_PROVIDER", None)
                else:
                    os.environ["LLM_PROVIDER"] = old
        self.assertEqual(provider.provider_name, "anthropic")
        self.assertEqual(packet["evidence"][0]["id"], "E01")

    def test_refuses_non_anthropic_provider_before_any_request(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "packet.json"
            artifact.write_text(json.dumps({"evidence_packet": {}}), encoding="utf-8")
            with patch("src.run_claude_truth_benchmark.provider_from_env", return_value=type("Local", (), {"provider_name": "ollama"})()):
                with self.assertRaisesRegex(ValueError, "no model request"):
                    prepare_controlled_claude_run(artifact)


if __name__ == "__main__":
    unittest.main()
