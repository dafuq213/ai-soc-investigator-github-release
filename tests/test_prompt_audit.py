import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from src.prompt_audit import persist_prompt_audit


class PromptAuditTests(unittest.TestCase):
    def test_persists_exact_prompt_and_hash(self):
        prompt = "COMPACT DOSSIER\nNo raw log.\n"
        with tempfile.TemporaryDirectory() as directory:
            result = persist_prompt_audit(
                Path(directory), case_id="CASE/1", stage="assessment-attempt-01",
                prompt=prompt, provider="ollama", model="qwen2.5:7b-instruct",
                contract_version="judgment_v2",
            )
            record = json.loads(Path(result["path"]).read_text(encoding="utf-8"))
        self.assertEqual(record["prompt"], prompt)
        self.assertEqual(record["sha256"], hashlib.sha256(prompt.encode()).hexdigest())
        self.assertEqual(record["contract_version"], "judgment_v2")
        self.assertEqual(record["provider"], "ollama")

    def test_refuses_to_overwrite_an_existing_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            args = dict(case_id="CASE", stage="assessment", prompt="x", provider="ollama", model="m", contract_version="v")
            persist_prompt_audit(Path(directory), **args)
            with self.assertRaises(FileExistsError):
                persist_prompt_audit(Path(directory), **args)

