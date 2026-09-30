import json
import tempfile
import unittest
from pathlib import Path

from src.process_poc_evaluation import run_process_poc


class ProcessPocEvaluationTests(unittest.TestCase):
    def test_rejects_manifest_with_wrong_case_count(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaises(ValueError):
                run_process_poc(path)

    def test_rejects_unknown_check_before_replaying_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "manifest.json"
            path.write_text(json.dumps([{"fixture": "x.json", "checks": ["not_real"]}] * 3), encoding="utf-8")
            with self.assertRaises(ValueError):
                run_process_poc(path)


if __name__ == "__main__":
    unittest.main()
