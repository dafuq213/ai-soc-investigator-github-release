import os
import unittest
from unittest.mock import patch

from src.wazuh_tools import _load_local_config


class LocalConfigTests(unittest.TestCase):
    def test_loader_accepts_qa_stage_variables(self):
        contents = "QA_PROVIDER=anthropic\nQA_MODEL=claude-haiku-test\n"
        fake_path = type("FakePath", (), {
            "exists": lambda self: True,
            "read_text": lambda self, encoding: contents,
            "__truediv__": lambda self, _: self,
        })()
        with patch("src.wazuh_tools.Path") as path, patch.dict(os.environ, {}, clear=True):
            path.return_value.resolve.return_value.parent.parent = fake_path
            _load_local_config()
            self.assertEqual(os.environ["QA_PROVIDER"], "anthropic")
            self.assertEqual(os.environ["QA_MODEL"], "claude-haiku-test")


if __name__ == "__main__":
    unittest.main()
