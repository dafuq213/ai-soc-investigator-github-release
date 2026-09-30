import os
import tempfile
import unittest
from pathlib import Path

from src.env_config import load_env_file


class EnvConfigTests(unittest.TestCase):
    def test_loads_simple_values_without_overriding_shell_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("# comment\nTEST_SOC_ENV=value\nTEST_SOC_QUOTED='two words'\n", encoding="utf-8")
            old = os.environ.get("TEST_SOC_ENV")
            try:
                os.environ["TEST_SOC_ENV"] = "shell"
                loaded = load_env_file(path)
                self.assertNotIn("TEST_SOC_ENV", loaded)
                self.assertEqual(os.environ["TEST_SOC_ENV"], "shell")
                self.assertEqual(os.environ["TEST_SOC_QUOTED"], "two words")
                loaded = load_env_file(path, override=True)
                self.assertIn("TEST_SOC_ENV", loaded)
                self.assertEqual(os.environ["TEST_SOC_ENV"], "value")
            finally:
                if old is None:
                    os.environ.pop("TEST_SOC_ENV", None)
                else:
                    os.environ["TEST_SOC_ENV"] = old
                os.environ.pop("TEST_SOC_QUOTED", None)


if __name__ == "__main__":
    unittest.main()
