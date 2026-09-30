import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from src import investigate_case


class CaseEntrypointCliTests(unittest.TestCase):
    def test_missing_alert_returns_structured_result(self):
        class MissingTools:
            def get_alert_by_id(self, _):
                return {"ok": True, "data": []}
        with patch.object(investigate_case, "WazuhToolLayer", return_value=MissingTools()), \
             patch.object(investigate_case.WazuhConfig, "from_env", return_value=object()), \
             patch("sys.argv", ["investigate_case", "--alert-id", "missing"]):
            output = io.StringIO()
            with redirect_stdout(output):
                result = investigate_case.main()
        self.assertEqual(result, 2)
        self.assertIn("alert was not found", output.getvalue())
