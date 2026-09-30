import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.baseline_lock import create_baseline_lock, verify_baseline_lock, write_baseline_lock


class BaselineLockTests(unittest.TestCase):
    def test_detects_changed_frozen_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch("src.baseline_lock.BASELINE_FILES", ("one.txt", "two.txt")):
                (root / "one.txt").write_text("one", encoding="utf-8")
                (root / "two.txt").write_text("two", encoding="utf-8")
                lock = root / "lock.json"
                write_baseline_lock(lock, root)
                self.assertTrue(verify_baseline_lock(lock, root)["baseline_verified"])
                (root / "two.txt").write_text("changed", encoding="utf-8")
                result = verify_baseline_lock(lock, root)
        self.assertFalse(result["baseline_verified"])
        self.assertEqual(result["changed"], ["two.txt"])

    def test_create_fails_for_missing_baseline_file(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("src.baseline_lock.BASELINE_FILES", ("missing.txt",)):
                with self.assertRaises(ValueError):
                    create_baseline_lock(directory)
