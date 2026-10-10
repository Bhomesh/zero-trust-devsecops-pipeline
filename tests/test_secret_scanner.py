import json
import tempfile
import unittest
from pathlib import Path

from src.secret_scanner import SecretScanner


class TestSecretScanner(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_file = Path(self.temp_dir.name) / "trufflehog.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_lines(self, entries):
        with open(self.output_file, "w", encoding="utf-8") as f:
            for item in entries:
                f.write(json.dumps(item) + "\n")

    def test_clean_scan_passes(self):
        self._write_lines([])
        scanner = SecretScanner()
        passed, violations, findings = scanner.evaluate_secrets(self.output_file)
        self.assertTrue(passed)
        self.assertEqual(len(violations), 0)

    def test_verified_secret_fails(self):
        self._write_lines([
            {
                "DetectorName": "GitHubToken",
                "Verified": True,
                "Raw": "ghp_1234567890abcdef1234567890abcdef",
                "SourceMetadata": {
                    "Data": {
                        "Git": {"file": "sample-app/config.py", "line": 14}
                    }
                },
            }
        ])
        scanner = SecretScanner()
        passed, violations, findings = scanner.evaluate_secrets(self.output_file)
        self.assertFalse(passed)
        self.assertEqual(len(violations), 1)
        self.assertIn("CRITICAL VERIFIED SECRET", violations[0])
        self.assertIn("sample-app/config.py:14", violations[0])
        # Masked output
        self.assertTrue("ghp_****************************cdef" in findings[0]["masked_secret"])

    def test_unverified_secret_filtering(self):
        self._write_lines([
            {
                "DetectorName": "GenericKey",
                "Verified": False,
                "Raw": "random-test-token-string",
                "SourceName": "test.txt",
            }
        ])
        # Default scanner does not block unverified
        scanner = SecretScanner(block_unverified=False)
        passed, violations, _ = scanner.evaluate_secrets(self.output_file)
        self.assertTrue(passed)

        # Strict scanner blocks unverified
        strict_scanner = SecretScanner(block_unverified=True)
        passed, violations, _ = strict_scanner.evaluate_secrets(self.output_file)
        self.assertFalse(passed)
        self.assertIn("HIGH UNVERIFIED SECRET", violations[0])


if __name__ == "__main__":
    unittest.main()
