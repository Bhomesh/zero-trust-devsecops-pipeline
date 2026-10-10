import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
import yaml

from src.cve_gatekeeper import CVEGatekeeper


class TestCVEGatekeeper(unittest.TestCase):
    def setUp(self):
        self.gatekeeper = CVEGatekeeper(max_critical=0, max_high=1)
        self.temp_dir = tempfile.TemporaryDirectory()
        self.report_file = Path(self.temp_dir.name) / "trivy.json"
        self.waiver_file = Path(self.temp_dir.name) / "waivers.yaml"

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_report(self, vulnerabilities):
        data = {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Target": "sample-app:latest (debian 12.5)",
                    "Vulnerabilities": vulnerabilities,
                }
            ],
        }
        with open(self.report_file, "w", encoding="utf-8") as f:
            json.dump(data, f)

    def test_clean_report_passes(self):
        self._write_report([
            {"VulnerabilityID": "CVE-2023-0001", "Severity": "LOW", "PkgName": "bash"},
            {"VulnerabilityID": "CVE-2023-0002", "Severity": "MEDIUM", "PkgName": "curl"},
        ])
        result = self.gatekeeper.evaluate(self.report_file)
        self.assertTrue(result["passed"])
        self.assertEqual(result["violations"], [])
        self.assertEqual(result["counts"]["critical"], 0)

    def test_critical_cve_blocked(self):
        self._write_report([
            {"VulnerabilityID": "CVE-2023-9999", "Severity": "CRITICAL", "PkgName": "glibc"},
        ])
        result = self.gatekeeper.evaluate(self.report_file)
        self.assertFalse(result["passed"])
        self.assertTrue(any("Critical Threshold Violation" in v for v in result["violations"]))

    def test_cisa_kev_blocked(self):
        self._write_report([
            {"VulnerabilityID": "CVE-2021-44228", "Severity": "HIGH", "PkgName": "log4j-core"},
        ])
        result = self.gatekeeper.evaluate(self.report_file)
        self.assertFalse(result["passed"])
        self.assertTrue(any("CISA KEV Violation" in v for v in result["violations"]))

    def test_active_waiver_applied(self):
        self._write_report([
            {"VulnerabilityID": "CVE-2023-44487", "Severity": "HIGH", "PkgName": "golang.org/x/net"},
        ])
        # Write active waiver
        future_date = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        waivers = {
            "waivers": [
                {
                    "cve_id": "CVE-2023-44487",
                    "reason": "WAF mitigation active",
                    "expires_at": future_date,
                    "approved_by": "secops",
                }
            ]
        }
        with open(self.waiver_file, "w", encoding="utf-8") as f:
            yaml.dump(waivers, f)

        result = self.gatekeeper.evaluate(self.report_file, self.waiver_file)
        self.assertTrue(result["passed"])
        self.assertEqual(result["counts"]["waived"], 1)

    def test_expired_waiver_rejected(self):
        self._write_report([
            {"VulnerabilityID": "CVE-2023-44487", "Severity": "HIGH", "PkgName": "golang.org/x/net"},
        ])
        past_date = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        waivers = {
            "waivers": [
                {
                    "cve_id": "CVE-2023-44487",
                    "reason": "Expired mitigation",
                    "expires_at": past_date,
                    "approved_by": "secops",
                }
            ]
        }
        with open(self.waiver_file, "w", encoding="utf-8") as f:
            yaml.dump(waivers, f)

        result = self.gatekeeper.evaluate(self.report_file, self.waiver_file)
        # Should NOT be waived, and CISA KEV violation triggered
        self.assertFalse(result["passed"])
        self.assertEqual(result["counts"]["waived"], 0)


if __name__ == "__main__":
    unittest.main()
