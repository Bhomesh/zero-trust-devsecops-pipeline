import json
import tempfile
import unittest
from pathlib import Path

from src.sbom_analyzer import SBOMAnalyzer


class TestSBOMAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = SBOMAnalyzer()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.sbom_file = Path(self.temp_dir.name) / "sbom.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_cyclonedx_compliant_licenses(self):
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "name": "requests",
                    "version": "2.31.0",
                    "licenses": [{"license": {"id": "Apache-2.0"}}],
                },
                {
                    "name": "flask",
                    "version": "3.0.0",
                    "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                },
            ],
        }
        with open(self.sbom_file, "w", encoding="utf-8") as f:
            json.dump(data, f)

        passed, violations, summary = self.analyzer.audit_licenses(self.sbom_file)
        self.assertTrue(passed)
        self.assertEqual(len(violations), 0)
        self.assertEqual(summary["total_components"], 2)

    def test_banned_gpl_license_blocked(self):
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "name": "viral-lib",
                    "version": "1.0.0",
                    "licenses": [{"license": {"id": "AGPL-3.0"}}],
                }
            ],
        }
        with open(self.sbom_file, "w", encoding="utf-8") as f:
            json.dump(data, f)

        passed, violations, summary = self.analyzer.audit_licenses(self.sbom_file)
        self.assertFalse(passed)
        self.assertEqual(len(violations), 1)
        self.assertIn("BANNED LICENSE VIOLATION", violations[0])
        self.assertIn("AGPL-3.0", violations[0])

    def test_spdx_format_parsing(self):
        data = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": "cryptography",
                    "versionInfo": "41.0.0",
                    "licenseDeclared": "Apache-2.0",
                    "licenseConcluded": "Apache-2.0",
                }
            ],
        }
        with open(self.sbom_file, "w", encoding="utf-8") as f:
            json.dump(data, f)

        passed, violations, summary = self.analyzer.audit_licenses(self.sbom_file)
        self.assertTrue(passed)
        self.assertEqual(summary["total_components"], 1)


    def test_allowlist_enforcement_blocks_unapproved_license(self):
        strict_analyzer = SBOMAnalyzer(enforce_allowlist=True)
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "name": "proprietary-sdk",
                    "version": "1.0.0",
                    "licenses": [{"license": {"id": "Commercial-Closed"}}],
                }
            ],
        }
        with open(self.sbom_file, "w", encoding="utf-8") as f:
            json.dump(data, f)

        passed, violations, summary = strict_analyzer.audit_licenses(self.sbom_file)
        self.assertFalse(passed)
        self.assertEqual(len(violations), 1)
        self.assertIn("UNAPPROVED LICENSE VIOLATION", violations[0])

    def test_restricted_licenses_generate_warnings(self):
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "name": "dual-licensed-module",
                    "version": "2.0.0",
                    "licenses": [{"license": {"id": "LGPL-3.0"}}],
                }
            ],
        }
        with open(self.sbom_file, "w", encoding="utf-8") as f:
            json.dump(data, f)

        passed, violations, summary = self.analyzer.audit_licenses(self.sbom_file)
        self.assertTrue(passed)
        self.assertEqual(summary["warnings_count"], 1)
        self.assertIn("RESTRICTED LICENSE", summary["warnings"][0])

    def test_from_policy_file_factory(self):
        policy_path = Path("policies/license_policy.yaml")
        if policy_path.exists():
            analyzer = SBOMAnalyzer.from_policy_file(policy_path, enforce_allowlist=True)
            self.assertIn("MIT", analyzer.allowed_licenses)
            self.assertIn("GPL-3.0", analyzer.banned_licenses)
            self.assertIn("LGPL-3.0", analyzer.restricted_licenses)


if __name__ == "__main__":
    unittest.main()
