"""
Trivy Vulnerability Gatekeeper & Security Policy Evaluator
Parses Trivy JSON and SARIF reports, enforces CVSS thresholds, CISA KEV checks,
and evaluates time-bound security waivers.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import yaml

logger = logging.getLogger("cve-gatekeeper")


class CVEGatekeeper:
    """Evaluates container and dependency vulnerability scan outputs against enterprise policies."""

    def __init__(
        self,
        max_critical: int = 0,
        max_high: int = 2,
        block_cisa_kev: bool = True,
        cisa_kev_cves: Optional[Set[str]] = None,
    ):
        self.max_critical = max_critical
        self.max_high = max_high
        self.block_cisa_kev = block_cisa_kev
        # Sample CISA Known Exploited Vulnerabilities catalog
        self.cisa_kev_cves = cisa_kev_cves or {
            "CVE-2021-44228",  # Log4Shell
            "CVE-2022-22965",  # Spring4Shell
            "CVE-2023-44487",  # HTTP/2 Rapid Reset
            "CVE-2023-38606",  # WebKit
            "CVE-2024-3094",   # XZ Utils Backdoor
        }

    def load_waivers(self, waiver_file: Path) -> Dict[str, Dict[str, Any]]:
        """Loads and filters valid time-bound CVE waivers."""
        if not waiver_file.exists():
            return {}

        try:
            with open(waiver_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        except Exception as e:
            logger.error("Failed to parse waiver file %s: %s", waiver_file, e)
            return {}

        now = datetime.now(timezone.utc)
        active_waivers: Dict[str, Dict[str, Any]] = {}

        for w in data.get("waivers", []):
            cve_id = w.get("cve_id")
            expires_at_str = w.get("expires_at")
            if not cve_id or not expires_at_str:
                continue

            try:
                expires_at = datetime.fromisoformat(expires_at_str)
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
                if now < expires_at:
                    active_waivers[cve_id] = w
                else:
                    logger.warning("Waiver for %s expired at %s", cve_id, expires_at_str)
            except Exception as e:
                logger.error("Invalid expiration format for %s: %s", cve_id, e)

        return active_waivers

    def parse_trivy_report(self, report_path: Path) -> List[Dict[str, Any]]:
        """Parses Trivy JSON format report and flattens vulnerabilities."""
        if not report_path.exists():
            raise FileNotFoundError(f"Report file not found: {report_path}")

        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        vulnerabilities = []
        results = data.get("Results", [])
        for r in results:
            target = r.get("Target", "unknown")
            for v in r.get("Vulnerabilities", []):
                vulnerabilities.append({
                    "id": v.get("VulnerabilityID", "UNKNOWN"),
                    "pkg_name": v.get("PkgName", "unknown"),
                    "installed_version": v.get("InstalledVersion", ""),
                    "fixed_version": v.get("FixedVersion", ""),
                    "severity": v.get("Severity", "UNKNOWN").upper(),
                    "title": v.get("Title", ""),
                    "target": target,
                })
        return vulnerabilities

    def evaluate(
        self,
        report_path: Path,
        waiver_file: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Evaluates scan report against policy rules and waivers."""
        vulnerabilities = self.parse_trivy_report(report_path)
        active_waivers = self.load_waivers(waiver_file) if waiver_file else {}

        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0

        violations: List[str] = []
        waived: List[Dict[str, Any]] = []

        for v in vulnerabilities:
            cve_id = v["id"]
            severity = v["severity"]

            if cve_id in active_waivers:
                waived.append({
                    "cve": cve_id,
                    "reason": active_waivers[cve_id].get("reason", "Approved exception"),
                    "approved_by": active_waivers[cve_id].get("approved_by", "security-team"),
                })
                continue

            # Check CISA KEV
            if self.block_cisa_kev and cve_id in self.cisa_kev_cves:
                violations.append(
                    f"CISA KEV Violation: {cve_id} in {v['pkg_name']} is actively exploited in the wild!"
                )

            if severity == "CRITICAL":
                critical_count += 1
            elif severity == "HIGH":
                high_count += 1
            elif severity == "MEDIUM":
                medium_count += 1
            elif severity == "LOW":
                low_count += 1

        if critical_count > self.max_critical:
            violations.append(
                f"Critical Threshold Violation: Found {critical_count} Critical CVEs (Max allowed: {self.max_critical})"
            )

        if high_count > self.max_high:
            violations.append(
                f"High Threshold Violation: Found {high_count} High CVEs (Max allowed: {self.max_high})"
            )

        passed = len(violations) == 0

        return {
            "passed": passed,
            "violations": violations,
            "counts": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
                "waived": len(waived),
            },
            "waived_details": waived,
        }
