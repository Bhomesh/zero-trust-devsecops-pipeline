"""
SBOM Analyzer & License Compliance Verifier
Validates CycloneDX & SPDX Software Bill of Materials (SBOM),
audits dependency licensing against corporate open-source policies.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import yaml

logger = logging.getLogger("sbom-analyzer")


class SBOMAnalyzer:
    """Analyzes SBOM structures and checks for non-compliant licenses."""

    DEFAULT_ALLOWED_LICENSES = {
        "MIT",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "Python-2.0",
        "PSF-2.0",
    }
    DEFAULT_BANNED_LICENSES = {
        "GPL-2.0",
        "GPL-3.0",
        "AGPL-3.0",
        "SSPL-1.0",
        "Commons-Clause",
    }

    def __init__(
        self,
        allowed_licenses: Optional[Set[str]] = None,
        banned_licenses: Optional[Set[str]] = None,
    ):
        self.allowed_licenses = allowed_licenses or self.DEFAULT_ALLOWED_LICENSES
        self.banned_licenses = banned_licenses or self.DEFAULT_BANNED_LICENSES

    def parse_sbom(self, sbom_path: Path) -> List[Dict[str, Any]]:
        """Parses CycloneDX or SPDX JSON format SBOM."""
        if not sbom_path.exists():
            raise FileNotFoundError(f"SBOM not found: {sbom_path}")

        with open(sbom_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        components = []
        # Check CycloneDX format
        if "bomFormat" in data and data.get("bomFormat") == "CycloneDX":
            for c in data.get("components", []):
                name = c.get("name", "unknown")
                version = c.get("version", "")
                licenses = []
                for lic_entry in c.get("licenses", []):
                    lic_obj = lic_entry.get("license", {})
                    lic_id = lic_obj.get("id") or lic_obj.get("name")
                    if lic_id:
                        licenses.append(lic_id)
                components.append({
                    "name": name,
                    "version": version,
                    "licenses": licenses,
                    "purl": c.get("purl", ""),
                })
        # Check SPDX format
        elif "spdxVersion" in data:
            for p in data.get("packages", []):
                name = p.get("name", "unknown")
                version = p.get("versionInfo", "")
                concluded = p.get("licenseConcluded")
                declared = p.get("licenseDeclared")
                licenses = [lic for lic in [concluded, declared] if lic and lic != "NOASSERTION"]
                components.append({
                    "name": name,
                    "version": version,
                    "licenses": licenses,
                    "purl": "",
                })
        else:
            raise ValueError(f"Unrecognized SBOM schema format in {sbom_path}")

        return components

    def audit_licenses(self, sbom_path: Path) -> Tuple[bool, List[str], Dict[str, Any]]:
        """Audits all packages in SBOM against licensing rules."""
        components = self.parse_sbom(sbom_path)
        violations: List[str] = []
        license_counts: Dict[str, int] = {}

        for c in components:
            for lic in c["licenses"]:
                license_counts[lic] = license_counts.get(lic, 0) + 1
                if lic in self.banned_licenses:
                    violations.append(
                        f"BANNED LICENSE VIOLATION: Package '{c['name']}@{c['version']}' uses prohibited license '{lic}'"
                    )

        passed = len(violations) == 0
        summary = {
            "total_components": len(components),
            "licenses_observed": license_counts,
            "violations_count": len(violations),
        }
        return passed, violations, summary
