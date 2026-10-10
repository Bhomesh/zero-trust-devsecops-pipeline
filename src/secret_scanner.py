"""
TruffleHog Secret Scanner & Verifier Parser
Parses TruffleHog stream JSON output, isolates verified active credentials,
and enforces zero-secret tolerance in code and git commit history.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("secret-scanner")


class SecretScanner:
    """Evaluates TruffleHog secret scan findings."""

    def __init__(self, block_unverified: bool = False):
        self.block_unverified = block_unverified

    def parse_trufflehog_json(self, output_path: Path) -> List[Dict[str, Any]]:
        """Parses line-delimited JSON output from TruffleHog."""
        if not output_path.exists():
            return []

        findings: List[Dict[str, Any]] = []
        with open(output_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    detector = data.get("DetectorName", "Unknown")
                    verified = bool(data.get("Verified", False))
                    raw = data.get("Raw", "")
                    masked = raw[:4] + ("*" * max(0, len(raw) - 8)) + raw[-4:] if len(raw) > 8 else "***"

                    source_meta = data.get("SourceMetadata", {}).get("Data", {})
                    git_meta = source_meta.get("Git", {})
                    file_path = git_meta.get("file", data.get("SourceName", "unknown"))
                    line_num = git_meta.get("line", 0)

                    findings.append({
                        "detector": detector,
                        "verified": verified,
                        "masked_secret": masked,
                        "file": file_path,
                        "line": line_num,
                    })
                except json.JSONDecodeError:
                    continue

        return findings

    def evaluate_secrets(self, output_path: Path) -> Tuple[bool, List[str], List[Dict[str, Any]]]:
        """Evaluates findings; returns (passed, violations, findings)."""
        findings = self.parse_trufflehog_json(output_path)
        violations: List[str] = []

        for f in findings:
            if f["verified"]:
                violations.append(
                    f"CRITICAL VERIFIED SECRET: {f['detector']} verified live credential in {f['file']}:{f['line']}"
                )
            elif self.block_unverified:
                violations.append(
                    f"HIGH UNVERIFIED SECRET: {f['detector']} candidate key in {f['file']}:{f['line']}"
                )

        passed = len(violations) == 0
        return passed, violations, findings
