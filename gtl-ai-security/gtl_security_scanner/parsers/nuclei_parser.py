"""
Nuclei JSON Output Parser

Parses nuclei JSON Lines output into structured format.
"""

import json
import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class NucleiParser:
    """Parse nuclei JSON Lines output"""

    def parse(self, json_output: str) -> Dict[str, Any]:
        """
        Parse nuclei JSON Lines output.

        Args:
            json_output: Raw JSON Lines output from nuclei

        Returns:
            Structured nuclei results

        Example:
            >>> parser = NucleiParser()
            >>> results = parser.parse(json_lines_string)
            >>> print(len(results['vulnerabilities']))
        """
        vulnerabilities = []

        try:
            # Nuclei outputs JSON Lines format (one JSON object per line)
            for line in json_output.strip().split("\n"):
                if not line.strip():
                    continue

                try:
                    finding = json.loads(line)
                    vuln = self._parse_finding(finding)
                    if vuln:
                        vulnerabilities.append(vuln)
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse nuclei line: {e}")
                    continue

        except Exception as e:
            logger.error(f"Failed to parse nuclei output: {e}")

        return {
            "vulnerabilities": vulnerabilities,
            "total_vulnerabilities": len(vulnerabilities),
        }

    def _parse_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Parse individual nuclei finding"""
        info = finding.get("info", {})

        vuln = {
            "template_id": finding.get("template-id"),
            "name": info.get("name", "Unknown Vulnerability"),
            "description": info.get("description", ""),
            "severity": info.get("severity", "info"),
            "tags": info.get("tags", []),
            "reference": info.get("reference", []),
            "classification": info.get("classification", {}),
            "matched_at": finding.get("matched-at"),
            "extracted_results": finding.get("extracted-results", []),
            "curl_command": finding.get("curl-command"),
        }

        # Extract CVE IDs if present
        classification = info.get("classification", {})
        cve_ids = classification.get("cve-id", [])
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        vuln["cve"] = cve_ids

        # Extract CVSS score
        cvss_score = classification.get("cvss-score")
        if cvss_score:
            vuln["cvss_score"] = float(cvss_score)

        # Extract CWE
        cwe_id = classification.get("cwe-id", [])
        if isinstance(cwe_id, str):
            cwe_id = [cwe_id]
        vuln["cwe"] = cwe_id

        return vuln
