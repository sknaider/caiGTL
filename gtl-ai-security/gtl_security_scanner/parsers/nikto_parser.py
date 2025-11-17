"""
Nikto CSV Output Parser

Parses nikto CSV output to extract web server vulnerabilities.
"""

import csv
import io
import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class NiktoParser:
    """Parse nikto CSV output"""

    def parse(self, csv_output: str) -> Dict[str, Any]:
        """
        Parse nikto CSV output.

        Args:
            csv_output: Raw CSV output from nikto

        Returns:
            Structured nikto results

        Example:
            >>> parser = NiktoParser()
            >>> results = parser.parse(csv_string)
            >>> print(results['findings'])
        """
        result = {
            "findings": [],
            "total_findings": 0,
            "hosts_scanned": [],
        }

        try:
            # Parse CSV
            csv_reader = csv.DictReader(io.StringIO(csv_output))

            for row in csv_reader:
                finding = self._parse_finding(row)
                if finding:
                    result["findings"].append(finding)

                    # Track unique hosts
                    host = row.get("host", "")
                    if host and host not in result["hosts_scanned"]:
                        result["hosts_scanned"].append(host)

            result["total_findings"] = len(result["findings"])

        except Exception as e:
            logger.error(f"Failed to parse nikto CSV output: {e}")

        return result

    def _parse_finding(self, row: Dict[str, str]) -> Dict[str, Any]:
        """
        Parse individual nikto finding from CSV row.

        Nikto CSV format:
        "host","ip","port","osvdb","method","uri","description"
        """
        description = row.get("description", "").strip()
        if not description:
            return None

        finding = {
            "host": row.get("host", "").strip(),
            "ip": row.get("ip", "").strip(),
            "port": row.get("port", "").strip(),
            "osvdb": row.get("osvdb", "").strip(),
            "method": row.get("method", "GET").strip(),
            "uri": row.get("uri", "/").strip(),
            "description": description,
        }

        # Determine severity from description
        finding["severity"] = self._determine_severity(description)

        # Build full URL
        protocol = "https" if finding["port"] == "443" else "http"
        finding["url"] = f"{protocol}://{finding['host']}:{finding['port']}{finding['uri']}"

        # Categorize finding
        finding["category"] = self._categorize_finding(description)

        return finding

    def _determine_severity(self, description: str) -> str:
        """
        Determine severity based on description keywords.

        Args:
            description: Nikto finding description

        Returns:
            Severity level (critical, high, medium, low, info)
        """
        desc_lower = description.lower()

        # Critical indicators
        critical_keywords = [
            "remote code execution",
            "shell",
            "arbitrary file",
            "sql injection",
            "authentication bypass",
        ]
        if any(keyword in desc_lower for keyword in critical_keywords):
            return "critical"

        # High indicators
        high_keywords = [
            "vulnerable",
            "exploit",
            "backdoor",
            "password",
            "credentials",
            "xss",
            "csrf",
        ]
        if any(keyword in desc_lower for keyword in high_keywords):
            return "high"

        # Medium indicators
        medium_keywords = [
            "outdated",
            "insecure",
            "misconfigur",
            "information disclosure",
            "directory listing",
        ]
        if any(keyword in desc_lower for keyword in medium_keywords):
            return "medium"

        # Low indicators
        low_keywords = ["header", "cookie", "banner"]
        if any(keyword in desc_lower for keyword in low_keywords):
            return "low"

        return "info"

    def _categorize_finding(self, description: str) -> str:
        """
        Categorize finding based on description.

        Args:
            description: Finding description

        Returns:
            Category name
        """
        desc_lower = description.lower()

        if "outdated" in desc_lower or "old version" in desc_lower:
            return "outdated_software"

        if "directory listing" in desc_lower or "index of" in desc_lower:
            return "information_disclosure"

        if "header" in desc_lower:
            return "security_headers"

        if "ssl" in desc_lower or "tls" in desc_lower:
            return "ssl_tls"

        if "cookie" in desc_lower:
            return "cookie_security"

        if "default" in desc_lower:
            return "default_files"

        if "config" in desc_lower:
            return "misconfiguration"

        if any(
            word in desc_lower
            for word in ["xss", "injection", "exploit", "vulnerability"]
        ):
            return "vulnerability"

        return "general"
