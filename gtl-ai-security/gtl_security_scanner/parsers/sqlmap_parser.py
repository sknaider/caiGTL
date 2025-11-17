"""
SQLMap Text Output Parser

Parses sqlmap text output to extract SQL injection vulnerabilities.
"""

import logging
import re
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class SQLMapParser:
    """Parse sqlmap text output"""

    def parse(self, text_output: str) -> Dict[str, Any]:
        """
        Parse sqlmap text output.

        Args:
            text_output: Raw text output from sqlmap

        Returns:
            Structured sqlmap results

        Example:
            >>> parser = SQLMapParser()
            >>> results = parser.parse(sqlmap_output)
            >>> print(results['injections'])
        """
        result = {
            "injections_found": False,
            "injections": [],
            "database_info": {},
            "vulnerable_parameters": [],
        }

        try:
            # Check if SQL injection was found
            if "sqlmap identified the following injection" not in text_output.lower():
                logger.info("No SQL injection found in sqlmap output")
                return result

            result["injections_found"] = True

            # Extract injection techniques
            result["injections"] = self._extract_injections(text_output)

            # Extract database information
            result["database_info"] = self._extract_database_info(text_output)

            # Extract vulnerable parameters
            result["vulnerable_parameters"] = self._extract_parameters(text_output)

        except Exception as e:
            logger.error(f"Failed to parse sqlmap output: {e}")

        return result

    def _extract_injections(self, output: str) -> List[Dict[str, Any]]:
        """Extract SQL injection techniques found"""
        injections = []

        # Pattern matches for different injection types
        patterns = {
            "boolean-based blind": r"boolean-based blind",
            "time-based blind": r"time-based blind",
            "error-based": r"error-based",
            "UNION query": r"UNION query",
            "stacked queries": r"stacked queries",
        }

        for injection_type, pattern in patterns.items():
            matches = re.findall(pattern, output, re.IGNORECASE)
            if matches:
                injections.append(
                    {
                        "type": injection_type,
                        "technique": injection_type.upper().replace(" ", "_"),
                    }
                )

        # If no specific types found but injection confirmed, add generic
        if not injections and "sqlmap identified the following injection" in output.lower():
            injections.append({"type": "Generic SQL Injection", "technique": "UNKNOWN"})

        return injections

    def _extract_database_info(self, output: str) -> Dict[str, Any]:
        """Extract database information"""
        db_info = {}

        # Extract DBMS type
        dbms_match = re.search(
            r"back-end DBMS:\s*([^\n]+)", output, re.IGNORECASE
        )
        if dbms_match:
            db_info["dbms"] = dbms_match.group(1).strip()

        # Extract web server info
        web_server_match = re.search(
            r"web server operating system:\s*([^\n]+)", output, re.IGNORECASE
        )
        if web_server_match:
            db_info["os"] = web_server_match.group(1).strip()

        # Extract web application technology
        web_app_match = re.search(
            r"web application technology:\s*([^\n]+)", output, re.IGNORECASE
        )
        if web_app_match:
            db_info["technology"] = web_app_match.group(1).strip()

        # Extract current user
        user_match = re.search(
            r"current user:\s*['\"]?([^'\"\n]+)['\"]?", output, re.IGNORECASE
        )
        if user_match:
            db_info["current_user"] = user_match.group(1).strip()

        # Extract current database
        db_match = re.search(
            r"current database:\s*['\"]?([^'\"\n]+)['\"]?", output, re.IGNORECASE
        )
        if db_match:
            db_info["current_database"] = db_match.group(1).strip()

        return db_info

    def _extract_parameters(self, output: str) -> List[str]:
        """Extract vulnerable parameter names"""
        parameters = []

        # Look for parameter mentions
        # Example: "Parameter: id (GET)"
        param_matches = re.findall(
            r"Parameter:\s*([^\s\(]+)", output, re.IGNORECASE
        )
        parameters.extend(param_matches)

        # Remove duplicates
        return list(set(parameters))

    def _extract_payload(self, output: str) -> str:
        """Extract example payload if available"""
        # Look for payload in output
        payload_match = re.search(r"Payload:\s*([^\n]+)", output, re.IGNORECASE)
        if payload_match:
            return payload_match.group(1).strip()
        return ""
