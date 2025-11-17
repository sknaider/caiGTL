"""
JSON Exporter

Exports security scan results to JSON format for API consumption,
data analysis, and integration with other tools.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class JSONExporter:
    """
    Export security scan results to JSON format.

    Provides structured JSON output suitable for:
    - API responses
    - Data analysis and visualization
    - Integration with SIEM systems
    - Machine learning pipelines
    """

    def __init__(self, pretty: bool = True, indent: int = 2):
        """
        Initialize JSON exporter.

        Args:
            pretty: Use pretty-printing with indentation
            indent: Indentation level for pretty printing
        """
        self.pretty = pretty
        self.indent = indent if pretty else None

    def export(self, scan_result: Any, config: Any) -> bytes:
        """
        Export scan results to JSON.

        Args:
            scan_result: ScanResult object from scanner
            config: ReportConfig

        Returns:
            JSON content as bytes
        """
        logger.info(f"Exporting scan {scan_result.scan_id} to JSON")

        # Build complete JSON structure
        json_data = {
            "metadata": self._export_metadata(scan_result),
            "scan_info": self._export_scan_info(scan_result),
            "vulnerabilities": self._export_vulnerabilities(scan_result, config),
            "services": self._export_services(scan_result),
            "statistics": self._export_statistics(scan_result),
            "compliance": self._export_compliance(scan_result),
        }

        # Convert to JSON bytes
        json_str = json.dumps(json_data, indent=self.indent, default=self._json_serializer)
        return json_str.encode("utf-8")

    def _export_metadata(self, scan_result: Any) -> Dict[str, Any]:
        """Export scan metadata"""
        return {
            "scan_id": scan_result.scan_id,
            "version": "1.0",
            "format": "gtl_security_scanner_json",
            "exported_at": datetime.utcnow().isoformat(),
            "scanner_version": "1.0.0",
        }

    def _export_scan_info(self, scan_result: Any) -> Dict[str, Any]:
        """Export scan information"""
        target_info = {}
        if hasattr(scan_result.target, 'url'):
            target_info['url'] = scan_result.target.url
        if hasattr(scan_result.target, 'scan_type'):
            target_info['scan_type'] = scan_result.target.scan_type.value if hasattr(scan_result.target.scan_type, 'value') else str(scan_result.target.scan_type)

        return {
            "scan_id": scan_result.scan_id,
            "target": target_info,
            "status": scan_result.status.value if hasattr(scan_result.status, 'value') else str(scan_result.status),
            "started_at": scan_result.started_at.isoformat() if scan_result.started_at else None,
            "completed_at": scan_result.completed_at.isoformat() if scan_result.completed_at else None,
            "duration_seconds": scan_result.duration_seconds,
            "risk_score": scan_result.risk_score,
        }

    def _export_vulnerabilities(
        self, scan_result: Any, config: Any
    ) -> List[Dict[str, Any]]:
        """Export vulnerability findings"""
        vulnerabilities = []

        for vuln in scan_result.vulnerabilities:
            # Filter by CVSS threshold
            if vuln.cvss_score < config.cvss_threshold:
                continue

            vuln_data = {
                "id": f"{scan_result.scan_id}_{len(vulnerabilities) + 1}",
                "title": vuln.title,
                "severity": vuln.severity,
                "cvss_score": vuln.cvss_score,
                "cve_id": vuln.cve_id,
                "description": vuln.description,
                "affected_asset": {
                    "url": vuln.affected_url,
                    "parameter": vuln.affected_parameter,
                },
                "proof_of_concept": vuln.proof_of_concept,
                "remediation": vuln.remediation,
                "references": vuln.references,
                "detection": {
                    "tool": vuln.tool,
                    "confidence": vuln.confidence,
                },
            }

            vulnerabilities.append(vuln_data)

        return vulnerabilities

    def _export_services(self, scan_result: Any) -> List[Dict[str, Any]]:
        """Export discovered services"""
        services = []

        if hasattr(scan_result, 'services'):
            for service in scan_result.services:
                service_data = {
                    "port": service.port,
                    "protocol": service.protocol,
                    "service": service.service,
                    "version": service.version,
                    "state": service.state,
                }
                services.append(service_data)

        return services

    def _export_statistics(self, scan_result: Any) -> Dict[str, Any]:
        """Export scan statistics"""
        # Calculate severity counts
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for vuln in scan_result.vulnerabilities:
            severity = vuln.severity.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Calculate CVSS statistics
        cvss_scores = [v.cvss_score for v in scan_result.vulnerabilities if v.cvss_score > 0]

        avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0.0
        max_cvss = max(cvss_scores) if cvss_scores else 0.0

        return {
            "total_vulnerabilities": len(scan_result.vulnerabilities),
            "severity_breakdown": severity_counts,
            "cvss_statistics": {
                "average": round(avg_cvss, 2),
                "maximum": max_cvss,
            },
            "total_services": len(scan_result.services) if hasattr(scan_result, 'services') else 0,
            "tools_used": list(set(v.tool for v in scan_result.vulnerabilities)),
        }

    def _export_compliance(self, scan_result: Any) -> Dict[str, Any]:
        """Export compliance check results"""
        if hasattr(scan_result, 'compliance_results') and scan_result.compliance_results:
            return scan_result.compliance_results

        return {
            "status": "not_checked",
            "frameworks": [],
        }

    def _json_serializer(self, obj: Any) -> str:
        """
        Custom JSON serializer for objects not serializable by default.

        Handles datetime, dataclasses, enums, etc.
        """
        if isinstance(obj, datetime):
            return obj.isoformat()

        if hasattr(obj, '__dict__'):
            return obj.__dict__

        if hasattr(obj, 'value'):  # Enums
            return obj.value

        return str(obj)

    def export_compact(self, scan_result: Any) -> bytes:
        """
        Export compact JSON (single line, no indentation).

        Useful for log streaming and high-volume data transfer.

        Args:
            scan_result: ScanResult object

        Returns:
            Compact JSON bytes
        """
        # Temporarily disable pretty printing
        original_indent = self.indent
        self.indent = None

        from gtl_security_scanner.reporters.report_generator import ReportConfig
        config = ReportConfig(cvss_threshold=0.0)

        result = self.export(scan_result, config)

        # Restore original setting
        self.indent = original_indent

        return result

    def export_summary_only(self, scan_result: Any) -> bytes:
        """
        Export summary data only (no detailed findings).

        Useful for dashboards and high-level reporting.

        Args:
            scan_result: ScanResult object

        Returns:
            JSON summary bytes
        """
        summary = {
            "scan_id": scan_result.scan_id,
            "risk_score": scan_result.risk_score,
            "status": scan_result.status.value if hasattr(scan_result.status, 'value') else str(scan_result.status),
            "duration_seconds": scan_result.duration_seconds,
            "statistics": self._export_statistics(scan_result),
        }

        json_str = json.dumps(summary, indent=self.indent, default=self._json_serializer)
        return json_str.encode("utf-8")
