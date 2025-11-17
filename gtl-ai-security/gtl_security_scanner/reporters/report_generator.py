"""
Report Generator - Main Report Generation Logic

Orchestrates generation of executive and technical security reports.
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)


@dataclass
class ReportConfig:
    """Report generation configuration"""

    format: str = "pdf"  # json, pdf, html
    language: str = "es"  # es, en
    include_executive_summary: bool = True
    include_technical_details: bool = True
    include_remediation: bool = True
    include_compliance: bool = True
    cvss_threshold: float = 0.0  # Only include findings above this score
    company_name: Optional[str] = None
    company_logo: Optional[str] = None
    confidential: bool = True


@dataclass
class ExecutiveSummary:
    """Executive summary data structure"""

    scan_id: str
    client_id: str
    scan_date: datetime
    duration_seconds: float
    risk_score: float  # 0-100
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW, MINIMAL
    total_findings: int
    severity_counts: Dict[str, int]
    top_risks: List[Dict[str, Any]]
    compliance_status: Optional[Dict[str, Any]] = None


@dataclass
class TechnicalReport:
    """Technical report data structure"""

    findings: List[Dict[str, Any]]
    network_scan_results: Dict[str, Any]
    vulnerability_details: List[Dict[str, Any]]
    remediation_plan: List[Dict[str, Any]]
    affected_assets: List[str]


class ReportGenerator:
    """
    Main report generator class.

    Generates comprehensive security reports from scan results.
    Supports executive summaries and detailed technical reports.

    Example:
        >>> generator = ReportGenerator()
        >>> config = ReportConfig(format="pdf", language="es")
        >>> report = generator.generate_executive_report(scan_result, config)
        >>> report.save("executive_report.pdf")
    """

    def __init__(self, templates_dir: Optional[str] = None):
        """
        Initialize report generator.

        Args:
            templates_dir: Directory containing Jinja2 templates
        """
        if templates_dir is None:
            # Use default templates directory
            templates_dir = Path(__file__).parent / "templates"

        self.templates_dir = Path(templates_dir)
        self.templates_dir.mkdir(parents=True, exist_ok=True)

        # Initialize Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=True
        )

        logger.info(f"ReportGenerator initialized with templates: {self.templates_dir}")

    def generate_executive_report(
        self,
        scan_result: Any,
        config: ReportConfig,
        client_info: Optional[Dict[str, Any]] = None
    ) -> bytes:
        """
        Generate executive summary report (high-level, business-focused).

        Args:
            scan_result: ScanResult object from scanner
            config: Report configuration
            client_info: Optional client metadata

        Returns:
            Report content as bytes (PDF or HTML)
        """
        logger.info(f"Generating executive report for scan {scan_result.scan_id}")

        # Prepare executive summary data
        summary = self._prepare_executive_summary(scan_result, client_info)

        # Generate based on format
        if config.format == "pdf":
            from gtl_security_scanner.reporters.exporters.pdf_exporter import PDFExporter
            exporter = PDFExporter()
            return exporter.generate_executive_pdf(summary, config)

        elif config.format == "html":
            template = self.jinja_env.get_template("executive.html")
            html_content = template.render(
                summary=summary,
                config=config,
                generated_at=datetime.utcnow()
            )
            return html_content.encode('utf-8')

        else:
            raise ValueError(f"Unsupported format for executive report: {config.format}")

    def generate_technical_report(
        self,
        scan_result: Any,
        config: ReportConfig
    ) -> bytes:
        """
        Generate detailed technical report (findings, remediation, technical details).

        Args:
            scan_result: ScanResult object from scanner
            config: Report configuration

        Returns:
            Report content as bytes (PDF or HTML)
        """
        logger.info(f"Generating technical report for scan {scan_result.scan_id}")

        # Prepare technical report data
        tech_report = self._prepare_technical_report(scan_result, config)

        # Generate based on format
        if config.format == "pdf":
            from gtl_security_scanner.reporters.exporters.pdf_exporter import PDFExporter
            exporter = PDFExporter()
            return exporter.generate_technical_pdf(tech_report, config)

        elif config.format == "html":
            template = self.jinja_env.get_template("technical.html")
            html_content = template.render(
                report=tech_report,
                config=config,
                generated_at=datetime.utcnow()
            )
            return html_content.encode('utf-8')

        else:
            raise ValueError(f"Unsupported format for technical report: {config.format}")

    def generate_json_export(
        self,
        scan_result: Any,
        config: ReportConfig
    ) -> bytes:
        """
        Generate JSON export of scan results.

        Args:
            scan_result: ScanResult object from scanner
            config: Report configuration

        Returns:
            JSON content as bytes
        """
        logger.info(f"Generating JSON export for scan {scan_result.scan_id}")

        from gtl_security_scanner.reporters.exporters.json_exporter import JSONExporter
        exporter = JSONExporter()
        return exporter.export(scan_result, config)

    def _prepare_executive_summary(
        self,
        scan_result: Any,
        client_info: Optional[Dict[str, Any]]
    ) -> ExecutiveSummary:
        """Prepare executive summary data from scan results"""

        # Calculate severity counts
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }

        for vuln in scan_result.vulnerabilities:
            severity = vuln.severity.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Extract top 5 critical/high risks
        top_risks = sorted(
            [
                {
                    "title": v.title,
                    "severity": v.severity,
                    "cvss_score": v.cvss_score,
                    "description": v.description[:200] + "..."
                }
                for v in scan_result.vulnerabilities
                if v.severity in ["critical", "high"]
            ],
            key=lambda x: x["cvss_score"],
            reverse=True
        )[:5]

        # Calculate risk score
        risk_score = scan_result.risk_score
        risk_level = self._get_risk_level(risk_score)

        return ExecutiveSummary(
            scan_id=scan_result.scan_id,
            client_id=scan_result.target.url if hasattr(scan_result.target, 'url') else str(scan_result.target),
            scan_date=scan_result.started_at,
            duration_seconds=scan_result.duration_seconds,
            risk_score=risk_score,
            risk_level=risk_level,
            total_findings=len(scan_result.vulnerabilities),
            severity_counts=severity_counts,
            top_risks=top_risks,
            compliance_status=scan_result.compliance_results if hasattr(scan_result, 'compliance_results') else None
        )

    def _prepare_technical_report(
        self,
        scan_result: Any,
        config: ReportConfig
    ) -> TechnicalReport:
        """Prepare technical report data from scan results"""

        # Filter findings by CVSS threshold
        findings = [
            {
                "title": v.title,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "cve_id": v.cve_id,
                "description": v.description,
                "affected_url": v.affected_url,
                "affected_parameter": v.affected_parameter,
                "proof_of_concept": v.proof_of_concept,
                "remediation": v.remediation,
                "references": v.references,
                "tool": v.tool,
                "confidence": v.confidence
            }
            for v in scan_result.vulnerabilities
            if v.cvss_score >= config.cvss_threshold
        ]

        # Sort by severity and CVSS score
        findings = sorted(
            findings,
            key=lambda x: (
                {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(x["severity"], 0),
                x["cvss_score"]
            ),
            reverse=True
        )

        # Extract network scan results
        network_results = {
            "hosts_discovered": len(scan_result.services) if hasattr(scan_result, 'services') else 0,
            "open_ports": len(scan_result.services) if hasattr(scan_result, 'services') else 0,
            "services": [
                {
                    "port": s.port,
                    "protocol": s.protocol,
                    "service": s.service,
                    "version": s.version
                }
                for s in (scan_result.services if hasattr(scan_result, 'services') else [])
            ]
        }

        # Build remediation plan
        remediation_plan = self._build_remediation_plan(findings)

        # Extract affected assets
        affected_assets = list(set(
            f.get("affected_url", "") for f in findings if f.get("affected_url")
        ))

        return TechnicalReport(
            findings=findings,
            network_scan_results=network_results,
            vulnerability_details=findings,
            remediation_plan=remediation_plan,
            affected_assets=affected_assets
        )

    def _build_remediation_plan(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Build prioritized remediation plan from findings.

        Groups similar findings and prioritizes by severity.
        """
        remediation_items = []

        # Group by remediation advice
        remediation_groups = {}
        for finding in findings:
            remediation = finding.get("remediation", "No remediation advice available")
            if remediation not in remediation_groups:
                remediation_groups[remediation] = {
                    "remediation": remediation,
                    "priority": finding.get("severity", "info"),
                    "affected_count": 0,
                    "findings": []
                }
            remediation_groups[remediation]["affected_count"] += 1
            remediation_groups[remediation]["findings"].append(finding["title"])

        # Convert to list and sort by priority
        remediation_items = list(remediation_groups.values())
        remediation_items = sorted(
            remediation_items,
            key=lambda x: {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(x["priority"], 0),
            reverse=True
        )

        return remediation_items

    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to risk level"""
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH"
        elif risk_score >= 40:
            return "MEDIUM"
        elif risk_score >= 20:
            return "LOW"
        else:
            return "MINIMAL"
