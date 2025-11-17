"""
GTL Report Generator

Generates executive and technical reports from scan results.
Supports multiple formats: JSON, PDF, HTML.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, Template
from pydantic import BaseModel
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .scanner import ScanResult

# Configure logging
logger = logging.getLogger(__name__)


# ===========================================
# DATA MODELS
# ===========================================


class ReportConfig(BaseModel):
    """Report generation configuration"""

    format: str = "pdf"  # json, pdf, html
    language: str = "es"  # es, en
    include_executive_summary: bool = True
    include_technical_details: bool = True
    include_remediation: bool = True
    cvss_threshold: float = 0.0  # Only include findings above this score
    company_name: Optional[str] = None
    company_logo: Optional[str] = None


class Finding(BaseModel):
    """Standardized security finding"""

    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    affected_systems: List[str]
    cvss_score: Optional[float] = None
    cve_ids: List[str] = []
    remediation: Optional[str] = None
    references: List[str] = []


# ===========================================
# REPORT GENERATOR
# ===========================================


class ReportGenerator:
    """
    Generate security assessment reports.

    Example:
        >>> generator = ReportGenerator()
        >>> report = generator.generate(
        ...     scan_result=result,
        ...     config=ReportConfig(format="pdf", language="es")
        ... )
        >>> report.save("report.pdf")
    """

    def __init__(self, templates_dir: str = "templates"):
        """
        Initialize report generator.

        Args:
            templates_dir: Directory containing report templates
        """
        self.templates_dir = Path(templates_dir)
        self.templates_dir.mkdir(parents=True, exist_ok=True)

        # Initialize Jinja2 for HTML templates
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.templates_dir))
        )

        logger.info("ReportGenerator initialized")

    def generate(
        self, scan_result: ScanResult, config: ReportConfig
    ) -> "GeneratedReport":
        """
        Generate report from scan results.

        Args:
            scan_result: Scan results to report on
            config: Report configuration

        Returns:
            GeneratedReport instance

        Raises:
            ValueError: If format is not supported
        """
        logger.info(
            f"Generating {config.format} report for scan {scan_result.scan_id}"
        )

        # Prepare report data
        report_data = self._prepare_data(scan_result, config)

        # Generate based on format
        if config.format == "json":
            content = self._generate_json(report_data)
        elif config.format == "pdf":
            content = self._generate_pdf(report_data, config)
        elif config.format == "html":
            content = self._generate_html(report_data, config)
        else:
            raise ValueError(f"Unsupported format: {config.format}")

        return GeneratedReport(
            scan_id=scan_result.scan_id,
            format=config.format,
            content=content,
            generated_at=datetime.utcnow(),
        )

    def _prepare_data(
        self, scan_result: ScanResult, config: ReportConfig
    ) -> Dict[str, Any]:
        """Prepare report data from scan results"""
        # Filter findings by CVSS threshold
        findings = [
            f
            for f in scan_result.findings
            if f.get("cvss_score", 0) >= config.cvss_threshold
        ]

        # Count by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        for finding in findings:
            severity = finding.get("severity", "info").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Calculate risk score (0-100)
        risk_score = self._calculate_risk_score(severity_counts)

        return {
            "scan_id": scan_result.scan_id,
            "client_id": scan_result.client_id,
            "scan_date": scan_result.started_at,
            "duration": scan_result.duration_seconds,
            "findings": findings,
            "severity_counts": severity_counts,
            "total_findings": len(findings),
            "risk_score": risk_score,
            "risk_level": self._get_risk_level(risk_score),
            "language": config.language,
        }

    def _calculate_risk_score(self, severity_counts: Dict[str, int]) -> int:
        """
        Calculate overall risk score (0-100).

        Weighted by severity:
        - Critical: 10 points each
        - High: 5 points each
        - Medium: 2 points each
        - Low: 1 point each
        - Info: 0.5 points each
        """
        score = (
            severity_counts["critical"] * 10
            + severity_counts["high"] * 5
            + severity_counts["medium"] * 2
            + severity_counts["low"] * 1
            + severity_counts["info"] * 0.5
        )

        # Normalize to 0-100 (cap at 100)
        return min(int(score), 100)

    def _get_risk_level(self, risk_score: int) -> str:
        """Convert risk score to level"""
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

    def _generate_json(self, data: Dict[str, Any]) -> bytes:
        """Generate JSON report"""
        return json.dumps(data, indent=2, default=str).encode("utf-8")

    def _generate_pdf(
        self, data: Dict[str, Any], config: ReportConfig
    ) -> bytes:
        """Generate PDF report using ReportLab"""
        from io import BytesIO

        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()

        # Title
        if config.language == "es":
            title = "Informe de Evaluación de Seguridad"
        else:
            title = "Security Assessment Report"

        story.append(Paragraph(title, styles["Title"]))
        story.append(Spacer(1, 12))

        # Executive Summary
        if config.include_executive_summary:
            if config.language == "es":
                story.append(Paragraph("Resumen Ejecutivo", styles["Heading1"]))
            else:
                story.append(Paragraph("Executive Summary", styles["Heading1"]))

            # Risk level with color
            risk_level = data["risk_level"]
            risk_colors = {
                "CRITICAL": colors.red,
                "HIGH": colors.orange,
                "MEDIUM": colors.yellow,
                "LOW": colors.lightblue,
                "MINIMAL": colors.lightgreen,
            }

            summary_data = [
                ["Cliente / Client", data["client_id"]],
                ["Fecha / Date", str(data["scan_date"])],
                ["Duración / Duration", f"{data['duration']} segundos / seconds"],
                ["Nivel de Riesgo / Risk Level", risk_level],
                ["Puntaje de Riesgo / Risk Score", f"{data['risk_score']}/100"],
            ]

            summary_table = Table(summary_data, colWidths=[200, 300])
            summary_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 12),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                    ]
                )
            )
            story.append(summary_table)
            story.append(Spacer(1, 12))

            # Findings by severity
            severity_data = [
                ["Severidad / Severity", "Cantidad / Count"],
                ["Crítica / Critical", str(data["severity_counts"]["critical"])],
                ["Alta / High", str(data["severity_counts"]["high"])],
                ["Media / Medium", str(data["severity_counts"]["medium"])],
                ["Baja / Low", str(data["severity_counts"]["low"])],
                ["Info / Info", str(data["severity_counts"]["info"])],
            ]

            severity_table = Table(severity_data, colWidths=[200, 100])
            severity_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                    ]
                )
            )
            story.append(severity_table)
            story.append(PageBreak())

        # Technical Details
        if config.include_technical_details and data["findings"]:
            if config.language == "es":
                story.append(Paragraph("Detalles Técnicos", styles["Heading1"]))
            else:
                story.append(Paragraph("Technical Details", styles["Heading1"]))

            story.append(Spacer(1, 12))

            # List each finding
            for i, finding in enumerate(data["findings"][:20], 1):  # Limit to 20
                # Finding header
                severity = finding.get("severity", "info").upper()
                title = finding.get("title", "Unknown")

                story.append(
                    Paragraph(
                        f"<b>{i}. [{severity}] {title}</b>", styles["Heading2"]
                    )
                )

                # Finding details
                desc = finding.get("description", "No description")
                story.append(Paragraph(desc, styles["Normal"]))

                # CVE if available
                if finding.get("cve"):
                    cves = ", ".join(finding["cve"])
                    story.append(Paragraph(f"<b>CVE:</b> {cves}", styles["Normal"]))

                # CVSS score if available
                if finding.get("cvss_score"):
                    story.append(
                        Paragraph(
                            f"<b>CVSS Score:</b> {finding['cvss_score']}",
                            styles["Normal"],
                        )
                    )

                story.append(Spacer(1, 12))

        # Build PDF
        doc.build(story)
        pdf_content = buffer.getvalue()
        buffer.close()

        return pdf_content

    def _generate_html(
        self, data: Dict[str, Any], config: ReportConfig
    ) -> bytes:
        """Generate HTML report using Jinja2 template"""
        # Simple HTML template (in production, use external template file)
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Assessment Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background: #333; color: white; padding: 20px; }
                .summary { background: #f0f0f0; padding: 20px; margin: 20px 0; }
                .finding { border: 1px solid #ccc; padding: 10px; margin: 10px 0; }
                .critical { border-left: 5px solid red; }
                .high { border-left: 5px solid orange; }
                .medium { border-left: 5px solid yellow; }
                .low { border-left: 5px solid blue; }
                .info { border-left: 5px solid green; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Assessment Report</h1>
                <p>Client: {{ client_id }}</p>
                <p>Date: {{ scan_date }}</p>
            </div>

            <div class="summary">
                <h2>Executive Summary</h2>
                <p><strong>Risk Level:</strong> {{ risk_level }}</p>
                <p><strong>Risk Score:</strong> {{ risk_score }}/100</p>
                <p><strong>Total Findings:</strong> {{ total_findings }}</p>

                <h3>Findings by Severity:</h3>
                <ul>
                    <li>Critical: {{ severity_counts.critical }}</li>
                    <li>High: {{ severity_counts.high }}</li>
                    <li>Medium: {{ severity_counts.medium }}</li>
                    <li>Low: {{ severity_counts.low }}</li>
                    <li>Info: {{ severity_counts.info }}</li>
                </ul>
            </div>

            <h2>Detailed Findings</h2>
            {% for finding in findings %}
            <div class="finding {{ finding.severity }}">
                <h3>[{{ finding.severity.upper() }}] {{ finding.title }}</h3>
                <p>{{ finding.description }}</p>
                {% if finding.cvss_score %}
                <p><strong>CVSS Score:</strong> {{ finding.cvss_score }}</p>
                {% endif %}
                {% if finding.cve %}
                <p><strong>CVE:</strong> {{ finding.cve | join(', ') }}</p>
                {% endif %}
            </div>
            {% endfor %}
        </body>
        </html>
        """

        template = Template(html_template)
        html = template.render(**data)

        return html.encode("utf-8")


class GeneratedReport:
    """Container for generated report"""

    def __init__(
        self,
        scan_id: str,
        format: str,
        content: bytes,
        generated_at: datetime,
    ):
        self.scan_id = scan_id
        self.format = format
        self.content = content
        self.generated_at = generated_at

    def save(self, filepath: str) -> None:
        """Save report to file"""
        with open(filepath, "wb") as f:
            f.write(self.content)
        logger.info(f"Report saved to {filepath}")

    def to_base64(self) -> str:
        """Convert content to base64 for API transfer"""
        import base64

        return base64.b64encode(self.content).decode("utf-8")


# ===========================================
# EXAMPLE USAGE
# ===========================================

if __name__ == "__main__":
    from .scanner import ScanResult

    # Create mock scan result
    scan_result = ScanResult(
        scan_id="test-scan-123",
        client_id="logistics_company_1",
        status="completed",
        findings=[
            {
                "severity": "critical",
                "title": "SQL Injection Vulnerability",
                "description": "SQL injection found in login form",
                "cvss_score": 9.8,
                "cve": ["CVE-2024-1234"],
            },
            {
                "severity": "high",
                "title": "Outdated Software Version",
                "description": "Apache 2.2.15 detected (EOL)",
                "cvss_score": 7.5,
            },
            {
                "severity": "medium",
                "title": "Missing Security Headers",
                "description": "X-Frame-Options not set",
                "cvss_score": 4.3,
            },
        ],
    )

    # Generate reports
    generator = ReportGenerator()

    # JSON report
    json_report = generator.generate(
        scan_result, ReportConfig(format="json", language="es")
    )
    json_report.save("report.json")

    # PDF report
    pdf_report = generator.generate(
        scan_result, ReportConfig(format="pdf", language="es")
    )
    pdf_report.save("report.pdf")

    # HTML report
    html_report = generator.generate(
        scan_result, ReportConfig(format="html", language="en")
    )
    html_report.save("report.html")

    print("Reports generated successfully!")
