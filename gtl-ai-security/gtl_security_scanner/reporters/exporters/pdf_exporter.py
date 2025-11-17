"""
PDF Exporter

Exports security reports to PDF format using ReportLab.
"""

import logging
from io import BytesIO
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    Image,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

logger = logging.getLogger(__name__)


class PDFExporter:
    """
    Export security reports to PDF format.

    Uses ReportLab for high-quality PDF generation with
    tables, charts, and professional formatting.
    """

    def __init__(self):
        """Initialize PDF exporter"""
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        # Title style
        self.styles.add(
            ParagraphStyle(
                name="CustomTitle",
                parent=self.styles["Heading1"],
                fontSize=24,
                textColor=colors.HexColor("#667eea"),
                spaceAfter=30,
                alignment=TA_CENTER,
            )
        )

        # Section header style
        self.styles.add(
            ParagraphStyle(
                name="SectionHeader",
                parent=self.styles["Heading2"],
                fontSize=16,
                textColor=colors.HexColor("#333333"),
                spaceBefore=20,
                spaceAfter=12,
                borderWidth=0,
                borderColor=colors.HexColor("#667eea"),
                borderPadding=5,
            )
        )

        # Finding title style
        self.styles.add(
            ParagraphStyle(
                name="FindingTitle",
                parent=self.styles["Heading3"],
                fontSize=12,
                textColor=colors.HexColor("#1a1a1a"),
                spaceBefore=10,
                spaceAfter=6,
            )
        )

    def generate_executive_pdf(
        self, summary: Any, config: Any
    ) -> bytes:
        """
        Generate executive summary PDF.

        Args:
            summary: ExecutiveSummary dataclass
            config: ReportConfig

        Returns:
            PDF content as bytes
        """
        logger.info(f"Generating executive PDF for scan {summary.scan_id}")

        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72,
        )

        story = []

        # Title
        if config.language == "es":
            title = "Resumen Ejecutivo - Evaluación de Seguridad"
        else:
            title = "Executive Summary - Security Assessment"

        story.append(Paragraph(title, self.styles["CustomTitle"]))
        story.append(Spacer(1, 0.5 * inch))

        # Metadata table
        metadata = [
            ["Scan ID", summary.scan_id],
            ["Client", summary.client_id],
            ["Scan Date", summary.scan_date.strftime("%Y-%m-%d %H:%M")],
            ["Duration", f"{summary.duration_seconds:.2f} seconds"],
        ]

        metadata_table = Table(metadata, colWidths=[2 * inch, 4 * inch])
        metadata_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        story.append(metadata_table)
        story.append(Spacer(1, 0.3 * inch))

        # Risk assessment
        story.append(
            Paragraph(
                "Risk Assessment" if config.language == "en" else "Evaluación de Riesgo",
                self.styles["SectionHeader"],
            )
        )

        risk_color = self._get_risk_color(summary.risk_level)
        risk_data = [
            ["Risk Level", "Risk Score"],
            [summary.risk_level, f"{summary.risk_score:.1f}/100"],
        ]

        risk_table = Table(risk_data, colWidths=[3 * inch, 3 * inch])
        risk_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 12),
                    ("BACKGROUND", (0, 1), (-1, -1), risk_color),
                    ("FONTSIZE", (0, 1), (-1, -1), 18),
                    ("FONTNAME", (0, 1), (-1, -1), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        story.append(risk_table)
        story.append(Spacer(1, 0.3 * inch))

        # Severity breakdown
        story.append(
            Paragraph(
                "Findings by Severity" if config.language == "en" else "Hallazgos por Severidad",
                self.styles["SectionHeader"],
            )
        )

        severity_data = [
            ["Severity", "Count"],
            ["Critical", str(summary.severity_counts["critical"])],
            ["High", str(summary.severity_counts["high"])],
            ["Medium", str(summary.severity_counts["medium"])],
            ["Low", str(summary.severity_counts["low"])],
            ["Info", str(summary.severity_counts["info"])],
        ]

        severity_table = Table(severity_data, colWidths=[3 * inch, 2 * inch])
        severity_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 11),
                    # Color rows by severity
                    ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#ffebee")),  # Critical
                    ("BACKGROUND", (0, 2), (-1, 2), colors.HexColor("#fff3e0")),  # High
                    ("BACKGROUND", (0, 3), (-1, 3), colors.HexColor("#fffde7")),  # Medium
                    ("BACKGROUND", (0, 4), (-1, 4), colors.HexColor("#e1f5fe")),  # Low
                    ("BACKGROUND", (0, 5), (-1, 5), colors.HexColor("#f1f8e9")),  # Info
                    ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        story.append(severity_table)
        story.append(Spacer(1, 0.3 * inch))

        # Top risks
        if summary.top_risks:
            story.append(PageBreak())
            story.append(
                Paragraph(
                    "Top Risks" if config.language == "en" else "Principales Riesgos",
                    self.styles["SectionHeader"],
                )
            )

            for i, risk in enumerate(summary.top_risks, 1):
                story.append(
                    Paragraph(
                        f"<b>{i}. [{risk['severity'].upper()}] {risk['title']}</b>",
                        self.styles["FindingTitle"],
                    )
                )
                story.append(
                    Paragraph(
                        f"CVSS Score: {risk['cvss_score']:.1f}",
                        self.styles["Normal"],
                    )
                )
                story.append(
                    Paragraph(risk["description"], self.styles["Normal"])
                )
                story.append(Spacer(1, 0.2 * inch))

        # Build PDF
        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()

        logger.info("Executive PDF generated successfully")
        return pdf_bytes

    def generate_technical_pdf(
        self, report: Any, config: Any
    ) -> bytes:
        """
        Generate detailed technical report PDF.

        Args:
            report: TechnicalReport dataclass
            config: ReportConfig

        Returns:
            PDF content as bytes
        """
        logger.info("Generating technical PDF report")

        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72,
        )

        story = []

        # Title
        if config.language == "es":
            title = "Informe Técnico - Evaluación de Seguridad"
        else:
            title = "Technical Report - Security Assessment"

        story.append(Paragraph(title, self.styles["CustomTitle"]))
        story.append(Spacer(1, 0.5 * inch))

        # Network scan results
        story.append(
            Paragraph(
                "Network Scan Results" if config.language == "en" else "Resultados del Escaneo de Red",
                self.styles["SectionHeader"],
            )
        )

        network_data = [
            ["Hosts Discovered", str(report.network_scan_results.get("hosts_discovered", 0))],
            ["Open Ports", str(report.network_scan_results.get("open_ports", 0))],
        ]

        network_table = Table(network_data, colWidths=[3 * inch, 3 * inch])
        network_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
                    ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        story.append(network_table)
        story.append(Spacer(1, 0.3 * inch))

        # Vulnerability findings
        story.append(PageBreak())
        story.append(
            Paragraph(
                "Security Findings" if config.language == "en" else "Hallazgos de Seguridad",
                self.styles["SectionHeader"],
            )
        )

        # Limit to first 50 findings in PDF
        for i, finding in enumerate(report.findings[:50], 1):
            # Finding header
            story.append(
                Paragraph(
                    f"<b>{i}. [{finding['severity'].upper()}] {finding['title']}</b>",
                    self.styles["FindingTitle"],
                )
            )

            # Finding details
            details_data = [
                ["CVSS Score", f"{finding['cvss_score']:.1f}"],
                ["Tool", finding.get("tool", "N/A")],
                ["Confidence", finding.get("confidence", "N/A")],
            ]

            if finding.get("cve_id"):
                details_data.append(["CVE", finding["cve_id"]])

            details_table = Table(details_data, colWidths=[1.5 * inch, 4.5 * inch])
            details_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(details_table)
            story.append(Spacer(1, 0.1 * inch))

            # Description
            story.append(
                Paragraph(f"<b>Description:</b> {finding['description']}", self.styles["Normal"])
            )
            story.append(Spacer(1, 0.1 * inch))

            # Affected asset
            if finding.get("affected_url"):
                story.append(
                    Paragraph(f"<b>Affected:</b> {finding['affected_url']}", self.styles["Normal"])
                )
                story.append(Spacer(1, 0.1 * inch))

            # Remediation
            if config.include_remediation and finding.get("remediation"):
                story.append(
                    Paragraph(f"<b>Remediation:</b> {finding['remediation']}", self.styles["Normal"])
                )

            story.append(Spacer(1, 0.2 * inch))

            # Page break every 5 findings
            if i % 5 == 0 and i < len(report.findings[:50]):
                story.append(PageBreak())

        # Build PDF
        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()

        logger.info("Technical PDF generated successfully")
        return pdf_bytes

    def _get_risk_color(self, risk_level: str) -> colors.Color:
        """Get color for risk level"""
        color_map = {
            "CRITICAL": colors.HexColor("#d32f2f"),
            "HIGH": colors.HexColor("#f57c00"),
            "MEDIUM": colors.HexColor("#fbc02d"),
            "LOW": colors.HexColor("#0288d1"),
            "MINIMAL": colors.HexColor("#388e3c"),
        }
        return color_map.get(risk_level, colors.grey)
