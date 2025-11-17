"""
Test Report Generators

Unit tests for PDF and JSON report generation.
"""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch

from gtl_security_scanner.reporters.report_generator import (
    ReportGenerator,
    ReportConfig,
    ExecutiveSummary,
    TechnicalReport,
)
from gtl_security_scanner.reporters.exporters.pdf_exporter import PDFExporter
from gtl_security_scanner.reporters.exporters.json_exporter import JSONExporter
from gtl_security_scanner.scanner import ScanResult, ScanTarget, ScanType, ScanStatus, Vulnerability


class TestReportGenerator:
    """Test ReportGenerator class"""

    @pytest.fixture
    def generator(self):
        return ReportGenerator()

    @pytest.fixture
    def sample_scan_result(self):
        """Create sample scan result"""
        return ScanResult(
            scan_id="test-001",
            target=ScanTarget(url="https://example.com", scan_type=ScanType.WEBAPP),
            status=ScanStatus.COMPLETED,
            vulnerabilities=[
                Vulnerability(
                    title="SQL Injection",
                    severity="critical",
                    cvss_score=9.8,
                    description="SQL injection in login form",
                    affected_url="https://example.com/login",
                    remediation="Use parameterized queries",
                    references=["https://owasp.org/sqli"],
                    tool="sqlmap",
                    confidence="high"
                ),
                Vulnerability(
                    title="XSS Vulnerability",
                    severity="high",
                    cvss_score=7.5,
                    description="Reflected XSS",
                    affected_url="https://example.com/search",
                    remediation="Sanitize user input",
                    references=[],
                    tool="nuclei",
                    confidence="medium"
                ),
            ],
            services=[],
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            duration_seconds=300.0,
            risk_score=75.5
        )

    def test_generator_initialization(self, generator):
        """Test report generator initializes"""
        assert generator is not None
        assert generator.templates_dir is not None

    def test_prepare_executive_summary(self, generator, sample_scan_result):
        """Test executive summary preparation"""
        summary = generator._prepare_executive_summary(sample_scan_result, None)

        assert isinstance(summary, ExecutiveSummary)
        assert summary.scan_id == "test-001"
        assert summary.total_findings == 2
        assert summary.risk_score == 75.5
        assert summary.severity_counts["critical"] == 1
        assert summary.severity_counts["high"] == 1

    def test_risk_level_determination(self, generator):
        """Test risk level calculation"""
        assert generator._get_risk_level(90.0) == "CRITICAL"
        assert generator._get_risk_level(70.0) == "HIGH"
        assert generator._get_risk_level(50.0) == "MEDIUM"
        assert generator._get_risk_level(30.0) == "LOW"
        assert generator._get_risk_level(10.0) == "MINIMAL"

    def test_generate_json_export(self, generator, sample_scan_result):
        """Test JSON export generation"""
        config = ReportConfig(format="json", cvss_threshold=0.0)

        json_bytes = generator.generate_json_export(sample_scan_result, config)

        assert isinstance(json_bytes, bytes)
        assert len(json_bytes) > 0

        # Should be valid JSON
        import json
        data = json.loads(json_bytes)
        assert "metadata" in data
        assert "vulnerabilities" in data
        assert "statistics" in data


class TestPDFExporter:
    """Test PDF exporter"""

    @pytest.fixture
    def exporter(self):
        return PDFExporter()

    @pytest.fixture
    def sample_summary(self):
        return ExecutiveSummary(
            scan_id="test-001",
            client_id="client-123",
            scan_date=datetime.utcnow(),
            duration_seconds=300.0,
            risk_score=75.5,
            risk_level="HIGH",
            total_findings=5,
            severity_counts={"critical": 1, "high": 2, "medium": 1, "low": 1, "info": 0},
            top_risks=[
                {
                    "title": "SQL Injection",
                    "severity": "critical",
                    "cvss_score": 9.8,
                    "description": "Critical SQL injection vulnerability"
                }
            ]
        )

    def test_exporter_initialization(self, exporter):
        """Test PDF exporter initializes"""
        assert exporter is not None
        assert hasattr(exporter, 'styles')

    def test_generate_executive_pdf(self, exporter, sample_summary):
        """Test executive PDF generation"""
        config = ReportConfig(format="pdf", language="es")

        pdf_bytes = exporter.generate_executive_pdf(sample_summary, config)

        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 0
        # PDF should start with %PDF
        assert pdf_bytes[:4] == b'%PDF'

    def test_risk_color_mapping(self, exporter):
        """Test risk level color mapping"""
        from reportlab.lib import colors

        critical_color = exporter._get_risk_color("CRITICAL")
        assert isinstance(critical_color, colors.Color)

        high_color = exporter._get_risk_color("HIGH")
        assert isinstance(high_color, colors.Color)


class TestJSONExporter:
    """Test JSON exporter"""

    @pytest.fixture
    def exporter(self):
        return JSONExporter()

    @pytest.fixture
    def sample_scan_result(self):
        return ScanResult(
            scan_id="test-001",
            target=ScanTarget(url="https://example.com", scan_type=ScanType.WEBAPP),
            status=ScanStatus.COMPLETED,
            vulnerabilities=[
                Vulnerability(
                    title="Test Vuln",
                    severity="high",
                    cvss_score=7.5,
                    description="Test",
                    affected_url="https://example.com",
                    remediation="Fix",
                    references=[],
                    tool="test",
                    confidence="high"
                )
            ],
            services=[],
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            duration_seconds=120.0,
            risk_score=45.0
        )

    def test_exporter_initialization(self, exporter):
        """Test JSON exporter initializes"""
        assert exporter is not None
        assert exporter.pretty == True
        assert exporter.indent == 2

    def test_export(self, exporter, sample_scan_result):
        """Test JSON export"""
        config = ReportConfig(cvss_threshold=0.0)

        json_bytes = exporter.export(sample_scan_result, config)

        assert isinstance(json_bytes, bytes)
        assert len(json_bytes) > 0

        # Validate JSON structure
        import json
        data = json.loads(json_bytes)

        assert "metadata" in data
        assert "scan_info" in data
        assert "vulnerabilities" in data
        assert "statistics" in data
        assert data["metadata"]["scan_id"] == "test-001"

    def test_export_compact(self, exporter, sample_scan_result):
        """Test compact JSON export"""
        compact_bytes = exporter.export_compact(sample_scan_result)

        assert isinstance(compact_bytes, bytes)
        # Compact JSON should have no newlines (except possible trailing)
        assert b'\n  ' not in compact_bytes  # No indentation

    def test_export_summary_only(self, exporter, sample_scan_result):
        """Test summary-only export"""
        summary_bytes = exporter.export_summary_only(sample_scan_result)

        assert isinstance(summary_bytes, bytes)

        import json
        data = json.loads(summary_bytes)

        # Should only have summary fields
        assert "scan_id" in data
        assert "risk_score" in data
        assert "statistics" in data
        # Should NOT have full vulnerability details
        assert "vulnerabilities" not in data or len(data.get("vulnerabilities", [])) == 0


class TestReportConfig:
    """Test ReportConfig dataclass"""

    def test_default_config(self):
        """Test default configuration"""
        config = ReportConfig()

        assert config.format == "pdf"
        assert config.language == "es"
        assert config.include_executive_summary == True
        assert config.include_technical_details == True
        assert config.cvss_threshold == 0.0

    def test_custom_config(self):
        """Test custom configuration"""
        config = ReportConfig(
            format="json",
            language="en",
            cvss_threshold=5.0,
            company_name="ACME Corp"
        )

        assert config.format == "json"
        assert config.language == "en"
        assert config.cvss_threshold == 5.0
        assert config.company_name == "ACME Corp"
