"""
Test GTL Security Scanner Core Module

Unit and integration tests for the main scanner orchestrator.
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import Mock, patch, AsyncMock

from gtl_security_scanner.scanner import (
    SecurityScanner,
    ScanTarget,
    ScanType,
    ScanStatus,
    ScanResult,
    Vulnerability,
    Service,
)


class TestSecurityScanner:
    """Test SecurityScanner class"""

    @pytest.fixture
    def scanner(self):
        """Create scanner instance"""
        return SecurityScanner()

    @pytest.fixture
    def sample_target(self):
        """Create sample scan target"""
        return ScanTarget(
            url="https://testapp.example.com",
            scan_type=ScanType.WEBAPP,
        )

    @pytest.mark.asyncio
    async def test_scanner_initialization(self, scanner):
        """Test scanner initializes correctly"""
        assert scanner is not None
        assert hasattr(scanner, 'nmap_scanner')
        assert hasattr(scanner, 'nuclei_scanner')
        assert hasattr(scanner, 'sqlmap_scanner')
        assert hasattr(scanner, 'nikto_scanner')

    @pytest.mark.asyncio
    async def test_scan_execution(self, scanner, sample_target):
        """Test scan execution workflow"""
        scan_id = "test-scan-001"

        # Mock the tool scanners to return empty results
        with patch.object(scanner.nmap_scanner, 'scan', new_callable=AsyncMock) as mock_nmap, \
             patch.object(scanner.nuclei_scanner, 'scan', new_callable=AsyncMock) as mock_nuclei, \
             patch.object(scanner.nikto_scanner, 'scan', new_callable=AsyncMock) as mock_nikto:

            mock_nmap.return_value = {
                'hosts': [],
                'open_ports': [],
                'services': [],
                'os_matches': []
            }
            mock_nuclei.return_value = []
            mock_nikto.return_value = []

            result = await scanner.scan(sample_target, scan_id)

            assert result is not None
            assert result.scan_id == scan_id
            assert result.status == ScanStatus.COMPLETED
            assert isinstance(result.vulnerabilities, list)

    @pytest.mark.asyncio
    async def test_scan_with_vulnerabilities(self, scanner, sample_target):
        """Test scan that finds vulnerabilities"""
        scan_id = "test-scan-002"

        # Mock vulnerability findings
        mock_vuln = Vulnerability(
            title="SQL Injection",
            severity="critical",
            cvss_score=9.8,
            description="SQL injection vulnerability found",
            affected_url="https://testapp.example.com/login",
            remediation="Use parameterized queries",
            references=["https://owasp.org/sqli"],
            tool="sqlmap",
            confidence="high"
        )

        with patch.object(scanner.nmap_scanner, 'scan', new_callable=AsyncMock) as mock_nmap, \
             patch.object(scanner.nuclei_scanner, 'scan', new_callable=AsyncMock) as mock_nuclei, \
             patch.object(scanner.sqlmap_scanner, 'scan', new_callable=AsyncMock) as mock_sqlmap:

            mock_nmap.return_value = {'hosts': [], 'open_ports': [], 'services': [], 'os_matches': []}
            mock_nuclei.return_value = []
            mock_sqlmap.return_value = [mock_vuln]

            result = await scanner.scan(sample_target, scan_id)

            assert len(result.vulnerabilities) > 0
            assert result.vulnerabilities[0].severity == "critical"
            assert result.risk_score > 0

    def test_risk_score_calculation(self, scanner):
        """Test risk score calculation algorithm"""
        vulnerabilities = [
            Vulnerability(
                title="Critical Vuln", severity="critical", cvss_score=9.8,
                description="Test", affected_url="http://test.com",
                remediation="Fix it", references=[], tool="test", confidence="high"
            ),
            Vulnerability(
                title="High Vuln", severity="high", cvss_score=7.5,
                description="Test", affected_url="http://test.com",
                remediation="Fix it", references=[], tool="test", confidence="high"
            ),
            Vulnerability(
                title="Medium Vuln", severity="medium", cvss_score=5.0,
                description="Test", affected_url="http://test.com",
                remediation="Fix it", references=[], tool="test", confidence="medium"
            ),
        ]

        risk_score = scanner._calculate_risk_score(vulnerabilities)

        assert isinstance(risk_score, float)
        assert 0.0 <= risk_score <= 100.0
        assert risk_score > 0  # Should have some risk with critical vuln

    def test_vulnerability_deduplication(self, scanner):
        """Test that duplicate vulnerabilities are removed"""
        vulnerabilities = [
            Vulnerability(
                title="XSS Vulnerability", severity="high", cvss_score=7.5,
                description="Reflected XSS", affected_url="http://test.com/page",
                remediation="Sanitize input", references=[], tool="nuclei", confidence="high"
            ),
            Vulnerability(
                title="XSS Vulnerability", severity="high", cvss_score=7.5,
                description="Reflected XSS", affected_url="http://test.com/page",
                remediation="Sanitize input", references=[], tool="nikto", confidence="medium"
            ),
        ]

        deduplicated = scanner._deduplicate_vulnerabilities(vulnerabilities)

        # Should keep only one with higher confidence
        assert len(deduplicated) == 1
        assert deduplicated[0].confidence == "high"

    @pytest.mark.asyncio
    async def test_scan_progress_callback(self, scanner, sample_target):
        """Test progress callback functionality"""
        scan_id = "test-scan-003"
        progress_updates = []

        def progress_callback(progress: int, stage: str):
            progress_updates.append({"progress": progress, "stage": stage})

        with patch.object(scanner.nmap_scanner, 'scan', new_callable=AsyncMock) as mock_nmap:
            mock_nmap.return_value = {'hosts': [], 'open_ports': [], 'services': [], 'os_matches': []}

            result = await scanner.scan(sample_target, scan_id, progress_callback=progress_callback)

            # Should have received progress updates
            assert len(progress_updates) > 0
            assert progress_updates[-1]["progress"] == 100
            assert progress_updates[-1]["stage"] == "completed"

    @pytest.mark.asyncio
    async def test_scan_error_handling(self, scanner, sample_target):
        """Test scan error handling"""
        scan_id = "test-scan-004"

        # Mock scanner that raises exception
        with patch.object(scanner.nmap_scanner, 'scan', new_callable=AsyncMock) as mock_nmap:
            mock_nmap.side_effect = Exception("Network error")

            result = await scanner.scan(sample_target, scan_id)

            # Should complete scan despite error in one tool
            assert result is not None
            assert result.status in [ScanStatus.COMPLETED, ScanStatus.FAILED]


class TestScanTarget:
    """Test ScanTarget dataclass"""

    def test_webapp_target_creation(self):
        """Test web app target creation"""
        target = ScanTarget(
            url="https://example.com",
            scan_type=ScanType.WEBAPP
        )

        assert target.url == "https://example.com"
        assert target.scan_type == ScanType.WEBAPP
        assert target.network_range is None

    def test_network_target_creation(self):
        """Test network target creation"""
        target = ScanTarget(
            network_range="192.168.1.0/24",
            scan_type=ScanType.NETWORK
        )

        assert target.network_range == "192.168.1.0/24"
        assert target.scan_type == ScanType.NETWORK
        assert target.url is None


class TestVulnerability:
    """Test Vulnerability dataclass"""

    def test_vulnerability_creation(self):
        """Test vulnerability object creation"""
        vuln = Vulnerability(
            title="Test Vulnerability",
            severity="high",
            cvss_score=7.5,
            description="Test description",
            affected_url="https://example.com",
            remediation="Fix it",
            references=["https://cve.org/CVE-2024-1234"],
            tool="nuclei",
            confidence="high"
        )

        assert vuln.title == "Test Vulnerability"
        assert vuln.severity == "high"
        assert vuln.cvss_score == 7.5
        assert vuln.tool == "nuclei"

    def test_vulnerability_with_cve(self):
        """Test vulnerability with CVE ID"""
        vuln = Vulnerability(
            title="Known CVE",
            severity="critical",
            cvss_score=9.8,
            cve_id="CVE-2024-1234",
            description="Known vulnerability",
            affected_url="https://example.com",
            remediation="Patch immediately",
            references=[],
            tool="nuclei",
            confidence="high"
        )

        assert vuln.cve_id == "CVE-2024-1234"


class TestIntegration:
    """Integration tests for full scan workflow"""

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_full_scan_workflow(self):
        """Test complete scan workflow (requires actual tools)"""
        # This test should be marked with @pytest.mark.integration
        # and only run when actual scanning tools are available

        scanner = SecurityScanner()
        target = ScanTarget(
            url="http://testphp.vulnweb.com",  # Test vulnerable app
            scan_type=ScanType.WEBAPP
        )

        result = await scanner.scan(target, "integration-test-001")

        assert result is not None
        assert result.status == ScanStatus.COMPLETED
        # May or may not find vulnerabilities depending on test site
        assert isinstance(result.vulnerabilities, list)


# Test fixtures
@pytest.fixture
def sample_scan_result():
    """Create sample scan result for testing"""
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
        duration_seconds=120.5,
        risk_score=45.0
    )
