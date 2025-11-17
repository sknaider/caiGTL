"""
GTL Security Agents Tests

Unit and integration tests for sector-specific security agents.
"""

import pytest
import asyncio
from datetime import datetime
from dataclasses import dataclass
from typing import List

from gtl_agents import (
    LogisticsSecurityAgent,
    MedicalAIComplianceAgent,
    CustomsDataProtectionAgent,
    AgentFinding,
    FindingSeverity,
)


# Mock ScanResult for testing
@dataclass
class MockVulnerability:
    """Mock vulnerability for testing"""
    title: str
    description: str
    severity: str
    affected_url: str = "http://example.com/test"
    tool: str = "nuclei"


@dataclass
class MockService:
    """Mock service for testing"""
    port: int
    protocol: str
    service: str
    state: str = "open"


@dataclass
class MockScanResult:
    """Mock scan result for testing"""
    scan_id: str = "test-001"
    vulnerabilities: List = None
    services: List = None
    discovered_urls: List = None
    risk_score: float = 50.0

    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.services is None:
            self.services = []
        if self.discovered_urls is None:
            self.discovered_urls = []


# ===========================================
# LOGISTICS AGENT TESTS
# ===========================================

class TestLogisticsAgent:
    """Test LogisticsSecurityAgent"""

    @pytest.fixture
    def agent(self):
        return LogisticsSecurityAgent()

    @pytest.mark.asyncio
    async def test_agent_initialization(self, agent):
        """Test agent initializes correctly"""
        assert agent is not None
        assert len(agent.edi_patterns) > 0
        assert len(agent.customs_api_patterns) > 0

    @pytest.mark.asyncio
    async def test_detect_unencrypted_edi(self, agent):
        """Test detection of unencrypted EDI endpoints"""
        scan_result = MockScanResult(
            discovered_urls=["http://example.com/edi/receive", "http://example.com/as2/endpoint"]
        )

        result = await agent.analyze(scan_result)

        assert result.total_findings > 0
        assert any("Unencrypted EDI" in f.title for f in result.findings)
        assert result.findings[0].severity == FindingSeverity.CRITICAL

    @pytest.mark.asyncio
    async def test_detect_bol_exposure(self, agent):
        """Test detection of exposed Bill of Lading documents"""
        scan_result = MockScanResult(
            vulnerabilities=[
                MockVulnerability(
                    title="Directory Listing Enabled",
                    description="Directory listing allowed",
                    severity="medium",
                    affected_url="http://example.com/shipping/documents/"
                )
            ]
        )

        result = await agent.analyze(scan_result)

        assert result.total_findings > 0
        bol_findings = [f for f in result.findings if "bill of lading" in f.title.lower()]
        assert len(bol_findings) > 0

    @pytest.mark.asyncio
    async def test_calculate_business_risk(self, agent):
        """Test business risk calculation"""
        findings = [
            AgentFinding(
                title="Critical EDI Issue",
                severity=FindingSeverity.CRITICAL,
                category="EDI Security",
                description="Test",
                affected_component="test",
                business_impact="test",
                remediation="test"
            )
        ]

        risk_score = agent.calculate_business_risk_score(findings)

        assert 0.0 <= risk_score <= 100.0
        assert risk_score > 0  # Should have some risk


# ===========================================
# MEDICAL AI AGENT TESTS
# ===========================================

class TestMedicalAIAgent:
    """Test MedicalAIComplianceAgent"""

    @pytest.fixture
    def agent(self):
        return MedicalAIComplianceAgent()

    @pytest.mark.asyncio
    async def test_agent_initialization(self, agent):
        """Test agent initializes correctly"""
        assert agent is not None
        assert len(agent.phi_patterns) > 0
        assert len(agent.ai_api_patterns) > 0

    @pytest.mark.asyncio
    async def test_detect_phi_exposure(self, agent):
        """Test detection of PHI in error messages"""
        scan_result = MockScanResult(
            vulnerabilities=[
                MockVulnerability(
                    title="Error Message Disclosure",
                    description="Error: Patient MRN123456 not found. SSN: 123-45-6789",
                    severity="high",
                    affected_url="http://example.com/api/patients"
                )
            ]
        )

        result = await agent.analyze(scan_result)

        assert result.total_findings > 0
        phi_findings = [f for f in result.findings if "phi" in f.title.lower()]
        assert len(phi_findings) > 0
        assert phi_findings[0].severity == FindingSeverity.CRITICAL

    @pytest.mark.asyncio
    async def test_detect_external_ai_without_baa(self, agent):
        """Test detection of PHI sent to external AI without BAA"""
        scan_result = MockScanResult(
            discovered_urls=["https://api.openai.com/v1/chat", "https://api.anthropic.com/v1/messages"]
        )

        result = await agent.analyze(scan_result)

        assert result.total_findings > 0
        baa_findings = [f for f in result.findings if "baa" in f.title.lower()]
        assert len(baa_findings) > 0

    @pytest.mark.asyncio
    async def test_detect_open_dicom(self, agent):
        """Test detection of open DICOM server"""
        scan_result = MockScanResult(
            services=[
                MockService(port=104, protocol="tcp", service="dicom"),
                MockService(port=11112, protocol="tcp", service="dicom-pacs")
            ]
        )

        result = await agent.analyze(scan_result)

        assert result.total_findings > 0
        dicom_findings = [f for f in result.findings if "dicom" in f.title.lower()]
        assert len(dicom_findings) > 0
        assert dicom_findings[0].severity == FindingSeverity.CRITICAL


# ===========================================
# CUSTOMS AGENT TESTS
# ===========================================

class TestCustomsAgent:
    """Test CustomsDataProtectionAgent"""

    @pytest.fixture
    def agent(self):
        return CustomsDataProtectionAgent()

    @pytest.mark.asyncio
    async def test_agent_initialization(self, agent):
        """Test agent initializes correctly"""
        assert agent is not None
        assert len(agent.sunat_patterns) > 0

    @pytest.mark.asyncio
    async def test_detect_sunat_credentials(self, agent):
        """Test detection of exposed SUNAT credentials"""
        scan_result = MockScanResult(
            vulnerabilities=[
                MockVulnerability(
                    title="Configuration File Exposed",
                    description="Found clave_sol and usuario_sol in config file",
                    severity="critical",
                    affected_url="http://example.com/.env"
                )
            ]
        )

        result = await agent.analyze(scan_result)

        assert result.total_findings > 0
        sunat_findings = [f for f in result.findings if "sunat" in f.title.lower()]
        assert len(sunat_findings) > 0
        assert sunat_findings[0].severity == FindingSeverity.CRITICAL

    @pytest.mark.asyncio
    async def test_compliance_mapping(self, agent):
        """Test compliance mapping functionality"""
        finding = AgentFinding(
            title="Test Finding",
            severity=FindingSeverity.HIGH,
            category="Test",
            description="Test",
            affected_component="test",
            business_impact="test",
            remediation="test",
            compliance_violations=["SUNAT Resolución 185-2020", "Ley 29733 Article 17"]
        )

        mapping = agent.get_compliance_mapping(finding)

        assert "frameworks" in mapping
        assert len(mapping["frameworks"]) > 0
        assert "SUNAT Regulations" in mapping["frameworks"] or "Peru Data Protection Law" in mapping["frameworks"]


# ===========================================
# INTEGRATION TESTS
# ===========================================

class TestAgentIntegration:
    """Integration tests for agent system"""

    @pytest.mark.asyncio
    async def test_all_agents_run_in_parallel(self):
        """Test that all agents can run concurrently"""
        scan_result = MockScanResult(
            discovered_urls=["http://example.com/edi", "https://api.openai.com/v1"],
            vulnerabilities=[
                MockVulnerability(
                    title="Directory Listing",
                    description="Test",
                    severity="medium",
                    affected_url="http://example.com/documents/"
                )
            ]
        )

        # Run all agents in parallel
        logistics = LogisticsSecurityAgent()
        medical = MedicalAIComplianceAgent()
        customs = CustomsDataProtectionAgent()

        results = await asyncio.gather(
            logistics.analyze(scan_result),
            medical.analyze(scan_result),
            customs.analyze(scan_result)
        )

        assert len(results) == 3
        for result in results:
            assert result.analysis_duration_seconds >= 0
            assert result.total_findings >= 0


# ===========================================
# RUN TESTS
# ===========================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
