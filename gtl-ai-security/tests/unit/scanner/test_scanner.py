"""
Tests for Security Scanner
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import asyncio
from pathlib import Path


class TestScannerInitialization:
    """Tests for scanner initialization"""

    def test_scanner_initialization(self):
        """Test scanner initializes correctly"""
        from gtl_security_scanner.scanner import SecurityScanner

        scanner = SecurityScanner()

        assert scanner is not None
        assert scanner.results_dir.exists()
        assert isinstance(scanner.profiles, dict)

    def test_scanner_loads_profiles(self):
        """Test scanner loads profiles from YAML"""
        from gtl_security_scanner.scanner import SecurityScanner

        scanner = SecurityScanner()

        # Should have loaded some profiles
        assert len(scanner.profiles) > 0

        # Check for expected profiles
        expected_profiles = ["logistics", "medical_ai", "ecommerce", "default"]
        for profile in expected_profiles:
            if profile in scanner.profiles:
                assert isinstance(scanner.profiles[profile], dict)


class TestScanConfig:
    """Tests for scan configuration"""

    def test_scan_config_creation(self):
        """Test creating scan configuration"""
        from gtl_security_scanner.scanner import ScanConfig, ScanTarget

        config = ScanConfig(
            client_id="test-client",
            profile="logistics",
            target=ScanTarget(ip_address="192.168.1.1")
        )

        assert config.client_id == "test-client"
        assert config.profile == "logistics"
        assert config.target.ip_address == "192.168.1.1"
        assert config.scan_id is not None  # Auto-generated

    def test_scan_config_default_tools(self):
        """Test default tools configuration"""
        from gtl_security_scanner.scanner import ScanConfig, ScanTarget

        config = ScanConfig(
            client_id="test-client",
            profile="logistics",
            target=ScanTarget(ip_address="192.168.1.1")
        )

        # Default tools should be set
        assert "nmap" in config.tools_enabled
        assert "nuclei" in config.tools_enabled

    def test_scan_target_string_representation(self):
        """Test scan target string conversion"""
        from gtl_security_scanner.scanner import ScanTarget

        # Test IP address
        target1 = ScanTarget(ip_address="192.168.1.1")
        assert target1.get_target_string() == "192.168.1.1"

        # Test domain
        target2 = ScanTarget(domain="example.com")
        assert target2.get_target_string() == "example.com"

        # Test network range
        target3 = ScanTarget(network_range="192.168.1.0/24")
        assert target3.get_target_string() == "192.168.1.0/24"


class TestScanExecution:
    """Tests for scan execution"""

    @pytest.mark.asyncio
    @patch('subprocess.run')
    async def test_nmap_scan_execution(self, mock_subprocess):
        """Test nmap scan execution"""
        from gtl_security_scanner.scanner import SecurityScanner, ScanConfig, ScanTarget

        # Mock nmap output
        mock_subprocess.return_value = Mock(
            returncode=0,
            stdout='<?xml version="1.0"?><nmaprun></nmaprun>',
            stderr=''
        )

        scanner = SecurityScanner()
        config = ScanConfig(
            client_id="test-client",
            profile="logistics",
            target=ScanTarget(ip_address="192.168.1.1"),
            tools_enabled={"nmap": True}
        )

        profile = scanner.profiles.get("logistics", scanner.profiles.get("default"))
        result = await scanner._run_nmap(config, profile)

        # Should have called subprocess
        mock_subprocess.assert_called_once()
        assert result is not None

    @pytest.mark.asyncio
    @patch('subprocess.run')
    async def test_nmap_scan_timeout(self, mock_subprocess):
        """Test nmap scan handles timeout"""
        import subprocess
        from gtl_security_scanner.scanner import SecurityScanner, ScanConfig, ScanTarget

        # Mock timeout
        mock_subprocess.side_effect = subprocess.TimeoutExpired(
            cmd='nmap', timeout=60
        )

        scanner = SecurityScanner()
        config = ScanConfig(
            client_id="test-client",
            profile="logistics",
            target=ScanTarget(ip_address="192.168.1.1"),
            timeout_minutes=1
        )

        profile = scanner.profiles.get("logistics", scanner.profiles.get("default"))

        with pytest.raises(RuntimeError, match="timed out"):
            await scanner._run_nmap(config, profile)

    @pytest.mark.asyncio
    async def test_scan_result_structure(self):
        """Test scan result has correct structure"""
        from gtl_security_scanner.scanner import ScanResult

        result = ScanResult(
            scan_id="test-scan",
            client_id="test-client",
            status="completed"
        )

        assert result.scan_id == "test-scan"
        assert result.client_id == "test-client"
        assert result.status == "completed"
        assert isinstance(result.findings, list)
        assert isinstance(result.tool_outputs, dict)

    @pytest.mark.asyncio
    @patch('gtl_security_scanner.scanner.SecurityScanner._run_nmap')
    @patch('gtl_security_scanner.scanner.SecurityScanner._run_nuclei')
    async def test_parallel_tool_execution(self, mock_nuclei, mock_nmap):
        """Test that multiple tools run in parallel"""
        from gtl_security_scanner.scanner import SecurityScanner, ScanConfig, ScanTarget

        # Mock tool outputs
        mock_nmap.return_value = {"hosts": []}
        mock_nuclei.return_value = {"vulnerabilities": []}

        scanner = SecurityScanner()
        config = ScanConfig(
            client_id="test-client",
            profile="logistics",
            target=ScanTarget(ip_address="192.168.1.1"),
            tools_enabled={"nmap": True, "nuclei": True}
        )

        result = await scanner.run_scan(config)

        # Both tools should have been called
        mock_nmap.assert_called_once()
        mock_nuclei.assert_called_once()

        assert result.status == "completed"


class TestFindingsExtraction:
    """Tests for findings extraction"""

    def test_extract_nmap_findings(self):
        """Test extracting findings from nmap output"""
        from gtl_security_scanner.scanner import SecurityScanner

        scanner = SecurityScanner()

        nmap_output = {
            "hosts": [
                {
                    "ip": "192.168.1.1",
                    "ports": [
                        {
                            "port": 22,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "ssh"
                        },
                        {
                            "port": 80,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "http"
                        }
                    ]
                }
            ]
        }

        findings = scanner._extract_findings("nmap", nmap_output)

        assert len(findings) == 2
        assert findings[0]["type"] == "open_port"
        assert findings[0]["port"] == 22
        assert findings[1]["port"] == 80

    def test_extract_nuclei_findings(self):
        """Test extracting findings from nuclei output"""
        from gtl_security_scanner.scanner import SecurityScanner

        scanner = SecurityScanner()

        nuclei_output = {
            "vulnerabilities": [
                {
                    "name": "Apache Struts RCE",
                    "severity": "critical",
                    "description": "Remote code execution",
                    "cve": ["CVE-2017-5638"],
                    "cvss_score": 9.8
                }
            ]
        }

        findings = scanner._extract_findings("nuclei", nuclei_output)

        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"
        assert "CVE-2017-5638" in findings[0]["cve"]

    def test_extract_sqlmap_findings(self):
        """Test extracting findings from sqlmap output"""
        from gtl_security_scanner.scanner import SecurityScanner

        scanner = SecurityScanner()

        sqlmap_output = {
            "output": "Parameter 'id' is vulnerable to SQL injection",
            "sql_injection_found": True
        }

        findings = scanner._extract_findings("sqlmap", sqlmap_output)

        assert len(findings) == 1
        assert findings[0]["type"] == "sql_injection"
        assert findings[0]["severity"] == "critical"


class TestResultsSaving:
    """Tests for saving scan results"""

    @pytest.mark.asyncio
    async def test_save_results_to_disk(self, tmp_path):
        """Test saving scan results to disk"""
        from gtl_security_scanner.scanner import SecurityScanner, ScanResult
        from datetime import datetime
        import json

        # Create scanner with temp directory
        scanner = SecurityScanner(results_dir=str(tmp_path))

        result = ScanResult(
            scan_id="test-scan-001",
            client_id="test-client",
            status="completed",
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow()
        )

        scanner._save_results(result)

        # Check file was created
        expected_file = tmp_path / "test-client" / "test-scan-001.json"
        assert expected_file.exists()

        # Verify content
        with open(expected_file) as f:
            saved_data = json.load(f)

        assert saved_data["scan_id"] == "test-scan-001"
        assert saved_data["client_id"] == "test-client"
        assert saved_data["status"] == "completed"


class TestErrorHandling:
    """Tests for error handling"""

    @pytest.mark.asyncio
    @patch('subprocess.run')
    async def test_tool_failure_doesnt_crash_scan(self, mock_subprocess):
        """Test that one tool failing doesn't crash entire scan"""
        from gtl_security_scanner.scanner import SecurityScanner, ScanConfig, ScanTarget

        # Mock nmap failure
        mock_subprocess.side_effect = RuntimeError("Tool failed")

        scanner = SecurityScanner()
        config = ScanConfig(
            client_id="test-client",
            profile="logistics",
            target=ScanTarget(ip_address="192.168.1.1"),
            tools_enabled={"nmap": True}
        )

        # Should handle error gracefully
        result = await scanner.run_scan(config)

        # Scan should complete but with error recorded
        assert result.status in ["completed", "failed"]
        if result.status == "failed":
            assert result.error is not None

    @pytest.mark.asyncio
    async def test_invalid_profile_raises_error(self):
        """Test that invalid profile raises error"""
        from gtl_security_scanner.scanner import SecurityScanner, ScanConfig, ScanTarget

        scanner = SecurityScanner()
        config = ScanConfig(
            client_id="test-client",
            profile="nonexistent-profile",
            target=ScanTarget(ip_address="192.168.1.1")
        )

        result = await scanner.run_scan(config)

        # Should fail with error
        assert result.status == "failed"
        assert "not found" in result.error.lower()
