"""
Test Scanner Tools

Unit tests for nmap, nuclei, sqlmap, and nikto scanner wrappers.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock

from gtl_security_scanner.tools.nmap_scanner import NmapScanner
from gtl_security_scanner.tools.nuclei_scanner import NucleiScanner
from gtl_security_scanner.tools.sqlmap_scanner import SQLMapScanner
from gtl_security_scanner.tools.nikto_scanner import NiktoScanner


class TestNmapScanner:
    """Test Nmap scanner wrapper"""

    @pytest.fixture
    def scanner(self):
        return NmapScanner()

    def test_scanner_initialization(self, scanner):
        """Test nmap scanner initializes"""
        assert scanner is not None
        assert scanner.nmap_path == "/usr/bin/nmap"

    def test_build_command_quick_scan(self, scanner):
        """Test quick scan command building"""
        cmd = scanner._build_command("192.168.1.1", "1-1000", "quick")

        assert "/usr/bin/nmap" in cmd
        assert "192.168.1.1" in cmd
        assert "--top-ports" in cmd
        assert "100" in cmd

    def test_build_command_full_scan(self, scanner):
        """Test full scan command building"""
        cmd = scanner._build_command("192.168.1.1", "1-1000", "full")

        assert "-sV" in cmd  # Service detection
        assert "-O" in cmd   # OS detection
        assert "-sC" in cmd  # Default scripts

    @pytest.mark.asyncio
    async def test_scan_execution_mock(self, scanner):
        """Test scan execution with mocked subprocess"""
        mock_xml = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <status state="up"/>
                <address addr="192.168.1.1"/>
                <ports>
                    <port protocol="tcp" portid="80">
                        <state state="open"/>
                        <service name="http"/>
                    </port>
                </ports>
            </host>
        </nmaprun>"""

        with patch.object(scanner, '_execute_scan', new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = mock_xml

            result = await scanner.scan("192.168.1.1", "80", "quick")

            assert result is not None
            assert 'hosts' in result
            assert len(result['hosts']) > 0


class TestNucleiScanner:
    """Test Nuclei scanner wrapper"""

    @pytest.fixture
    def scanner(self):
        return NucleiScanner()

    def test_scanner_initialization(self, scanner):
        """Test nuclei scanner initializes"""
        assert scanner is not None
        assert scanner.nuclei_path == "/usr/local/bin/nuclei"

    def test_build_command(self, scanner):
        """Test nuclei command building"""
        cmd = scanner._build_command(
            "https://example.com",
            ["critical", "high"],
            ["cve", "xss"],
            None
        )

        assert "/usr/local/bin/nuclei" in cmd
        assert "-u" in cmd
        assert "https://example.com" in cmd
        assert "-json" in cmd
        assert "-severity" in cmd

    @pytest.mark.asyncio
    async def test_scan_with_findings(self, scanner):
        """Test nuclei scan with mock findings"""
        mock_jsonl = """{"template-id":"CVE-2024-1234","info":{"name":"Test Vuln","severity":"high","classification":{"cvss-score":7.5}}}"""

        with patch.object(scanner, '_execute_scan', new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = mock_jsonl

            result = await scanner.scan("https://example.com")

            assert isinstance(result, list)
            assert len(result) > 0


class TestSQLMapScanner:
    """Test SQLMap scanner wrapper"""

    @pytest.fixture
    def scanner(self):
        return SQLMapScanner()

    def test_scanner_initialization(self, scanner):
        """Test sqlmap scanner initializes"""
        assert scanner is not None
        assert scanner.sqlmap_path == "/usr/bin/sqlmap"

    def test_build_command_get(self, scanner):
        """Test GET request command"""
        cmd = scanner._build_command(
            "https://example.com/page?id=1",
            None,
            None,
            "GET"
        )

        assert "/usr/bin/sqlmap" in cmd
        assert "-u" in cmd
        assert "--batch" in cmd
        assert "https://example.com/page?id=1" in cmd

    def test_build_command_post(self, scanner):
        """Test POST request command"""
        params = {"username": "admin", "password": "test"}
        cmd = scanner._build_command(
            "https://example.com/login",
            params,
            None,
            "POST"
        )

        assert "--method=POST" in cmd
        assert "--data" in cmd

    @pytest.mark.asyncio
    async def test_scan_no_injection(self, scanner):
        """Test scan with no SQL injection found"""
        mock_output = "No SQL injection found"

        with patch.object(scanner, '_execute_scan', new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = mock_output

            result = await scanner.scan("https://example.com/page?id=1")

            assert isinstance(result, list)
            assert len(result) == 0

    @pytest.mark.asyncio
    async def test_scan_with_injection(self, scanner):
        """Test scan with SQL injection detected"""
        mock_output = """
        sqlmap identified the following injection point(s):
        Parameter: id (GET)
            Type: boolean-based blind
            Title: AND boolean-based blind
        """

        with patch.object(scanner, '_execute_scan', new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = mock_output

            result = await scanner.scan("https://example.com/page?id=1")

            assert isinstance(result, list)
            assert len(result) > 0
            assert result[0].severity == "critical"


class TestNiktoScanner:
    """Test Nikto scanner wrapper"""

    @pytest.fixture
    def scanner(self):
        return NiktoScanner()

    def test_scanner_initialization(self, scanner):
        """Test nikto scanner initializes"""
        assert scanner is not None
        assert scanner.nikto_path == "/usr/bin/nikto"

    def test_build_command_http(self, scanner):
        """Test HTTP scan command"""
        cmd = scanner._build_command("example.com", 80, False)

        assert "/usr/bin/nikto" in cmd
        assert "-h" in cmd
        assert "example.com" in cmd
        assert "-port" in cmd
        assert "80" in cmd
        assert "-Format" in cmd
        assert "csv" in cmd

    def test_build_command_https(self, scanner):
        """Test HTTPS scan command"""
        cmd = scanner._build_command("example.com", 443, True)

        assert "-ssl" in cmd

    @pytest.mark.asyncio
    async def test_scan_with_findings(self, scanner):
        """Test nikto scan with mock findings"""
        mock_csv = """"host","ip","port","osvdb","method","uri","description"
"example.com","192.168.1.1","80","3092","GET","/","Server version is outdated"
"example.com","192.168.1.1","80","3233","GET","/admin/","Directory indexing enabled"
"""

        with patch.object(scanner, '_execute_scan', new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = mock_csv

            result = await scanner.scan("example.com", 80, False)

            assert isinstance(result, list)
            assert len(result) > 0

    def test_determine_severity(self, scanner):
        """Test severity determination logic"""
        assert scanner._determine_severity("SQL injection found") == "critical"
        assert scanner._determine_severity("Vulnerable to XSS") == "high"
        assert scanner._determine_severity("Outdated software") == "medium"
        assert scanner._determine_severity("Security header missing") == "low"
        assert scanner._determine_severity("Server banner disclosed") == "low"


# Pytest configuration
pytest_plugins = ['pytest_asyncio']
