"""
Nikto Scanner - Web Server Vulnerability Detection
Web server scanner that checks for outdated software, dangerous files, and misconfigurations.
"""

import subprocess
import asyncio
import logging
import re
import csv
import io
from typing import List, Optional

logger = logging.getLogger(__name__)


class NiktoScanner:
    """
    Nikto web server scanner wrapper.
    
    Scans web servers for:
    - Outdated server software
    - Dangerous files/CGI scripts
    - Server misconfigurations
    - Default files
    - Insecure HTTP headers
    """
    
    def __init__(self, nikto_path: str = "/usr/bin/nikto"):
        """
        Initialize Nikto scanner.
        
        Args:
            nikto_path: Path to nikto executable
        """
        self.nikto_path = nikto_path
    
    async def scan(
        self,
        target: str,
        port: int = 80,
        ssl: bool = False
    ) -> List:
        """
        Execute Nikto web server scan.
        
        Args:
            target: Target hostname or IP
            port: Port to scan (default: 80)
            ssl: Use HTTPS (default: False)
            
        Returns:
            List of Vulnerability objects for web server issues found
        """
        logger.info(f"Starting Nikto scan: target={target}, port={port}, ssl={ssl}")
        
        try:
            # Build command
            cmd = self._build_command(target, port, ssl)
            
            # Execute scan
            csv_output = await self._execute_scan(cmd)
            
            # Parse CSV output
            vulnerabilities = self._parse_output(csv_output, target)
            
            logger.info(f"Nikto scan completed: {len(vulnerabilities)} web server vulnerabilities found")
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Nikto scan failed: {e}")
            return []
    
    def _build_command(
        self,
        target: str,
        port: int,
        ssl: bool
    ) -> List[str]:
        """
        Build nikto command.
        
        Args:
            target: Target host
            port: Port number
            ssl: Use SSL
            
        Returns:
            Command as list of arguments
        """
        cmd = [
            self.nikto_path,
            "-h", target,
            "-port", str(port),
            "-Format", "csv",  # CSV output for parsing
            "-Tuning", "x",  # All tests
            "-timeout", "30",  # Request timeout
            "-maxtime", "300",  # Max scan time (5 minutes)
            "-Display", "V"  # Verbose
        ]
        
        # Add SSL flag if needed
        if ssl or port == 443:
            cmd.append("-ssl")
        
        return cmd
    
    async def _execute_scan(self, cmd: List[str]) -> str:
        """
        Execute nikto command asynchronously.
        
        Args:
            cmd: Nikto command to execute
            
        Returns:
            CSV output from nikto
        """
        logger.debug(f"Executing command: {' '.join(cmd)}")
        
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Set timeout for scan (10 minutes max)
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=600
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            logger.warning("Nikto scan timed out after 10 minutes")
            return ""
        
        return stdout.decode('utf-8', errors='replace')
    
    def _parse_output(self, csv_output: str, target: str) -> List:
        """
        Parse Nikto CSV output to extract vulnerabilities.
        
        Nikto CSV format:
        "host","ip","port","osvdb","method","uri","description"
        
        Args:
            csv_output: CSV string from nikto
            target: Target URL
            
        Returns:
            List of Vulnerability objects
        """
        from gtl_security_scanner.scanner import Vulnerability
        
        vulnerabilities = []
        
        try:
            # Parse CSV
            csv_reader = csv.DictReader(io.StringIO(csv_output))
            
            for row in csv_reader:
                # Skip header rows or invalid entries
                if not row.get('description'):
                    continue
                
                vuln = self._convert_to_vulnerability(row, target)
                if vuln:
                    vulnerabilities.append(vuln)
                    
        except Exception as e:
            logger.error(f"Failed to parse Nikto CSV output: {e}")
        
        return vulnerabilities
    
    def _convert_to_vulnerability(self, row: dict, target: str) -> Optional:
        """
        Convert Nikto CSV row to Vulnerability object.
        
        Args:
            row: CSV row dict
            target: Target URL
            
        Returns:
            Vulnerability object or None
        """
        from gtl_security_scanner.scanner import Vulnerability
        
        description = row.get('description', '').strip()
        if not description:
            return None
        
        # Extract details
        uri = row.get('uri', '/')
        method = row.get('method', 'GET')
        osvdb = row.get('osvdb', '')
        
        # Determine severity from description
        severity = self._determine_severity(description)
        cvss_score = self._severity_to_cvss(severity)
        
        # Build title from description (first sentence)
        title = description.split('.')[0][:100]
        
        # Build full URL
        port = row.get('port', '80')
        protocol = 'https' if port == '443' else 'http'
        host = row.get('host', target)
        affected_url = f"{protocol}://{host}:{port}{uri}"
        
        # Build remediation based on issue type
        remediation = self._get_remediation(description)
        
        # Build references
        references = []
        if osvdb:
            references.append(f"OSVDB-{osvdb}")
        references.append("https://cirt.net/Nikto2")
        
        return Vulnerability(
            title=title,
            severity=severity,
            cvss_score=cvss_score,
            description=description,
            affected_url=affected_url,
            affected_parameter=method,
            remediation=remediation,
            references=references,
            tool='nikto',
            confidence='medium'  # Nikto can have false positives
        )
    
    def _determine_severity(self, description: str) -> str:
        """
        Determine severity based on description keywords.
        
        Args:
            description: Nikto finding description
            
        Returns:
            Severity level
        """
        desc_lower = description.lower()
        
        # Critical indicators
        if any(word in desc_lower for word in [
            'remote code execution',
            'shell',
            'arbitrary file',
            'sql injection',
            'authentication bypass'
        ]):
            return 'critical'
        
        # High indicators
        if any(word in desc_lower for word in [
            'vulnerable',
            'exploit',
            'backdoor',
            'password',
            'credentials',
            'xss',
            'csrf'
        ]):
            return 'high'
        
        # Medium indicators
        if any(word in desc_lower for word in [
            'outdated',
            'insecure',
            'misconfigur',
            'information disclosure',
            'directory listing'
        ]):
            return 'medium'
        
        # Low/info by default
        if any(word in desc_lower for word in [
            'header',
            'cookie',
            'banner'
        ]):
            return 'low'
        
        return 'info'
    
    def _severity_to_cvss(self, severity: str) -> float:
        """Convert severity to CVSS score."""
        severity_map = {
            'critical': 9.5,
            'high': 7.5,
            'medium': 5.0,
            'low': 3.0,
            'info': 0.0
        }
        return severity_map.get(severity, 5.0)
    
    def _get_remediation(self, description: str) -> str:
        """
        Get remediation advice based on issue type.
        
        Args:
            description: Issue description
            
        Returns:
            Remediation advice
        """
        desc_lower = description.lower()
        
        if 'outdated' in desc_lower or 'old version' in desc_lower:
            return "Update the web server software to the latest stable version. "\
                   "Regularly apply security patches and monitor security advisories."
        
        if 'directory listing' in desc_lower:
            return "Disable directory listing in web server configuration. "\
                   "Add index files to all directories or configure autoindex off."
        
        if 'header' in desc_lower:
            return "Configure security headers in web server configuration. "\
                   "Add Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, etc."
        
        if 'ssl' in desc_lower or 'tls' in desc_lower:
            return "Update SSL/TLS configuration. Disable weak ciphers and protocols. "\
                   "Use TLS 1.2 or higher with strong cipher suites."
        
        if 'cookie' in desc_lower:
            return "Configure cookies with Secure, HttpOnly, and SameSite flags. "\
                   "Use secure session management practices."
        
        if 'default' in desc_lower:
            return "Remove or rename default files and directories. "\
                   "Change default credentials. Remove sample/test files."
        
        # Generic remediation
        return "Review the finding description and apply appropriate security measures. "\
               "Consult web server security guidelines and best practices."


# Export
__all__ = ['NiktoScanner']
