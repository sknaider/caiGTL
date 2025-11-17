"""
SQLMap Scanner - SQL Injection Detection
Automated SQL injection and database takeover tool wrapper.
"""

import subprocess
import asyncio
import logging
import re
from typing import List, Optional, Dict

logger = logging.getLogger(__name__)


class SQLMapScanner:
    """
    SQLMap scanner wrapper for SQL injection detection.
    
    Detects and exploits SQL injection vulnerabilities in web applications.
    """
    
    def __init__(self, sqlmap_path: str = "/usr/bin/sqlmap"):
        """
        Initialize SQLMap scanner.
        
        Args:
            sqlmap_path: Path to sqlmap executable
        """
        self.sqlmap_path = sqlmap_path
    
    async def scan(
        self,
        target: str,
        params: Optional[Dict[str, str]] = None,
        cookies: Optional[str] = None,
        method: str = "GET"
    ) -> List:
        """
        Execute sqlmap scan for SQL injection.
        
        Args:
            target: URL to test
            params: Query parameters to test
            cookies: Cookie header for authentication
            method: HTTP method (GET or POST)
            
        Returns:
            List of Vulnerability objects for SQL injections found
        """
        logger.info(f"Starting sqlmap scan: target={target}")
        
        try:
            # Build command
            cmd = self._build_command(target, params, cookies, method)
            
            # Execute scan
            output = await self._execute_scan(cmd)
            
            # Parse output
            vulnerabilities = self._parse_output(output, target)
            
            logger.info(f"SQLMap scan completed: {len(vulnerabilities)} SQL injection vulnerabilities found")
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"SQLMap scan failed: {e}")
            return []
    
    def _build_command(
        self,
        target: str,
        params: Optional[Dict[str, str]],
        cookies: Optional[str],
        method: str
    ) -> List[str]:
        """
        Build sqlmap command.
        
        Args:
            target: Target URL
            params: Parameters to test
            cookies: Cookie header
            method: HTTP method
            
        Returns:
            Command as list of arguments
        """
        cmd = [
            self.sqlmap_path,
            "-u", target,
            "--batch",  # Never ask for user input
            "--random-agent",  # Random User-Agent
            "--level=1",  # Test level (1-5, higher is more thorough)
            "--risk=1",  # Risk level (1-3, higher tests more payloads)
            "--threads=5",  # Concurrent requests
            "--timeout=30",  # Request timeout
            "--retries=2",  # Retry failed requests
            "--technique=BEUSTQ",  # All SQL injection techniques
        ]
        
        # Add method
        if method.upper() == "POST":
            cmd.extend(["--method=POST"])
        
        # Add cookies if provided
        if cookies:
            cmd.extend(["--cookie", cookies])
        
        # Add parameters to test
        if params:
            data = "&".join([f"{k}={v}" for k, v in params.items()])
            if method.upper() == "POST":
                cmd.extend(["--data", data])
            else:
                # Params already in URL for GET
                pass
        
        return cmd
    
    async def _execute_scan(self, cmd: List[str]) -> str:
        """
        Execute sqlmap command asynchronously.
        
        Args:
            cmd: SQLMap command to execute
            
        Returns:
            Text output from sqlmap
        """
        logger.debug(f"Executing command: {' '.join(cmd)}")
        
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Set timeout for scan (5 minutes max)
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=300
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            logger.warning("SQLMap scan timed out after 5 minutes")
            return ""
        
        return stdout.decode('utf-8', errors='replace')
    
    def _parse_output(self, output: str, target: str) -> List:
        """
        Parse sqlmap text output to extract SQL injection vulnerabilities.
        
        Args:
            output: SQLMap text output
            target: Target URL
            
        Returns:
            List of Vulnerability objects
        """
        from gtl_security_scanner.scanner import Vulnerability
        
        vulnerabilities = []
        
        # Check if SQL injection was found
        if "sqlmap identified the following injection" not in output.lower():
            logger.info("No SQL injection vulnerabilities found by SQLMap")
            return vulnerabilities
        
        # Extract injection details
        injection_types = self._extract_injection_types(output)
        database_info = self._extract_database_info(output)
        parameters = self._extract_vulnerable_parameters(output)
        
        # Create vulnerability for each injection type found
        for injection_type in injection_types:
            vuln = Vulnerability(
                title=f"SQL Injection - {injection_type}",
                severity="critical",  # SQL injection is always critical
                cvss_score=9.8,  # High CVSS for SQL injection
                description=f"SQL injection vulnerability detected using {injection_type} technique. "
                           f"An attacker can manipulate SQL queries to extract sensitive data, "
                           f"modify database contents, or execute arbitrary SQL commands.",
                affected_url=target,
                affected_parameter=", ".join(parameters) if parameters else "Unknown",
                proof_of_concept=f"SQLMap detected {injection_type} SQL injection. "
                                f"Database: {database_info.get('dbms', 'Unknown')}",
                remediation="1. Use parameterized queries (prepared statements) instead of string concatenation\n"
                           "2. Implement input validation and sanitization\n"
                           "3. Use ORM frameworks that handle SQL escaping\n"
                           "4. Apply principle of least privilege for database accounts\n"
                           "5. Enable WAF rules to block SQL injection attempts",
                references=[
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                    "https://cwe.mitre.org/data/definitions/89.html"
                ],
                tool='sqlmap',
                confidence='high'
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _extract_injection_types(self, output: str) -> List[str]:
        """Extract SQL injection types from output."""
        injection_types = []
        
        # Common SQLMap injection technique indicators
        patterns = [
            r'boolean-based blind',
            r'time-based blind',
            r'error-based',
            r'UNION query',
            r'stacked queries'
        ]
        
        for pattern in patterns:
            if re.search(pattern, output, re.IGNORECASE):
                injection_types.append(pattern.title())
        
        return injection_types if injection_types else ['Generic SQL Injection']
    
    def _extract_database_info(self, output: str) -> Dict[str, str]:
        """Extract database information from output."""
        info = {}
        
        # Extract DBMS type
        dbms_match = re.search(r'back-end DBMS:\s*([^\n]+)', output, re.IGNORECASE)
        if dbms_match:
            info['dbms'] = dbms_match.group(1).strip()
        
        return info
    
    def _extract_vulnerable_parameters(self, output: str) -> List[str]:
        """Extract vulnerable parameter names from output."""
        parameters = []
        
        # Look for parameter mentions
        param_match = re.findall(r'Parameter:\s*([^\s]+)', output, re.IGNORECASE)
        parameters.extend(param_match)
        
        return list(set(parameters))  # Remove duplicates


# Export
__all__ = ['SQLMapScanner']
