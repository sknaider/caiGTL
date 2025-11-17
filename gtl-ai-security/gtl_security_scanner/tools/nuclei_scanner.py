"""
Nuclei Scanner - Vulnerability Detection with Templates
Fast vulnerability scanner using community templates for CVEs, misconfigurations, etc.
"""

import subprocess
import json
import asyncio
import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


class NucleiScanner:
    """
    Nuclei vulnerability scanner wrapper.
    
    Uses YAML templates from nuclei-templates community project to detect:
    - CVEs
    - Misconfigurations
    - Exposed services
    - Security issues
    """
    
    def __init__(
        self,
        nuclei_path: str = "/usr/local/bin/nuclei",
        templates_path: str = "/opt/nuclei-templates"
    ):
        """
        Initialize Nuclei scanner.
        
        Args:
            nuclei_path: Path to nuclei binary
            templates_path: Path to nuclei templates directory
        """
        self.nuclei_path = nuclei_path
        self.templates_path = templates_path
    
    async def scan(
        self,
        target: str,
        severity: List[str] = None,
        tags: List[str] = None,
        templates: List[str] = None
    ) -> List:
        """
        Execute nuclei scan.
        
        Args:
            target: URL or IP to scan
            severity: Filter by severity (critical, high, medium, low, info)
            tags: Filter by tags (cve, misconfig, xss, sqli, etc.)
            templates: Specific template files to use
            
        Returns:
            List of Vulnerability objects
            
        Raises:
            Exception: If nuclei fails to execute
        """
        if severity is None:
            severity = ['critical', 'high', 'medium']
        
        logger.info(f"Starting nuclei scan: target={target}, severity={severity}, tags={tags}")
        
        try:
            # Build command
            cmd = self._build_command(target, severity, tags, templates)
            
            # Execute scan
            jsonl_output = await self._execute_scan(cmd)
            
            # Parse JSONL output
            vulnerabilities = self._parse_output(jsonl_output)
            
            logger.info(f"Nuclei scan completed: {len(vulnerabilities)} vulnerabilities found")
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}")
            # Return empty list instead of failing entire scan
            return []
    
    def _build_command(
        self,
        target: str,
        severity: List[str],
        tags: Optional[List[str]],
        templates: Optional[List[str]]
    ) -> List[str]:
        """
        Build nuclei command with filters.
        
        Args:
            target: Scan target
            severity: Severity levels to include
            tags: Tags to filter templates
            templates: Specific template paths
            
        Returns:
            Command as list of arguments
        """
        cmd = [
            self.nuclei_path,
            "-u", target,
            "-json",  # JSONL output
            "-silent",  # Less verbose
            "-no-color",
            "-rate-limit", "150",  # Requests per second
            "-bulk-size", "25",  # Parallel targets
            "-c", "25"  # Concurrent templates
        ]
        
        # Add templates directory if no specific templates provided
        if not templates:
            cmd.extend(["-t", self.templates_path])
        else:
            for template in templates:
                cmd.extend(["-t", template])
        
        # Add severity filter
        if severity:
            cmd.extend(["-severity", ",".join(severity)])
        
        # Add tag filters
        if tags:
            cmd.extend(["-tags", ",".join(tags)])
        
        return cmd
    
    async def _execute_scan(self, cmd: List[str]) -> str:
        """
        Execute nuclei command asynchronously.
        
        Args:
            cmd: Nuclei command to execute
            
        Returns:
            JSONL output from nuclei
        """
        logger.debug(f"Executing command: {' '.join(cmd)}")
        
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await proc.communicate()
        
        # Nuclei sometimes returns non-zero even on success
        if proc.returncode not in [0, 1]:
            error_msg = stderr.decode('utf-8', errors='replace')
            logger.warning(f"Nuclei returned code {proc.returncode}: {error_msg}")
        
        return stdout.decode('utf-8', errors='replace')
    
    def _parse_output(self, jsonl_output: str) -> List:
        """
        Parse nuclei JSONL output.
        
        Each line is a JSON object representing a finding.
        
        Args:
            jsonl_output: JSONL string from nuclei
            
        Returns:
            List of Vulnerability objects
        """
        from gtl_security_scanner.scanner import Vulnerability
        
        vulnerabilities = []
        
        for line in jsonl_output.strip().split('\n'):
            if not line or not line.strip():
                continue
            
            try:
                finding = json.loads(line)
                vuln = self._convert_to_vulnerability(finding)
                if vuln:
                    vulnerabilities.append(vuln)
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse JSON line: {e}")
                continue
        
        return vulnerabilities
    
    def _convert_to_vulnerability(self, finding: Dict) -> Optional:
        """
        Convert nuclei finding to Vulnerability object.
        
        Args:
            finding: Nuclei JSON finding
            
        Returns:
            Vulnerability object or None if invalid
        """
        from gtl_security_scanner.scanner import Vulnerability
        
        info = finding.get('info', {})
        
        # Extract basic info
        title = info.get('name', 'Unknown Vulnerability')
        severity = info.get('severity', 'info').lower()
        description = info.get('description', '')
        
        # Extract CVSS score
        cvss_score = self._extract_cvss(info)
        
        # Extract CVE IDs
        cve_id = self._extract_cve(info)
        
        # Extract affected URL
        affected_url = finding.get('matched-at') or finding.get('matched')
        
        # Extract remediation
        remediation = info.get('remediation', '')
        if not remediation and info.get('reference'):
            # Use references as remediation guidance
            remediation = f"See references: {', '.join(info.get('reference', []))}"
        
        # Extract references
        references = info.get('reference', [])
        if isinstance(references, str):
            references = [references]
        
        # Get template ID as additional reference
        template_id = finding.get('template-id', '')
        if template_id:
            references.append(f"nuclei-templates/{template_id}")
        
        return Vulnerability(
            title=title,
            severity=severity,
            cvss_score=cvss_score,
            cve_id=cve_id,
            description=description,
            affected_url=affected_url,
            remediation=remediation,
            references=references,
            tool='nuclei',
            confidence='high'  # Nuclei templates are generally reliable
        )
    
    def _extract_cvss(self, info: Dict) -> float:
        """
        Extract CVSS score from info dict.
        
        Args:
            info: Nuclei info dict
            
        Returns:
            CVSS score (0.0-10.0)
        """
        # Try classification first
        classification = info.get('classification', {})
        if isinstance(classification, dict):
            cvss_score = classification.get('cvss-score')
            if cvss_score:
                try:
                    return float(cvss_score)
                except (ValueError, TypeError):
                    pass
        
        # Map severity to CVSS if no score available
        severity = info.get('severity', 'info').lower()
        severity_to_cvss = {
            'critical': 9.5,
            'high': 7.5,
            'medium': 5.0,
            'low': 3.0,
            'info': 0.0
        }
        
        return severity_to_cvss.get(severity, 5.0)
    
    def _extract_cve(self, info: Dict) -> Optional[str]:
        """
        Extract CVE ID from info dict.
        
        Args:
            info: Nuclei info dict
            
        Returns:
            CVE ID string or None
        """
        classification = info.get('classification', {})
        
        if isinstance(classification, dict):
            cve_id = classification.get('cve-id')
            if cve_id:
                if isinstance(cve_id, list):
                    return cve_id[0] if cve_id else None
                return str(cve_id)
        
        # Check tags for CVE IDs
        tags = info.get('tags', [])
        if isinstance(tags, str):
            tags = tags.split(',')
        
        for tag in tags:
            if tag.startswith('cve-'):
                return tag.upper().replace('CVE-', 'CVE-')
        
        return None


# Export
__all__ = ['NucleiScanner']
