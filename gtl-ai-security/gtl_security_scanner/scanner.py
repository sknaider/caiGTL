"""
GTL Security Scanner - Main Scanner Orchestrator

Coordinates vulnerability scanning using multiple security tools:
- nmap (network scanning)
- nuclei (vulnerability scanning)
- nikto (web server scanning)
- sqlmap (SQL injection testing)
- CAI agents (AI-powered analysis)
"""

import asyncio
import json
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

import yaml
from pydantic import BaseModel, Field

# CAI Framework imports
from cai.sdk.agents import Agent, Runner

# Local imports
from .parsers.nmap_parser import NmapParser
from .parsers.nuclei_parser import NucleiParser

# Configure logging
logger = logging.getLogger(__name__)


# ===========================================
# DATA MODELS
# ===========================================


class ScanTarget(BaseModel):
    """Target system for security scanning"""

    ip_address: Optional[str] = None
    domain: Optional[str] = None
    network_range: Optional[str] = None
    ports: Optional[List[int]] = None

    def get_target_string(self) -> str:
        """Get target as string for command-line tools"""
        return self.ip_address or self.domain or self.network_range or "127.0.0.1"


class ScanConfig(BaseModel):
    """Scan configuration"""

    scan_id: str = Field(default_factory=lambda: str(uuid4()))
    client_id: str
    profile: str = "default"  # From scanner_profiles.yaml
    target: ScanTarget
    tools_enabled: Dict[str, bool] = Field(
        default_factory=lambda: {
            "nmap": True,
            "nuclei": True,
            "nikto": False,
            "sqlmap": False,
        }
    )
    timeout_minutes: int = 30
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ScanResult(BaseModel):
    """Results from a security scan"""

    scan_id: str
    client_id: str
    status: str  # pending, running, completed, failed
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    tool_outputs: Dict[str, Any] = Field(default_factory=dict)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    error: Optional[str] = None


# ===========================================
# SECURITY SCANNER
# ===========================================


class SecurityScanner:
    """
    Main security scanner orchestrator.

    Coordinates multiple security tools and CAI agents to perform
    comprehensive vulnerability assessments.

    Example:
        >>> scanner = SecurityScanner()
        >>> config = ScanConfig(
        ...     client_id="logistics_company_1",
        ...     profile="logistics",
        ...     target=ScanTarget(network_range="192.168.1.0/24")
        ... )
        >>> result = await scanner.run_scan(config)
        >>> print(f"Found {len(result.findings)} vulnerabilities")
    """

    def __init__(
        self,
        config_path: str = "config/scanner_profiles.yaml",
        results_dir: str = "scan_results",
    ):
        """
        Initialize security scanner.

        Args:
            config_path: Path to scanner profiles configuration
            results_dir: Directory to store scan results
        """
        self.config_path = Path(config_path)
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)

        # Load scanner profiles
        self.profiles = self._load_profiles()

        logger.info("SecurityScanner initialized")

    def _load_profiles(self) -> Dict[str, Any]:
        """Load scanner profiles from YAML config"""
        try:
            with open(self.config_path, "r") as f:
                profiles = yaml.safe_load(f)
            logger.info(f"Loaded {len(profiles)} scanner profiles")
            return profiles
        except Exception as e:
            logger.error(f"Failed to load scanner profiles: {e}")
            return {}

    async def run_scan(self, config: ScanConfig) -> ScanResult:
        """
        Run comprehensive security scan.

        Args:
            config: Scan configuration

        Returns:
            ScanResult with findings from all tools

        Raises:
            RuntimeError: If scan fails
        """
        logger.info(f"Starting scan {config.scan_id} for client {config.client_id}")

        result = ScanResult(
            scan_id=config.scan_id,
            client_id=config.client_id,
            status="running",
            started_at=datetime.utcnow(),
        )

        try:
            # Get profile configuration
            profile = self.profiles.get(config.profile, self.profiles.get("default"))
            if not profile:
                raise ValueError(f"Profile '{config.profile}' not found")

            # Run enabled tools in parallel
            tasks = []

            if config.tools_enabled.get("nmap", False):
                tasks.append(self._run_nmap(config, profile))

            if config.tools_enabled.get("nuclei", False):
                tasks.append(self._run_nuclei(config, profile))

            if config.tools_enabled.get("nikto", False):
                tasks.append(self._run_nikto(config, profile))

            if config.tools_enabled.get("sqlmap", False):
                tasks.append(self._run_sqlmap(config, profile))

            # Execute all tools concurrently
            tool_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Collect results
            for i, tool_name in enumerate(["nmap", "nuclei", "nikto", "sqlmap"]):
                if i < len(tool_results):
                    tool_result = tool_results[i]
                    if isinstance(tool_result, Exception):
                        logger.error(f"{tool_name} failed: {tool_result}")
                        result.tool_outputs[tool_name] = {"error": str(tool_result)}
                    else:
                        result.tool_outputs[tool_name] = tool_result
                        # Extract findings
                        findings = self._extract_findings(tool_name, tool_result)
                        result.findings.extend(findings)

            # Mark as completed
            result.status = "completed"
            result.completed_at = datetime.utcnow()
            result.duration_seconds = int(
                (result.completed_at - result.started_at).total_seconds()
            )

            # Save results to disk
            self._save_results(result)

            logger.info(
                f"Scan {config.scan_id} completed with {len(result.findings)} findings"
            )

        except Exception as e:
            logger.error(f"Scan {config.scan_id} failed: {e}")
            result.status = "failed"
            result.error = str(e)
            result.completed_at = datetime.utcnow()

        return result

    async def _run_nmap(self, config: ScanConfig, profile: Dict) -> Dict[str, Any]:
        """
        Run nmap network scanner.

        Args:
            config: Scan configuration
            profile: Scanner profile

        Returns:
            Parsed nmap results
        """
        logger.info(f"Running nmap for scan {config.scan_id}")

        nmap_config = profile.get("tools", {}).get("nmap", {})
        args = nmap_config.get("args", "-sV -sC")
        target = config.target.get_target_string()

        # Build nmap command
        cmd = f"nmap {args} -oX - {target}"

        try:
            # Execute nmap
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=config.timeout_minutes * 60,
            )

            if result.returncode != 0:
                raise RuntimeError(f"nmap failed: {result.stderr}")

            # Parse XML output
            parser = NmapParser()
            parsed = parser.parse(result.stdout)

            logger.info(f"nmap completed for scan {config.scan_id}")
            return parsed

        except subprocess.TimeoutExpired:
            logger.error(f"nmap timeout for scan {config.scan_id}")
            raise RuntimeError("nmap scan timed out")
        except Exception as e:
            logger.error(f"nmap error: {e}")
            raise

    async def _run_nuclei(self, config: ScanConfig, profile: Dict) -> Dict[str, Any]:
        """
        Run nuclei vulnerability scanner.

        Args:
            config: Scan configuration
            profile: Scanner profile

        Returns:
            Parsed nuclei results
        """
        logger.info(f"Running nuclei for scan {config.scan_id}")

        nuclei_config = profile.get("tools", {}).get("nuclei", {})
        templates = nuclei_config.get("templates", ["cves", "exposures"])
        severity = nuclei_config.get("severity", ["critical", "high"])
        target = config.target.get_target_string()

        # Build nuclei command
        template_args = " ".join([f"-t {t}" for t in templates])
        severity_args = " ".join([f"-s {s}" for s in severity])
        cmd = f"nuclei -u {target} {template_args} {severity_args} -json -silent"

        try:
            # Execute nuclei
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=config.timeout_minutes * 60,
            )

            # Nuclei returns findings via stdout as JSON lines
            parser = NucleiParser()
            parsed = parser.parse(result.stdout)

            logger.info(f"nuclei completed for scan {config.scan_id}")
            return parsed

        except subprocess.TimeoutExpired:
            logger.error(f"nuclei timeout for scan {config.scan_id}")
            raise RuntimeError("nuclei scan timed out")
        except Exception as e:
            logger.error(f"nuclei error: {e}")
            raise

    async def _run_nikto(self, config: ScanConfig, profile: Dict) -> Dict[str, Any]:
        """
        Run nikto web server scanner.

        Args:
            config: Scan configuration
            profile: Scanner profile

        Returns:
            Parsed nikto results
        """
        logger.info(f"Running nikto for scan {config.scan_id}")

        target = config.target.get_target_string()
        nikto_config = profile.get("tools", {}).get("nikto", {})
        plugins = nikto_config.get("plugins", "all")

        # Build nikto command
        cmd = f"nikto -h {target} -Format json -output -"

        try:
            # Execute nikto
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=config.timeout_minutes * 60,
            )

            # Parse JSON output
            if result.stdout.strip():
                parsed = json.loads(result.stdout)
            else:
                parsed = {"vulnerabilities": []}

            logger.info(f"nikto completed for scan {config.scan_id}")
            return parsed

        except subprocess.TimeoutExpired:
            logger.error(f"nikto timeout for scan {config.scan_id}")
            raise RuntimeError("nikto scan timed out")
        except Exception as e:
            logger.error(f"nikto error: {e}")
            raise

    async def _run_sqlmap(self, config: ScanConfig, profile: Dict) -> Dict[str, Any]:
        """
        Run sqlmap SQL injection scanner.

        Args:
            config: Scan configuration
            profile: Scanner profile

        Returns:
            Parsed sqlmap results
        """
        logger.info(f"Running sqlmap for scan {config.scan_id}")

        target = config.target.get_target_string()
        sqlmap_config = profile.get("tools", {}).get("sqlmap", {})
        level = sqlmap_config.get("level", 1)
        risk = sqlmap_config.get("risk", 1)

        # Build sqlmap command
        # Note: This is a simplified example. In production, you'd want to
        # target specific URLs with parameters
        cmd = f"sqlmap -u http://{target} --batch --level={level} --risk={risk} --output-dir=/tmp/sqlmap_{config.scan_id}"

        try:
            # Execute sqlmap
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=config.timeout_minutes * 60,
            )

            # Parse output (sqlmap doesn't have structured JSON output by default)
            parsed = {
                "output": result.stdout,
                "sql_injection_found": "injectable" in result.stdout.lower(),
            }

            logger.info(f"sqlmap completed for scan {config.scan_id}")
            return parsed

        except subprocess.TimeoutExpired:
            logger.error(f"sqlmap timeout for scan {config.scan_id}")
            raise RuntimeError("sqlmap scan timed out")
        except Exception as e:
            logger.error(f"sqlmap error: {e}")
            raise

    def _extract_findings(
        self, tool_name: str, tool_output: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Extract standardized findings from tool output.

        Args:
            tool_name: Name of the tool
            tool_output: Raw tool output

        Returns:
            List of standardized findings
        """
        findings = []

        if tool_name == "nmap":
            # Extract findings from nmap
            for host in tool_output.get("hosts", []):
                for port in host.get("ports", []):
                    if port.get("state") == "open":
                        findings.append(
                            {
                                "source": "nmap",
                                "type": "open_port",
                                "severity": "info",
                                "title": f"Open Port: {port.get('port')}/{port.get('protocol')}",
                                "description": f"Service: {port.get('service', 'unknown')}",
                                "host": host.get("ip"),
                                "port": port.get("port"),
                            }
                        )

        elif tool_name == "nuclei":
            # Extract findings from nuclei
            for vuln in tool_output.get("vulnerabilities", []):
                findings.append(
                    {
                        "source": "nuclei",
                        "type": "vulnerability",
                        "severity": vuln.get("severity", "info"),
                        "title": vuln.get("name", "Unknown Vulnerability"),
                        "description": vuln.get("description", ""),
                        "cve": vuln.get("cve", []),
                        "cvss_score": vuln.get("cvss_score"),
                    }
                )

        elif tool_name == "nikto":
            # Extract findings from nikto
            for vuln in tool_output.get("vulnerabilities", []):
                findings.append(
                    {
                        "source": "nikto",
                        "type": "web_vulnerability",
                        "severity": "medium",  # Nikto doesn't provide severity
                        "title": vuln.get("msg", "Web Server Issue"),
                        "description": vuln.get("msg", ""),
                        "url": vuln.get("url", ""),
                    }
                )

        elif tool_name == "sqlmap":
            # Extract findings from sqlmap
            if tool_output.get("sql_injection_found"):
                findings.append(
                    {
                        "source": "sqlmap",
                        "type": "sql_injection",
                        "severity": "critical",
                        "title": "SQL Injection Vulnerability",
                        "description": "SQLMap detected SQL injection vulnerability",
                    }
                )

        return findings

    def _save_results(self, result: ScanResult) -> None:
        """
        Save scan results to disk.

        Args:
            result: Scan result to save
        """
        try:
            # Create client directory
            client_dir = self.results_dir / result.client_id
            client_dir.mkdir(parents=True, exist_ok=True)

            # Save as JSON
            result_file = client_dir / f"{result.scan_id}.json"
            with open(result_file, "w") as f:
                json.dump(result.model_dump(), f, indent=2, default=str)

            logger.info(f"Saved scan results to {result_file}")

        except Exception as e:
            logger.error(f"Failed to save scan results: {e}")


# ===========================================
# EXAMPLE USAGE
# ===========================================

if __name__ == "__main__":
    import asyncio

    async def main():
        # Initialize scanner
        scanner = SecurityScanner()

        # Configure scan
        config = ScanConfig(
            client_id="logistics_company_1",
            profile="logistics",
            target=ScanTarget(network_range="127.0.0.1"),  # Scan localhost for demo
            tools_enabled={
                "nmap": True,
                "nuclei": False,  # Requires nuclei to be installed
                "nikto": False,  # Requires nikto to be installed
                "sqlmap": False,  # Too aggressive for demo
            },
        )

        # Run scan
        result = await scanner.run_scan(config)

        # Print results
        print(f"\nScan {result.scan_id} - Status: {result.status}")
        print(f"Findings: {len(result.findings)}")
        print(f"Duration: {result.duration_seconds} seconds\n")

        for finding in result.findings[:5]:  # Show first 5 findings
            print(f"[{finding['severity'].upper()}] {finding['title']}")
            print(f"  Source: {finding['source']}")
            print(f"  {finding['description']}\n")

    asyncio.run(main())
