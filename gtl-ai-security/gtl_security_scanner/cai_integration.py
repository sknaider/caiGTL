"""
CAI Framework Integration

Integrates the CAI (Cybersecurity Analysis and Intelligence) framework
from Alias Robotics for robotic system security assessment.

CAI GitHub: https://github.com/aliasrobotics/cai

This module provides a wrapper around the CAI framework to enable
automated security analysis of robotic systems, IoT devices, and
industrial control systems.
"""

import logging
import subprocess
import json
import asyncio
from typing import Dict, List, Optional, Any
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CAITarget:
    """CAI scan target specification"""

    target_type: str  # robot, iot_device, plc, scada
    ip_address: str
    port: Optional[int] = None
    protocol: str = "tcp"  # tcp, udp, http, ros, mqtt
    vendor: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None


@dataclass
class CAIVulnerability:
    """CAI vulnerability finding"""

    cve_id: Optional[str]
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    cvss_score: float
    cwe_id: Optional[str]
    affected_component: str
    remediation: str
    references: List[str]
    robot_specific: bool = False  # True if robot-specific vulnerability


class CAIIntegration:
    """
    CAI Framework Integration Wrapper.

    Provides interface to CAI tools for robotic system security assessment.

    Example:
        >>> cai = CAIIntegration()
        >>> target = CAITarget(
        ...     target_type="robot",
        ...     ip_address="192.168.1.100",
        ...     protocol="ros",
        ...     vendor="Universal Robots",
        ...     model="UR5"
        ... )
        >>> results = await cai.scan(target)
    """

    def __init__(
        self,
        cai_path: Optional[str] = None,
        database_path: Optional[str] = None
    ):
        """
        Initialize CAI integration.

        Args:
            cai_path: Path to CAI installation directory
            database_path: Path to CAI vulnerability database
        """
        self.cai_path = Path(cai_path) if cai_path else Path("/opt/cai")
        self.database_path = Path(database_path) if database_path else self.cai_path / "database"

        # CAI tool paths
        self.tools = {
            "scanner": self.cai_path / "bin" / "cai-scanner",
            "analyzer": self.cai_path / "bin" / "cai-analyzer",
            "ros_scanner": self.cai_path / "bin" / "cai-ros-scanner",
        }

        logger.info(f"CAI Integration initialized: {self.cai_path}")

    async def scan(
        self,
        target: CAITarget,
        scan_type: str = "comprehensive"
    ) -> List[CAIVulnerability]:
        """
        Execute CAI security scan.

        Args:
            target: Target specification
            scan_type: Scan type (quick, comprehensive, deep)

        Returns:
            List of CAI vulnerabilities

        Raises:
            Exception: If CAI scan fails
        """
        logger.info(f"Starting CAI scan: {target.ip_address} ({target.target_type})")

        vulnerabilities = []

        try:
            # Select appropriate CAI tool based on target type
            if target.target_type == "robot" or target.protocol == "ros":
                vulnerabilities = await self._scan_robot(target, scan_type)

            elif target.target_type in ["iot_device", "plc", "scada"]:
                vulnerabilities = await self._scan_industrial(target, scan_type)

            else:
                # Generic CAI scan
                vulnerabilities = await self._scan_generic(target, scan_type)

            logger.info(f"CAI scan completed: {len(vulnerabilities)} vulnerabilities found")

            return vulnerabilities

        except Exception as e:
            logger.error(f"CAI scan failed: {e}")
            raise

    async def _scan_robot(
        self,
        target: CAITarget,
        scan_type: str
    ) -> List[CAIVulnerability]:
        """
        Scan robotic system using CAI ROS scanner.

        Args:
            target: Robot target
            scan_type: Scan intensity

        Returns:
            List of robot-specific vulnerabilities
        """
        logger.info(f"Scanning robot: {target.ip_address}")

        # Build CAI ROS scanner command
        cmd = [
            str(self.tools["ros_scanner"]),
            "--target", target.ip_address,
            "--scan-type", scan_type,
            "--output", "json",
        ]

        if target.port:
            cmd.extend(["--port", str(target.port)])

        if target.vendor:
            cmd.extend(["--vendor", target.vendor])

        if target.model:
            cmd.extend(["--model", target.model])

        # Execute scan
        output = await self._execute_cai_command(cmd)

        # Parse results
        vulnerabilities = self._parse_cai_output(output, robot_specific=True)

        return vulnerabilities

    async def _scan_industrial(
        self,
        target: CAITarget,
        scan_type: str
    ) -> List[CAIVulnerability]:
        """
        Scan industrial control system (ICS/SCADA/PLC).

        Args:
            target: Industrial system target
            scan_type: Scan intensity

        Returns:
            List of ICS-specific vulnerabilities
        """
        logger.info(f"Scanning industrial system: {target.ip_address}")

        # Build CAI ICS scanner command
        cmd = [
            str(self.tools["scanner"]),
            "--target", target.ip_address,
            "--type", target.target_type,
            "--scan-mode", scan_type,
            "--protocol", target.protocol,
            "--output", "json",
        ]

        if target.port:
            cmd.extend(["--port", str(target.port)])

        # Execute scan
        output = await self._execute_cai_command(cmd)

        # Parse results
        vulnerabilities = self._parse_cai_output(output)

        return vulnerabilities

    async def _scan_generic(
        self,
        target: CAITarget,
        scan_type: str
    ) -> List[CAIVulnerability]:
        """
        Generic CAI security scan.

        Args:
            target: Generic target
            scan_type: Scan intensity

        Returns:
            List of vulnerabilities
        """
        logger.info(f"Scanning target: {target.ip_address}")

        # Build generic scanner command
        cmd = [
            str(self.tools["scanner"]),
            "--target", target.ip_address,
            "--scan-type", scan_type,
            "--output", "json",
        ]

        if target.port:
            cmd.extend(["--port", str(target.port)])

        if target.protocol:
            cmd.extend(["--protocol", target.protocol])

        # Execute scan
        output = await self._execute_cai_command(cmd)

        # Parse results
        vulnerabilities = self._parse_cai_output(output)

        return vulnerabilities

    async def _execute_cai_command(
        self,
        cmd: List[str],
        timeout: int = 600
    ) -> str:
        """
        Execute CAI command asynchronously.

        Args:
            cmd: Command to execute
            timeout: Timeout in seconds

        Returns:
            Command output

        Raises:
            Exception: If command fails
        """
        logger.debug(f"Executing CAI command: {' '.join(cmd)}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Wait with timeout
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout
            )

            if proc.returncode != 0:
                error_msg = stderr.decode('utf-8', errors='replace')
                logger.error(f"CAI command failed: {error_msg}")
                raise Exception(f"CAI scan failed: {error_msg}")

            return stdout.decode('utf-8', errors='replace')

        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            logger.warning(f"CAI command timed out after {timeout} seconds")
            return ""

    def _parse_cai_output(
        self,
        output: str,
        robot_specific: bool = False
    ) -> List[CAIVulnerability]:
        """
        Parse CAI JSON output to extract vulnerabilities.

        Args:
            output: CAI JSON output
            robot_specific: Mark as robot-specific vulnerabilities

        Returns:
            List of CAI vulnerabilities
        """
        vulnerabilities = []

        try:
            # Parse JSON output
            data = json.loads(output)

            # Extract vulnerabilities
            findings = data.get("vulnerabilities", [])

            for finding in findings:
                vuln = CAIVulnerability(
                    cve_id=finding.get("cve_id"),
                    title=finding.get("title", "Unknown Vulnerability"),
                    description=finding.get("description", ""),
                    severity=finding.get("severity", "info").lower(),
                    cvss_score=float(finding.get("cvss_score", 0.0)),
                    cwe_id=finding.get("cwe_id"),
                    affected_component=finding.get("component", "Unknown"),
                    remediation=finding.get("remediation", "No remediation available"),
                    references=finding.get("references", []),
                    robot_specific=robot_specific
                )
                vulnerabilities.append(vuln)

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse CAI JSON output: {e}")

        except Exception as e:
            logger.error(f"Error parsing CAI output: {e}")

        return vulnerabilities

    async def analyze_robot_architecture(
        self,
        target: CAITarget
    ) -> Dict[str, Any]:
        """
        Analyze robot architecture and identify components.

        Args:
            target: Robot target

        Returns:
            Robot architecture analysis
        """
        logger.info(f"Analyzing robot architecture: {target.ip_address}")

        cmd = [
            str(self.tools["analyzer"]),
            "--target", target.ip_address,
            "--analyze-architecture",
            "--output", "json"
        ]

        if target.port:
            cmd.extend(["--port", str(target.port)])

        # Execute analysis
        output = await self._execute_cai_command(cmd)

        try:
            analysis = json.loads(output)
            return analysis

        except json.JSONDecodeError:
            logger.error("Failed to parse architecture analysis")
            return {}

    async def check_compliance(
        self,
        target: CAITarget,
        standard: str = "IEC-62443"
    ) -> Dict[str, Any]:
        """
        Check compliance against robotics security standards.

        Args:
            target: Target to check
            standard: Security standard (IEC-62443, ISO-21434, etc.)

        Returns:
            Compliance check results
        """
        logger.info(f"Checking {standard} compliance for {target.ip_address}")

        cmd = [
            str(self.tools["scanner"]),
            "--target", target.ip_address,
            "--compliance-check", standard,
            "--output", "json"
        ]

        # Execute compliance check
        output = await self._execute_cai_command(cmd)

        try:
            compliance = json.loads(output)
            return compliance

        except json.JSONDecodeError:
            logger.error("Failed to parse compliance results")
            return {
                "standard": standard,
                "status": "error",
                "checks": []
            }

    def is_installed(self) -> bool:
        """
        Check if CAI is installed and accessible.

        Returns:
            True if CAI is installed, False otherwise
        """
        return (
            self.cai_path.exists() and
            self.tools["scanner"].exists()
        )

    async def update_database(self) -> bool:
        """
        Update CAI vulnerability database.

        Returns:
            True if update successful, False otherwise
        """
        logger.info("Updating CAI vulnerability database")

        try:
            cmd = [str(self.cai_path / "bin" / "cai-update")]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                logger.info("CAI database updated successfully")
                return True
            else:
                logger.error(f"CAI database update failed: {stderr.decode()}")
                return False

        except Exception as e:
            logger.error(f"Failed to update CAI database: {e}")
            return False


# Export
__all__ = [
    "CAIIntegration",
    "CAITarget",
    "CAIVulnerability",
]
