"""
Nmap Scanner - Network Discovery and Port Scanning
Wrapper for Nmap network scanner with XML output parsing.
"""

import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
import asyncio
import logging

logger = logging.getLogger(__name__)


class NmapScanner:
    """
    Nmap scanner wrapper for network discovery and service enumeration.
    
    Executes nmap scans with various options and parses XML output.
    """
    
    def __init__(self, nmap_path: str = "/usr/bin/nmap"):
        """
        Initialize Nmap scanner.
        
        Args:
            nmap_path: Path to nmap binary
        """
        self.nmap_path = nmap_path
    
    async def scan(
        self,
        target: str,
        ports: str = "1-1000",
        scan_type: str = "normal"
    ) -> Dict:
        """
        Execute nmap scan.
        
        Args:
            target: IP address, hostname, or CIDR range
            ports: Port range (e.g., "1-65535", "80,443,8080")
            scan_type: "quick" | "normal" | "full" | "stealth"
            
        Returns:
            Parsed scan results with hosts, ports, services, OS detection
            
        Raises:
            Exception: If nmap fails to execute
        """
        logger.info(f"Starting nmap scan: target={target}, ports={ports}, type={scan_type}")
        
        try:
            # Build command
            cmd = self._build_command(target, ports, scan_type)
            
            # Execute scan
            xml_output = await self._execute_scan(cmd)
            
            # Parse XML results
            results = self._parse_xml(xml_output)
            
            logger.info(f"Nmap scan completed: {len(results['hosts'])} hosts, {len(results['open_ports'])} open ports")
            
            return results
            
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            raise
    
    def _build_command(self, target: str, ports: str, scan_type: str) -> List[str]:
        """
        Build nmap command based on scan type.
        
        Args:
            target: Scan target
            ports: Port range
            scan_type: Scan speed/depth
            
        Returns:
            List of command arguments
        """
        base_cmd = [self.nmap_path, "-oX", "-"]  # XML output to stdout
        
        if scan_type == "quick":
            # Fast scan: top 100 ports, no service detection
            cmd = base_cmd + [
                "-T4",  # Aggressive timing
                "--top-ports", "100",
                target
            ]
            
        elif scan_type == "stealth":
            # Stealth scan: SYN scan, no ping
            cmd = base_cmd + [
                "-sS",  # SYN stealth scan
                "-Pn",  # No ping (skip host discovery)
                "-p", ports,
                target
            ]
            
        elif scan_type == "full":
            # Comprehensive scan: all ports, OS detection, scripts
            cmd = base_cmd + [
                "-sV",  # Service/version detection
                "-O",   # OS detection
                "-sC",  # Default NSE scripts
                "--osscan-guess",  # Guess OS more aggressively
                "-p", ports,
                "-T3",  # Normal timing
                target
            ]
            
        else:  # normal
            # Balanced scan: common ports, service detection
            cmd = base_cmd + [
                "-sV",  # Service version detection
                "-sC",  # Default scripts
                "-p", ports,
                "-T4",  # Faster timing
                target
            ]
        
        return cmd
    
    async def _execute_scan(self, cmd: List[str]) -> str:
        """
        Execute nmap command asynchronously.
        
        Args:
            cmd: Nmap command to execute
            
        Returns:
            XML output from nmap
            
        Raises:
            Exception: If nmap returns non-zero exit code
        """
        logger.debug(f"Executing command: {' '.join(cmd)}")
        
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await proc.communicate()
        
        if proc.returncode != 0:
            error_msg = stderr.decode('utf-8', errors='replace')
            logger.error(f"Nmap failed with code {proc.returncode}: {error_msg}")
            raise Exception(f"Nmap scan failed: {error_msg}")
        
        return stdout.decode('utf-8', errors='replace')
    
    def _parse_xml(self, xml_output: str) -> Dict:
        """
        Parse nmap XML output into structured dict.
        
        Args:
            xml_output: XML string from nmap -oX output
            
        Returns:
            Dictionary with hosts, ports, services, OS matches
        """
        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError as e:
            logger.error(f"Failed to parse nmap XML: {e}")
            return self._empty_results()
        
        results = {
            'hosts': [],
            'open_ports': [],
            'services': [],
            'os_matches': []
        }
        
        # Parse each host
        for host_elem in root.findall('host'):
            host_info = self._parse_host(host_elem)
            
            if host_info:
                results['hosts'].append(host_info)
                results['open_ports'].extend(host_info.get('ports', []))
                results['services'].extend(host_info.get('services', []))
        
        # Parse OS detection (usually in first host)
        for osmatch in root.findall('.//osmatch'):
            results['os_matches'].append({
                'name': osmatch.get('name', 'Unknown'),
                'accuracy': int(osmatch.get('accuracy', 0))
            })
        
        return results
    
    def _parse_host(self, host_elem) -> Optional[Dict]:
        """
        Parse individual host element from nmap XML.
        
        Args:
            host_elem: XML Element for host
            
        Returns:
            Dictionary with host information
        """
        # Get host status
        status_elem = host_elem.find('status')
        if status_elem is None or status_elem.get('state') != 'up':
            return None
        
        # Get IP address
        address_elem = host_elem.find('address')
        ip_address = address_elem.get('addr') if address_elem is not None else 'unknown'
        
        # Get hostname
        hostname = None
        hostnames_elem = host_elem.find('hostnames')
        if hostnames_elem is not None:
            hostname_elem = hostnames_elem.find('hostname')
            if hostname_elem is not None:
                hostname = hostname_elem.get('name')
        
        host_info = {
            'ip_address': ip_address,
            'hostname': hostname,
            'status': 'up',
            'ports': [],
            'services': []
        }
        
        # Parse ports
        ports_elem = host_elem.find('ports')
        if ports_elem is not None:
            for port_elem in ports_elem.findall('port'):
                port_info = self._parse_port(port_elem, ip_address)
                if port_info:
                    host_info['ports'].append(port_info)
                    
                    # Extract service info
                    service_info = self._extract_service(port_elem, ip_address)
                    if service_info:
                        host_info['services'].append(service_info)
        
        return host_info
    
    def _parse_port(self, port_elem, ip_address: str) -> Optional[Dict]:
        """Parse port element."""
        state_elem = port_elem.find('state')
        if state_elem is None or state_elem.get('state') != 'open':
            return None
        
        port_id = int(port_elem.get('portid', 0))
        protocol = port_elem.get('protocol', 'tcp')
        
        # Get service info
        service_elem = port_elem.find('service')
        service_name = 'unknown'
        service_product = None
        service_version = None
        
        if service_elem is not None:
            service_name = service_elem.get('name', 'unknown')
            service_product = service_elem.get('product')
            service_version = service_elem.get('version')
        
        return {
            'ip_address': ip_address,
            'port': port_id,
            'protocol': protocol,
            'state': 'open',
            'service': service_name,
            'product': service_product,
            'version': service_version
        }
    
    def _extract_service(self, port_elem, ip_address: str) -> Optional[Dict]:
        """Extract service information for vulnerability scanning."""
        service_elem = port_elem.find('service')
        if service_elem is None:
            return None
        
        port_id = int(port_elem.get('portid', 0))
        protocol = port_elem.get('protocol', 'tcp')
        service_name = service_elem.get('name', 'unknown')
        
        # Build version string if available
        version_parts = []
        if service_elem.get('product'):
            version_parts.append(service_elem.get('product'))
        if service_elem.get('version'):
            version_parts.append(service_elem.get('version'))
        
        version = ' '.join(version_parts) if version_parts else None
        
        return {
            'port': port_id,
            'protocol': protocol,
            'service': service_name,
            'version': version,
            'state': 'open'
        }
    
    def _empty_results(self) -> Dict:
        """Return empty results structure."""
        return {
            'hosts': [],
            'open_ports': [],
            'services': [],
            'os_matches': []
        }


# Export
__all__ = ['NmapScanner']
