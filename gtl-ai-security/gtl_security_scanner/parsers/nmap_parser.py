"""
Nmap XML Output Parser

Parses nmap XML output into structured format.
"""

import logging
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class NmapParser:
    """Parse nmap XML output"""

    def parse(self, xml_output: str) -> Dict[str, Any]:
        """
        Parse nmap XML output.

        Args:
            xml_output: Raw XML output from nmap

        Returns:
            Structured nmap results

        Example:
            >>> parser = NmapParser()
            >>> results = parser.parse(xml_string)
            >>> print(results['hosts'][0]['ip'])
        """
        try:
            root = ET.fromstring(xml_output)

            hosts = []
            for host in root.findall("host"):
                host_data = self._parse_host(host)
                if host_data:
                    hosts.append(host_data)

            return {
                "scan_info": self._parse_scan_info(root),
                "hosts": hosts,
                "total_hosts": len(hosts),
            }

        except ET.ParseError as e:
            logger.error(f"Failed to parse nmap XML: {e}")
            return {"error": str(e), "hosts": []}

    def _parse_scan_info(self, root: ET.Element) -> Dict[str, Any]:
        """Extract scan metadata"""
        scaninfo = root.find("scaninfo")
        if scaninfo is not None:
            return {
                "type": scaninfo.get("type"),
                "protocol": scaninfo.get("protocol"),
                "numservices": scaninfo.get("numservices"),
            }
        return {}

    def _parse_host(self, host: ET.Element) -> Dict[str, Any]:
        """Parse individual host"""
        status = host.find("status")
        if status is None or status.get("state") != "up":
            return None

        # Get IP address
        address = host.find("address")
        ip = address.get("addr") if address is not None else "unknown"

        # Get hostname
        hostnames_elem = host.find("hostnames")
        hostname = None
        if hostnames_elem is not None:
            hostname_elem = hostnames_elem.find("hostname")
            if hostname_elem is not None:
                hostname = hostname_elem.get("name")

        # Parse ports
        ports = []
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                port_data = self._parse_port(port)
                if port_data:
                    ports.append(port_data)

        # Parse OS detection
        os_info = self._parse_os(host)

        return {
            "ip": ip,
            "hostname": hostname,
            "state": status.get("state"),
            "ports": ports,
            "os": os_info,
        }

    def _parse_port(self, port: ET.Element) -> Dict[str, Any]:
        """Parse port information"""
        state = port.find("state")
        service = port.find("service")

        if state is None:
            return None

        port_data = {
            "port": int(port.get("portid", 0)),
            "protocol": port.get("protocol"),
            "state": state.get("state"),
        }

        if service is not None:
            port_data["service"] = service.get("name")
            port_data["product"] = service.get("product")
            port_data["version"] = service.get("version")

        return port_data

    def _parse_os(self, host: ET.Element) -> List[Dict[str, Any]]:
        """Parse OS detection results"""
        os_list = []
        os_elem = host.find("os")

        if os_elem is not None:
            for osmatch in os_elem.findall("osmatch"):
                os_list.append(
                    {
                        "name": osmatch.get("name"),
                        "accuracy": int(osmatch.get("accuracy", 0)),
                    }
                )

        return os_list
