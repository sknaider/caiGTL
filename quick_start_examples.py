#!/usr/bin/env python3
"""
CAI Framework - Quick Start Examples for GTL AI Security Platform

This file contains 3 working examples to get started with CAI:
1. Basic Security Agent - Simple agent with built-in tools
2. Custom Tool Integration - Create and use custom security tools
3. Multi-Agent Coordination - Orchestrate specialist agents

Requirements:
    - CAI Framework installed (pip install cai-framework)
    - Environment variables set (OPENAI_API_KEY or DEEPSEEK_API_KEY)
    - Python 3.9+

Usage:
    # Run all examples
    python quick_start_examples.py

    # Run specific example
    python quick_start_examples.py --example 1
    python quick_start_examples.py --example 2
    python quick_start_examples.py --example 3

Author: GTL AI Security Platform
Version: 1.0.0
Date: November 2025
"""

import asyncio
import os
import sys
from typing import List

# Import CAI Framework components
try:
    from cai.sdk.agents import Agent, Runner, function_tool, handoff, OpenAIChatCompletionsModel
    from openai import AsyncOpenAI
    from pydantic import BaseModel
except ImportError as e:
    print(f"❌ Error importing CAI Framework: {e}")
    print("\n📦 Please install CAI Framework:")
    print("   pip install cai-framework\n")
    sys.exit(1)


# ============================================================================
# EXAMPLE 1: BASIC SECURITY AGENT
# ============================================================================

async def example_1_basic_security_agent():
    """
    Example 1: Basic Security Agent with Built-in Tools

    This example demonstrates:
    - Creating a simple security agent
    - Using CAI's built-in reconnaissance tools
    - Running the agent with a security assessment task

    Use Case: Quick security assessment using nmap
    """
    print("\n" + "="*70)
    print("EXAMPLE 1: Basic Security Agent")
    print("="*70)

    # Import built-in tools
    from cai.tools.reconnaissance.generic_linux_command import generic_linux_command

    # Create a basic security agent
    security_agent = Agent(
        name="Basic Security Agent",
        instructions="""You are a cybersecurity expert.

Use the generic_linux_command tool to perform security assessments.

When asked to scan a target:
1. First check if the target is reachable (ping)
2. Then scan for open ports
3. Summarize the findings

IMPORTANT: Only scan localhost or targets you have permission to test.""",
        tools=[generic_linux_command],
        model=OpenAIChatCompletionsModel(
            model=os.getenv('CAI_MODEL', 'alias0'),
            openai_client=AsyncOpenAI(),
        )
    )

    # Run security assessment
    print("\n📊 Running security assessment on localhost...")
    print("⏳ This may take a few seconds...\n")

    try:
        result = await Runner.run(
            security_agent,
            input="Scan localhost (127.0.0.1) for open ports. Use appropriate commands.",
            stream=False
        )

        print("✅ Assessment Complete!\n")
        print("📝 Results:")
        print("-" * 70)
        print(result.final_output)
        print("-" * 70)

        # Show usage statistics
        if hasattr(result, 'usage'):
            print(f"\n📊 Token Usage:")
            print(f"   Input tokens: {result.usage.input_tokens}")
            print(f"   Output tokens: {result.usage.output_tokens}")
            if hasattr(result, 'cost'):
                print(f"   Estimated cost: ${result.cost:.4f}")

    except Exception as e:
        print(f"❌ Error running security assessment: {e}")
        print("💡 Make sure you have API keys configured in .env file")


# ============================================================================
# EXAMPLE 2: CUSTOM TOOL INTEGRATION
# ============================================================================

async def example_2_custom_tool_integration():
    """
    Example 2: Custom Security Tool Integration

    This example demonstrates:
    - Creating custom security tools with @function_tool decorator
    - Using Pydantic models for structured output
    - Integrating custom tools with agents

    Use Case: GTL-specific logistics security checks
    """
    print("\n" + "="*70)
    print("EXAMPLE 2: Custom Tool Integration (GTL Logistics)")
    print("="*70)

    # Define custom data models
    class VulnerabilityReport(BaseModel):
        severity: str
        cvss_score: float
        description: str
        affected_component: str
        remediation: str

    class LogisticsSystemScan(BaseModel):
        system_name: str
        ip_address: str
        system_type: str
        vulnerabilities_found: int
        critical_issues: List[str]
        recommendations: List[str]

    # Create custom tool #1: Check for common logistics software vulnerabilities
    @function_tool
    def check_logistics_vulnerability(system_type: str, version: str) -> VulnerabilityReport:
        """
        Check for known vulnerabilities in logistics software.

        This tool checks common logistics systems (WMS, TMS, ERP) for known
        vulnerabilities based on version information.

        Args:
            system_type: Type of logistics system (e.g., "SAP_EWM", "Oracle_WMS", "Manhattan_WMOS")
            version: Software version (e.g., "7.5.2")

        Returns:
            VulnerabilityReport with severity, CVSS score, and remediation steps
        """
        # Simulated vulnerability database (in production, query real CVE database)
        vulnerabilities = {
            "SAP_EWM": {
                "7.5.2": VulnerabilityReport(
                    severity="HIGH",
                    cvss_score=7.8,
                    description="Missing authorization check in warehouse task creation",
                    affected_component="SAP EWM Warehouse Management",
                    remediation="Apply SAP Security Note 3224161 or upgrade to version 7.5.3"
                ),
                "default": VulnerabilityReport(
                    severity="MEDIUM",
                    cvss_score=5.3,
                    description="Potential cross-site scripting in web interface",
                    affected_component="SAP EWM Web UI",
                    remediation="Implement input validation and output encoding"
                )
            },
            "Oracle_WMS": {
                "default": VulnerabilityReport(
                    severity="CRITICAL",
                    cvss_score=9.1,
                    description="SQL injection vulnerability in inventory query module",
                    affected_component="Oracle WMS Inventory Management",
                    remediation="Apply Oracle Critical Patch Update (CPU) Q4 2024"
                )
            }
        }

        # Look up vulnerability
        system_vulns = vulnerabilities.get(system_type, {})
        return system_vulns.get(version, system_vulns.get("default", VulnerabilityReport(
            severity="INFO",
            cvss_score=0.0,
            description="No known vulnerabilities for this version",
            affected_component=system_type,
            remediation="Keep system updated and monitor security advisories"
        )))

    # Create custom tool #2: Scan logistics IoT devices
    @function_tool
    def scan_logistics_system(ip_address: str, system_type: str) -> LogisticsSystemScan:
        """
        Perform security scan of a logistics system or IoT device.

        This tool simulates a comprehensive security scan of logistics infrastructure,
        including WMS, TMS, GPS trackers, RFID readers, etc.

        Args:
            ip_address: IP address of the system to scan
            system_type: Type of system (e.g., "WMS", "TMS", "GPS_Tracker", "RFID_Reader")

        Returns:
            LogisticsSystemScan with findings and recommendations
        """
        # Simulated scan results (in production, integrate with nmap, OpenVAS, etc.)
        scan_results = {
            "WMS": LogisticsSystemScan(
                system_name="Warehouse Management System",
                ip_address=ip_address,
                system_type=system_type,
                vulnerabilities_found=4,
                critical_issues=[
                    "Default credentials detected (admin/admin)",
                    "Unencrypted database connection",
                    "Missing security patches (3 months outdated)"
                ],
                recommendations=[
                    "Change default credentials immediately",
                    "Enable SSL/TLS for database connections",
                    "Apply latest security patches",
                    "Implement network segmentation",
                    "Enable audit logging"
                ]
            ),
            "GPS_Tracker": LogisticsSystemScan(
                system_name="Fleet GPS Tracking Device",
                ip_address=ip_address,
                system_type=system_type,
                vulnerabilities_found=2,
                critical_issues=[
                    "Unencrypted GPS data transmission",
                    "Weak authentication mechanism"
                ],
                recommendations=[
                    "Enable GPS data encryption",
                    "Implement certificate-based authentication",
                    "Update firmware to latest version",
                    "Restrict network access to management VLAN"
                ]
            )
        }

        return scan_results.get(system_type, LogisticsSystemScan(
            system_name=f"Unknown {system_type}",
            ip_address=ip_address,
            system_type=system_type,
            vulnerabilities_found=0,
            critical_issues=[],
            recommendations=["Perform manual security assessment"]
        ))

    # Create GTL Logistics Security Agent with custom tools
    gtl_agent = Agent(
        name="GTL Logistics Security Agent",
        instructions="""You are a specialized cybersecurity expert for logistics companies in Peru.

Your expertise includes:
- Warehouse Management Systems (WMS)
- Transportation Management Systems (TMS)
- ERP systems (SAP, Oracle)
- IoT devices (GPS trackers, RFID readers)

When performing security assessments:
1. Use check_logistics_vulnerability to check for known CVEs
2. Use scan_logistics_system to perform comprehensive scans
3. Prioritize findings by severity (CRITICAL > HIGH > MEDIUM > LOW)
4. Provide actionable remediation recommendations
5. Consider Peruvian compliance requirements (Ley 29733)

Always provide clear, actionable security recommendations.""",
        tools=[check_logistics_vulnerability, scan_logistics_system],
        model=OpenAIChatCompletionsModel(
            model=os.getenv('CAI_MODEL', 'alias0'),
            openai_client=AsyncOpenAI(),
        )
    )

    # Run GTL security assessment
    print("\n📊 Running GTL Logistics Security Assessment...")
    print("⏳ Analyzing logistics systems...\n")

    try:
        result = await Runner.run(
            gtl_agent,
            input="""Perform security assessment for a Peruvian logistics company:

1. Check vulnerabilities for SAP EWM version 7.5.2
2. Scan the WMS at IP 192.168.100.50
3. Scan GPS trackers at IP 192.168.200.10

Provide a comprehensive report with prioritized findings.""",
            stream=False
        )

        print("✅ GTL Assessment Complete!\n")
        print("📝 Security Report:")
        print("-" * 70)
        print(result.final_output)
        print("-" * 70)

    except Exception as e:
        print(f"❌ Error running GTL assessment: {e}")


# ============================================================================
# EXAMPLE 3: MULTI-AGENT COORDINATION
# ============================================================================

async def example_3_multi_agent_coordination():
    """
    Example 3: Multi-Agent Coordination (Specialist Delegation)

    This example demonstrates:
    - Creating specialist agents for different security domains
    - Using handoffs to delegate tasks between agents
    - Orchestrating complex security assessments

    Use Case: Comprehensive logistics security assessment with specialized agents
    """
    print("\n" + "="*70)
    print("EXAMPLE 3: Multi-Agent Coordination")
    print("="*70)

    # Define specialist agent tools
    @function_tool
    def scan_sap_system(ip: str) -> str:
        """
        Specialized SAP security scanning.

        Args:
            ip: IP address of SAP system

        Returns:
            SAP-specific security findings
        """
        return f"""SAP Security Scan Results for {ip}:
✓ SAP EWM detected (version 7.5.2)
⚠ Missing SAP Security Note 3224161 (HIGH severity)
⚠ Default SAP* user account still active (MEDIUM severity)
✓ Database encryption enabled
⚠ Weak password policy detected (MEDIUM severity)

Recommendation: Apply SAP security patches and disable default accounts."""

    @function_tool
    def scan_network_infrastructure(network: str) -> str:
        """
        Network security scanning.

        Args:
            network: Network range to scan (CIDR notation)

        Returns:
            Network security findings
        """
        return f"""Network Security Scan for {network}:
✓ Firewall detected and active
⚠ 3 devices with outdated firmware
⚠ Port 23 (Telnet) open on 192.168.1.100 (CRITICAL)
✓ VPN properly configured
⚠ Weak Wi-Fi encryption (WPA2-PSK) detected

Recommendation: Disable Telnet, update firmware, upgrade to WPA3."""

    @function_tool
    def scan_iot_devices(network: str) -> str:
        """
        IoT device security scanning for logistics.

        Args:
            network: Network range to scan

        Returns:
            IoT security findings
        """
        return f"""IoT Security Scan for {network}:
Found 15 GPS trackers:
  ⚠ 8 devices with default credentials (CRITICAL)
  ⚠ 12 devices with unencrypted data transmission (HIGH)
  ✓ 3 devices properly configured

Found 5 RFID readers:
  ⚠ All using outdated firmware v1.2.3 (HIGH)
  ⚠ Missing certificate validation (MEDIUM)

Recommendation: Update all device credentials, enable encryption, update firmware."""

    # Create specialist agents
    sap_specialist = Agent(
        name="SAP Security Specialist",
        instructions="""You are an expert in SAP security, specializing in SAP ERP,
SAP EWM (Extended Warehouse Management), and SAP TM (Transportation Management).

Focus on:
- SAP security notes and patches
- SAP authorization vulnerabilities
- SAP database security
- SAP web interface security""",
        tools=[scan_sap_system]
    )

    network_specialist = Agent(
        name="Network Security Specialist",
        instructions="""You are an expert in network infrastructure security.

Focus on:
- Firewall configuration
- Network segmentation
- Port security
- VPN security
- Wireless security""",
        tools=[scan_network_infrastructure]
    )

    iot_specialist = Agent(
        name="IoT Security Specialist",
        instructions="""You are an expert in IoT security for logistics, specializing in:
- GPS tracking devices
- RFID readers and scanners
- Barcode scanners
- Warehouse sensors
- Fleet management devices

Focus on firmware, credentials, encryption, and network exposure.""",
        tools=[scan_iot_devices]
    )

    # Create main orchestrator agent
    security_orchestrator = Agent(
        name="Security Assessment Orchestrator",
        instructions="""You are the lead security consultant coordinating comprehensive
security assessments for logistics companies.

DELEGATION STRATEGY:
- For SAP, Oracle, or ERP systems → delegate to SAP Security Specialist
- For network infrastructure, firewalls, VPNs → delegate to Network Security Specialist
- For GPS, RFID, IoT devices → delegate to IoT Security Specialist

WORKFLOW:
1. Understand the assessment scope
2. Delegate to appropriate specialists
3. Collect all findings
4. Create a comprehensive prioritized report
5. Provide executive summary with key recommendations

Always create a clear, actionable final report.""",
        handoffs=[
            handoff(sap_specialist),
            handoff(network_specialist),
            handoff(iot_specialist)
        ]
    )

    # Run coordinated assessment
    print("\n📊 Running Multi-Agent Security Assessment...")
    print("🤖 Coordinating specialist agents...")
    print("⏳ This may take a moment...\n")

    try:
        result = await Runner.run(
            security_orchestrator,
            input="""Perform comprehensive security assessment for Transportes Peruanos SAC:

SCOPE:
1. SAP EWM system at 192.168.100.50
2. Network infrastructure (192.168.0.0/16)
3. IoT devices in fleet network (192.168.200.0/24)

Coordinate with specialist agents to cover all areas.
Provide a consolidated executive report with prioritized findings.""",
            stream=False
        )

        print("✅ Multi-Agent Assessment Complete!\n")
        print("📝 Consolidated Security Report:")
        print("-" * 70)
        print(result.final_output)
        print("-" * 70)

        print("\n🎯 Multi-Agent Coordination Benefits:")
        print("   ✓ Specialist expertise for each domain")
        print("   ✓ Comprehensive coverage of all systems")
        print("   ✓ Efficient delegation and parallel processing")
        print("   ✓ Consolidated, actionable reporting")

    except Exception as e:
        print(f"❌ Error in multi-agent coordination: {e}")


# ============================================================================
# MAIN EXECUTION
# ============================================================================

async def run_all_examples():
    """Run all three examples sequentially."""
    print("\n" + "="*70)
    print("CAI FRAMEWORK - QUICK START EXAMPLES")
    print("GTL AI Security Platform")
    print("="*70)

    # Check API key configuration
    if not (os.getenv('OPENAI_API_KEY') or os.getenv('DEEPSEEK_API_KEY') or os.getenv('ANTHROPIC_API_KEY')):
        print("\n⚠️  WARNING: No API key found!")
        print("   Set one of these environment variables:")
        print("   - OPENAI_API_KEY (for OpenAI GPT models)")
        print("   - DEEPSEEK_API_KEY (for DeepSeek - most cost-effective)")
        print("   - ANTHROPIC_API_KEY (for Claude models)")
        print("\n   Example:")
        print("   export DEEPSEEK_API_KEY=sk-your-key-here")
        print("   or create a .env file with your keys\n")
        return

    print(f"\n✅ API key configured")
    print(f"🤖 Using model: {os.getenv('CAI_MODEL', 'alias0')}")

    try:
        # Run Example 1
        await example_1_basic_security_agent()
        await asyncio.sleep(2)  # Brief pause between examples

        # Run Example 2
        await example_2_custom_tool_integration()
        await asyncio.sleep(2)

        # Run Example 3
        await example_3_multi_agent_coordination()

        # Summary
        print("\n" + "="*70)
        print("🎉 ALL EXAMPLES COMPLETED SUCCESSFULLY!")
        print("="*70)
        print("\n📚 Next Steps:")
        print("   1. Review the code in this file to understand the patterns")
        print("   2. Read api_documentation.md for detailed API reference")
        print("   3. Check architecture_analysis.md for framework overview")
        print("   4. Explore tools_inventory.json for available security tools")
        print("   5. Create your own custom agents for GTL platform")
        print("\n💡 Start building GTL AI Security Platform!")
        print("="*70 + "\n")

    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        print("💡 Check your API key configuration and internet connection")


async def run_single_example(example_num: int):
    """Run a single example by number."""
    examples = {
        1: example_1_basic_security_agent,
        2: example_2_custom_tool_integration,
        3: example_3_multi_agent_coordination
    }

    if example_num not in examples:
        print(f"❌ Invalid example number: {example_num}")
        print("   Valid options: 1, 2, or 3")
        return

    await examples[example_num]()


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="CAI Framework Quick Start Examples for GTL AI Security Platform"
    )
    parser.add_argument(
        '--example',
        type=int,
        choices=[1, 2, 3],
        help='Run specific example (1, 2, or 3). If not specified, runs all examples.'
    )

    args = parser.parse_args()

    if args.example:
        asyncio.run(run_single_example(args.example))
    else:
        asyncio.run(run_all_examples())


if __name__ == "__main__":
    main()
