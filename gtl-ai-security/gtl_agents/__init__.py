"""
GTL Custom Security Agents

Sector-specific security analysis agents that extend the base GTL Security Scanner
with domain expertise, compliance mapping, and business impact analysis.

Agents:
- LogisticsSecurityAgent: Freight forwarding, customs, EDI, supply chain
- MedicalAIComplianceAgent: Healthcare AI, HIPAA, PHI protection, FDA compliance
- CustomsDataProtectionAgent: SUNAT, international trade, Ley 29733

These agents transform the GTL scanner from a commodity tool into a specialized
consultant, justifying premium pricing (2.5X-5X vs generic scanners).
"""

__version__ = "1.0.0"

from gtl_agents.base_agent import (
    BaseSecurityAgent,
    AgentFinding,
    AgentAnalysisResult,
    FindingSeverity,
    ComplianceFramework,
)

from gtl_agents.logistics_agent import LogisticsSecurityAgent
from gtl_agents.medical_agent import MedicalAIComplianceAgent
from gtl_agents.customs_agent import CustomsDataProtectionAgent

__all__ = [
    # Base classes
    "BaseSecurityAgent",
    "AgentFinding",
    "AgentAnalysisResult",
    "FindingSeverity",
    "ComplianceFramework",
    # Agents
    "LogisticsSecurityAgent",
    "MedicalAIComplianceAgent",
    "CustomsDataProtectionAgent",
]
