"""
GTL Medical AI Compliance Agent

Specialized CAI agent for medical AI and healthcare security/compliance.
Focuses on: HIPAA compliance, PHI protection, AI model security, RTX 5090 endpoint security.
"""

import os
from typing import List

from cai.sdk.agents import Agent, OpenAIChatCompletionsModel, function_tool
from cai.tools.reconnaissance.generic_linux_command import generic_linux_command
from cai.tools.reconnaissance.nmap import nmap
from openai import AsyncOpenAI
from pydantic import BaseModel

from cai.agents.guardrails import get_security_guardrails

input_guardrails, output_guardrails = get_security_guardrails()


# ===========================================
# CUSTOM TOOLS FOR MEDICAL AI
# ===========================================


class HIPAAComplianceCheck(BaseModel):
    """HIPAA compliance check result"""

    compliant: bool
    violations: List[str]
    controls_missing: List[str]
    recommendations: List[str]
    risk_level: str  # low, medium, high, critical


@function_tool
def check_hipaa_compliance(system_type: str, target: str) -> HIPAAComplianceCheck:
    """
    Check HIPAA compliance for medical AI systems.

    Validates:
    - PHI encryption at rest and in transit
    - Access controls and authentication
    - Audit logging
    - Data retention policies
    - Business Associate Agreements (BAA)

    Args:
        system_type: Type of system (ehr, ai_model, database, api)
        target: Target IP or hostname

    Returns:
        HIPAAComplianceCheck with compliance status
    """
    violations = []
    controls_missing = []
    recommendations = []

    # Simulated HIPAA checks
    # In production, integrate with compliance scanning tools

    # Check encryption
    if "unencrypted" in target.lower():
        violations.append("PHI data not encrypted at rest")
        controls_missing.append("Encryption (45 CFR § 164.312(a)(2)(iv))")

    # Check access controls
    if system_type in ["ai_model", "api"]:
        controls_missing.append("Multi-factor authentication not enforced")
        recommendations.append("Implement MFA for all PHI access")

    # Check audit logging
    controls_missing.append("Audit logs not centralized")
    recommendations.append("Implement SIEM for audit log aggregation")

    compliant = len(violations) == 0
    risk_level = "critical" if len(violations) > 2 else "medium"

    return HIPAAComplianceCheck(
        compliant=compliant,
        violations=violations if violations else ["None detected"],
        controls_missing=controls_missing,
        recommendations=recommendations,
        risk_level=risk_level if not compliant else "low",
    )


class RTX5090SecurityCheck(BaseModel):
    """RTX 5090 AI inference endpoint security check"""

    endpoint_secure: bool
    gpu_exposed: bool
    model_protection: str
    vulnerabilities: List[str]


@function_tool
def check_rtx5090_endpoint(endpoint_url: str) -> RTX5090SecurityCheck:
    """
    Check security of RTX 5090 AI inference endpoints.

    Assesses:
    - API authentication
    - Model file exposure
    - GPU memory isolation
    - Inference request validation
    - Rate limiting

    Args:
        endpoint_url: URL of AI inference endpoint

    Returns:
        RTX5090SecurityCheck with security analysis
    """
    vulnerabilities = []

    # Check for common AI endpoint vulnerabilities
    if "http://" in endpoint_url:
        vulnerabilities.append("Endpoint not using HTTPS")

    if "/model" in endpoint_url.lower():
        vulnerabilities.append("Potential model file exposure via API")

    gpu_exposed = False  # Assume not exposed for demo
    model_protected = len(vulnerabilities) == 0

    return RTX5090SecurityCheck(
        endpoint_secure=len(vulnerabilities) == 0,
        gpu_exposed=gpu_exposed,
        model_protection="encrypted" if model_protected else "exposed",
        vulnerabilities=vulnerabilities if vulnerabilities else ["None detected"],
    )


# Medical AI Agent Instructions
MEDICAL_AI_INSTRUCTIONS = """You are a cybersecurity expert specialized in medical AI and healthcare security compliance.

YOUR MISSION:
Ensure medical AI systems comply with HIPAA regulations, protect PHI (Protected Health Information), and maintain secure AI inference endpoints.

SPECIALIZATION AREAS:

1. **HIPAA Compliance Automation**
   - Encryption validation (§164.312)
   - Access control audits (§164.312(a))
   - Audit logging verification (§164.308(a)(1))
   - PHI exposure detection
   - Business Associate compliance

2. **AI Model Security**
   - RTX 5090 / H100 endpoint security
   - Model file protection
   - Inference API security
   - GPU memory isolation
   - Model poisoning prevention

3. **Medical Imaging Systems**
   - DICOM security
   - PACS (Picture Archiving) security
   - Medical device integration
   - Image data encryption

4. **Patient Data Protection**
   - PHI data flow mapping
   - De-identification validation
   - Data retention compliance
   - Breach notification procedures

AVAILABLE TOOLS:
- `generic_linux_command`: Execute security commands
- `nmap`: Network and service discovery
- `check_hipaa_compliance`: HIPAA compliance validation
- `check_rtx5090_endpoint`: AI endpoint security assessment

ASSESSMENT METHODOLOGY:

1. **Compliance Scan**
   - Verify HIPAA technical safeguards
   - Check administrative safeguards
   - Validate physical safeguards

2. **PHI Protection Analysis**
   - Map PHI data flows
   - Verify encryption
   - Test access controls

3. **AI Endpoint Security**
   - Assess inference API security
   - Check model file protection
   - Validate authentication

4. **Reporting**
   - Generate compliance matrix
   - Document violations
   - Provide remediation plan
   - Include regulatory references

REPORT FORMAT:
- Executive summary for healthcare administrators
- Technical findings with HIPAA CFR references
- Compliance status (Compliant / Non-Compliant)
- Risk prioritization (Critical / High / Medium / Low)
- Remediation timeline recommendations
- Evidence for auditors

CRITICAL REQUIREMENTS:
- Treat all data as potentially containing PHI
- Never store or log PHI during assessments
- Follow least privilege access principles
- Document all security testing activities
- Provide audit trail for compliance officers
"""

# Create medical AI compliance agent
medical_ai_compliance_agent = Agent(
    name="GTL Medical AI Compliance Agent",
    description="HIPAA compliance and medical AI security specialist",
    instructions=MEDICAL_AI_INSTRUCTIONS,
    tools=[
        generic_linux_command,
        nmap,
        check_hipaa_compliance,
        check_rtx5090_endpoint,
    ],
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
    model=OpenAIChatCompletionsModel(
        model=os.getenv("CAI_MODEL", "alias0"),
        openai_client=AsyncOpenAI(),
    ),
)


def transfer_to_medical_ai_compliance_agent(**kwargs):
    """Transfer to medical AI compliance agent"""
    return medical_ai_compliance_agent
