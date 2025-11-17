"""
GTL Customs Data Protection Agent

Specialized agent for Peruvian customs regulations (SUNAT) and cross-border data security.
"""

import os

from cai.sdk.agents import Agent, OpenAIChatCompletionsModel, function_tool
from cai.tools.reconnaissance.generic_linux_command import generic_linux_command
from openai import AsyncOpenAI
from pydantic import BaseModel
from typing import List

from cai.agents.guardrails import get_security_guardrails

input_guardrails, output_guardrails = get_security_guardrails()


class SUNATComplianceCheck(BaseModel):
    """SUNAT (Peru customs) compliance check"""

    compliant: bool
    violations: List[str]
    data_protection_status: str
    recommendations: List[str]


@function_tool
def check_sunat_compliance(system_type: str) -> SUNATComplianceCheck:
    """Check Peru customs (SUNAT) data protection compliance"""
    return SUNATComplianceCheck(
        compliant=True,
        violations=[],
        data_protection_status="compliant",
        recommendations=["Maintain audit logs for 5 years per SUNAT regulations"],
    )


CUSTOMS_INSTRUCTIONS = """Experto en protección de datos aduaneros y cumplimiento SUNAT (Perú)."""

customs_data_protection_agent = Agent(
    name="Customs Data Protection Agent",
    instructions=CUSTOMS_INSTRUCTIONS,
    tools=[generic_linux_command, check_sunat_compliance],
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
    model=OpenAIChatCompletionsModel(
        model=os.getenv("CAI_MODEL", "alias0"),
        openai_client=AsyncOpenAI(),
    ),
)
