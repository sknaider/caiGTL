# GTL AI Security Platform - Agent Development Guide

**Version**: 1.0
**Target Audience**: Developers, Security Engineers

---

## Quick Start

Create a custom security agent in 5 minutes:

```python
from cai.sdk.agents import Agent, OpenAIChatCompletionsModel, function_tool
from openai import AsyncOpenAI
import os

# 1. Define custom tool
@function_tool
def check_my_system(target: str) -> dict:
    """Check security of custom system"""
    return {"secure": True, "issues": []}

# 2. Create agent
my_agent = Agent(
    name="My Security Agent",
    instructions="You are an expert in [your domain]",
    tools=[check_my_system],
    model=OpenAIChatCompletionsModel(
        model=os.getenv("CAI_MODEL", "alias0"),
        openai_client=AsyncOpenAI()
    )
)

# 3. Run agent
from cai.sdk.agents import Runner
result = await Runner.run(my_agent, "Scan target system")
```

---

## Agent Lifecycle

```
┌──────────────────┐
│ Define Agent     │ ← instructions, tools, model
├──────────────────┤
│ Initialize       │ ← API keys, guardrails
├──────────────────┤
│ Execute          │ ← Runner.run()
├──────────────────┤
│ Tool Calls       │ ← Agent calls @function_tools
├──────────────────┤
│ Return Result    │ ← final_output, usage stats
└──────────────────┘
```

---

## Best Practices

### 1. Clear Instructions
✅ **Good:**
```python
instructions = """You are a SAP security expert.

WORKFLOW:
1. Use nmap to discover SAP systems
2. Check for known SAP CVEs
3. Validate security notes
4. Report findings in Spanish

TOOLS:
- nmap: Network scanning
- check_sap_security: SAP-specific checks"""
```

❌ **Bad:**
```python
instructions = "You are a security expert"
```

### 2. Type Hints & Validation
```python
from pydantic import BaseModel, Field

class SecurityCheck(BaseModel):
    target: str = Field(..., description="IP or hostname")
    severity: str = Field(..., regex="^(low|medium|high|critical)$")

@function_tool
def my_tool(target: str, severity: str = "medium") -> SecurityCheck:
    """Always use type hints and Pydantic models"""
    return SecurityCheck(target=target, severity=severity)
```

### 3. Error Handling
```python
@function_tool
def robust_tool(target: str) -> dict:
    try:
        result = do_security_check(target)
        return {"status": "success", "data": result}
    except ConnectionError:
        return {"status": "error", "message": "Connection failed"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
```

---

## Complete Example: Custom IoT Security Agent

```python
from cai.sdk.agents import Agent, function_tool
from pydantic import BaseModel
from typing import List

# Data model
class IoTDevice(BaseModel):
    ip: str
    device_type: str
    firmware_version: str
    vulnerabilities: List[str]
    risk_score: int

# Custom tool
@function_tool
def scan_iot_device(ip: str) -> IoTDevice:
    """Scan IoT device for vulnerabilities"""
    # Implement scanning logic
    return IoTDevice(
        ip=ip,
        device_type="GPS Tracker",
        firmware_version="1.2.3",
        vulnerabilities=["Default credentials", "Outdated firmware"],
        risk_score=75
    )

# Agent instructions
INSTRUCTIONS = """You are an IoT security specialist.

SCAN METHODOLOGY:
1. Identify device type (GPS, RFID, camera, sensor)
2. Check firmware version
3. Test for default credentials
4. Assess encryption
5. Rate risk (0-100)

REPORT FORMAT:
- Device inventory
- Vulnerability summary
- Risk prioritization
- Remediation steps"""

# Create agent
iot_agent = Agent(
    name="IoT Security Agent",
    instructions=INSTRUCTIONS,
    tools=[scan_iot_device]
)

# Usage
async def main():
    from cai.sdk.agents import Runner
    result = await Runner.run(
        iot_agent,
        "Scan IoT devices in 192.168.200.0/24 network"
    )
    print(result.final_output)
```

---

## Integration with GTL Platform

### Register Agent

**File**: `gtl_agents/my_custom_agent.py`

```python
from cai.sdk.agents import Agent
from cai.agents.guardrails import get_security_guardrails

input_guardrails, output_guardrails = get_security_guardrails()

my_custom_agent = Agent(
    name="My Custom Agent",
    instructions="...",
    tools=[...],
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails
)

# Export for API access
def transfer_to_my_custom_agent(**kwargs):
    return my_custom_agent
```

### Update Exports

**File**: `gtl_agents/__init__.py`

```python
from .my_custom_agent import my_custom_agent

__all__ = [
    "logistics_security_agent",
    "medical_ai_compliance_agent",
    "my_custom_agent"  # Add here
]
```

---

## Testing

```python
import pytest
import asyncio
from cai.sdk.agents import Runner

@pytest.mark.asyncio
async def test_my_agent():
    result = await Runner.run(my_agent, "Test input")
    assert result.status == "completed"
    assert "expected output" in result.final_output

# Run tests
# pytest gtl_agents/tests/test_my_agent.py
```

---

**Full Documentation**: See `/examples/` directory for more examples

**Next**: [Deployment Guide](DEPLOYMENT.md)
