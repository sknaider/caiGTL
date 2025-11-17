# CAI Framework - API Documentation
**How to Create Custom Agents for GTL AI Security Platform**

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Core Concepts](#core-concepts)
3. [Agent Creation](#agent-creation)
4. [Custom Tool Development](#custom-tool-development)
5. [Multi-Agent Orchestration](#multi-agent-orchestration)
6. [Advanced Features](#advanced-features)
7. [GTL-Specific Examples](#gtl-specific-examples)
8. [Best Practices](#best-practices)
9. [API Reference](#api-reference)

---

## Quick Start

### Minimal Agent (5 lines)

```python
import asyncio
from cai.sdk.agents import Agent, Runner

async def main():
    agent = Agent(
        name="My Security Agent",
        instructions="You are a cybersecurity expert."
    )
    result = await Runner.run(agent, "What are the OWASP Top 10?")
    print(result.final_output)

if __name__ == "__main__":
    asyncio.run(main())
```

**File location**: Save as `my_agent.py`

**Run**:
```bash
python my_agent.py
```

---

## Core Concepts

### 1. Agent

The **Agent** is the primary abstraction. It represents an AI agent with:
- **Instructions**: System prompt defining behavior
- **Tools**: Functions the agent can call
- **Handoffs**: Other agents it can delegate to
- **Guardrails**: Input/output security filters
- **Model**: LLM configuration

### 2. Tool

A **Tool** is a Python function decorated with `@function_tool` that the agent can call.

### 3. Handoff

A **Handoff** allows an agent to delegate work to specialist agents.

### 4. Runner

The **Runner** executes agents and returns results.

---

## Agent Creation

### Basic Agent Structure

```python
from cai.sdk.agents import Agent, OpenAIChatCompletionsModel
from openai import AsyncOpenAI
import os

agent = Agent(
    # Identity
    name="Agent Name",                    # Display name
    description="Short description",      # Agent description

    # Behavior
    instructions="System prompt...",      # How the agent behaves

    # Capabilities
    tools=[],                             # List of tools
    handoffs=[],                          # List of sub-agents

    # Security
    input_guardrails=[],                  # Input validation
    output_guardrails=[],                 # Output validation

    # Model Configuration
    model=OpenAIChatCompletionsModel(
        model=os.getenv('CAI_MODEL', 'alias0'),
        openai_client=AsyncOpenAI(),
    ),
    model_settings={
        "temperature": 0.7,
        "top_p": 0.9,
        "max_tokens": 2000,
    }
)
```

### Agent Instructions (System Prompt)

**Option 1: String**

```python
agent = Agent(
    name="Pentester",
    instructions="You are an expert penetration tester. Use nmap to scan targets."
)
```

**Option 2: File-based (Recommended for long prompts)**

```python
from cai.util import load_prompt_template, create_system_prompt_renderer

prompt = load_prompt_template("prompts/my_custom_prompt.md")
agent = Agent(
    name="Pentester",
    instructions=create_system_prompt_renderer(prompt)
)
```

**Option 3: Dynamic Function**

```python
def get_instructions(context):
    return f"You are testing {context.target}. Use appropriate tools."

agent = Agent(
    name="Pentester",
    instructions=get_instructions
)
```

### Model Configuration

**Supported Models**:
- **OpenAI**: `gpt-4o`, `gpt-4o-mini`, `o1-preview`, `o1-mini`
- **Anthropic**: `claude-sonnet-4-20250514`, `claude-opus-4-20250514`, `claude-haiku-3-5-20250514`
- **DeepSeek**: `alias0` (default - most cost-effective)
- **Ollama**: `llama3`, `mistral`, etc. (local)
- **Azure OpenAI**: Via Azure configuration
- **OpenRouter**: 150+ models

**Example: OpenAI**

```python
from cai.sdk.agents import OpenAIChatCompletionsModel
from openai import AsyncOpenAI

model = OpenAIChatCompletionsModel(
    model="gpt-4o",
    openai_client=AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))
)

agent = Agent(name="Agent", model=model)
```

**Example: Anthropic Claude**

```python
from cai.sdk.agents import OpenAIChatCompletionsModel
from openai import AsyncOpenAI

# CAI uses OpenAI SDK format for all models
model = OpenAIChatCompletionsModel(
    model="claude-sonnet-4-20250514",
    openai_client=AsyncOpenAI(
        api_key=os.getenv("ANTHROPIC_API_KEY"),
        base_url="https://api.anthropic.com/v1"
    )
)

agent = Agent(name="Agent", model=model)
```

**Example: DeepSeek (Budget-Friendly)**

```python
from cai.sdk.agents import OpenAIChatCompletionsModel
from openai import AsyncOpenAI

model = OpenAIChatCompletionsModel(
    model="alias0",  # DeepSeek V3
    openai_client=AsyncOpenAI(
        api_key=os.getenv("DEEPSEEK_API_KEY", "dummy"),
        base_url="https://api.deepseek.com/v1"
    )
)

agent = Agent(name="Agent", model=model)
```

**Example: Ollama (Free Local)**

```python
from cai.sdk.agents import OpenAIChatCompletionsModel
from openai import AsyncOpenAI

model = OpenAIChatCompletionsModel(
    model="llama3",
    openai_client=AsyncOpenAI(
        api_key="ollama",
        base_url="http://localhost:11434/v1"
    )
)

agent = Agent(name="Agent", model=model)
```

---

## Custom Tool Development

### Tool Basics

**Pattern**:
```python
from cai.sdk.agents import function_tool
from pydantic import BaseModel

# Define return type (optional but recommended)
class ToolResult(BaseModel):
    status: str
    message: str

@function_tool
def my_custom_tool(parameter1: str, parameter2: int = 10) -> ToolResult:
    """
    Brief description of what the tool does.

    Args:
        parameter1: Description of parameter1
        parameter2: Description of parameter2 (default: 10)

    Returns:
        ToolResult with status and message
    """
    # Implement tool logic
    result = f"Processed {parameter1} with {parameter2}"
    return ToolResult(status="success", message=result)
```

**Important**:
- Use `@function_tool` decorator
- Include type hints for parameters
- Write clear docstring (LLM uses this to understand the tool)
- Return structured data (Pydantic models recommended)

### Example 1: Simple Security Check

```python
from cai.sdk.agents import function_tool

@function_tool
def check_open_ports(ip: str) -> str:
    """
    Check if an IP address has common vulnerable ports open.

    Args:
        ip: IP address to check

    Returns:
        String with open ports and risk assessment
    """
    import socket

    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        80: "HTTP",
        443: "HTTPS",
        3389: "RDP",
        5432: "PostgreSQL",
        3306: "MySQL"
    }

    open_ports = []
    for port, service in common_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(f"{port}/{service}")
        sock.close()

    if not open_ports:
        return f"No common ports open on {ip}"

    return f"Open ports on {ip}: {', '.join(open_ports)}"

# Use in agent
agent = Agent(
    name="Port Scanner",
    instructions="Scan targets for open ports and assess risk.",
    tools=[check_open_ports]
)
```

### Example 2: SAP Security Check (GTL-Specific)

```python
from cai.sdk.agents import function_tool
from pydantic import BaseModel
from typing import List

class SAPVulnerability(BaseModel):
    note_number: str
    severity: str
    description: str
    patched: bool

@function_tool
def check_sap_security_notes(sap_version: str, component: str) -> List[SAPVulnerability]:
    """
    Check SAP system for known security vulnerabilities.

    Args:
        sap_version: SAP version (e.g., "SAP ERP 6.0 EHP8")
        component: SAP component (e.g., "ABAP", "JAVA", "HANA")

    Returns:
        List of known vulnerabilities with patch status
    """
    # In production: Query SAP security notes database
    # This is a simplified example

    vulnerabilities = [
        SAPVulnerability(
            note_number="3224161",
            severity="HIGH",
            description="Missing authorization check in SAP NetWeaver",
            patched=False
        ),
        SAPVulnerability(
            note_number="3223692",
            severity="CRITICAL",
            description="SQL injection in SAP Business Objects",
            patched=True
        )
    ]

    # Filter by component (simplified)
    return vulnerabilities

# GTL Logistics Agent
gtl_sap_agent = Agent(
    name="GTL SAP Security Agent",
    instructions="""You are specialized in SAP security for logistics companies.
    Use check_sap_security_notes to assess SAP systems.
    Focus on: SAP EWM, SAP TM, SAP ERP, and SAP S/4HANA.""",
    tools=[check_sap_security_notes]
)
```

### Example 3: Oracle Database Security (GTL-Specific)

```python
from cai.sdk.agents import function_tool
from pydantic import BaseModel
from typing import List

class OraclePrivilege(BaseModel):
    username: str
    privilege: str
    admin_option: bool
    risk_level: str

@function_tool
def audit_oracle_privileges(connection_string: str) -> List[OraclePrivilege]:
    """
    Audit Oracle database user privileges for security risks.

    Args:
        connection_string: Oracle connection string (format: user/pass@host:port/service)

    Returns:
        List of risky privileges found
    """
    # In production: Use cx_Oracle to query DBA_SYS_PRIVS
    # This is a simplified example

    risky_privs = [
        OraclePrivilege(
            username="LOGISTICS_APP",
            privilege="CREATE ANY TABLE",
            admin_option=False,
            risk_level="MEDIUM"
        ),
        OraclePrivilege(
            username="WMS_USER",
            privilege="DBA",
            admin_option=True,
            risk_level="CRITICAL"
        )
    ]

    return risky_privs

# GTL Oracle Agent
gtl_oracle_agent = Agent(
    name="GTL Oracle Security Agent",
    instructions="""You are specialized in Oracle database security for logistics.
    Focus on: Oracle E-Business Suite, Oracle WMS, Oracle TMS.
    Audit user privileges and identify overprivileged accounts.""",
    tools=[audit_oracle_privileges]
)
```

### Example 4: Logistics IoT Scanner (GTL-Specific)

```python
from cai.sdk.agents import function_tool
from pydantic import BaseModel
from typing import List

class IoTDevice(BaseModel):
    device_type: str
    ip: str
    mac: str
    firmware_version: str
    vulnerabilities: List[str]
    risk_score: int

@function_tool
def scan_logistics_iot_devices(network_range: str) -> List[IoTDevice]:
    """
    Scan network for logistics IoT devices and assess security.

    Args:
        network_range: Network range to scan (e.g., "192.168.1.0/24")

    Returns:
        List of discovered IoT devices with vulnerability assessment
    """
    # In production: Use nmap, shodan, and custom signatures
    # This is a simplified example

    devices = [
        IoTDevice(
            device_type="GPS Tracker",
            ip="192.168.1.50",
            mac="AA:BB:CC:DD:EE:FF",
            firmware_version="1.2.3",
            vulnerabilities=[
                "Default credentials (admin/admin)",
                "Unencrypted GPS data transmission",
                "Missing firmware signature verification"
            ],
            risk_score=85
        ),
        IoTDevice(
            device_type="RFID Reader",
            ip="192.168.1.51",
            mac="11:22:33:44:55:66",
            firmware_version="2.1.0",
            vulnerabilities=[
                "Outdated firmware (CVE-2023-12345)",
                "Weak WPA2 encryption"
            ],
            risk_score=65
        )
    ]

    return devices

# GTL IoT Security Agent
gtl_iot_agent = Agent(
    name="GTL IoT Security Agent",
    instructions="""You are specialized in IoT security for logistics companies.
    Scan for: GPS trackers, RFID readers, barcode scanners, warehouse sensors.
    Identify default credentials, outdated firmware, and network exposures.""",
    tools=[scan_logistics_iot_devices]
)
```

### Tool Integration with CAI Built-ins

You can combine custom tools with CAI's built-in tools:

```python
from cai.tools.reconnaissance.nmap import nmap
from cai.tools.reconnaissance.shodan import shodan_search, shodan_host_info
from cai.tools.web.headers import analyze_http_headers

# Combine with your custom tools
agent = Agent(
    name="Comprehensive Security Agent",
    tools=[
        nmap,                      # Built-in
        shodan_search,             # Built-in
        check_sap_security_notes,  # Custom
        audit_oracle_privileges,   # Custom
        scan_logistics_iot_devices # Custom
    ]
)
```

---

## Multi-Agent Orchestration

### Handoffs (Agent Delegation)

**Pattern**: Main agent delegates to specialist agents.

```python
from cai.sdk.agents import Agent, handoff, Runner

# Create specialist agents
network_specialist = Agent(
    name="Network Security Specialist",
    instructions="You are an expert in network security. Use nmap and shodan.",
    tools=[nmap, shodan_search]
)

web_specialist = Agent(
    name="Web Security Specialist",
    instructions="You are an expert in web application security.",
    tools=[analyze_http_headers, curl]
)

# Create main agent with handoffs
security_lead = Agent(
    name="Security Lead",
    instructions="""You coordinate security assessments.
    Delegate network tasks to Network Security Specialist.
    Delegate web tasks to Web Security Specialist.""",
    handoffs=[
        handoff(network_specialist),
        handoff(web_specialist)
    ]
)

# Execute
async def main():
    result = await Runner.run(
        security_lead,
        "Assess the security of example.com"
    )
    print(result.final_output)
```

### Parallel Agents

Run multiple agents concurrently:

**agents.yml**:
```yaml
parallel_agents:
  - name: network_agent
    model: alias0
    prompt: "Focus on network vulnerabilities"
    unified_context: false

  - name: web_agent
    model: alias0
    prompt: "Focus on web vulnerabilities"
    unified_context: false

  - name: iot_agent
    model: alias0
    prompt: "Focus on IoT device security"
    unified_context: false
```

**Run**:
```bash
CAI_PARALLEL=3 cai "Assess security of logistics company network"
```

### GTL Multi-Agent Pattern Example

```python
from cai.sdk.agents import Agent, handoff, Runner
from cai.tools.reconnaissance.nmap import nmap
from cai.tools.reconnaissance.shodan import shodan_search

# Specialist agents
sap_agent = Agent(
    name="SAP Security Specialist",
    instructions="Expert in SAP ERP, EWM, TM security.",
    tools=[check_sap_security_notes]
)

oracle_agent = Agent(
    name="Oracle Security Specialist",
    instructions="Expert in Oracle Database and E-Business Suite security.",
    tools=[audit_oracle_privileges]
)

iot_agent = Agent(
    name="IoT Security Specialist",
    instructions="Expert in logistics IoT device security.",
    tools=[scan_logistics_iot_devices, nmap, shodan_search]
)

network_agent = Agent(
    name="Network Security Specialist",
    instructions="Expert in network infrastructure security.",
    tools=[nmap, shodan_search]
)

# GTL Orchestrator
gtl_orchestrator = Agent(
    name="GTL Security Orchestrator",
    instructions="""You are the lead security consultant for GTL AI Security Platform.

    You coordinate comprehensive security assessments for logistics companies.

    DELEGATION:
    - SAP systems → SAP Security Specialist
    - Oracle databases → Oracle Security Specialist
    - IoT devices (GPS, RFID, sensors) → IoT Security Specialist
    - Network infrastructure → Network Security Specialist

    Create comprehensive reports with prioritized findings.""",
    handoffs=[
        handoff(sap_agent),
        handoff(oracle_agent),
        handoff(iot_agent),
        handoff(network_agent)
    ]
)

# Execute comprehensive assessment
async def main():
    result = await Runner.run(
        gtl_orchestrator,
        """Perform comprehensive security assessment for:
        - Company: Transportes Peruanos S.A.
        - SAP EWM system at 10.0.1.50
        - Oracle WMS at 10.0.1.51
        - IoT network range: 10.0.2.0/24
        - Internet-facing assets
        """
    )
    print(result.final_output)

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
```

---

## Advanced Features

### Security Guardrails

Add input/output guardrails to prevent misuse:

```python
from cai.agents.guardrails import get_security_guardrails

input_guardrails, output_guardrails = get_security_guardrails()

agent = Agent(
    name="Secure Agent",
    input_guardrails=input_guardrails,   # Detect prompt injection
    output_guardrails=output_guardrails  # Block dangerous commands
)
```

**Custom Guardrails**:

```python
from cai.sdk.agents import InputGuardrail, OutputGuardrail

class GTLComplianceGuardrail(InputGuardrail):
    """Ensure compliance with Peruvian regulations"""

    async def filter(self, context, user_message):
        # Check for prohibited actions
        if "delete customer data" in user_message.lower():
            raise ValueError("Cannot delete customer data without authorization (Ley 29733)")
        return user_message

agent = Agent(
    name="Compliant Agent",
    input_guardrails=[GTLComplianceGuardrail()]
)
```

### Streaming Responses

Stream agent responses in real-time:

```python
async def main():
    result = await Runner.run(
        agent,
        "Scan the network",
        stream=True  # Enable streaming
    )

    async for event in result:
        if hasattr(event, 'data'):
            print(event.data, end='', flush=True)
```

### Context Management

Access and modify agent context:

```python
from cai.sdk.agents import Agent, Runner

async def main():
    agent = Agent(name="Agent", instructions="You are helpful.")

    # Run with context
    result = await Runner.run(
        agent,
        input="Remember: target is 192.168.1.50",
        context={"target_ip": "192.168.1.50"}
    )

    # Access context in tools
    @function_tool
    def get_target(context) -> str:
        return context.get("target_ip", "unknown")
```

### Cost Tracking

Track LLM API costs:

```python
from cai.sdk.agents import Runner

result = await Runner.run(agent, "Assess security")

# Access cost information
print(f"Input tokens: {result.usage.input_tokens}")
print(f"Output tokens: {result.usage.output_tokens}")
print(f"Total cost: ${result.cost:.4f}")
```

---

## GTL-Specific Examples

### Complete GTL Logistics Security Agent

```python
import os
from cai.sdk.agents import Agent, OpenAIChatCompletionsModel, function_tool
from cai.tools.reconnaissance.nmap import nmap
from cai.tools.reconnaissance.shodan import shodan_search
from openai import AsyncOpenAI
from pydantic import BaseModel
from typing import List

# Custom GTL Tools
class ComplianceCheck(BaseModel):
    regulation: str
    status: str
    findings: List[str]

@function_tool
def check_peruvian_compliance(system_type: str) -> ComplianceCheck:
    """Check compliance with Peruvian regulations (Ley 29733, PCIDSS)."""
    # Implementation
    return ComplianceCheck(
        regulation="Ley 29733 - Protección de Datos Personales",
        status="COMPLIANT",
        findings=["Data encryption: OK", "Access controls: OK"]
    )

@function_tool
def check_sap_wms_security(ip: str) -> str:
    """Check SAP Extended Warehouse Management security."""
    # Implementation
    return f"SAP EWM at {ip}: Found 3 security issues"

@function_tool
def scan_fleet_tracking_devices(network: str) -> str:
    """Scan for GPS trackers and assess firmware security."""
    # Implementation
    return f"Found 15 GPS devices on {network}, 8 with outdated firmware"

# GTL Agent
gtl_agent = Agent(
    name="GTL Logistics Security Agent",
    description="Specialized security agent for Peruvian logistics companies",
    instructions="""You are a cybersecurity expert specializing in logistics and supply chain security for Peruvian companies.

FOCUS AREAS:
1. Warehouse Management Systems (SAP EWM, Oracle WMS, Manhattan Associates)
2. Transportation Management Systems (SAP TM, Oracle TMS)
3. ERP Systems (SAP S/4HANA, Oracle E-Business Suite)
4. IoT Devices (GPS trackers, RFID readers, barcode scanners)
5. Compliance (Ley 29733, PCIDSS, industry regulations)

METHODOLOGY:
1. Reconnaissance (nmap, shodan)
2. System-specific checks (SAP, Oracle, IoT)
3. Compliance validation
4. Risk prioritization
5. Detailed reporting in Spanish

DELIVERABLES:
- Executive summary (Spanish)
- Technical findings
- Remediation recommendations
- Compliance status""",

    tools=[
        # Built-in tools
        nmap,
        shodan_search,

        # Custom GTL tools
        check_peruvian_compliance,
        check_sap_wms_security,
        scan_fleet_tracking_devices
    ],

    model=OpenAIChatCompletionsModel(
        model=os.getenv('CAI_MODEL', 'alias0'),  # DeepSeek for cost efficiency
        openai_client=AsyncOpenAI(),
    )
)

# Usage
async def main():
    from cai.sdk.agents import Runner

    result = await Runner.run(
        gtl_agent,
        """Realizar evaluación de seguridad para:
        - Empresa: Transportes Rápidos del Sur SAC
        - Sistema SAP EWM: 192.168.100.50
        - Red IoT: 192.168.200.0/24
        - Verificar cumplimiento Ley 29733
        """
    )

    print(result.final_output)

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
```

### GTL Agent Registration

To make your agent available via CLI:

**File**: `src/cai/agents/gtl_logistics_agent.py`

```python
import os
from cai.sdk.agents import Agent, OpenAIChatCompletionsModel
from cai.tools.reconnaissance.nmap import nmap
from openai import AsyncOpenAI
from cai.agents.guardrails import get_security_guardrails

# Load guardrails
input_guardrails, output_guardrails = get_security_guardrails()

# Create agent
gtl_logistics_agent = Agent(
    name="GTL Logistics Security Agent",
    description="Specialized in logistics and supply chain security for Peru",
    instructions=open("src/cai/prompts/gtl_logistics_agent.md").read(),
    tools=[nmap, shodan_search, check_peruvian_compliance],
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
    model=OpenAIChatCompletionsModel(
        model=os.getenv('CAI_MODEL', 'alias0'),
        openai_client=AsyncOpenAI(),
    )
)

# Transfer function for handoffs
def transfer_to_gtl_logistics_agent(**kwargs):
    return gtl_logistics_agent
```

**Run via CLI**:
```bash
CAI_AGENT_TYPE=gtl_logistics_agent cai
```

---

## Best Practices

### 1. Clear Instructions

✅ **Good**:
```python
instructions = """You are a network security expert.

TOOLS:
- nmap: Use for port scanning
- shodan: Use for internet-wide reconnaissance

WORKFLOW:
1. Start with nmap for targeted scanning
2. Use shodan for OSINT on public IPs
3. Prioritize findings by severity
4. Report in clear, actionable format"""
```

❌ **Bad**:
```python
instructions = "You are a security expert. Do security things."
```

### 2. Type Hints and Docstrings

✅ **Good**:
```python
@function_tool
def check_vulnerability(cve_id: str, target_version: str) -> VulnerabilityReport:
    """
    Check if a CVE affects a specific software version.

    Args:
        cve_id: CVE identifier (e.g., "CVE-2024-1234")
        target_version: Software version to check (e.g., "1.2.3")

    Returns:
        VulnerabilityReport with affected status and details
    """
    pass
```

❌ **Bad**:
```python
def check_vuln(cve, ver):
    # No decorator, no types, no docstring
    pass
```

### 3. Error Handling in Tools

```python
@function_tool
def robust_tool(parameter: str) -> str:
    """Tool with proper error handling."""
    try:
        # Tool logic
        result = do_something(parameter)
        return f"Success: {result}"
    except ConnectionError as e:
        return f"Connection failed: {e}"
    except ValueError as e:
        return f"Invalid parameter: {e}"
    except Exception as e:
        return f"Unexpected error: {e}"
```

### 4. Security Guardrails

Always use guardrails for production agents:

```python
from cai.agents.guardrails import get_security_guardrails

input_guardrails, output_guardrails = get_security_guardrails()

agent = Agent(
    name="Production Agent",
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
    tools=[...]
)
```

### 5. Cost Management

```python
# Use budget-friendly models for routine tasks
model = OpenAIChatCompletionsModel(
    model="alias0",  # DeepSeek: $0.27/M tokens
    openai_client=AsyncOpenAI()
)

# Reserve expensive models for complex tasks
# gpt-4o: $2.50/M tokens (input), $10/M tokens (output)
```

### 6. Testing

```python
# Test tools independently
def test_my_tool():
    result = my_custom_tool("test_input")
    assert result.status == "success"

# Test agent with simple inputs
async def test_agent():
    result = await Runner.run(agent, "Simple test query")
    assert "expected" in result.final_output
```

---

## API Reference

### Agent Class

```python
@dataclass
class Agent(Generic[TContext]):
    name: str
    instructions: str | Callable[[TContext], str] | None = None
    description: str | None = None
    handoff_description: str | None = None
    handoffs: list[Agent | Handoff] = field(default_factory=list)
    tools: list[Tool] = field(default_factory=list)
    input_guardrails: list[InputGuardrail] = field(default_factory=list)
    output_guardrails: list[OutputGuardrail] = field(default_factory=list)
    model: Model | None = None
    model_settings: ModelSettings = field(default_factory=ModelSettings)
```

### Runner Class

```python
class Runner:
    @staticmethod
    async def run(
        agent: Agent,
        input: str,
        context: dict = None,
        stream: bool = False
    ) -> RunResult:
        """Execute an agent and return results."""
        pass
```

### function_tool Decorator

```python
@function_tool
def tool_name(param1: type1, param2: type2 = default) -> ReturnType:
    """Docstring describing the tool."""
    pass
```

### Handoff Function

```python
from cai.sdk.agents import handoff

specialist = Agent(name="Specialist", ...)
main_agent = Agent(
    name="Main",
    handoffs=[handoff(specialist)]
)
```

---

## Additional Resources

- **Framework Documentation**: `/home/user/caiGTL/docs/`
- **Example Agents**: `/home/user/caiGTL/src/cai/agents/`
- **Example Code**: `/home/user/caiGTL/examples/`
- **System Prompts**: `/home/user/caiGTL/src/cai/prompts/`

---

**Document Version**: 1.0
**Created**: November 2025
**For**: GTL AI Security Platform Development
**Framework**: CAI (Cybersecurity AI) v0.5.5
