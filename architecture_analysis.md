# CAI Framework - Architecture Analysis
**For GTL AI Security Platform Development**

---

## Executive Summary

**CAI (Cybersecurity AI Framework)** is an open-source, production-ready framework for building AI-powered offensive and defensive cybersecurity automation. Developed by Alias Robotics, it's used by thousands of individual users and hundreds of organizations for security research, penetration testing, bug bounty hunting, and CTF challenges.

**Key Strengths for GTL Platform:**
- ✅ **Budget-conscious**: 100% open-source (MIT license)
- ✅ **Security-focused**: Built specifically for cybersecurity automation
- ✅ **Extensible**: Easy to add custom agents and tools
- ✅ **Multi-agent orchestration**: Parallel execution for complex tasks
- ✅ **Enterprise-ready**: Built-in security guardrails and tracing
- ✅ **Active development**: Research-backed with continuous updates

---

## 1. High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        GTL AI SECURITY PLATFORM                      │
│                     (Built on CAI Framework)                         │
└────────────────────────┬────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      USER INTERFACE LAYER                            │
├─────────────────────────────────────────────────────────────────────┤
│  - CLI Interface (cai command)                                      │
│  - TUI (Text User Interface) for parallel agents                    │
│  - Python SDK for programmatic access                               │
│  - REPL with commands (/run, /load, /mcp, etc.)                    │
└────────────────────────┬────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    SECURITY GUARDRAILS LAYER                         │
├─────────────────────────────────────────────────────────────────────┤
│  INPUT GUARDRAILS:                                                   │
│  - Prompt injection detection (4-layer defense)                     │
│  - Unicode homograph normalization                                  │
│  - Encoding trick detection (base64, hex, rot13)                    │
│                                                                      │
│  OUTPUT GUARDRAILS:                                                  │
│  - Dangerous command filtering                                      │
│  - Credential exfiltration prevention                                │
│  - Command injection blocking                                        │
└────────────────────────┬────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      AGENT ORCHESTRATION LAYER                       │
├─────────────────────────────────────────────────────────────────────┤
│  AGENT PATTERNS:                                                     │
│  - Swarm (peer-to-peer)                                             │
│  - Hierarchical (delegation)                                        │
│  - Chain-of-Thought (sequential)                                    │
│  - Auction-based (competitive)                                      │
│  - Parallel (concurrent execution)                                  │
│                                                                      │
│  HANDOFFS: Agent → Agent delegation                                 │
│  MCP INTEGRATION: Model Context Protocol tools                      │
└────────────────────────┬────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    SPECIALIZED AGENT LAYER                           │
├─────────────────────────────────────────────────────────────────────┤
│  OFFENSIVE SECURITY:          DEFENSIVE SECURITY:                   │
│  - Red Team Agent             - Blue Team Agent                     │
│  - Bug Bounty Agent           - DFIR Agent                          │
│  - Exploit Expert             - Incident Response                   │
│  - CTF Solver                 - Hardening Agent                     │
│                                                                      │
│  SPECIALIZED DOMAINS:                                                │
│  - Reverse Engineering        - Network Analysis                    │
│  - Memory Analysis            - WiFi Security                       │
│  - Android SAST               - SubGHz SDR                          │
│  - Web Application Testing    - Code Agent (CodeAct)                │
└────────────────────────┬────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        TOOL EXECUTION LAYER                          │
├─────────────────────────────────────────────────────────────────────┤
│  RECONNAISSANCE:              WEB EXPLOITATION:                      │
│  - Nmap (port scanning)       - Curl (HTTP requests)                │
│  - Shodan API (OSINT)         - Headers analysis                    │
│  - Netstat (connections)      - PHP webshell generation             │
│  - Generic Linux commands     - Google/Perplexity search            │
│                                                                      │
│  NETWORK:                     COMMAND & CONTROL:                     │
│  - Packet capture (tcpdump)   - SSH with credentials                │
│  - Netcat (TCP/UDP)           - C2 communications                   │
│  - Filesystem operations                                             │
│                                                                      │
│  EXECUTION:                   CRYPTO:                                │
│  - Code interpreter           - Hash cracking                       │
│  - Python exec                - Encoding/decoding                   │
│  - Script automation          - Certificate analysis                │
└────────────────────────┬────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         LLM PROVIDER LAYER                           │
├─────────────────────────────────────────────────────────────────────┤
│  SUPPORTED MODELS:                                                   │
│  - OpenAI (GPT-4, GPT-4o, o1)                                       │
│  - Anthropic Claude (Sonnet, Opus, Haiku)                           │
│  - DeepSeek (alias0 - default)                                      │
│  - Ollama (local models)                                            │
│  - Azure OpenAI                                                      │
│  - OpenRouter (150+ models)                                         │
│  - LiteLLM proxy (unified interface)                                │
└────────────────────────┬────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    OBSERVABILITY & TELEMETRY                         │
├─────────────────────────────────────────────────────────────────────┤
│  - OpenTelemetry tracing                                             │
│  - Cost tracking (pricing.json)                                      │
│  - Performance metrics                                               │
│  - Logging (wasabi, rich formatting)                                │
│  - Session replay (cai-replay tool)                                 │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Core Components

### 2.1 Entry Points

| Component | Location | Purpose |
|-----------|----------|---------|
| **CLI Main** | `src/cai/cli.py:1823` | Primary command-line interface entry point |
| **SDK Agent** | `src/cai/sdk/agents/agent.py` | Core Agent class for programmatic use |
| **REPL** | `src/cai/repl/__init__.py` | Interactive shell with commands |
| **Scripts** | `pyproject.toml:232-236` | `cai`, `cai-replay`, `cai-asciinema`, `cai-gif` |

**How to Launch:**
```bash
# Standard CLI
cai

# With specific agent
CAI_AGENT_TYPE=bug_bounter_agent cai

# With initial prompt
cai "scan 192.168.1.0/24 for vulnerabilities"

# Python SDK
from cai.agents import get_agent_by_name
from cai.sdk.agents import Runner

agent = get_agent_by_name("redteam_agent")
result = await Runner.run(agent, "Find web vulnerabilities")
```

### 2.2 Agent System

**Agent Class Definition** (`src/cai/sdk/agents/agent.py`):

```python
@dataclass
class Agent(Generic[TContext]):
    name: str                              # Display name
    instructions: str | Callable           # System prompt
    description: str                       # Agent description
    handoffs: list[Agent | Handoff]        # Sub-agents for delegation
    tools: list[Tool]                      # Available capabilities
    input_guardrails: list[InputGuardrail] # Input validation
    output_guardrails: list[OutputGuardrail] # Output validation
    model: Model                           # LLM configuration
    model_settings: ModelSettings          # Temperature, top_p, etc.
```

**Agent Factory** (`src/cai/agents/factory.py:199`):
- Automatic agent discovery from `src/cai/agents/` directory
- Dynamic instantiation with `get_agent_by_name(agent_name)`
- Model override via environment variables
- MCP tool auto-injection

**Pre-built Agents** (40+ specialized agents):

| Category | Agents | Primary Use Case |
|----------|--------|------------------|
| **Offensive** | Red Team, Bug Bounty, Exploit Expert, CTF Solver | Penetration testing, vulnerability discovery |
| **Defensive** | Blue Team, DFIR, Incident Response | Security monitoring, incident investigation |
| **Analysis** | Reverse Engineering, Memory Analysis, Network Analyzer | Binary analysis, forensics, traffic inspection |
| **Specialized** | Android SAST, WiFi Security, SubGHz SDR | Domain-specific security testing |
| **Automation** | Code Agent (CodeAct), Flag Discriminator | Task automation, CTF flag extraction |

### 2.3 Tool System

**Tool Types** (`src/cai/sdk/agents/tool.py`):

1. **FunctionTool**: Python functions decorated with `@function_tool`
2. **FileSearchTool**: Vector store search (RAG)
3. **WebSearchTool**: Internet search capability
4. **ComputerTool**: Computer use (mouse/keyboard control)
5. **MCPTool**: Model Context Protocol tools

**Tool Organization** (`src/cai/tools/`):

```
tools/
├── reconnaissance/     # OSINT, scanning, enumeration (8 tools)
├── web/               # Web exploitation, search (4 tools)
├── network/           # Traffic capture, analysis (1 tool)
├── command_and_control/ # C2, SSH access (2 tools)
├── misc/              # Code execution, RAG, reasoning (4 tools)
├── others/            # Scripting utilities (1 tool)
├── exploitation/      # [EXTENSIBLE - empty]
├── privilege_scalation/ # [EXTENSIBLE - empty]
├── lateral_movement/  # [EXTENSIBLE - empty]
└── data_exfiltration/ # [EXTENSIBLE - empty]
```

**Total Built-in Tools**: 24 Python modules (expandable to 60+ with sub-functions)

### 2.4 Orchestration Patterns

**Pattern Types** (`src/cai/agents/patterns/`):

1. **Swarm**: Decentralized peer-to-peer coordination
2. **Hierarchical**: Main agent delegates to specialists
3. **Chain-of-Thought**: Sequential pipeline (A → B → C)
4. **Auction-Based**: Agents compete for tasks
5. **Recursive**: Single agent iteratively refines output
6. **Parallel**: Multiple agents run concurrently

**Implemented Patterns**:
- `red_team.py`: Red team orchestration
- `red_blue_team.py`: Red/Blue team collaboration
- `offsec.py`: Offensive security workflow
- `bb_triage.py`: Bug bounty triage automation
- `parallel_offensive_patterns.py`: Parallel agent execution

### 2.5 Security Guardrails

**Implementation** (`src/cai/agents/guardrails.py` - 21,000 lines):

**Input Guardrails**:
- Prompt injection pattern detection (50+ patterns)
- Unicode homograph normalization (Cyrillic → Latin)
- Encoding trick detection (base64, hex, rot13, URL encoding)
- Role manipulation prevention
- Indirect injection from external sources

**Output Guardrails**:
- Dangerous command blocking (`rm -rf`, `dd`, `mkfs`, etc.)
- Credential exfiltration prevention
- Command injection detection
- Sensitive file access prevention

**Research Foundation**: Based on [Prompt Injection Defense](https://arxiv.org/pdf/2508.21669) paper with 4-layer defense system

---

## 3. Data Flow Architecture

```
┌──────────────────┐
│   User Input     │
│   "Scan target"  │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────────────────┐
│   INPUT GUARDRAILS                           │
│   - Check for prompt injection               │
│   - Normalize Unicode homographs             │
│   - Detect encoding tricks                   │
└────────┬─────────────────────────────────────┘
         │ [VALIDATED INPUT]
         ▼
┌──────────────────────────────────────────────┐
│   AGENT SELECTION                            │
│   - Factory: get_agent_by_name()            │
│   - Load system prompt                       │
│   - Initialize tools                         │
└────────┬─────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────┐
│   LLM CALL                                   │
│   - Model: OpenAI/Claude/DeepSeek/Ollama    │
│   - API: Chat Completions or Responses API   │
│   - Settings: temperature, top_p, etc.       │
└────────┬─────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────┐
│   DECISION: Tool Call or Handoff?           │
└────┬──────────────────────────┬──────────────┘
     │                          │
     ▼                          ▼
┌─────────────┐        ┌───────────────────┐
│ TOOL CALL   │        │ HANDOFF TO        │
│             │        │ SPECIALIST AGENT  │
└─────┬───────┘        └─────────┬─────────┘
      │                          │
      │ Execute Python function  │ Recurse with
      │ (nmap, ssh, curl, etc.)  │ sub-agent
      │                          │
      ▼                          ▼
┌──────────────────────────────────────────────┐
│   TOOL RESULT / SUB-AGENT RESULT             │
└────────┬─────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────┐
│   OUTPUT GUARDRAILS                          │
│   - Validate command safety                  │
│   - Check for credential leakage             │
│   - Filter sensitive information             │
└────────┬─────────────────────────────────────┘
         │ [VALIDATED OUTPUT]
         ▼
┌──────────────────────────────────────────────┐
│   RETURN TO USER                             │
│   - Final answer                             │
│   - Tool outputs                             │
│   - Recommendations                          │
└──────────────────────────────────────────────┘
```

---

## 4. Configuration Architecture

### 4.1 Environment Configuration

**File**: `.env` (example: `.env.example`)

```bash
# API Keys (Required)
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...

# Optional API Keys
SHODAN_API_KEY=...
C99_API_KEY=...
GOOGLE_SEARCH_API_KEY=...
PERPLEXITY_API_KEY=...

# CAI Configuration
CAI_MODEL=alias0              # Default model
CAI_AGENT_TYPE=one_tool_agent # Default agent
CAI_DEBUG=1                   # Debug level (0-2)
CAI_GUARDRAILS=true           # Enable guardrails
CAI_TRACING=false             # OpenTelemetry tracing
CAI_PRICE_LIMIT=10.0          # Cost limit ($)
CAI_PARALLEL=0                # Parallel agents count
```

### 4.2 Agent Configuration

**File**: `agents.yml` (example: `agents.yml.example`)

```yaml
parallel_agents:
  - name: redteam_agent
    model: gpt-4o
    prompt: "Focus on finding vulnerabilities"
    unified_context: false  # Separate message history

  - name: blueteam_agent
    model: claude-sonnet-4-20250514
    prompt: "Focus on defensive measures"
    unified_context: false

  - name: bug_bounter_agent
    model: alias0
    prompt: "Search for bugs and create reports"
    unified_context: false
```

**Activation**:
```bash
# Automatically enables parallel mode if 2+ agents configured
cai
```

### 4.3 System Prompts

**Location**: `src/cai/prompts/`

Pre-built system prompts for each agent:
- `system_red_team_agent.md`: Red team instructions
- `system_blue_team_agent.md`: Blue team instructions
- `system_bug_bounter.md`: Bug bounty workflow
- `system_dfir_agent.md`: Forensics procedures
- `wifi_security_agent.md`: WiFi testing
- And 15+ more specialized prompts

**Loading Custom Prompts**:
```python
from cai.util import load_prompt_template

custom_prompt = load_prompt_template("prompts/my_custom_agent.md")
agent.instructions = create_system_prompt_renderer(custom_prompt)
```

---

## 5. Extension Points for GTL Platform

### 5.1 Custom Agent Creation

**Location**: Create new file in `src/cai/agents/gtl_logistics_agent.py`

```python
import os
from cai.sdk.agents import Agent, OpenAIChatCompletionsModel
from cai.tools.reconnaissance.generic_linux_command import generic_linux_command
from cai.tools.reconnaissance.nmap import nmap
from openai import AsyncOpenAI
from cai.agents.guardrails import get_security_guardrails

# Custom prompt for logistics security
instructions = """You are a cybersecurity expert specializing in logistics
and supply chain security. Focus on:
- Warehouse management systems (WMS)
- Transportation management systems (TMS)
- IoT devices (GPS trackers, RFID scanners)
- Fleet management software
- ERP systems (SAP, Oracle)

Use the available tools to assess security posture."""

input_guardrails, output_guardrails = get_security_guardrails()

gtl_logistics_agent = Agent(
    name="GTL Logistics Security Agent",
    description="Specialized in logistics and supply chain security",
    instructions=instructions,
    tools=[generic_linux_command, nmap],
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
    model=OpenAIChatCompletionsModel(
        model=os.getenv('CAI_MODEL', 'alias0'),
        openai_client=AsyncOpenAI(),
    ),
)
```

### 5.2 Custom Tool Creation

**Pattern**: `@function_tool` decorator

```python
from cai.sdk.agents import function_tool
from pydantic import BaseModel

class VulnerabilityReport(BaseModel):
    severity: str
    cvss_score: float
    description: str
    remediation: str

@function_tool
def check_logistics_vulnerability(system_type: str, version: str) -> VulnerabilityReport:
    """Check for known vulnerabilities in logistics software.

    Args:
        system_type: Type of system (WMS, TMS, ERP)
        version: Software version

    Returns:
        Vulnerability report with severity and remediation
    """
    # Implement vulnerability database lookup
    # Could integrate with NVD, Exploit-DB, etc.
    return VulnerabilityReport(
        severity="HIGH",
        cvss_score=7.5,
        description="SQL injection in login form",
        remediation="Upgrade to version X.Y.Z"
    )
```

### 5.3 GTL-Specific Integrations

**Recommended Extensions**:

1. **SAP/Oracle Security Module**
   - Custom tools for ERP vulnerability assessment
   - Integration with SAP Security Notes
   - Oracle patch verification

2. **IoT Device Scanner**
   - GPS tracker security assessment
   - RFID reader vulnerability testing
   - Fleet management API testing

3. **Supply Chain Risk Module**
   - Vendor security assessment
   - Third-party integration testing
   - API security validation

4. **Peruvian Compliance Module**
   - PCIDSS compliance checks
   - Data protection law (Ley 29733) validation
   - Industry-specific regulations

---

## 6. Scalability & Performance

### 6.1 Parallel Execution

**Configuration**: `agents.yml` with multiple agents

**Performance**:
- Up to 10 parallel agents tested
- Independent message histories (no context sharing overhead)
- Concurrent LLM API calls
- Parallel tool execution

### 6.2 Cost Optimization

**Pricing Tracking** (`pricing.json`):
- Real-time cost calculation for all models
- Price limits via `CAI_PRICE_LIMIT`
- Model selection based on cost/performance

**Budget-Friendly Models**:
- `alias0` (DeepSeek): $0.27/M tokens (default)
- `claude-haiku`: $0.80/M tokens (fast)
- `gpt-4o-mini`: $0.15/M tokens (economical)
- Ollama: Free (local execution)

### 6.3 Observability

**Tracing** (`CAI_TRACING=true`):
- OpenTelemetry integration
- Full LLM call tracing
- Tool execution monitoring
- Performance metrics

**Logging**:
- Rich console output
- Structured logging (wasabi)
- Session replay (`cai-replay` tool)
- Asciinema recording (`cai-asciinema`)

---

## 7. Security Architecture

### 7.1 Defense-in-Depth

**Layer 1: Input Validation**
- Prompt injection detection
- Unicode normalization
- Encoding detection

**Layer 2: Agent Guardrails**
- Input/output filtering
- Command validation
- Credential protection

**Layer 3: Tool Sandboxing**
- Container isolation (optional)
- Timeout enforcement
- Resource limits

**Layer 4: Observability**
- Full audit trail
- Tracing and monitoring
- Cost controls

### 7.2 Responsible AI

**Research-Backed**:
- [Automation vs Autonomy](https://arxiv.org/pdf/2506.23592): Capability taxonomy
- [Prompt Injection Defense](https://arxiv.org/pdf/2508.21669): 4-layer guardrails
- Human-in-the-loop by default
- Ethical security automation guidelines

---

## 8. Technology Stack Summary

| Layer | Technologies |
|-------|--------------|
| **Language** | Python 3.9+ |
| **LLM SDKs** | OpenAI SDK, Anthropic SDK, LiteLLM |
| **CLI/UI** | Click, Rich, Prompt Toolkit, Textual TUI |
| **Networking** | Paramiko (SSH), dnspython, requests |
| **Security** | Custom guardrails, OpenTelemetry |
| **Data** | Pandas, NumPy, NetworkX, PyPDF2 |
| **Build** | Hatchling, UV (package manager) |
| **Testing** | Pytest, Playwright, inline-snapshot |
| **Documentation** | MkDocs Material, MkDocstrings |

---

## 9. File Structure Overview

```
caiGTL/
├── src/cai/                    # Core framework
│   ├── cli.py                  # Main CLI entry point (1,869 lines)
│   ├── agents/                 # Pre-built agents (40+ agents)
│   │   ├── factory.py          # Agent factory
│   │   ├── guardrails.py       # Security guardrails (21k lines)
│   │   └── patterns/           # Orchestration patterns
│   ├── sdk/agents/             # SDK modules
│   │   ├── agent.py            # Core Agent class
│   │   ├── tool.py             # Tool definitions
│   │   ├── handoffs.py         # Handoff system
│   │   └── models/             # LLM integrations
│   ├── tools/                  # Security tools (24 modules)
│   │   ├── reconnaissance/     # Nmap, Shodan, etc.
│   │   ├── web/                # Web exploitation
│   │   ├── network/            # Packet capture
│   │   └── command_and_control/ # SSH, C2
│   ├── prompts/                # System prompts
│   ├── repl/                   # Interactive shell
│   └── internal/               # Internal utilities
├── examples/                   # Usage examples
│   ├── cai/                    # CAI-specific examples
│   ├── basic/                  # Basic agent usage
│   ├── handoffs/               # Multi-agent examples
│   └── mcp/                    # MCP integration
├── docs/                       # Documentation
│   ├── quickstart.md           # Getting started
│   ├── cai_architecture.md     # Architecture details
│   ├── multi_agent.md          # Multi-agent patterns
│   └── tui/                    # TUI documentation
├── tests/                      # Test suite
├── benchmarks/                 # Performance benchmarks
├── tools/                      # Utility scripts
│   ├── replay.py               # Session replay
│   ├── logs.py                 # Log analysis
│   └── case_study_generator.py # Case study automation
├── pyproject.toml              # Project configuration
├── agents.yml.example          # Agent configuration template
└── .env.example                # Environment template
```

---

## 10. Recommendations for GTL Platform

### 10.1 Immediate Use Cases

1. **Automated Pentesting for Logistics Companies**
   - Use `redteam_agent` or `bug_bounter_agent`
   - Custom tools for logistics software (WMS, TMS, ERP)
   - Automated vulnerability scanning and reporting

2. **Threat Detection & Response**
   - Use `blueteam_agent` or `dfir_agent`
   - Integration with logistics company SIEMs
   - Incident response automation

3. **Compliance Automation**
   - Custom agent for Peruvian regulations
   - Automated compliance checks (PCIDSS, ISO 27001)
   - Audit trail generation

### 10.2 Customization Priorities

1. **High Priority**:
   - Create `gtl_logistics_agent` (specialized for logistics)
   - Add tools for SAP/Oracle/logistics software
   - Peruvian compliance module

2. **Medium Priority**:
   - IoT device security tools (GPS, RFID)
   - Supply chain risk assessment tools
   - Integration with local threat intelligence

3. **Low Priority**:
   - Custom UI/dashboard (can start with CLI/TUI)
   - Advanced orchestration patterns
   - Multi-language support (Spanish prompts)

### 10.3 Architecture Decisions

**For GTL Platform:**
- ✅ **Use CAI as foundation** (don't reinvent the wheel)
- ✅ **Extend with custom agents** (logistics-specific)
- ✅ **Add custom tools** (WMS/TMS/ERP scanning)
- ✅ **Keep guardrails enabled** (enterprise security)
- ✅ **Use budget-friendly models** (alias0/DeepSeek)
- ✅ **Implement parallel agents** (faster assessments)
- ✅ **Add Peruvian compliance module** (local regulations)

---

## 11. Next Steps

1. **Install CAI Framework** (see `installation_guide.md`)
2. **Run basic examples** (see `quick_start_examples.py`)
3. **Create GTL logistics agent** (extend base agents)
4. **Add custom tools** (logistics software scanners)
5. **Test with pilot customer** (one mid-market logistics company)
6. **Iterate based on feedback**

---

## References

- **CAI Repository**: Current working directory (`/home/user/caiGTL`)
- **Documentation**: `docs/` directory
- **Research Papers**:
  - [CAI Framework](https://arxiv.org/pdf/2504.06017)
  - [Automation vs Autonomy](https://arxiv.org/pdf/2506.23592)
  - [Prompt Injection Defense](https://arxiv.org/pdf/2508.21669)
  - [CAIBench](https://arxiv.org/pdf/2510.24317)
- **GitHub**: https://github.com/openai/openai-agents-python (upstream)

---

**Document Version**: 1.0
**Created**: November 2025
**For**: GTL AI Security Platform Development
**Author**: AI Analysis of CAI Framework
