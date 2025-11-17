# GTL Custom Security Agents

**Sector-Specific Security Analysis for Competitive Differentiation**

## Overview

GTL Custom Security Agents transform the GTL Security Scanner from a commodity tool into a specialized security consultant. These agents add sector-specific expertise, compliance mapping, and business impact analysis that justify **2.5X-5X premium pricing**.

## Value Proposition

### Without Agents (Commodity Tool)
- Generic vulnerability scanning
- CVSS scores
- Technical remediation
- **Pricing: $8K + $2K/month**

### With Agents (Specialized Consultant)
- Sector-specific vulnerability detection
- Regulatory compliance mapping (HIPAA, SUNAT, C-TPAT)
- Business impact analysis in client language
- Prioritized remediation with ROI
- **Pricing: $15K-$30K + $5K-$10K/month** ← 2.5X-5X premium

## Available Agents

### 1. Logistics Security Agent

**Target Clients:** Freight forwarders, customs brokers, 3PL providers

**Specialized Checks:**
- EDI (Electronic Data Interchange) security (X12, EDIFACT)
- Bill of Lading data protection
- Customs API security (SUNAT, CBP, SAT)
- Supply chain data integrity
- Third-party logistics access controls

**Compliance Frameworks:**
- C-TPAT (Customs-Trade Partnership Against Terrorism)
- ISO 28000 Supply Chain Security
- WCO SAFE Framework
- SUNAT Regulations (Peru)

### 2. Medical AI Compliance Agent

**Target Clients:** Hospitals, medical AI startups, telemedicine platforms

**Specialized Checks:**
- PHI (Protected Health Information) exposure
- HIPAA Technical Safeguards (164.312)
- Medical AI endpoint security (BAA compliance)
- DICOM medical imaging server security
- FDA Medical Device Cybersecurity
- HL7/FHIR API protection

**Compliance Frameworks:**
- HIPAA Security Rule
- FDA Cybersecurity Guidance
- GDPR (for EU patient data)
- Ley 29733 (Peru data protection)

### 3. Customs Data Protection Agent

**Target Clients:** Import/export companies, customs brokers, e-commerce

**Specialized Checks:**
- SUNAT integration security (Clave SOL)
- Customs declaration (DAM) protection
- E-invoice system security
- Cross-border data transfer compliance
- RUC and tax data protection

**Compliance Frameworks:**
- SUNAT Regulations
- Ley 29733 (Peru Data Protection Law)
- International trade data protection
- Cross-border transfer requirements

## Installation

```bash
# Agents are included in GTL AI Security Platform
cd gtl-ai-security
pip install -r requirements.txt

# Verify agents
python -c "from gtl_agents import LogisticsSecurityAgent, MedicalAIComplianceAgent, CustomsDataProtectionAgent; print('✓ All agents loaded')"
```

## Usage

### Basic Usage

```python
import asyncio
from gtl_security_scanner.scanner_with_agents import SecurityScannerWithAgents, ScanProfile

async def run_sector_scan():
    # 1. Run base security scan (using existing scanner)
    from gtl_security_scanner.scanner import SecurityScanner
    scanner = SecurityScanner()
    base_result = await scanner.scan(target, scan_id="scan-001")

    # 2. Run sector-specific analysis
    agent_scanner = SecurityScannerWithAgents()
    enhanced_result = await agent_scanner.scan(
        scan_result=base_result,
        profile=ScanProfile.LOGISTICS  # or MEDICAL_AI, CUSTOMS, FULL
    )

    # 3. Review findings
    print(f"Base vulnerabilities: {enhanced_result.total_base_vulnerabilities}")
    print(f"Agent findings: {enhanced_result.total_agent_findings}")
    print(f"Compliance violations: {len(enhanced_result.compliance_violations)}")
    print(f"Overall risk: {enhanced_result.overall_risk_score}/100")

    # 4. Get top priorities
    print("\n🚨 TOP PRIORITIES:")
    for i, priority in enumerate(enhanced_result.top_priorities, 1):
        print(f"{i}. {priority}")

    # 5. Get quick wins
    print("\n✅ QUICK WINS:")
    for i, win in enumerate(enhanced_result.quick_wins, 1):
        print(f"{i}. {win}")

asyncio.run(run_sector_scan())
```

### Logistics Sector Example

```python
from gtl_agents import LogisticsSecurityAgent

async def scan_logistics_company():
    agent = LogisticsSecurityAgent()

    # Analyze scan results
    result = await agent.analyze(scan_result)

    print(f"Found {result.total_findings} logistics-specific issues:")
    for finding in result.findings:
        print(f"\n[{finding.severity.value.upper()}] {finding.title}")
        print(f"Category: {finding.category}")
        print(f"Business Impact:\n{finding.business_impact}")
        print(f"Compliance: {', '.join(finding.compliance_violations)}")
        print(f"Remediation Priority: {finding.remediation_priority}")

asyncio.run(scan_logistics_company())
```

### Medical AI Sector Example

```python
from gtl_agents import MedicalAIComplianceAgent

async def scan_healthtech_platform():
    agent = MedicalAIComplianceAgent()

    result = await agent.analyze(scan_result)

    # Check for critical HIPAA violations
    critical = [f for f in result.findings if f.severity == FindingSeverity.CRITICAL]

    if critical:
        print(f"⚠️ CRITICAL: {len(critical)} HIPAA violations found!")
        for finding in critical:
            print(f"\n{finding.title}")
            print(f"Financial Impact: {finding.financial_impact}")
            print(f"Regulatory Risk: {finding.regulatory_risk}")

    # Get compliance report
    compliance = await agent_scanner.get_compliance_report(enhanced_result)
    print(f"\nCompliance Status:")
    for framework, details in compliance["frameworks"].items():
        print(f"  {framework}: {details['total_violations']} violations ({details['severity']})")

asyncio.run(scan_healthtech_platform())
```

### API Integration

```python
from fastapi import APIRouter
from gtl_security_scanner.scanner_with_agents import scan_with_agents, ScanProfile

router = APIRouter()

@router.post("/api/v1/scan/enhanced")
async def run_enhanced_scan(
    target: str,
    profile: str = "default"
):
    # Run base scan
    base_result = await run_base_scan(target)

    # Run with agents
    enhanced_result = await scan_with_agents(base_result, profile=profile)

    return {
        "scan_id": enhanced_result.scan_id,
        "summary": {
            "base_vulnerabilities": enhanced_result.total_base_vulnerabilities,
            "agent_findings": enhanced_result.total_agent_findings,
            "overall_risk": enhanced_result.overall_risk_score,
        },
        "compliance": {
            "violations": enhanced_result.compliance_violations,
            "regulatory_risks": enhanced_result.regulatory_risks,
        },
        "recommendations": {
            "top_priorities": enhanced_result.top_priorities,
            "quick_wins": enhanced_result.quick_wins,
        }
    }
```

## Scan Profiles

| Profile | Agents Executed | Use Case |
|---------|----------------|----------|
| `logistics` | Logistics Agent | Freight forwarders, customs brokers, 3PL |
| `medical_ai` | Medical AI Agent | Hospitals, healthtech, telemedicine |
| `customs` | Customs Agent | Import/export, e-commerce with intl sales |
| `full` | All 3 agents | Comprehensive multi-sector analysis |
| `default` | None | Base scan only (no agents) |

## Finding Structure

Each agent finding includes:

```python
@dataclass
class AgentFinding:
    # Core
    title: str
    severity: FindingSeverity  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # e.g., "EDI Security", "HIPAA Violation"

    # Description
    description: str
    affected_component: str

    # Business Context
    business_impact: str  # Human-readable impact explanation
    financial_impact: Optional[str]  # e.g., "$50K-$1.5M HIPAA fines"

    # Remediation
    remediation: str
    remediation_priority: str  # immediate, high, medium, low
    remediation_effort: str  # hours, days, weeks, months

    # Compliance
    compliance_violations: List[str]  # e.g., ["HIPAA 164.312(a)(1)"]
    regulatory_risk: Optional[str]  # e.g., "RUC suspension possible"

    # Evidence
    evidence: Dict[str, Any]
    proof_of_concept: Optional[str]
```

## Knowledge Bases

Agents use YAML knowledge bases with sector-specific threat intelligence:

- `logistics_vulnerabilities.yaml`: EDI vulnerabilities, customs APIs, supply chain threats
- `medical_ai_threats.yaml`: PHI exposure risks, HIPAA requirements, FDA guidance
- `customs_regulations.yaml`: SUNAT systems, Ley 29733, cross-border compliance

Knowledge bases are automatically loaded and can be customized per client.

## Compliance Mapping

Agents automatically map findings to regulatory requirements:

```python
compliance_mapping = agent.get_compliance_mapping(finding)
# Returns:
{
    "frameworks": ["HIPAA", "ISO 27001"],
    "controls": {
        "HIPAA": ["164.312(a)(1)", "164.312(e)(1)"],
        "ISO 27001": ["A.9.4.1", "A.10.1.1"]
    },
    "severity_per_framework": {
        "HIPAA": "critical",
        "ISO 27001": "high"
    }
}
```

## Business Risk Scoring

Agents calculate sector-specific business risk (0-100):

```python
risk_score = agent.calculate_business_risk_score(findings)
# Considers:
# - Regulatory penalties
# - Business disruption potential
# - Reputation damage
# - Client SLA violations
```

## Testing

```bash
# Run agent tests
pytest gtl_agents/tests/test_agents.py -v

# Test specific agent
pytest gtl_agents/tests/test_agents.py::TestLogisticsAgent -v

# Integration tests
pytest gtl_agents/tests/test_agents.py::TestAgentIntegration -v
```

## Architecture

```
gtl_agents/
├── base_agent.py              # Abstract base class
├── logistics_agent.py         # Logistics sector specialist
├── medical_agent.py           # Healthcare/medical AI specialist
├── customs_agent.py           # Customs/trade specialist
├── knowledge_bases/
│   ├── logistics_vulnerabilities.yaml
│   ├── medical_ai_threats.yaml
│   └── customs_regulations.yaml
└── tests/
    └── test_agents.py

gtl_security_scanner/
└── scanner_with_agents.py     # Integration with base scanner
```

## Pricing Strategy

### Tier 1: Generic Scanner ($8K + $2K/month)
- Base vulnerability scanning
- Generic CVSS scoring
- Technical remediation

### Tier 2: With Agents ($15K + $5K/month) ← **2.5X PREMIUM**
- Sector-specific analysis
- Compliance mapping
- Business impact assessment
- Priority 1: Logistics OR Medical AI OR Customs

### Tier 3: Enterprise + SOC ($30K + $10K/month) ← **5X PREMIUM**
- All agents (full profile)
- Custom knowledge bases
- Quarterly compliance audits
- 24/7 SOC monitoring
- Dedicated security consultant

## Client Examples

### Logistics Client: "GlobalShip Peru"
**Problem:** SUNAT Clave SOL exposed in GitHub, 15 unencrypted EDI endpoints

**Agent Findings:**
- 🚨 CRITICAL: SUNAT Credentials Exposed → "$2,300-$4,600 fine + RUC suspension risk"
- 🚨 CRITICAL: 15 Unencrypted EDI Endpoints → "C-TPAT certification violation"
- ⚠️ HIGH: Bill of Lading Directory Listing → "$250K-$2M competitive intelligence loss"

**Business Impact:** Client avoided RUC suspension, passed C-TPAT audit
**Revenue:** $18K setup + $6K/month (3X base pricing)

### Healthcare Client: "MediAI Diagnostics"
**Problem:** Sending patient data to ChatGPT without BAA

**Agent Findings:**
- 🚨 CRITICAL: PHI to OpenAI Without BAA → "$100-$50K per patient, mandatory breach notification"
- 🚨 CRITICAL: PHI in Error Messages → "HIPAA 164.312(a)(1) violation"
- 🚨 CRITICAL: Open DICOM Server → "All patient images exposed to internet"

**Business Impact:** Client avoided $5M+ HIPAA breach, implemented Azure OpenAI with BAA
**Revenue:** $25K setup + $8K/month (4X base pricing)

## Support

- Email: agents@gtl.pe
- Docs: https://docs.gtl.pe/agents
- Slack: gtl-security.slack.com #agents

## License

Copyright © 2025 GTL Security Peru. All rights reserved.

---

**🚀 Differentiation Through Specialization**

These agents are the reason clients pay premium prices. They're not buying a scanner - they're buying a specialized security consultant who speaks their language and understands their regulatory landscape.
