"""
GTL Custom Security Agents - Base Classes

Abstract base classes and data models for sector-specific security agents.
These agents extend the base GTL Security Scanner with domain-specific checks.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum
import yaml
import logging

logger = logging.getLogger(__name__)


class FindingSeverity(Enum):
    """Finding severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComplianceFramework(Enum):
    """Regulatory and compliance frameworks"""
    # General
    ISO_27001 = "ISO 27001"
    NIST_CSF = "NIST Cybersecurity Framework"
    GDPR = "GDPR"

    # Healthcare
    HIPAA = "HIPAA"
    FDA_MEDICAL_DEVICE = "FDA Medical Device Cybersecurity"
    HL7_SECURITY = "HL7 Security"

    # Logistics/Customs
    CTPAT = "C-TPAT"
    SUNAT = "SUNAT Peru"
    ISO_28000 = "ISO 28000 Supply Chain Security"
    WCO_SAFE = "WCO SAFE Framework"

    # Peru
    LEY_29733 = "Ley 29733 - Peru Data Protection"


@dataclass
class AgentFinding:
    """
    Sector-specific security finding discovered by custom agent.

    This extends base scanner findings with domain-specific context.
    """

    # Core identification
    title: str
    severity: FindingSeverity
    category: str  # e.g., "EDI Security", "PHI Exposure", "Customs API Security"

    # Description
    description: str
    affected_component: str

    # Business context (critical for client reporting)
    business_impact: str  # Human-readable impact explanation
    financial_impact: Optional[str] = None  # e.g., "$50K-$1.5M HIPAA fines"

    # Remediation
    remediation: str
    remediation_priority: str = "medium"  # immediate, high, medium, low
    remediation_effort: str = "medium"  # hours, days, weeks, months

    # Compliance
    compliance_violations: List[str] = field(default_factory=list)  # e.g., ["HIPAA 164.312(a)(1)"]
    regulatory_risk: Optional[str] = None  # e.g., "Criminal charges possible"

    # Evidence
    evidence: Dict[str, Any] = field(default_factory=dict)
    proof_of_concept: Optional[str] = None

    # Metadata
    discovered_by: str = "GTL Agent"  # Agent name
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    confidence: str = "high"  # high, medium, low
    false_positive_likelihood: str = "low"  # low, medium, high

    # References
    references: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
            "affected_component": self.affected_component,
            "business_impact": self.business_impact,
            "financial_impact": self.financial_impact,
            "remediation": self.remediation,
            "remediation_priority": self.remediation_priority,
            "remediation_effort": self.remediation_effort,
            "compliance_violations": self.compliance_violations,
            "regulatory_risk": self.regulatory_risk,
            "evidence": self.evidence,
            "proof_of_concept": self.proof_of_concept,
            "discovered_by": self.discovered_by,
            "discovered_at": self.discovered_at.isoformat(),
            "confidence": self.confidence,
            "false_positive_likelihood": self.false_positive_likelihood,
            "references": self.references,
            "cve_ids": self.cve_ids,
        }


@dataclass
class AgentAnalysisResult:
    """Results from agent analysis"""

    agent_name: str
    sector: str  # logistics, medical_ai, customs, etc.
    findings: List[AgentFinding]
    analysis_duration_seconds: float

    # Summary statistics
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    compliance_violations_found: int = 0

    # Recommendations
    top_priorities: List[str] = field(default_factory=list)
    quick_wins: List[str] = field(default_factory=list)  # Easy fixes with high impact

    def __post_init__(self):
        """Calculate statistics"""
        self.total_findings = len(self.findings)
        self.critical_findings = sum(1 for f in self.findings if f.severity == FindingSeverity.CRITICAL)
        self.high_findings = sum(1 for f in self.findings if f.severity == FindingSeverity.HIGH)
        self.compliance_violations_found = sum(len(f.compliance_violations) for f in self.findings)


class BaseSecurityAgent(ABC):
    """
    Abstract base class for sector-specific security agents.

    Agents analyze scan results from the GTL Security Scanner and add
    domain-specific context, compliance mapping, and business impact analysis.

    Example:
        >>> agent = LogisticsSecurityAgent()
        >>> findings = await agent.analyze(scan_result)
        >>> for finding in findings:
        ...     print(f"[{finding.severity.value}] {finding.title}")
        ...     print(f"Compliance: {finding.compliance_violations}")
    """

    def __init__(
        self,
        knowledge_base_path: Optional[str] = None,
        enable_external_enrichment: bool = False
    ):
        """
        Initialize security agent.

        Args:
            knowledge_base_path: Path to YAML knowledge base (optional)
            enable_external_enrichment: Enable external threat intelligence (optional)
        """
        self.knowledge_base = {}
        if knowledge_base_path:
            self.knowledge_base = self._load_knowledge_base(knowledge_base_path)

        self.enable_external_enrichment = enable_external_enrichment
        self.findings: List[AgentFinding] = []

        logger.info(f"{self.__class__.__name__} initialized")

    @abstractmethod
    async def analyze(self, scan_result: Any) -> AgentAnalysisResult:
        """
        Analyze scan results with sector-specific logic.

        This is the main entry point for agents. Implement sector-specific
        vulnerability detection, compliance checking, and business impact analysis.

        Args:
            scan_result: ScanResult from GTL Security Scanner

        Returns:
            AgentAnalysisResult with sector-specific findings
        """
        pass

    @abstractmethod
    def get_compliance_mapping(self, finding: AgentFinding) -> Dict[str, Any]:
        """
        Map finding to regulatory requirements and standards.

        Args:
            finding: Agent finding to map

        Returns:
            Dictionary with compliance details:
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
        """
        pass

    @abstractmethod
    def calculate_business_risk_score(self, findings: List[AgentFinding]) -> float:
        """
        Calculate sector-specific business risk score (0-100).

        Unlike generic CVSS scoring, this considers:
        - Regulatory penalties
        - Business disruption potential
        - Reputation damage
        - Client SLA violations

        Args:
            findings: List of findings to score

        Returns:
            Risk score 0-100
        """
        pass

    def _load_knowledge_base(self, path: str) -> Dict[str, Any]:
        """
        Load sector-specific knowledge base from YAML.

        Args:
            path: Path to YAML file

        Returns:
            Parsed knowledge base dict
        """
        try:
            with open(path, 'r', encoding='utf-8') as f:
                kb = yaml.safe_load(f)
                logger.info(f"Loaded knowledge base: {path}")
                return kb
        except FileNotFoundError:
            logger.warning(f"Knowledge base not found: {path}")
            return {}
        except yaml.YAMLError as e:
            logger.error(f"Failed to parse knowledge base {path}: {e}")
            return {}

    def _prioritize_findings(
        self,
        findings: List[AgentFinding]
    ) -> List[AgentFinding]:
        """
        Sort findings by priority.

        Priority factors:
        1. Compliance violations (highest priority)
        2. Severity level
        3. Business impact
        4. Ease of exploitation

        Args:
            findings: Unsorted findings

        Returns:
            Sorted findings list
        """
        def priority_score(finding: AgentFinding) -> float:
            score = 0.0

            # Compliance violations = highest priority
            if finding.compliance_violations:
                score += 100.0

            # Severity
            severity_scores = {
                FindingSeverity.CRITICAL: 50.0,
                FindingSeverity.HIGH: 30.0,
                FindingSeverity.MEDIUM: 15.0,
                FindingSeverity.LOW: 5.0,
                FindingSeverity.INFO: 1.0,
            }
            score += severity_scores.get(finding.severity, 0.0)

            # Remediation priority
            if finding.remediation_priority == "immediate":
                score += 25.0
            elif finding.remediation_priority == "high":
                score += 15.0

            # Financial impact present
            if finding.financial_impact:
                score += 10.0

            return score

        return sorted(findings, key=priority_score, reverse=True)

    def _identify_quick_wins(
        self,
        findings: List[AgentFinding]
    ) -> List[str]:
        """
        Identify quick wins (easy fixes with high impact).

        Quick wins are:
        - High/critical severity
        - Low remediation effort (hours/days)
        - Clear remediation steps

        Args:
            findings: All findings

        Returns:
            List of quick win descriptions
        """
        quick_wins = []

        for finding in findings:
            # High impact
            if finding.severity not in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]:
                continue

            # Low effort
            if finding.remediation_effort not in ["hours", "days"]:
                continue

            quick_wins.append(
                f"{finding.title} - {finding.remediation_effort} effort, "
                f"{finding.severity.value} severity"
            )

        return quick_wins[:5]  # Top 5 quick wins

    async def enrich_with_threat_intelligence(
        self,
        finding: AgentFinding
    ) -> AgentFinding:
        """
        Enrich finding with external threat intelligence.

        Optional: Integrate with threat intel feeds for context.

        Args:
            finding: Finding to enrich

        Returns:
            Enriched finding
        """
        if not self.enable_external_enrichment:
            return finding

        # TODO: Integrate with threat intel APIs
        # - Shodan for exposed services
        # - VirusTotal for IOCs
        # - MITRE ATT&CK for TTPs

        return finding


# Export
__all__ = [
    "BaseSecurityAgent",
    "AgentFinding",
    "AgentAnalysisResult",
    "FindingSeverity",
    "ComplianceFramework",
]
