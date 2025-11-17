"""
GTL Security Scanner with Sector-Specific Agents

Extended scanner that integrates custom security agents for sector-specific analysis.
This module connects the base GTL Security Scanner with specialized agents.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, asdict

from gtl_agents import (
    LogisticsSecurityAgent,
    MedicalAIComplianceAgent,
    CustomsDataProtectionAgent,
    AgentAnalysisResult,
    AgentFinding,
)

logger = logging.getLogger(__name__)


# ===========================================
# SCAN PROFILES
# ===========================================

class ScanProfile:
    """Scan profile with associated agents"""

    LOGISTICS = "logistics"
    MEDICAL_AI = "medical_ai"
    CUSTOMS = "customs"
    FULL = "full"  # All agents
    DEFAULT = "default"  # No sector agents, just base scan


@dataclass
class EnhancedScanResult:
    """
    Enhanced scan result with agent analysis.

    Combines base scanner results with sector-specific agent findings.
    """

    # Base scan info
    scan_id: str
    scan_profile: str
    started_at: datetime
    completed_at: datetime
    duration_seconds: float

    # Base scanner results
    base_scan_results: Any  # Original ScanResult from scanner
    total_base_vulnerabilities: int
    base_risk_score: float

    # Agent analysis results
    agent_results: List[AgentAnalysisResult]
    total_agent_findings: int
    critical_agent_findings: int
    high_agent_findings: int

    # Compliance summary
    compliance_violations: List[str]
    regulatory_risks: List[str]

    # Recommendations
    top_priorities: List[str]
    quick_wins: List[str]

    # Overall risk
    overall_risk_score: float  # 0-100, combines base + agent analysis

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "scan_id": self.scan_id,
            "scan_profile": self.scan_profile,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "duration_seconds": self.duration_seconds,
            "summary": {
                "total_base_vulnerabilities": self.total_base_vulnerabilities,
                "total_agent_findings": self.total_agent_findings,
                "critical_agent_findings": self.critical_agent_findings,
                "high_agent_findings": self.high_agent_findings,
                "overall_risk_score": self.overall_risk_score,
            },
            "compliance": {
                "violations": self.compliance_violations,
                "regulatory_risks": self.regulatory_risks,
            },
            "recommendations": {
                "top_priorities": self.top_priorities,
                "quick_wins": self.quick_wins,
            },
            "agent_results": [
                {
                    "agent": result.agent_name,
                    "sector": result.sector,
                    "total_findings": result.total_findings,
                    "critical_findings": result.critical_findings,
                    "high_findings": result.high_findings,
                    "findings": [finding.to_dict() for finding in result.findings],
                }
                for result in self.agent_results
            ],
        }


# ===========================================
# SCANNER WITH AGENTS
# ===========================================

class SecurityScannerWithAgents:
    """
    Enhanced security scanner with sector-specific agents.

    This scanner extends the base GTL Security Scanner by adding
    sector-specific analysis agents that provide:
    - Domain expertise
    - Compliance mapping
    - Business impact analysis
    - Regulatory risk assessment

    Usage:
        >>> scanner = SecurityScannerWithAgents()
        >>> result = await scanner.scan(
        ...     scan_result=base_scan_result,
        ...     profile="logistics"
        ... )
        >>> print(f"Found {result.total_agent_findings} sector-specific issues")
        >>> print(f"Compliance violations: {result.compliance_violations}")
    """

    def __init__(self):
        """Initialize scanner with agents"""
        # Initialize agents
        self.agents = {
            ScanProfile.LOGISTICS: LogisticsSecurityAgent(),
            ScanProfile.MEDICAL_AI: MedicalAIComplianceAgent(),
            ScanProfile.CUSTOMS: CustomsDataProtectionAgent(),
        }

        logger.info("SecurityScannerWithAgents initialized with 3 agents")

    async def scan(
        self,
        scan_result: Any,
        profile: str = ScanProfile.DEFAULT,
        scan_id: Optional[str] = None
    ) -> EnhancedScanResult:
        """
        Run sector-specific analysis on scan results.

        Args:
            scan_result: Base scan result from GTL Security Scanner
            profile: Scan profile determining which agents to run
            scan_id: Optional scan ID (uses scan_result.scan_id if not provided)

        Returns:
            EnhancedScanResult with base + agent findings
        """
        start_time = datetime.utcnow()
        scan_id = scan_id or getattr(scan_result, 'scan_id', 'unknown')

        logger.info(f"Starting agent analysis for scan {scan_id} with profile {profile}")

        # Determine which agents to run
        agents_to_run = self._select_agents(profile)

        # Run agents in parallel
        agent_results = await self._run_agents(scan_result, agents_to_run)

        # Aggregate findings
        all_findings = []
        for result in agent_results:
            all_findings.extend(result.findings)

        # Calculate statistics
        total_agent_findings = sum(r.total_findings for r in agent_results)
        critical_findings = sum(r.critical_findings for r in agent_results)
        high_findings = sum(r.high_findings for r in agent_results)

        # Extract compliance violations
        compliance_violations = list(set(
            violation
            for result in agent_results
            for finding in result.findings
            for violation in finding.compliance_violations
        ))

        # Extract regulatory risks
        regulatory_risks = list(set(
            finding.regulatory_risk
            for result in agent_results
            for finding in result.findings
            if finding.regulatory_risk
        ))

        # Collect top priorities (from all agents)
        top_priorities = []
        for result in agent_results:
            top_priorities.extend(result.top_priorities)
        top_priorities = top_priorities[:10]  # Top 10 overall

        # Collect quick wins (from all agents)
        quick_wins = []
        for result in agent_results:
            quick_wins.extend(result.quick_wins)
        quick_wins = quick_wins[:5]  # Top 5 overall

        # Calculate overall risk score
        base_risk_score = getattr(scan_result, 'risk_score', 0.0)
        agent_risk_scores = [
            agent.calculate_business_risk_score(result.findings)
            for agent, result in zip(agents_to_run, agent_results)
        ]
        overall_risk_score = self._calculate_overall_risk(
            base_risk_score,
            agent_risk_scores,
            compliance_violations
        )

        # Build enhanced result
        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()

        enhanced_result = EnhancedScanResult(
            scan_id=scan_id,
            scan_profile=profile,
            started_at=start_time,
            completed_at=end_time,
            duration_seconds=duration,
            base_scan_results=scan_result,
            total_base_vulnerabilities=len(getattr(scan_result, 'vulnerabilities', [])),
            base_risk_score=base_risk_score,
            agent_results=agent_results,
            total_agent_findings=total_agent_findings,
            critical_agent_findings=critical_findings,
            high_agent_findings=high_findings,
            compliance_violations=compliance_violations,
            regulatory_risks=regulatory_risks,
            top_priorities=top_priorities,
            quick_wins=quick_wins,
            overall_risk_score=overall_risk_score,
        )

        logger.info(
            f"Agent analysis complete for {scan_id}: "
            f"{total_agent_findings} findings, "
            f"{len(compliance_violations)} compliance violations, "
            f"overall risk: {overall_risk_score:.1f}/100"
        )

        return enhanced_result

    def _select_agents(self, profile: str) -> List:
        """Select which agents to run based on profile"""
        if profile == ScanProfile.LOGISTICS:
            return [self.agents[ScanProfile.LOGISTICS]]

        elif profile == ScanProfile.MEDICAL_AI:
            return [self.agents[ScanProfile.MEDICAL_AI]]

        elif profile == ScanProfile.CUSTOMS:
            return [self.agents[ScanProfile.CUSTOMS]]

        elif profile == ScanProfile.FULL:
            return list(self.agents.values())

        else:  # DEFAULT
            return []

    async def _run_agents(
        self,
        scan_result: Any,
        agents: List
    ) -> List[AgentAnalysisResult]:
        """Run multiple agents in parallel"""
        if not agents:
            return []

        # Run agents concurrently
        tasks = [agent.analyze(scan_result) for agent in agents]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Agent {agents[i].__class__.__name__} failed: {result}")
            else:
                valid_results.append(result)

        return valid_results

    def _calculate_overall_risk(
        self,
        base_risk: float,
        agent_risks: List[float],
        compliance_violations: List[str]
    ) -> float:
        """
        Calculate overall risk score combining base scan and agents.

        Algorithm:
        - Base risk: 40% weight
        - Agent risks: 40% weight (averaged)
        - Compliance violations: 20% weight (up to +20 points)

        Returns:
            Risk score 0-100
        """
        # Base risk (40% weight)
        risk_from_base = base_risk * 0.4

        # Agent risks (40% weight)
        avg_agent_risk = sum(agent_risks) / len(agent_risks) if agent_risks else 0
        risk_from_agents = avg_agent_risk * 0.4

        # Compliance violations (20% weight, up to +20 points)
        compliance_penalty = min(len(compliance_violations) * 2, 20)

        # Total risk
        total_risk = risk_from_base + risk_from_agents + compliance_penalty

        return min(total_risk, 100.0)

    async def get_compliance_report(
        self,
        enhanced_result: EnhancedScanResult
    ) -> Dict[str, Any]:
        """
        Generate compliance report from enhanced scan result.

        Returns:
            Dictionary with compliance details per framework
        """
        compliance_report = {
            "scan_id": enhanced_result.scan_id,
            "frameworks": {},
            "violations": enhanced_result.compliance_violations,
            "regulatory_risks": enhanced_result.regulatory_risks,
        }

        # Aggregate compliance info from all agent findings
        for agent_result in enhanced_result.agent_results:
            for finding in agent_result.findings:
                # Get compliance mapping from agent
                agent_class = None
                if agent_result.sector == "logistics":
                    agent_class = self.agents[ScanProfile.LOGISTICS]
                elif agent_result.sector == "healthcare":
                    agent_class = self.agents[ScanProfile.MEDICAL_AI]
                elif agent_result.sector == "customs_trade":
                    agent_class = self.agents[ScanProfile.CUSTOMS]

                if agent_class:
                    mapping = agent_class.get_compliance_mapping(finding)

                    for framework in mapping["frameworks"]:
                        if framework not in compliance_report["frameworks"]:
                            compliance_report["frameworks"][framework] = {
                                "total_violations": 0,
                                "controls": [],
                                "severity": "low",
                            }

                        compliance_report["frameworks"][framework]["total_violations"] += 1

                        if framework in mapping["controls"]:
                            compliance_report["frameworks"][framework]["controls"].extend(
                                mapping["controls"][framework]
                            )

                        # Update severity (take highest)
                        current_severity = compliance_report["frameworks"][framework]["severity"]
                        finding_severity = mapping["severity_per_framework"].get(framework, "low")

                        if self._severity_higher(finding_severity, current_severity):
                            compliance_report["frameworks"][framework]["severity"] = finding_severity

        return compliance_report

    def _severity_higher(self, new: str, current: str) -> bool:
        """Check if new severity is higher than current"""
        severity_order = ["info", "low", "medium", "high", "critical"]
        return severity_order.index(new) > severity_order.index(current)


# ===========================================
# CONVENIENCE FUNCTIONS
# ===========================================

async def scan_with_agents(
    scan_result: Any,
    profile: str = "default"
) -> EnhancedScanResult:
    """
    Convenience function to run scan with agents.

    Args:
        scan_result: Base scan result
        profile: Scan profile (logistics, medical_ai, customs, full)

    Returns:
        Enhanced scan result with agent findings
    """
    scanner = SecurityScannerWithAgents()
    return await scanner.scan(scan_result, profile=profile)


# Export
__all__ = [
    "SecurityScannerWithAgents",
    "EnhancedScanResult",
    "ScanProfile",
    "scan_with_agents",
]
