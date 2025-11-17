"""
GTL Compliance Auditor - Automated Compliance Checking
Supports HIPAA, ISO 27001, SOC 2, SUNAT, Ley 29733 (Peru Data Protection)
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
import asyncio
import json

logger = logging.getLogger(__name__)


class ComplianceStatus(Enum):
    """Compliance status levels"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    NOT_TESTED = "not_tested"


class Severity(Enum):
    """Severity of non-compliance"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Control:
    """Compliance control/requirement"""
    control_id: str
    control_name: str
    description: str
    category: str
    framework: str  # HIPAA, ISO27001, SOC2, SUNAT, Ley29733
    test_procedure: str
    expected_outcome: str
    severity: Severity
    automated: bool = True
    frequency: str = "quarterly"  # daily, weekly, monthly, quarterly, annual


@dataclass
class ComplianceCheckResult:
    """Result of a single compliance check"""
    control_id: str
    control_name: str
    framework: str
    status: ComplianceStatus
    severity: Severity
    evidence: List[str] = field(default_factory=list)
    findings: Optional[str] = None
    remediation: Optional[str] = None
    tested_at: datetime = field(default_factory=datetime.utcnow)
    next_test_date: Optional[datetime] = None
    compliance_score: float = 0.0  # 0-100


@dataclass
class ComplianceReport:
    """Full compliance audit report"""
    report_id: str
    framework: str
    client_id: str
    generated_at: datetime
    results: List[ComplianceCheckResult]
    overall_score: float  # 0-100
    compliant_controls: int
    non_compliant_controls: int
    total_controls: int
    critical_findings: int
    high_findings: int
    executive_summary: str
    recommendations: List[str]


class HIPAACompliance:
    """HIPAA (Health Insurance Portability and Accountability Act) compliance checks"""

    def __init__(self):
        self.controls = self._load_hipaa_controls()

    def _load_hipaa_controls(self) -> List[Control]:
        """Load HIPAA controls"""
        return [
            # Security Rule - Administrative Safeguards
            Control(
                control_id="HIPAA-164.308(a)(1)(i)",
                control_name="Security Management Process",
                description="Implement policies and procedures to prevent, detect, contain, and correct security violations",
                category="Administrative Safeguards",
                framework="HIPAA",
                test_procedure="Verify security policies exist and are current",
                expected_outcome="Security policies documented and approved",
                severity=Severity.CRITICAL,
                automated=True,
                frequency="quarterly"
            ),
            Control(
                control_id="HIPAA-164.308(a)(3)(i)",
                control_name="Workforce Security",
                description="Implement procedures to ensure workforce access to ePHI is appropriate",
                category="Administrative Safeguards",
                framework="HIPAA",
                test_procedure="Review access controls and user permissions",
                expected_outcome="All users have appropriate access levels",
                severity=Severity.HIGH,
                automated=True,
                frequency="monthly"
            ),
            Control(
                control_id="HIPAA-164.308(a)(5)(ii)(C)",
                control_name="Log-in Monitoring",
                description="Monitor log-in attempts and report discrepancies",
                category="Administrative Safeguards",
                framework="HIPAA",
                test_procedure="Review failed login attempts and anomalies",
                expected_outcome="Failed logins logged and monitored",
                severity=Severity.MEDIUM,
                automated=True,
                frequency="weekly"
            ),

            # Security Rule - Physical Safeguards
            Control(
                control_id="HIPAA-164.310(a)(1)",
                control_name="Facility Access Controls",
                description="Limit physical access to electronic information systems and facilities",
                category="Physical Safeguards",
                framework="HIPAA",
                test_procedure="Review physical access logs and badge systems",
                expected_outcome="Only authorized personnel have facility access",
                severity=Severity.HIGH,
                automated=False,
                frequency="quarterly"
            ),
            Control(
                control_id="HIPAA-164.310(d)(1)",
                control_name="Device and Media Controls",
                description="Implement policies for disposal of ePHI and hardware/media",
                category="Physical Safeguards",
                framework="HIPAA",
                test_procedure="Review disposal procedures and sanitization logs",
                expected_outcome="Secure disposal procedures documented and followed",
                severity=Severity.MEDIUM,
                automated=False,
                frequency="quarterly"
            ),

            # Security Rule - Technical Safeguards
            Control(
                control_id="HIPAA-164.312(a)(1)",
                control_name="Access Control",
                description="Implement technical policies to allow only authorized access to ePHI",
                category="Technical Safeguards",
                framework="HIPAA",
                test_procedure="Test access controls and authentication mechanisms",
                expected_outcome="Only authorized users can access ePHI",
                severity=Severity.CRITICAL,
                automated=True,
                frequency="monthly"
            ),
            Control(
                control_id="HIPAA-164.312(a)(2)(i)",
                control_name="Unique User Identification",
                description="Assign unique identifier for tracking user identity",
                category="Technical Safeguards",
                framework="HIPAA",
                test_procedure="Verify all users have unique IDs",
                expected_outcome="No shared accounts or generic usernames",
                severity=Severity.HIGH,
                automated=True,
                frequency="monthly"
            ),
            Control(
                control_id="HIPAA-164.312(a)(2)(iv)",
                control_name="Encryption and Decryption",
                description="Implement encryption mechanisms to protect ePHI",
                category="Technical Safeguards",
                framework="HIPAA",
                test_procedure="Verify encryption at rest and in transit",
                expected_outcome="All ePHI encrypted with approved algorithms",
                severity=Severity.CRITICAL,
                automated=True,
                frequency="monthly"
            ),
            Control(
                control_id="HIPAA-164.312(b)",
                control_name="Audit Controls",
                description="Implement hardware, software, and procedures to record and examine activity",
                category="Technical Safeguards",
                framework="HIPAA",
                test_procedure="Review audit logs for ePHI access",
                expected_outcome="Comprehensive audit logs maintained",
                severity=Severity.HIGH,
                automated=True,
                frequency="weekly"
            ),
            Control(
                control_id="HIPAA-164.312(e)(1)",
                control_name="Transmission Security",
                description="Implement technical security measures to guard against unauthorized access to ePHI during transmission",
                category="Technical Safeguards",
                framework="HIPAA",
                test_procedure="Verify TLS/SSL for data in transit",
                expected_outcome="All ePHI transmissions encrypted",
                severity=Severity.CRITICAL,
                automated=True,
                frequency="monthly"
            ),
        ]

    async def check_access_control(self, system_config: Dict[str, Any]) -> ComplianceCheckResult:
        """Check HIPAA 164.312(a)(1) - Access Control"""
        findings = []
        evidence = []
        status = ComplianceStatus.COMPLIANT

        # Check for multi-factor authentication
        if not system_config.get('mfa_enabled', False):
            findings.append("Multi-factor authentication not enabled")
            status = ComplianceStatus.NON_COMPLIANT

        # Check password policy
        password_policy = system_config.get('password_policy', {})
        if password_policy.get('min_length', 0) < 12:
            findings.append("Password minimum length below recommended 12 characters")
            status = ComplianceStatus.PARTIAL

        # Check session timeout
        if system_config.get('session_timeout_minutes', 0) > 30:
            findings.append("Session timeout exceeds recommended 30 minutes")
            status = ComplianceStatus.PARTIAL

        evidence.append(f"MFA enabled: {system_config.get('mfa_enabled', False)}")
        evidence.append(f"Password policy: {password_policy}")
        evidence.append(f"Session timeout: {system_config.get('session_timeout_minutes')} minutes")

        return ComplianceCheckResult(
            control_id="HIPAA-164.312(a)(1)",
            control_name="Access Control",
            framework="HIPAA",
            status=status,
            severity=Severity.CRITICAL,
            evidence=evidence,
            findings='; '.join(findings) if findings else None,
            remediation="Enable MFA, enforce 12+ char passwords, set 30min session timeout" if findings else None,
            compliance_score=100.0 if status == ComplianceStatus.COMPLIANT else 50.0
        )

    async def check_encryption(self, system_config: Dict[str, Any]) -> ComplianceCheckResult:
        """Check HIPAA 164.312(a)(2)(iv) - Encryption"""
        findings = []
        evidence = []
        status = ComplianceStatus.COMPLIANT

        # Check encryption at rest
        if not system_config.get('encryption_at_rest', {}).get('enabled', False):
            findings.append("Encryption at rest not enabled")
            status = ComplianceStatus.NON_COMPLIANT
        else:
            algorithm = system_config['encryption_at_rest'].get('algorithm')
            if algorithm not in ['AES-256', 'AES-128']:
                findings.append(f"Weak encryption algorithm: {algorithm}")
                status = ComplianceStatus.PARTIAL

        # Check encryption in transit
        if not system_config.get('encryption_in_transit', {}).get('enabled', False):
            findings.append("Encryption in transit not enabled")
            status = ComplianceStatus.NON_COMPLIANT
        else:
            tls_version = system_config['encryption_in_transit'].get('tls_version')
            if tls_version and tls_version < 1.2:
                findings.append(f"TLS version below 1.2: {tls_version}")
                status = ComplianceStatus.PARTIAL

        evidence.append(f"Encryption at rest: {system_config.get('encryption_at_rest')}")
        evidence.append(f"Encryption in transit: {system_config.get('encryption_in_transit')}")

        return ComplianceCheckResult(
            control_id="HIPAA-164.312(a)(2)(iv)",
            control_name="Encryption and Decryption",
            framework="HIPAA",
            status=status,
            severity=Severity.CRITICAL,
            evidence=evidence,
            findings='; '.join(findings) if findings else None,
            remediation="Enable AES-256 at rest, TLS 1.3 in transit" if findings else None,
            compliance_score=100.0 if status == ComplianceStatus.COMPLIANT else 30.0
        )


class ISO27001Compliance:
    """ISO 27001 Information Security Management System compliance checks"""

    def __init__(self):
        self.controls = self._load_iso27001_controls()

    def _load_iso27001_controls(self) -> List[Control]:
        """Load ISO 27001 controls (Annex A)"""
        return [
            # A.5 - Information Security Policies
            Control(
                control_id="ISO27001-A.5.1.1",
                control_name="Policies for Information Security",
                description="Information security policy shall be defined, approved, published, and communicated",
                category="Information Security Policies",
                framework="ISO27001",
                test_procedure="Verify security policy exists and is current",
                expected_outcome="Policy documented, approved, and accessible",
                severity=Severity.HIGH,
                automated=False,
                frequency="annual"
            ),

            # A.9 - Access Control
            Control(
                control_id="ISO27001-A.9.2.1",
                control_name="User Registration and De-registration",
                description="Formal user registration and de-registration process",
                category="Access Control",
                framework="ISO27001",
                test_procedure="Review user provisioning/deprovisioning logs",
                expected_outcome="All users properly registered/de-registered",
                severity=Severity.HIGH,
                automated=True,
                frequency="monthly"
            ),
            Control(
                control_id="ISO27001-A.9.4.1",
                control_name="Information Access Restriction",
                description="Access to information and application system functions restricted",
                category="Access Control",
                framework="ISO27001",
                test_procedure="Test access controls and permissions",
                expected_outcome="Users have minimum necessary access",
                severity=Severity.CRITICAL,
                automated=True,
                frequency="quarterly"
            ),

            # A.12 - Operations Security
            Control(
                control_id="ISO27001-A.12.4.1",
                control_name="Event Logging",
                description="Event logs recording user activities, exceptions, and security events",
                category="Operations Security",
                framework="ISO27001",
                test_procedure="Review logging configuration and retention",
                expected_outcome="Comprehensive logs maintained for 90+ days",
                severity=Severity.HIGH,
                automated=True,
                frequency="monthly"
            ),
            Control(
                control_id="ISO27001-A.12.6.1",
                control_name="Management of Technical Vulnerabilities",
                description="Information about technical vulnerabilities shall be obtained timely",
                category="Operations Security",
                framework="ISO27001",
                test_procedure="Review vulnerability management process",
                expected_outcome="Regular vulnerability scans and patching",
                severity=Severity.CRITICAL,
                automated=True,
                frequency="weekly"
            ),

            # A.18 - Compliance
            Control(
                control_id="ISO27001-A.18.1.5",
                control_name="Regulation of Cryptographic Controls",
                description="Cryptographic controls used in compliance with agreements, laws, and regulations",
                category="Compliance",
                framework="ISO27001",
                test_procedure="Review encryption implementation",
                expected_outcome="Approved cryptographic algorithms in use",
                severity=Severity.HIGH,
                automated=True,
                frequency="quarterly"
            ),
        ]

    async def check_event_logging(self, system_config: Dict[str, Any]) -> ComplianceCheckResult:
        """Check ISO27001 A.12.4.1 - Event Logging"""
        findings = []
        evidence = []
        status = ComplianceStatus.COMPLIANT

        logging_config = system_config.get('logging', {})

        # Check if logging enabled
        if not logging_config.get('enabled', False):
            findings.append("Event logging not enabled")
            status = ComplianceStatus.NON_COMPLIANT

        # Check retention period
        retention_days = logging_config.get('retention_days', 0)
        if retention_days < 90:
            findings.append(f"Log retention below 90 days: {retention_days} days")
            status = ComplianceStatus.PARTIAL

        # Check log types
        required_logs = ['authentication', 'access', 'changes', 'errors']
        enabled_logs = logging_config.get('log_types', [])
        missing_logs = set(required_logs) - set(enabled_logs)
        if missing_logs:
            findings.append(f"Missing log types: {', '.join(missing_logs)}")
            status = ComplianceStatus.PARTIAL

        evidence.append(f"Logging enabled: {logging_config.get('enabled')}")
        evidence.append(f"Retention period: {retention_days} days")
        evidence.append(f"Log types: {enabled_logs}")

        return ComplianceCheckResult(
            control_id="ISO27001-A.12.4.1",
            control_name="Event Logging",
            framework="ISO27001",
            status=status,
            severity=Severity.HIGH,
            evidence=evidence,
            findings='; '.join(findings) if findings else None,
            remediation="Enable all log types, set 90+ day retention" if findings else None,
            compliance_score=100.0 if status == ComplianceStatus.COMPLIANT else 60.0
        )


class SUNATCompliance:
    """SUNAT (Peru Tax Administration) compliance for customs and logistics data"""

    def __init__(self):
        self.controls = self._load_sunat_controls()

    def _load_sunat_controls(self) -> List[Control]:
        """Load SUNAT compliance controls"""
        return [
            Control(
                control_id="SUNAT-001",
                control_name="Customs Data Protection",
                description="Protect customs declarations and trade data per SUNAT regulations",
                category="Data Protection",
                framework="SUNAT",
                test_procedure="Verify encryption of customs data",
                expected_outcome="All customs data encrypted and access logged",
                severity=Severity.CRITICAL,
                automated=True,
                frequency="monthly"
            ),
            Control(
                control_id="SUNAT-002",
                control_name="Electronic Invoice Security",
                description="Secure storage and transmission of electronic invoices",
                category="Document Security",
                framework="SUNAT",
                test_procedure="Check digital signature and encryption",
                expected_outcome="Invoices digitally signed and stored securely",
                severity=Severity.HIGH,
                automated=True,
                frequency="monthly"
            ),
            Control(
                control_id="SUNAT-003",
                control_name="Audit Trail for Tax Documents",
                description="Maintain audit trail for all tax-related documents",
                category="Audit & Compliance",
                framework="SUNAT",
                test_procedure="Review audit logs for tax documents",
                expected_outcome="Complete audit trail for minimum 5 years",
                severity=Severity.HIGH,
                automated=True,
                frequency="quarterly"
            ),
        ]

    async def check_customs_data_protection(self, system_config: Dict[str, Any]) -> ComplianceCheckResult:
        """Check SUNAT-001 - Customs Data Protection"""
        findings = []
        evidence = []
        status = ComplianceStatus.COMPLIANT

        # Check encryption
        if not system_config.get('customs_encryption_enabled', False):
            findings.append("Customs data encryption not enabled")
            status = ComplianceStatus.NON_COMPLIANT

        # Check access controls
        if not system_config.get('customs_access_controls', False):
            findings.append("Customs data access controls not configured")
            status = ComplianceStatus.NON_COMPLIANT

        # Check audit logging
        if not system_config.get('customs_audit_logging', False):
            findings.append("Customs data access not logged")
            status = ComplianceStatus.PARTIAL

        evidence.append(f"Encryption: {system_config.get('customs_encryption_enabled')}")
        evidence.append(f"Access controls: {system_config.get('customs_access_controls')}")
        evidence.append(f"Audit logging: {system_config.get('customs_audit_logging')}")

        return ComplianceCheckResult(
            control_id="SUNAT-001",
            control_name="Customs Data Protection",
            framework="SUNAT",
            status=status,
            severity=Severity.CRITICAL,
            evidence=evidence,
            findings='; '.join(findings) if findings else None,
            remediation="Enable encryption, access controls, and audit logging for customs data" if findings else None,
            compliance_score=100.0 if status == ComplianceStatus.COMPLIANT else 40.0
        )


class Ley29733Compliance:
    """Ley 29733 - Peru Personal Data Protection Law compliance"""

    def __init__(self):
        self.controls = self._load_ley29733_controls()

    def _load_ley29733_controls(self) -> List[Control]:
        """Load Ley 29733 controls"""
        return [
            Control(
                control_id="LEY29733-ART8",
                control_name="Consent for Data Processing",
                description="Obtain explicit consent before processing personal data",
                category="Consent",
                framework="Ley29733",
                test_procedure="Verify consent records exist",
                expected_outcome="Documented consent for all data subjects",
                severity=Severity.CRITICAL,
                automated=False,
                frequency="quarterly"
            ),
            Control(
                control_id="LEY29733-ART17",
                control_name="Data Security Measures",
                description="Implement technical and organizational measures to protect personal data",
                category="Security",
                framework="Ley29733",
                test_procedure="Review security controls",
                expected_outcome="Encryption, access controls, and monitoring in place",
                severity=Severity.CRITICAL,
                automated=True,
                frequency="monthly"
            ),
            Control(
                control_id="LEY29733-ART19",
                control_name="Data Breach Notification",
                description="Notify authority and data subjects of security breaches",
                category="Incident Response",
                framework="Ley29733",
                test_procedure="Review incident response procedures",
                expected_outcome="Breach notification process documented",
                severity=Severity.HIGH,
                automated=False,
                frequency="annual"
            ),
        ]

    async def check_data_security(self, system_config: Dict[str, Any]) -> ComplianceCheckResult:
        """Check LEY29733-ART17 - Data Security Measures"""
        findings = []
        evidence = []
        status = ComplianceStatus.COMPLIANT

        # Check encryption
        if not system_config.get('personal_data_encrypted', False):
            findings.append("Personal data not encrypted")
            status = ComplianceStatus.NON_COMPLIANT

        # Check access controls
        if not system_config.get('rbac_enabled', False):
            findings.append("Role-based access control not implemented")
            status = ComplianceStatus.PARTIAL

        # Check monitoring
        if not system_config.get('data_access_monitoring', False):
            findings.append("Data access monitoring not enabled")
            status = ComplianceStatus.PARTIAL

        evidence.append(f"Encryption: {system_config.get('personal_data_encrypted')}")
        evidence.append(f"RBAC: {system_config.get('rbac_enabled')}")
        evidence.append(f"Monitoring: {system_config.get('data_access_monitoring')}")

        return ComplianceCheckResult(
            control_id="LEY29733-ART17",
            control_name="Data Security Measures",
            framework="Ley29733",
            status=status,
            severity=Severity.CRITICAL,
            evidence=evidence,
            findings='; '.join(findings) if findings else None,
            remediation="Enable encryption, RBAC, and access monitoring for personal data" if findings else None,
            compliance_score=100.0 if status == ComplianceStatus.COMPLIANT else 50.0
        )


class ComplianceAuditor:
    """Main compliance auditor orchestrating all frameworks"""

    def __init__(self):
        self.hipaa = HIPAACompliance()
        self.iso27001 = ISO27001Compliance()
        self.sunat = SUNATCompliance()
        self.ley29733 = Ley29733Compliance()

    async def run_audit(
        self,
        client_id: str,
        framework: str,
        system_config: Dict[str, Any]
    ) -> ComplianceReport:
        """
        Run full compliance audit

        Args:
            client_id: Client identifier
            framework: Compliance framework (HIPAA, ISO27001, SUNAT, Ley29733, ALL)
            system_config: System configuration to audit

        Returns:
            ComplianceReport with audit results
        """
        logger.info(f"Running compliance audit for {client_id} - Framework: {framework}")

        results = []

        # Select framework(s) to audit
        if framework == "HIPAA" or framework == "ALL":
            results.extend(await self._audit_hipaa(system_config))

        if framework == "ISO27001" or framework == "ALL":
            results.extend(await self._audit_iso27001(system_config))

        if framework == "SUNAT" or framework == "ALL":
            results.extend(await self._audit_sunat(system_config))

        if framework == "Ley29733" or framework == "ALL":
            results.extend(await self._audit_ley29733(system_config))

        # Calculate statistics
        total_controls = len(results)
        compliant = sum(1 for r in results if r.status == ComplianceStatus.COMPLIANT)
        non_compliant = sum(1 for r in results if r.status == ComplianceStatus.NON_COMPLIANT)
        critical_findings = sum(1 for r in results if r.severity == Severity.CRITICAL and r.status != ComplianceStatus.COMPLIANT)
        high_findings = sum(1 for r in results if r.severity == Severity.HIGH and r.status != ComplianceStatus.COMPLIANT)

        # Calculate overall score
        if total_controls > 0:
            overall_score = sum(r.compliance_score for r in results) / total_controls
        else:
            overall_score = 0.0

        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            framework, overall_score, compliant, non_compliant, critical_findings, high_findings
        )

        # Generate recommendations
        recommendations = self._generate_recommendations(results)

        # Create report
        import secrets
        report = ComplianceReport(
            report_id=f"COMP-{secrets.token_hex(8).upper()}",
            framework=framework,
            client_id=client_id,
            generated_at=datetime.utcnow(),
            results=results,
            overall_score=overall_score,
            compliant_controls=compliant,
            non_compliant_controls=non_compliant,
            total_controls=total_controls,
            critical_findings=critical_findings,
            high_findings=high_findings,
            executive_summary=executive_summary,
            recommendations=recommendations
        )

        logger.info(f"Compliance audit completed. Score: {overall_score:.1f}%")

        return report

    async def _audit_hipaa(self, system_config: Dict[str, Any]) -> List[ComplianceCheckResult]:
        """Run HIPAA compliance checks"""
        results = []

        results.append(await self.hipaa.check_access_control(system_config))
        results.append(await self.hipaa.check_encryption(system_config))

        return results

    async def _audit_iso27001(self, system_config: Dict[str, Any]) -> List[ComplianceCheckResult]:
        """Run ISO 27001 compliance checks"""
        results = []

        results.append(await self.iso27001.check_event_logging(system_config))

        return results

    async def _audit_sunat(self, system_config: Dict[str, Any]) -> List[ComplianceCheckResult]:
        """Run SUNAT compliance checks"""
        results = []

        results.append(await self.sunat.check_customs_data_protection(system_config))

        return results

    async def _audit_ley29733(self, system_config: Dict[str, Any]) -> List[ComplianceCheckResult]:
        """Run Ley 29733 compliance checks"""
        results = []

        results.append(await self.ley29733.check_data_security(system_config))

        return results

    def _generate_executive_summary(
        self,
        framework: str,
        score: float,
        compliant: int,
        non_compliant: int,
        critical: int,
        high: int
    ) -> str:
        """Generate executive summary"""
        return f"""
COMPLIANCE AUDIT SUMMARY - {framework}

Overall Compliance Score: {score:.1f}%

Controls Status:
- Compliant: {compliant}
- Non-Compliant: {non_compliant}
- Total Tested: {compliant + non_compliant}

Findings Severity:
- Critical: {critical}
- High: {high}

{self._score_interpretation(score)}
        """.strip()

    def _score_interpretation(self, score: float) -> str:
        """Interpret compliance score"""
        if score >= 90:
            return "EXCELLENT: Organization demonstrates strong compliance posture."
        elif score >= 75:
            return "GOOD: Organization is largely compliant with minor gaps."
        elif score >= 60:
            return "FAIR: Significant improvements needed to achieve compliance."
        else:
            return "POOR: Critical compliance gaps require immediate attention."

    def _generate_recommendations(self, results: List[ComplianceCheckResult]) -> List[str]:
        """Generate remediation recommendations"""
        recommendations = []

        # Group by severity
        critical_issues = [r for r in results if r.severity == Severity.CRITICAL and r.status != ComplianceStatus.COMPLIANT]
        high_issues = [r for r in results if r.severity == Severity.HIGH and r.status != ComplianceStatus.COMPLIANT]

        if critical_issues:
            recommendations.append(f"URGENT: Address {len(critical_issues)} critical compliance gaps immediately:")
            for issue in critical_issues[:3]:  # Top 3
                recommendations.append(f"  - {issue.control_name}: {issue.remediation}")

        if high_issues:
            recommendations.append(f"HIGH PRIORITY: Remediate {len(high_issues)} high-severity findings within 30 days")

        if not recommendations:
            recommendations.append("Maintain current compliance posture through continuous monitoring")

        return recommendations


# Export main classes
__all__ = [
    'ComplianceAuditor',
    'ComplianceReport',
    'ComplianceCheckResult',
    'ComplianceStatus',
    'Severity',
]
