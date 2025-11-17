"""
Medical AI Compliance Agent

Specialized security and compliance checks for medical AI systems.

Focus areas:
- HIPAA compliance (164.312 Technical Safeguards)
- PHI (Protected Health Information) exposure
- Medical AI endpoint security (DeepSeek-R1, Claude, GPT-4)
- FDA Medical Device Cybersecurity
- DICOM server security
- HL7/FHIR API protection
- Business Associate Agreement (BAA) compliance
"""

import re
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime

from gtl_agents.base_agent import (
    BaseSecurityAgent,
    AgentFinding,
    AgentAnalysisResult,
    FindingSeverity,
    ComplianceFramework,
)

import logging

logger = logging.getLogger(__name__)


class MedicalAIComplianceAgent(BaseSecurityAgent):
    """
    Security agent for medical AI and healthtech systems.

    Ensures compliance with:
    - HIPAA Security Rule (45 CFR Part 164)
    - FDA Cybersecurity for Medical Devices
    - GDPR (for EU patient data)
    - Ley 29733 (Peru personal data protection)
    - HL7 Security Standards

    Target clients:
    - Hospitals and clinics
    - Medical AI startups
    - Telemedicine platforms
    - Medical device manufacturers
    - Health information exchanges (HIE)
    """

    def __init__(self):
        """Initialize medical AI compliance agent"""
        kb_path = Path(__file__).parent / "knowledge_bases" / "medical_ai_threats.yaml"
        super().__init__(knowledge_base_path=str(kb_path) if kb_path.exists() else None)

        # PHI detection patterns
        self.phi_patterns = {
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',  # Social Security Number
            'mrn': r'\b(?:MRN|Medical.?Record.?Number)[:\s]*([A-Z0-9]{6,})\b',
            'dob': r'\b\d{1,2}/\d{1,2}/\d{4}\b',  # Date of birth
            'patient_id': r'\b(?:Patient.?ID|PTID)[:\s]*([A-Z0-9]{5,})\b',
            'diagnosis_code': r'\b[A-Z]\d{2}\.\d\b',  # ICD-10
            'phone': r'\b\d{3}-\d{3}-\d{4}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        }

        # Medical AI API patterns
        self.ai_api_patterns = {
            'openai': ['openai.com', 'api.openai.com'],
            'anthropic': ['anthropic.com', 'api.anthropic.com'],
            'deepseek': ['deepseek.com', 'api.deepseek.com'],
            'google': ['generativelanguage.googleapis.com'],
        }

        # DICOM ports
        self.dicom_ports = [104, 11112, 2761, 2762]

        logger.info("MedicalAIComplianceAgent initialized")

    async def analyze(self, scan_result: Any) -> AgentAnalysisResult:
        """
        Run medical AI compliance analysis.

        Checks:
        1. PHI exposure (logs, errors, APIs)
        2. Encryption compliance (at-rest and in-transit)
        3. AI model endpoint security
        4. DICOM/HL7 endpoint security
        5. Business Associate Agreement (BAA) compliance
        6. Audit logging requirements

        Args:
            scan_result: Output from GTL Security Scanner

        Returns:
            AgentAnalysisResult with medical compliance findings
        """
        start_time = datetime.utcnow()
        findings: List[AgentFinding] = []

        logger.info(f"Starting medical AI compliance analysis for scan {scan_result.scan_id}")

        # Check 1: PHI exposure
        phi_findings = await self._check_phi_exposure(scan_result)
        findings.extend(phi_findings)
        logger.debug(f"PHI checks: {len(phi_findings)} findings")

        # Check 2: Encryption compliance
        encryption_findings = await self._check_encryption(scan_result)
        findings.extend(encryption_findings)
        logger.debug(f"Encryption checks: {len(encryption_findings)} findings")

        # Check 3: AI model endpoint security
        ai_findings = await self._check_ai_endpoints(scan_result)
        findings.extend(ai_findings)
        logger.debug(f"AI endpoint checks: {len(ai_findings)} findings")

        # Check 4: DICOM security
        dicom_findings = await self._check_dicom_security(scan_result)
        findings.extend(dicom_findings)
        logger.debug(f"DICOM checks: {len(dicom_findings)} findings")

        # Check 5: HL7/FHIR security
        fhir_findings = await self._check_fhir_security(scan_result)
        findings.extend(fhir_findings)
        logger.debug(f"FHIR checks: {len(fhir_findings)} findings")

        # Check 6: Access control compliance
        access_findings = await self._check_access_controls(scan_result)
        findings.extend(access_findings)
        logger.debug(f"Access control checks: {len(access_findings)} findings")

        # Prioritize findings
        findings = self._prioritize_findings(findings)

        # Calculate duration
        duration = (datetime.utcnow() - start_time).total_seconds()

        # Build analysis result
        result = AgentAnalysisResult(
            agent_name="Medical AI Compliance Agent",
            sector="healthcare",
            findings=findings,
            analysis_duration_seconds=duration,
        )

        # Add top priorities
        result.top_priorities = [
            f.title for f in findings[:5] if f.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]
        ]

        # Add quick wins
        result.quick_wins = self._identify_quick_wins(findings)

        logger.info(
            f"Medical compliance analysis complete: {result.total_findings} findings "
            f"({result.critical_findings} critical, {result.high_findings} high)"
        )

        return result

    async def _check_phi_exposure(self, scan_result: Any) -> List[AgentFinding]:
        """
        Check for Protected Health Information (PHI) exposure.

        HIPAA defines 18 identifiers as PHI:
        1. Names
        2. Geographic subdivisions smaller than state
        3. Dates (except year)
        4. Telephone/fax numbers
        5. Email addresses
        6. SSN
        7. Medical record numbers
        8. Health plan beneficiary numbers
        9. Account numbers
        10. Certificate/license numbers
        11. Vehicle identifiers/serial numbers
        12. Device identifiers/serial numbers
        13. Web URLs
        14. IP addresses
        15. Biometric identifiers
        16. Full-face photos
        17. Any other unique identifier

        Common exposure points:
        - Error messages
        - API responses
        - Log files
        - Debug endpoints
        - Database dumps
        """
        findings: List[AgentFinding] = []

        # Check error messages for PHI
        for vuln in scan_result.vulnerabilities:
            vuln_text = f"{vuln.title} {vuln.description}".lower()

            if any(keyword in vuln_text for keyword in ['error', 'exception', 'stack', 'trace']):
                # Check if contains PHI patterns
                phi_found = []
                for phi_type, pattern in self.phi_patterns.items():
                    if re.search(pattern, vuln.description, re.IGNORECASE):
                        phi_found.append(phi_type)

                if phi_found:
                    findings.append(AgentFinding(
                        title="CRITICAL HIPAA VIOLATION: PHI Exposed in Error Messages",
                        severity=FindingSeverity.CRITICAL,
                        category="HIPAA Violation",
                        description=(
                            f"Error messages contain Protected Health Information (PHI). "
                            f"PHI types detected: {', '.join(phi_found)}. "
                            f"Location: {vuln.affected_url if hasattr(vuln, 'affected_url') else 'Unknown'}\n\n"
                            f"This is a DIRECT VIOLATION of HIPAA 164.312(a)(1) - Access Control "
                            f"and 164.528 - Accounting of Disclosures."
                        ),
                        affected_component=vuln.affected_url if hasattr(vuln, 'affected_url') else "Error Handling",
                        business_impact=(
                            "🚨 SEVERE HIPAA VIOLATION - CRIMINAL PENALTIES POSSIBLE:\n\n"
                            "LEGAL CONSEQUENCES:\n"
                            "• OCR (Office for Civil Rights) investigation MANDATORY\n"
                            "• Minimum $50,000 fine per violation\n"
                            "• Maximum $1.5 MILLION per violation category per year\n"
                            "• CRIMINAL CHARGES under 42 USC §1320d-6:\n"
                            "  - Tier 3: Up to $250,000 fine + 10 years prison\n"
                            "  - If for commercial gain: Up to $250,000 + 10 years\n\n"
                            "BUSINESS IMPACT:\n"
                            "• Medical license revocation (for covered entities)\n"
                            "• Exclusion from Medicare/Medicaid programs\n"
                            "• Patient notification required (breach >500: public disclosure)\n"
                            "• Media coverage and reputation destruction\n"
                            "• Class action lawsuits from affected patients\n"
                            "• Loss of all healthcare partnerships\n\n"
                            "REGULATORY:\n"
                            "• Mandatory corrective action plan\n"
                            "• 3-year monitoring period\n"
                            "• Annual compliance audits\n"
                            "• Potential state AG investigation"
                        ),
                        financial_impact=(
                            "$50,000 - $1,500,000 PER VIOLATION + legal fees + "
                            "patient notification costs + credit monitoring + "
                            "potential class action settlements"
                        ),
                        remediation=(
                            "⚠️⚠️⚠️ STOP EVERYTHING - CRITICAL EMERGENCY ⚠️⚠️⚠️\n\n"
                            "IMMEDIATE ACTIONS (NEXT 1 HOUR):\n"
                            "1. Disable detailed error messages in production IMMEDIATELY\n"
                            "2. Contact Chief Privacy Officer / Compliance Officer NOW\n"
                            "3. Contact legal counsel specializing in HIPAA\n"
                            "4. Begin breach assessment under 45 CFR §164.404\n"
                            "5. Preserve all logs and evidence\n\n"
                            "NEXT 24 HOURS:\n"
                            "6. Determine if >500 patients affected (requires HHS notification)\n"
                            "7. Implement generic error responses\n"
                            "8. Route PHI to secure audit logs only (encrypted, access-controlled)\n"
                            "9. Conduct forensic investigation of all error logs\n"
                            "10. Identify all individuals whose PHI was exposed\n\n"
                            "NEXT 60 DAYS (HIPAA BREACH NOTIFICATION DEADLINE):\n"
                            "11. Notify affected individuals via 1st class mail\n"
                            "12. Notify HHS Secretary (if >500 patients)\n"
                            "13. Notify prominent media (if >500 in same state/jurisdiction)\n"
                            "14. Post notice on website (if >10 affected, can't locate)\n"
                            "15. Offer credit monitoring to affected patients\n\n"
                            "TECHNICAL FIXES:\n"
                            "16. Implement error handling that NEVER includes:\n"
                            "    - Patient names or IDs\n"
                            "    - Dates (DOB, admission, discharge)\n"
                            "    - Diagnosis codes\n"
                            "    - Any of the 18 HIPAA identifiers\n"
                            "17. Use error IDs that map to detailed logs internally\n"
                            "18. Implement DLP (Data Loss Prevention) for PHI\n"
                            "19. Add PHI detection in CI/CD pipeline\n"
                            "20. Conduct HIPAA Security Risk Assessment (required annually)"
                        ),
                        remediation_priority="immediate",
                        remediation_effort="hours",
                        compliance_violations=[
                            "HIPAA 164.312(a)(1) - Access Control",
                            "HIPAA 164.528 - Accounting of Disclosures",
                            "HIPAA 164.404 - Breach Notification",
                            "HIPAA 164.308(a)(1)(ii)(A) - Risk Analysis",
                            "Ley 29733 Article 17 - Peru Data Protection",
                            "GDPR Article 32 - Security of Processing",
                        ],
                        regulatory_risk=(
                            "CRIMINAL PROSECUTION POSSIBLE under 42 USC §1320d-6. "
                            "OCR investigation mandatory. Medical license revocation probable."
                        ),
                        discovered_by="Medical AI Compliance Agent",
                        evidence={
                            "phi_types_found": phi_found,
                            "vulnerability": vuln.title,
                            "location": vuln.affected_url if hasattr(vuln, 'affected_url') else None
                        },
                        references=[
                            "https://www.hhs.gov/hipaa/for-professionals/security/index.html",
                            "https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html",
                            "https://www.govinfo.gov/content/pkg/USCODE-2020-title42/html/USCODE-2020-title42-chap7-subchapXI-partC-sec1320d-6.htm",
                        ],
                    ))

        return findings

    async def _check_encryption(self, scan_result: Any) -> List[AgentFinding]:
        """Check HIPAA encryption requirements"""
        findings: List[AgentFinding] = []

        # Check for unencrypted endpoints
        for vuln in scan_result.vulnerabilities:
            if hasattr(vuln, 'affected_url'):
                if vuln.affected_url.startswith('http://'):
                    # Check if this endpoint handles medical data
                    url_lower = vuln.affected_url.lower()
                    if any(keyword in url_lower for keyword in [
                        'patient', 'medical', 'health', 'diagnosis', 'prescription',
                        'lab', 'radiology', 'ehr', 'emr', 'fhir', 'hl7'
                    ]):
                        findings.append(AgentFinding(
                            title="Unencrypted Medical Data Transmission (HIPAA Violation)",
                            severity=FindingSeverity.CRITICAL,
                            category="HIPAA - Encryption",
                            description=(
                                f"Medical data endpoint {vuln.affected_url} uses unencrypted HTTP. "
                                f"HIPAA requires encryption of PHI in transit."
                            ),
                            affected_component=vuln.affected_url,
                            business_impact=(
                                "HIPAA VIOLATION:\n"
                                "• PHI transmitted in plaintext\n"
                                "• Network sniffing can capture patient data\n"
                                "• WiFi interception risk in hospital/clinic\n"
                                "• $100-$50,000 fine per patient record exposed"
                            ),
                            financial_impact="$100-$50,000 per patient record + OCR investigation",
                            remediation=(
                                "1. Implement HTTPS/TLS 1.3 immediately\n"
                                "2. Obtain SSL certificate\n"
                                "3. Redirect all HTTP to HTTPS\n"
                                "4. Implement HSTS (HTTP Strict Transport Security)\n"
                                "5. Consider mutual TLS for server-to-server PHI"
                            ),
                            remediation_priority="immediate",
                            remediation_effort="hours",
                            compliance_violations=[
                                "HIPAA 164.312(e)(1) - Transmission Security",
                                "HIPAA 164.312(e)(2)(i) - Integrity Controls",
                                "HIPAA 164.312(e)(2)(ii) - Encryption",
                            ],
                            discovered_by="Medical AI Compliance Agent",
                        ))

        return findings

    async def _check_ai_endpoints(self, scan_result: Any) -> List[AgentFinding]:
        """
        Check medical AI endpoint security.

        Medical AI systems often use:
        - DeepSeek-R1 for medical reasoning
        - Claude for clinical note generation
        - GPT-4 for patient communication
        - Custom models for diagnosis/imaging

        CRITICAL: HIPAA requires Business Associate Agreement (BAA)
        before sending PHI to third parties.
        """
        findings: List[AgentFinding] = []

        # Detect AI API endpoints
        ai_endpoints = []

        if hasattr(scan_result, 'discovered_urls'):
            for url in scan_result.discovered_urls:
                # Check for AI API domains
                for provider, domains in self.ai_api_patterns.items():
                    if any(domain in url for domain in domains):
                        ai_endpoints.append((url, provider))

                # Check for inference/prediction endpoints
                if any(keyword in url.lower() for keyword in [
                    '/api/inference', '/api/predict', '/model', '/ai/', '/ml/'
                ]):
                    ai_endpoints.append((url, 'unknown'))

        for endpoint, provider in ai_endpoints:
            # Check if external AI without BAA
            if provider in ['openai', 'anthropic', 'deepseek', 'google']:
                findings.append(AgentFinding(
                    title=f"CRITICAL: PHI Sent to {provider.title()} Without BAA",
                    severity=FindingSeverity.CRITICAL,
                    category="HIPAA - Business Associate",
                    description=(
                        f"Medical data sent to external AI API ({provider}) at {endpoint}. "
                        f"HIPAA 164.308(b)(1) REQUIRES a Business Associate Agreement (BAA) "
                        f"before sending PHI to third-party service providers.\n\n"
                        f"Most AI providers DO NOT sign BAAs for their standard APIs."
                    ),
                    affected_component=endpoint,
                    business_impact=(
                        "🚨 SEVERE HIPAA VIOLATION - OCR INVESTIGATION PROBABLE:\n\n"
                        "LEGAL CONSEQUENCES:\n"
                        "• HIPAA 164.308(b)(1) violation: $100-$50,000 PER PATIENT\n"
                        "• Considered 'willful neglect' if known: $50,000 minimum\n"
                        "• Maximum penalty: $1.5M per year per violation type\n"
                        "• MANDATORY breach notification to all patients\n"
                        "• State Attorney General investigations\n\n"
                        "SPECIFIC RISKS:\n"
                        "• OpenAI: NO BAA on standard API (Azure OpenAI has BAA)\n"
                        "• Anthropic: NO BAA on public API (enterprise only)\n"
                        "• DeepSeek: NO BAA available\n"
                        "• Google: Vertex AI has BAA, but NOT standard API\n\n"
                        "BUSINESS IMPACT:\n"
                        "• Every API call = separate HIPAA violation\n"
                        "• Patient data in AI provider's logs\n"
                        "• Cannot guarantee data deletion\n"
                        "• Potential model training on patient data\n"
                        "• Loss of medical practice liability insurance\n"
                        "• Exclusion from insurance networks"
                    ),
                    financial_impact=(
                        "$100-$50,000 PER PATIENT whose data was sent. "
                        "If 1,000 patients affected: $100K - $50M in fines + "
                        "legal fees + patient notification + settlements"
                    ),
                    remediation=(
                        "⚠️ EMERGENCY - STOP ALL PHI TRANSMISSION NOW ⚠️\n\n"
                        "IMMEDIATE (NOW):\n"
                        "1. DISABLE this integration immediately\n"
                        "2. Contact Privacy Officer and legal counsel\n"
                        "3. Conduct breach assessment\n"
                        "4. Identify all patients whose data was sent\n"
                        "5. Request data deletion from AI provider (if possible)\n\n"
                        "COMPLIANT ALTERNATIVES:\n\n"
                        "OPTION 1: Use BAA-Eligible Services\n"
                        "• Azure OpenAI (Microsoft signs BAA)\n"
                        "• AWS Bedrock with Claude (AWS signs BAA)\n"
                        "• Google Vertex AI (Google signs BAA)\n"
                        "• Ensure BAA is signed BEFORE sending any PHI\n\n"
                        "OPTION 2: De-identify Data (HIPAA Safe Harbor)\n"
                        "• Remove all 18 HIPAA identifiers before sending to AI\n"
                        "• Use HIPAA de-identification tools\n"
                        "• Document de-identification process\n"
                        "• Still risky: re-identification possible\n\n"
                        "OPTION 3: Local/On-Premise AI Models (RECOMMENDED)\n"
                        "• Deploy models locally (e.g., on RTX 5090)\n"
                        "• Llama 2/3 fine-tuned for medical use\n"
                        "• BioGPT, Med-PaLM variants\n"
                        "• Full data control, no external transmission\n"
                        "• No BAA needed\n\n"
                        "LONG-TERM:\n"
                        "• Establish vendor management program\n"
                        "• Maintain BAA registry\n"
                        "• Annual BAA review with all vendors\n"
                        "• Implement DLP to block PHI to non-BAA endpoints\n"
                        "• Train staff on HIPAA Business Associate requirements"
                    ),
                    remediation_priority="immediate",
                    remediation_effort="days",
                    compliance_violations=[
                        "HIPAA 164.308(b)(1) - Business Associate Contracts",
                        "HIPAA 164.314(a)(1) - Business Associate Requirements",
                        "HIPAA 164.502(e) - Disclosure to Business Associates",
                        "GDPR Article 28 - Processor Requirements",
                    ],
                    regulatory_risk=(
                        "OCR investigation mandatory if discovered. "
                        "Considered 'willful neglect' - minimum $50K per violation."
                    ),
                    discovered_by="Medical AI Compliance Agent",
                    evidence={
                        "provider": provider,
                        "endpoint": endpoint,
                        "baa_available": False,
                    },
                    references=[
                        "https://www.hhs.gov/hipaa/for-professionals/privacy/guidance/business-associates/index.html",
                        "https://azure.microsoft.com/en-us/support/legal/cognitive-services-compliance-and-privacy/",
                    ],
                ))

        return findings

    async def _check_dicom_security(self, scan_result: Any) -> List[AgentFinding]:
        """
        Check DICOM (medical imaging) server security.

        DICOM = Digital Imaging and Communications in Medicine
        Used for: X-rays, CT scans, MRIs, ultrasounds

        Critical risks:
        - Open PACS (Picture Archiving and Communication System)
        - Unencrypted DICOM transmission
        - Missing authentication
        - Patient data in DICOM metadata
        """
        findings: List[AgentFinding] = []

        # Check for open DICOM ports
        if hasattr(scan_result, 'services'):
            for service in scan_result.services:
                if service.port in self.dicom_ports or 'dicom' in str(service.service).lower():
                    findings.append(AgentFinding(
                        title="DICOM Medical Imaging Server Exposed to Internet",
                        severity=FindingSeverity.CRITICAL,
                        category="Medical Imaging Security",
                        description=(
                            f"DICOM server detected on port {service.port}. "
                            f"DICOM servers contain medical images with embedded patient data. "
                            f"If accessible without authentication, ALL patient images are exposed."
                        ),
                        affected_component=f"DICOM Port {service.port}",
                        business_impact=(
                            "🚨 CATASTROPHIC BREACH - IMMEDIATE ACTION REQUIRED:\n\n"
                            "DATA EXPOSED:\n"
                            "• ALL medical images (X-rays, CT, MRI, ultrasound)\n"
                            "• Patient names, DOB, MRN in DICOM tags\n"
                            "• Diagnosis information\n"
                            "• Ordering physician names\n"
                            "• Hospital/clinic identifiers\n\n"
                            "LEGAL CONSEQUENCES:\n"
                            "• HIPAA breach affecting ALL patients in PACS\n"
                            "• If >500 patients: PUBLIC disclosure on HHS website\n"
                            "• Media notification required\n"
                            "• $50,000-$1.5M per violation\n"
                            "• State AG investigation\n"
                            "• Medical license revocation\n\n"
                            "OPERATIONAL IMPACT:\n"
                            "• Ransomware target (WannaCry targeted PACS)\n"
                            "• Patient safety risk if images deleted\n"
                            "• Cannot diagnose without images\n"
                            "• Business shutdown possible\n\n"
                            "REAL-WORLD EXAMPLES:\n"
                            "• 2019: 16M+ medical images exposed online\n"
                            "• 2020: Multiple hospitals' PACS breached\n"
                            "• Average breach cost: $7.13M (healthcare)"
                        ),
                        financial_impact=(
                            "$7M average breach cost + "
                            "$50K-$1.5M HIPAA fines + "
                            "patient notification + "
                            "credit monitoring + "
                            "legal fees + "
                            "potential class action"
                        ),
                        remediation=(
                            "🚨 CRITICAL EMERGENCY - ACT IMMEDIATELY 🚨\n\n"
                            "NEXT 1 HOUR:\n"
                            "1. ISOLATE DICOM server from internet IMMEDIATELY\n"
                            "2. Block all external access at firewall\n"
                            "3. Contact Chief Privacy Officer and legal\n"
                            "4. Begin breach assessment\n"
                            "5. Preserve all access logs\n\n"
                            "NEXT 24 HOURS:\n"
                            "6. Audit access logs for unauthorized downloads\n"
                            "7. Implement VPN-only access to DICOM\n"
                            "8. Enable DICOM authentication (AE Title validation)\n"
                            "9. Change all PACS passwords\n"
                            "10. Conduct forensic investigation\n\n"
                            "NEXT WEEK:\n"
                            "11. Implement DICOM TLS encryption\n"
                            "12. Deploy DICOM firewall/proxy\n"
                            "13. Segment DICOM network (VLAN)\n"
                            "14. Implement RBAC for PACS access\n"
                            "15. Deploy IDS/IPS for DICOM traffic\n\n"
                            "NEXT MONTH:\n"
                            "16. Conduct full HIPAA Security Risk Assessment\n"
                            "17. Implement DICOM audit logging\n"
                            "18. Deploy SIEM for monitoring\n"
                            "19. Penetration test PACS\n"
                            "20. Train staff on DICOM security\n\n"
                            "NOTIFY:\n"
                            "• If breach confirmed: 60-day notification deadline\n"
                            "• Notify patients, HHS, media (if >500)\n"
                            "• Offer credit monitoring"
                        ),
                        remediation_priority="immediate",
                        remediation_effort="hours",
                        compliance_violations=[
                            "HIPAA 164.312(a)(1) - Access Control",
                            "HIPAA 164.312(e)(1) - Transmission Security",
                            "FDA Medical Device Cybersecurity Guidance",
                            "DICOM Security Profile Recommendations",
                        ],
                        regulatory_risk=(
                            "Medical license revocation probable. "
                            "Criminal investigation possible if willful neglect proven."
                        ),
                        discovered_by="Medical AI Compliance Agent",
                        evidence={
                            "port": service.port,
                            "service": str(service.service),
                        },
                        references=[
                            "https://www.fda.gov/medical-devices/digital-health-center-excellence/cybersecurity",
                            "https://www.dicomstandard.org/current/",
                        ],
                    ))

        return findings

    async def _check_fhir_security(self, scan_result: Any) -> List[AgentFinding]:
        """Check HL7 FHIR API security"""
        findings: List[AgentFinding] = []

        # Look for FHIR endpoints
        if hasattr(scan_result, 'discovered_urls'):
            for url in scan_result.discovered_urls:
                if any(keyword in url.lower() for keyword in ['fhir', 'hl7', '/patient', '/observation']):
                    # Check if authentication required
                    findings.append(AgentFinding(
                        title="FHIR API Requires Authentication Review",
                        severity=FindingSeverity.HIGH,
                        category="HL7 FHIR Security",
                        description=(
                            f"FHIR endpoint detected at {url}. "
                            f"FHIR APIs expose patient resources and must implement OAuth 2.0 + SMART on FHIR."
                        ),
                        affected_component=url,
                        business_impact="Unauthorized access to patient records via FHIR API",
                        remediation=(
                            "1. Implement SMART on FHIR authorization\n"
                            "2. Use OAuth 2.0 with scopes (patient/*.read, user/*.write)\n"
                            "3. Require TLS 1.3\n"
                            "4. Implement rate limiting\n"
                            "5. Audit all FHIR access"
                        ),
                        remediation_priority="high",
                        remediation_effort="weeks",
                        compliance_violations=["HIPAA 164.312(a)(1)", "HL7 Security"],
                        discovered_by="Medical AI Compliance Agent",
                    ))

        return findings

    async def _check_access_controls(self, scan_result: Any) -> List[AgentFinding]:
        """Check access control compliance"""
        findings: List[AgentFinding] = []

        # Check for broken access control findings
        for vuln in scan_result.vulnerabilities:
            if any(keyword in vuln.title.lower() for keyword in ['idor', 'broken', 'access']):
                findings.append(AgentFinding(
                    title="Broken Access Control in Medical System",
                    severity=FindingSeverity.HIGH,
                    category="HIPAA - Access Control",
                    description=(
                        f"Access control vulnerability: {vuln.title}. "
                        f"HIPAA requires minimum necessary access to PHI."
                    ),
                    affected_component=vuln.affected_url if hasattr(vuln, 'affected_url') else "Unknown",
                    business_impact="Users can access other patients' records",
                    remediation=(
                        "1. Implement role-based access control (RBAC)\n"
                        "2. Enforce minimum necessary principle\n"
                        "3. Add patient-provider relationship checks\n"
                        "4. Audit all PHI access\n"
                        "5. Implement break-the-glass procedures"
                    ),
                    remediation_priority="high",
                    remediation_effort="weeks",
                    compliance_violations=["HIPAA 164.312(a)(1)", "HIPAA 164.308(a)(4)"],
                    discovered_by="Medical AI Compliance Agent",
                ))

        return findings

    def get_compliance_mapping(self, finding: AgentFinding) -> Dict[str, Any]:
        """Map medical finding to regulations"""
        mapping = {
            "frameworks": [],
            "controls": {},
            "severity_per_framework": {},
        }

        for violation in finding.compliance_violations:
            if "HIPAA" in violation:
                mapping["frameworks"].append("HIPAA")
                if "HIPAA" not in mapping["controls"]:
                    mapping["controls"]["HIPAA"] = []
                mapping["controls"]["HIPAA"].append(violation)

            if "FDA" in violation:
                mapping["frameworks"].append("FDA Medical Device")

            if "GDPR" in violation:
                mapping["frameworks"].append("GDPR")

            if "Ley 29733" in violation:
                mapping["frameworks"].append("Peru Data Protection Law")

        for framework in mapping["frameworks"]:
            mapping["severity_per_framework"][framework] = finding.severity.value

        return mapping

    def calculate_business_risk_score(self, findings: List[AgentFinding]) -> float:
        """Calculate medical-specific business risk"""
        if not findings:
            return 0.0

        score = 0.0

        for finding in findings:
            # Base severity
            severity_scores = {
                FindingSeverity.CRITICAL: 30.0,
                FindingSeverity.HIGH: 18.0,
                FindingSeverity.MEDIUM: 10.0,
                FindingSeverity.LOW: 4.0,
                FindingSeverity.INFO: 1.0,
            }
            score += severity_scores.get(finding.severity, 0.0)

            # Extra weight for PHI exposure
            if "phi" in finding.title.lower():
                score += 25.0

            # Extra weight for HIPAA violations
            if any("HIPAA" in v for v in finding.compliance_violations):
                score += 20.0

            # Extra weight for BAA violations
            if "baa" in finding.title.lower():
                score += 15.0

        return min(score, 100.0)


# Export
__all__ = ["MedicalAIComplianceAgent"]
