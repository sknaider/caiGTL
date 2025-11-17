"""
Customs Data Protection Agent

Specialized security checks for customs and international trade systems.

Focus areas:
- SUNAT (Peru) integration security
- Customs declaration data protection
- International trade compliance
- Cross-border data transfer security
- E-invoice system security (Facturación Electrónica)
- Peruvian data protection law (Ley 29733)
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


class CustomsDataProtectionAgent(BaseSecurityAgent):
    """
    Security agent for customs and international trade systems.

    Focuses on Peruvian market with SUNAT integration.

    Ensures compliance with:
    - SUNAT regulations (Resolución 185-2020)
    - Ley 29733 - Peru Data Protection Law
    - International trade data protection
    - WCO SAFE Framework
    - Cross-border data transfer requirements

    Target clients:
    - Import/export companies
    - Customs brokers (agentes de aduana)
    - International freight forwarders
    - E-commerce platforms with international sales
    - SUNAT service providers
    """

    def __init__(self):
        """Initialize customs data protection agent"""
        kb_path = Path(__file__).parent / "knowledge_bases" / "customs_regulations.yaml"
        super().__init__(knowledge_base_path=str(kb_path) if kb_path.exists() else None)

        # SUNAT system patterns
        self.sunat_patterns = {
            'clave_sol': r'clave[_\s]?sol',
            'usuario_sol': r'usuario[_\s]?sol',
            'ruc': r'\b\d{11}\b',  # RUC: 11 digits
            'see': r'see[_\s]',  # Sistema de Emisión Electrónica
            'vuce': r'vuce[_\s]',  # Ventanilla Única de Comercio Exterior
        }

        # Sensitive customs data patterns
        self.customs_data_patterns = {
            'dam': r'DAM[:\s]*\d{3}-\d{4}-\d{2}-\d{6}',  # Declaración Aduanera de Mercancías
            'factura': r'FACTURA[:\s]*[A-Z0-9\-]+',
            'partida_arancelaria': r'\d{4}\.\d{2}\.\d{2}\.\d{2}',  # 10-digit tariff code
        }

        # Cross-border data transfer compliance
        self.cbdt_requirements = {
            'gdpr_countries': [
                'españa', 'alemania', 'francia', 'italia', 'holanda',
                'bélgica', 'portugal', 'polonia', 'suecia', 'austria'
            ],
            'adequacy_countries': ['argentina', 'uruguay'],  # Countries with adequacy decisions
        }

        logger.info("CustomsDataProtectionAgent initialized")

    async def analyze(self, scan_result: Any) -> AgentAnalysisResult:
        """
        Run customs data protection analysis.

        Checks:
        1. SUNAT API security
        2. Customs declaration data protection
        3. E-invoice system security
        4. Cross-border data transfer compliance
        5. RUC and tax data protection
        6. Peru data protection law (Ley 29733) compliance

        Args:
            scan_result: Output from GTL Security Scanner

        Returns:
            AgentAnalysisResult with customs-specific findings
        """
        start_time = datetime.utcnow()
        findings: List[AgentFinding] = []

        logger.info(f"Starting customs data protection analysis for scan {scan_result.scan_id}")

        # Check 1: SUNAT API security
        sunat_findings = await self._check_sunat_integration(scan_result)
        findings.extend(sunat_findings)
        logger.debug(f"SUNAT checks: {len(sunat_findings)} findings")

        # Check 2: Customs declaration protection
        declaration_findings = await self._check_declaration_security(scan_result)
        findings.extend(declaration_findings)
        logger.debug(f"Declaration checks: {len(declaration_findings)} findings")

        # Check 3: E-invoice security
        einvoice_findings = await self._check_einvoice_security(scan_result)
        findings.extend(einvoice_findings)
        logger.debug(f"E-invoice checks: {len(einvoice_findings)} findings")

        # Check 4: Cross-border data compliance
        cbdt_findings = await self._check_cross_border_transfers(scan_result)
        findings.extend(cbdt_findings)
        logger.debug(f"Cross-border checks: {len(cbdt_findings)} findings")

        # Check 5: Ley 29733 compliance
        ley29733_findings = await self._check_ley29733_compliance(scan_result)
        findings.extend(ley29733_findings)
        logger.debug(f"Ley 29733 checks: {len(ley29733_findings)} findings")

        # Prioritize findings
        findings = self._prioritize_findings(findings)

        # Calculate duration
        duration = (datetime.utcnow() - start_time).total_seconds()

        # Build analysis result
        result = AgentAnalysisResult(
            agent_name="Customs Data Protection Agent",
            sector="customs_trade",
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
            f"Customs analysis complete: {result.total_findings} findings "
            f"({result.critical_findings} critical, {result.high_findings} high)"
        )

        return result

    async def _check_sunat_integration(self, scan_result: Any) -> List[AgentFinding]:
        """
        Check SUNAT integration security.

        SUNAT systems:
        - SOL (Sistema de Operaciones en Línea)
        - SEE (Sistema de Emisión Electrónica)
        - VUCE (Ventanilla Única de Comercio Exterior)
        - Portal SUNAT
        - API REST SUNAT

        Critical risks:
        - Clave SOL exposure
        - RUC number leakage
        - Unencrypted SUNAT API calls
        - Missing audit logging
        """
        findings: List[AgentFinding] = []

        # Check for exposed SUNAT credentials
        for vuln in scan_result.vulnerabilities:
            if hasattr(vuln, 'description') or hasattr(vuln, 'title'):
                text = f"{getattr(vuln, 'title', '')} {getattr(vuln, 'description', '')}".lower()

                # Check for Clave SOL patterns
                if any(pattern in text for pattern in ['clave_sol', 'usuario_sol', 'sunat_key', 'sunat_pass']):
                    findings.append(AgentFinding(
                        title="SUNAT Credentials (Clave SOL) Exposed",
                        severity=FindingSeverity.CRITICAL,
                        category="SUNAT Security",
                        description=(
                            "SUNAT credentials (Clave SOL) found exposed. "
                            "Clave SOL provides access to:\n"
                            "• Customs declarations (DAM)\n"
                            "• Tax filings and payments\n"
                            "• E-invoice submission\n"
                            "• Import/export permits\n"
                            "• Company financial data in SUNAT systems"
                        ),
                        affected_component=vuln.affected_url if hasattr(vuln, 'affected_url') else "Configuration",
                        business_impact=(
                            "🚨 SUNAT CREDENTIALS COMPROMISED - EMERGENCY:\n\n"
                            "IMMEDIATE RISKS:\n"
                            "• Fraudulent customs declarations filed under your RUC\n"
                            "• Unauthorized tax payments or refund requests\n"
                            "• Modification of existing import/export declarations\n"
                            "• Access to confidential commercial information\n"
                            "• Submission of false e-invoices\n\n"
                            "REGULATORY CONSEQUENCES:\n"
                            "• SUNAT audit and investigation\n"
                            "• Administrative sanctions (Resolución 157-2004)\n"
                            "• Fines: 50% - 100% UIT ($2,300 - $4,600 USD)\n"
                            "• Criminal charges if fraud detected\n"
                            "• Suspension of RUC (business shutdown)\n"
                            "• Inclusion in SUNAT blacklist\n\n"
                            "BUSINESS IMPACT:\n"
                            "• Cannot import/export if RUC suspended\n"
                            "• Customs clearance delays\n"
                            "• Loss of authorized economic operator (AEO) status\n"
                            "• Banking relationships affected\n"
                            "• Customer trust destroyed"
                        ),
                        financial_impact=(
                            "$2,300-$4,600 USD in fines + "
                            "legal fees + "
                            "potential fraud losses + "
                            "business interruption costs"
                        ),
                        remediation=(
                            "⚠️ EMERGENCY - ACT NOW ⚠️\n\n"
                            "IMMEDIATE (Next 1 Hour):\n"
                            "1. Contact SUNAT to suspend compromised Clave SOL IMMEDIATELY\n"
                            "   Phone: (01) 315-0730 (Peru)\n"
                            "2. Request new Clave SOL from SUNAT office (requires in-person visit)\n"
                            "3. Review ALL declarations/filings in past 90 days\n"
                            "4. Check for unauthorized transactions\n"
                            "5. Notify legal counsel and tax advisor\n\n"
                            "NEXT 24 HOURS:\n"
                            "6. File incident report with SUNAT\n"
                            "7. Move new credentials to secure vault (HashiCorp Vault)\n"
                            "8. Scan entire codebase for hardcoded credentials\n"
                            "9. Review Git history for exposed secrets\n"
                            "10. Rotate ALL SUNAT-related credentials\n\n"
                            "NEXT WEEK:\n"
                            "11. Implement secrets management system\n"
                            "12. Set up secret scanning in CI/CD (GitGuardian, detect-secrets)\n"
                            "13. Implement 2FA for SUNAT access\n"
                            "14. Set up SUNAT transaction monitoring\n"
                            "15. Document SUNAT access in audit log\n\n"
                            "LONG-TERM:\n"
                            "16. Quarterly credential rotation policy\n"
                            "17. Limit SUNAT access to specific IP addresses\n"
                            "18. Implement just-in-time access for SUNAT\n"
                            "19. Annual security training on credentials management\n"
                            "20. Consider SUNAT API integration instead of SOL"
                        ),
                        remediation_priority="immediate",
                        remediation_effort="hours",
                        compliance_violations=[
                            "SUNAT Resolución 185-2020 - Seguridad de la Información",
                            "Ley 29733 Article 17 - Medidas de Seguridad",
                            "ISO 27001 A.9.4.1 - Restricción de Acceso",
                            "Código Tributario Article 87 - Infracciones",
                        ],
                        regulatory_risk=(
                            "RUC suspension possible. Criminal prosecution if fraud detected. "
                            "Loss of AEO (Authorized Economic Operator) status."
                        ),
                        discovered_by="Customs Data Protection Agent",
                        evidence={
                            "credential_type": "Clave SOL",
                            "location": vuln.affected_url if hasattr(vuln, 'affected_url') else "Unknown"
                        },
                        references=[
                            "https://www.sunat.gob.pe/",
                            "https://www.sunat.gob.pe/legislacion/codigo/index.html",
                        ],
                    ))

        return findings

    async def _check_declaration_security(self, scan_result: Any) -> List[AgentFinding]:
        """
        Check customs declaration (DAM) data security.

        DAM contains highly sensitive data:
        - Importer/exporter details
        - Product descriptions and HS codes
        - Commercial invoice values
        - Country of origin
        - Supplier information
        """
        findings: List[AgentFinding] = []

        # Check for exposed customs documents
        for vuln in scan_result.vulnerabilities:
            if 'directory' in vuln.title.lower() and 'listing' in vuln.title.lower():
                affected_url = vuln.affected_url.lower() if hasattr(vuln, 'affected_url') else ""

                if any(keyword in affected_url for keyword in [
                    'customs', 'aduana', 'dam', 'declaracion', 'importacion', 'exportacion'
                ]):
                    findings.append(AgentFinding(
                        title="Customs Declarations (DAM) Publicly Exposed",
                        severity=FindingSeverity.HIGH,
                        category="Customs Data Protection",
                        description=(
                            f"Customs declaration documents exposed at {vuln.affected_url}. "
                            "DAM documents contain sensitive commercial and trade data."
                        ),
                        affected_component=vuln.affected_url,
                        business_impact=(
                            "Exposed DAM documents reveal:\n\n"
                            "COMMERCIAL INTELLIGENCE:\n"
                            "• Complete supplier lists and relationships\n"
                            "• Product sourcing countries\n"
                            "• Purchase prices and volumes\n"
                            "• Margins and pricing strategies\n"
                            "• HS codes and product classifications\n\n"
                            "COMPETITIVE RISKS:\n"
                            "• Competitors identify your suppliers\n"
                            "• Direct sourcing from your suppliers\n"
                            "• Price undercutting with market knowledge\n"
                            "• Product reverse engineering from descriptions\n\n"
                            "COMPLIANCE RISKS:\n"
                            "• Ley 29733 violation (personal/commercial data)\n"
                            "• Breach of supplier confidentiality agreements\n"
                            "• Trade secret exposure"
                        ),
                        financial_impact="$100K-$1M in lost competitive advantage",
                        remediation=(
                            "IMMEDIATE:\n"
                            "1. Disable directory listing\n"
                            "2. Move documents outside web root\n"
                            "3. Audit access logs\n\n"
                            "SHORT-TERM:\n"
                            "4. Implement authentication for all customs docs\n"
                            "5. Use document IDs instead of filenames\n"
                            "6. Add watermarking to PDFs\n"
                            "7. Implement access logging\n\n"
                            "LONG-TERM:\n"
                            "8. Encrypt documents at rest (AES-256)\n"
                            "9. Set up DLP monitoring\n"
                            "10. Annual security audit"
                        ),
                        remediation_priority="high",
                        remediation_effort="hours",
                        compliance_violations=[
                            "Ley 29733 Article 17 - Medidas de Seguridad",
                            "Ley 29733 Article 18 - Confidencialidad",
                            "ISO 27001 A.18.1.3",
                        ],
                        discovered_by="Customs Data Protection Agent",
                    ))

        return findings

    async def _check_einvoice_security(self, scan_result: Any) -> List[AgentFinding]:
        """
        Check e-invoice (Facturación Electrónica) system security.

        SUNAT requires electronic invoicing for most businesses.
        Critical data in e-invoices:
        - RUC (tax ID)
        - Customer details
        - Product/service descriptions
        - Pricing
        """
        findings: List[AgentFinding] = []

        # Check for e-invoice endpoint security
        if hasattr(scan_result, 'discovered_urls'):
            for url in scan_result.discovered_urls:
                if any(keyword in url.lower() for keyword in ['factura', 'invoice', 'see', 'sunat']):
                    if url.startswith('http://'):
                        findings.append(AgentFinding(
                            title="Unencrypted E-Invoice Transmission to SUNAT",
                            severity=FindingSeverity.HIGH,
                            category="E-Invoice Security",
                            description=(
                                f"E-invoice endpoint {url} uses unencrypted HTTP. "
                                "SUNAT requires secure transmission of electronic invoices."
                            ),
                            affected_component=url,
                            business_impact=(
                                "RISKS:\n"
                                "• E-invoice data intercepted (RUC, customer data, pricing)\n"
                                "• Man-in-the-middle attacks\n"
                                "• Invoice tampering\n"
                                "• SUNAT compliance violation\n\n"
                                "REGULATORY:\n"
                                "• Resolución 300-2014/SUNAT requires secure transmission\n"
                                "• Potential rejection of e-invoices\n"
                                "• Sanctions for non-compliance"
                            ),
                            remediation=(
                                "1. Implement HTTPS/TLS 1.3\n"
                                "2. Use SUNAT's official SSL certificates\n"
                                "3. Implement certificate pinning\n"
                                "4. Test with SUNAT Beta environment first"
                            ),
                            remediation_priority="high",
                            remediation_effort="days",
                            compliance_violations=[
                                "SUNAT Resolución 300-2014 - Facturación Electrónica",
                                "Ley 29733 Article 17",
                            ],
                            discovered_by="Customs Data Protection Agent",
                        ))

        return findings

    async def _check_cross_border_transfers(self, scan_result: Any) -> List[AgentFinding]:
        """
        Check cross-border data transfer compliance.

        Peru regulations require safeguards for international data transfers,
        especially to countries without adequacy decisions.
        """
        findings: List[AgentFinding] = []

        # Check for data transfers to foreign cloud providers
        if hasattr(scan_result, 'discovered_urls'):
            for url in scan_result.discovered_urls:
                # Check for foreign cloud services
                if any(domain in url for domain in [
                    'amazonaws.com', 'azure.com', 'googlecloud.com',
                    'cloudflare.com', 'fastly.com'
                ]):
                    findings.append(AgentFinding(
                        title="Cross-Border Data Transfer Without Safeguards",
                        severity=FindingSeverity.MEDIUM,
                        category="International Data Transfer",
                        description=(
                            f"Data transferred to foreign cloud service: {url}. "
                            "Ley 29733 requires safeguards for international transfers."
                        ),
                        affected_component=url,
                        business_impact=(
                            "COMPLIANCE REQUIREMENTS:\n"
                            "• Ley 29733 Article 19 - International transfers require:\n"
                            "  1. Adequate level of protection in destination country, OR\n"
                            "  2. Contractual safeguards (Data Processing Agreement), OR\n"
                            "  3. User consent for transfer\n\n"
                            "RISKS:\n"
                            "• Regulatory sanctions from Autoridad Nacional de Protección de Datos\n"
                            "• Customer trust issues\n"
                            "• Potential data sovereignty concerns"
                        ),
                        remediation=(
                            "1. Execute Data Processing Agreement (DPA) with cloud provider\n"
                            "2. Ensure Standard Contractual Clauses (SCC)\n"
                            "3. Document data flow mapping\n"
                            "4. Implement data residency controls where possible\n"
                            "5. Add transfer basis in privacy policy\n"
                            "6. Consider Peru or LATAM regions for cloud deployment"
                        ),
                        remediation_priority="medium",
                        remediation_effort="weeks",
                        compliance_violations=[
                            "Ley 29733 Article 19 - Flujo Transfronterizo",
                            "Ley 29733 Article 13 - Información al Titular",
                        ],
                        discovered_by="Customs Data Protection Agent",
                    ))

        return findings

    async def _check_ley29733_compliance(self, scan_result: Any) -> List[AgentFinding]:
        """
        Check Ley 29733 (Peru Data Protection Law) compliance.

        Key requirements:
        - Consent for personal data processing
        - Security measures
        - Data subject rights
        - Privacy policy
        - Registration with Autoridad Nacional
        """
        findings: List[AgentFinding] = []

        # Check for missing privacy policy
        has_privacy_policy = False
        if hasattr(scan_result, 'discovered_urls'):
            has_privacy_policy = any(
                'privacy' in url.lower() or 'privacidad' in url.lower()
                for url in scan_result.discovered_urls
            )

        if not has_privacy_policy:
            findings.append(AgentFinding(
                title="Missing Privacy Policy (Ley 29733 Required)",
                severity=FindingSeverity.MEDIUM,
                category="Peru Data Protection",
                description=(
                    "No privacy policy detected. Ley 29733 requires clear privacy information "
                    "for all personal data processing."
                ),
                affected_component="Website",
                business_impact=(
                    "LEY 29733 REQUIREMENTS:\n"
                    "• Article 13: Must inform data subjects about:\n"
                    "  - What data is collected\n"
                    "  - Purpose of processing\n"
                    "  - Recipients of data\n"
                    "  - Rights (access, rectification, cancellation, opposition)\n"
                    "  - Security measures\n\n"
                    "CONSEQUENCES OF NON-COMPLIANCE:\n"
                    "• Fines from Autoridad Nacional de Protección de Datos\n"
                    "• Cannot process personal data legally\n"
                    "• Customer complaints and reputational damage"
                ),
                remediation=(
                    "1. Create comprehensive privacy policy covering:\n"
                    "   - Data controller identity and contact\n"
                    "   - Types of data collected\n"
                    "   - Processing purposes\n"
                    "   - Legal basis for processing\n"
                    "   - Data retention periods\n"
                    "   - Data subject rights\n"
                    "   - Security measures\n"
                    "   - International transfers (if any)\n"
                    "   - Contact for privacy inquiries\n"
                    "2. Make policy easily accessible on website\n"
                    "3. Obtain legal review\n"
                    "4. Register data bank with Autoridad Nacional\n"
                    "5. Implement consent mechanisms"
                ),
                remediation_priority="medium",
                remediation_effort="days",
                compliance_violations=[
                    "Ley 29733 Article 13 - Información al Titular",
                    "Ley 29733 Article 8 - Principio de Información",
                ],
                discovered_by="Customs Data Protection Agent",
                references=[
                    "https://www.gob.pe/institucion/minjus/informes-publicaciones/2272487-ley-n-29733-ley-de-proteccion-de-datos-personales",
                ],
            ))

        return findings

    def get_compliance_mapping(self, finding: AgentFinding) -> Dict[str, Any]:
        """Map customs finding to regulations"""
        mapping = {
            "frameworks": [],
            "controls": {},
            "severity_per_framework": {},
        }

        for violation in finding.compliance_violations:
            if "SUNAT" in violation:
                mapping["frameworks"].append("SUNAT Regulations")
                if "SUNAT" not in mapping["controls"]:
                    mapping["controls"]["SUNAT"] = []
                mapping["controls"]["SUNAT"].append(violation)

            if "Ley 29733" in violation:
                mapping["frameworks"].append("Peru Data Protection Law")
                if "Ley 29733" not in mapping["controls"]:
                    mapping["controls"]["Ley 29733"] = []
                mapping["controls"]["Ley 29733"].append(violation)

            if "ISO 27001" in violation:
                mapping["frameworks"].append("ISO 27001")

        for framework in mapping["frameworks"]:
            mapping["severity_per_framework"][framework] = finding.severity.value

        return mapping

    def calculate_business_risk_score(self, findings: List[AgentFinding]) -> float:
        """Calculate customs-specific business risk"""
        if not findings:
            return 0.0

        score = 0.0

        for finding in findings:
            # Base severity
            severity_scores = {
                FindingSeverity.CRITICAL: 28.0,
                FindingSeverity.HIGH: 16.0,
                FindingSeverity.MEDIUM: 9.0,
                FindingSeverity.LOW: 4.0,
                FindingSeverity.INFO: 1.0,
            }
            score += severity_scores.get(finding.severity, 0.0)

            # Extra weight for SUNAT credential issues
            if "sunat" in finding.title.lower() and "credential" in finding.title.lower():
                score += 25.0

            # Extra weight for DAM exposure
            if "dam" in finding.title.lower() or "declaration" in finding.title.lower():
                score += 15.0

            # Extra weight for RUC suspension risk
            if finding.regulatory_risk and "ruc" in finding.regulatory_risk.lower():
                score += 20.0

        return min(score, 100.0)


# Export
__all__ = ["CustomsDataProtectionAgent"]
