"""
Logistics Security Agent

Specialized security checks for logistics/freight forwarding/customs sector.

Focus areas:
- EDI (Electronic Data Interchange) security (X12, EDIFACT)
- Bill of Lading (BoL) data protection
- Customs API integrations (SUNAT, CBP, SAT)
- Supply chain data integrity
- Third-party logistics (3PL) access controls
- Fleet tracking systems
- Warehouse management systems (WMS)
"""

import re
import asyncio
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime, timedelta

from gtl_agents.base_agent import (
    BaseSecurityAgent,
    AgentFinding,
    AgentAnalysisResult,
    FindingSeverity,
    ComplianceFramework,
)

import logging

logger = logging.getLogger(__name__)


class LogisticsSecurityAgent(BaseSecurityAgent):
    """
    Security agent for logistics and supply chain sector.

    Detects vulnerabilities specific to:
    - International freight forwarding
    - Customs declarations and clearance
    - EDI systems (X12, EDIFACT, XML)
    - Bill of Lading and shipping documents
    - Third-party logistics integrations
    - Fleet and asset tracking

    Target clients:
    - Freight forwarders
    - Customs brokers
    - 3PL providers
    - Shipping lines
    - Warehouse operators
    """

    def __init__(self):
        """Initialize logistics security agent"""
        kb_path = Path(__file__).parent / "knowledge_bases" / "logistics_vulnerabilities.yaml"
        super().__init__(knowledge_base_path=str(kb_path) if kb_path.exists() else None)

        # EDI format detection patterns
        self.edi_patterns = {
            'x12': r'ISA\*\d{2}\*',  # X12 EDI header
            'edifact': r'UNB\+UN[A-Z]{2}',  # EDIFACT header
            'xml_edi': r'<EDI.*?xmlns',
            'tradacoms': r'STX\+',
        }

        # Customs API patterns
        self.customs_api_patterns = {
            'sunat_peru': ['clave_sol', 'usuario_sol', 'sunat', 'ruc_'],
            'cbp_us': ['filer_code', 'ace_password', 'cbp', 'scac'],
            'sat_mexico': ['sat_', 'rfc_', 'ciec'],
            'sii_chile': ['sii_', 'rut_'],
            'afip_argentina': ['afip_', 'cuit_'],
        }

        # Sensitive logistics data patterns
        self.sensitive_patterns = {
            'bol_number': r'(?:BOL|B/L|BILL.?OF.?LADING)[:\s#]*([A-Z0-9]{8,20})',
            'container_number': r'[A-Z]{4}\d{7}',  # ISO 6346 format
            'hs_code': r'\d{4}\.\d{2}\.\d{2}',  # Harmonized System code
            'importer_number': r'IOR[:\s]*\d{10,}',
        }

        logger.info("LogisticsSecurityAgent initialized")

    async def analyze(self, scan_result: Any) -> AgentAnalysisResult:
        """
        Run logistics-specific security analysis.

        Checks:
        1. EDI endpoint security (encryption, authentication)
        2. Bill of Lading data exposure
        3. Customs API security (key leakage, insecure storage)
        4. Document upload vulnerabilities
        5. Third-party access controls
        6. Supply chain data integrity

        Args:
            scan_result: Output from GTL Security Scanner

        Returns:
            AgentAnalysisResult with logistics-specific findings
        """
        start_time = datetime.utcnow()
        findings: List[AgentFinding] = []

        logger.info(f"Starting logistics security analysis for scan {scan_result.scan_id}")

        # Check 1: EDI endpoint security
        edi_findings = await self._check_edi_security(scan_result)
        findings.extend(edi_findings)
        logger.debug(f"EDI checks: {len(edi_findings)} findings")

        # Check 2: Bill of Lading exposure
        bol_findings = await self._check_bol_exposure(scan_result)
        findings.extend(bol_findings)
        logger.debug(f"BoL checks: {len(bol_findings)} findings")

        # Check 3: Customs API security
        customs_findings = await self._check_customs_apis(scan_result)
        findings.extend(customs_findings)
        logger.debug(f"Customs API checks: {len(customs_findings)} findings")

        # Check 4: Document upload security
        upload_findings = await self._check_document_uploads(scan_result)
        findings.extend(upload_findings)
        logger.debug(f"Upload checks: {len(upload_findings)} findings")

        # Check 5: Third-party logistics access
        access_findings = await self._check_3pl_access(scan_result)
        findings.extend(access_findings)
        logger.debug(f"3PL access checks: {len(access_findings)} findings")

        # Check 6: Fleet/asset tracking security
        tracking_findings = await self._check_tracking_systems(scan_result)
        findings.extend(tracking_findings)
        logger.debug(f"Tracking system checks: {len(tracking_findings)} findings")

        # Prioritize findings
        findings = self._prioritize_findings(findings)

        # Calculate duration
        duration = (datetime.utcnow() - start_time).total_seconds()

        # Build analysis result
        result = AgentAnalysisResult(
            agent_name="Logistics Security Agent",
            sector="logistics",
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
            f"Logistics analysis complete: {result.total_findings} findings "
            f"({result.critical_findings} critical, {result.high_findings} high)"
        )

        return result

    async def _check_edi_security(self, scan_result: Any) -> List[AgentFinding]:
        """
        Check Electronic Data Interchange (EDI) endpoint security.

        EDI systems exchange critical logistics data:
        - 856 ASN (Advance Ship Notice)
        - 850 Purchase Order
        - 810 Invoice
        - 214 Transportation Carrier Shipment Status
        - 990 Response to Load Tender

        Common vulnerabilities:
        - Unencrypted transmission (HTTP vs HTTPS/AS2)
        - Missing authentication
        - EDI injection attacks
        - Partner validation bypasses
        - Message tampering (no digital signatures)

        Args:
            scan_result: Scanner output

        Returns:
            List of EDI-related findings
        """
        findings: List[AgentFinding] = []

        # Detect EDI endpoints
        edi_endpoints = []

        # Check discovered URLs
        if hasattr(scan_result, 'discovered_urls'):
            for url in scan_result.discovered_urls:
                if any(pattern in url.lower() for pattern in ['edi', 'as2', 'x12', 'edifact', 'b2b']):
                    edi_endpoints.append(url)

        # Check open ports for common EDI ports
        if hasattr(scan_result, 'services'):
            for service in scan_result.services:
                if service.port in [5000, 5001, 5002, 5050, 5051]:  # Common EDI ports
                    edi_endpoints.append(f"tcp://{service.host if hasattr(service, 'host') else 'target'}:{service.port}")

        if not edi_endpoints:
            logger.debug("No EDI endpoints detected")
            return findings

        logger.info(f"Detected {len(edi_endpoints)} potential EDI endpoints")

        for endpoint in edi_endpoints:
            # Check 1: Unencrypted transmission
            if isinstance(endpoint, str) and endpoint.startswith('http://'):
                findings.append(AgentFinding(
                    title="Unencrypted EDI Transmission",
                    severity=FindingSeverity.CRITICAL,
                    category="EDI Security",
                    description=(
                        f"EDI endpoint {endpoint} uses unencrypted HTTP. "
                        f"EDI messages contain sensitive commercial and logistics data including: "
                        f"customer information, pricing, shipping routes, inventory levels, and "
                        f"business relationships. Unencrypted transmission allows interception."
                    ),
                    affected_component=endpoint,
                    business_impact=(
                        "Intercepted EDI messages could expose:\n"
                        "• Customer lists and shipping volumes (competitive intelligence)\n"
                        "• Pricing structures and margins\n"
                        "• Supply chain routes and partners\n"
                        "• Inventory levels and turnover rates\n"
                        "• Product specifications and commodities\n"
                        "\n"
                        "Regulatory implications:\n"
                        "• C-TPAT certification violation (US customs)\n"
                        "• ISO 27001 non-compliance\n"
                        "• Potential contract violations with partners"
                    ),
                    financial_impact="$50K-$500K in lost business if data leaked to competitors",
                    remediation=(
                        "IMMEDIATE ACTIONS:\n"
                        "1. Implement HTTPS/TLS 1.3 for all EDI endpoints\n"
                        "2. Consider AS2 protocol with digital signatures (RFC 4130)\n"
                        "3. Use VPN tunnels for partner EDI connections\n"
                        "4. Implement certificate-based mutual authentication\n"
                        "\n"
                        "LONG-TERM:\n"
                        "5. Deploy EDI gateway with encryption enforcement\n"
                        "6. Audit all partner connections quarterly\n"
                        "7. Document encryption requirements in partner contracts"
                    ),
                    remediation_priority="immediate",
                    remediation_effort="days",
                    compliance_violations=[
                        "ISO 27001 A.10.1.1 - Cryptographic Controls",
                        "ISO 27001 A.13.2.1 - Information Transfer Policies",
                        "C-TPAT Security Criteria",
                        "NIST CSF PR.DS-2 - Data-in-transit Protection",
                    ],
                    regulatory_risk="C-TPAT certification revocation possible",
                    discovered_by="Logistics Security Agent",
                    evidence={"endpoint": endpoint, "protocol": "HTTP"},
                    references=[
                        "https://www.cbp.gov/border-security/ports-entry/cargo-security/ctpat",
                        "https://www.iso.org/standard/54534.html",
                    ]
                ))

            # Check 2: Missing authentication
            # Note: Would require actual testing - simulated here
            if self._endpoint_likely_unauthenticated(endpoint):
                findings.append(AgentFinding(
                    title="EDI Endpoint Lacks Authentication",
                    severity=FindingSeverity.CRITICAL,
                    category="EDI Security",
                    description=(
                        f"EDI endpoint {endpoint} appears to accept messages without proper "
                        f"authentication. This allows anyone to inject fraudulent EDI transactions "
                        f"or access sensitive logistics data."
                    ),
                    affected_component=endpoint,
                    business_impact=(
                        "Attackers could:\n"
                        "• Inject fake shipping orders (fraud)\n"
                        "• Modify delivery addresses (cargo theft)\n"
                        "• Cancel legitimate shipments (business disruption)\n"
                        "• Access customer pricing and volumes\n"
                        "• Submit fraudulent customs declarations\n"
                        "\n"
                        "Real-world impact:\n"
                        "• $100K-$1M+ in fraudulent shipments\n"
                        "• Customs penalties if fraudulent declarations submitted\n"
                        "• Customer SLA violations and penalties\n"
                        "• Reputation damage and loss of trust"
                    ),
                    financial_impact="$100K-$1M+ in fraud/disruption costs",
                    remediation=(
                        "Implement EDI authentication using:\n"
                        "\n"
                        "OPTION 1: AS2 with Digital Certificates (RECOMMENDED)\n"
                        "1. Deploy AS2 gateway (e.g., Cleo, IBM Sterling)\n"
                        "2. Issue X.509 certificates to each trading partner\n"
                        "3. Require digital signatures on all EDI messages\n"
                        "4. Implement certificate revocation checking\n"
                        "\n"
                        "OPTION 2: API Keys + IP Whitelisting\n"
                        "1. Generate unique API key per partner\n"
                        "2. Whitelist partner IP ranges\n"
                        "3. Implement rate limiting per partner\n"
                        "4. Log all EDI transactions with partner ID\n"
                        "\n"
                        "OPTION 3: OAuth 2.0 Client Credentials\n"
                        "1. Set up OAuth provider\n"
                        "2. Issue client_id/client_secret to partners\n"
                        "3. Require Bearer token on all requests\n"
                        "4. Short-lived tokens with refresh mechanism"
                    ),
                    remediation_priority="immediate",
                    remediation_effort="weeks",
                    compliance_violations=[
                        "ISO 27001 A.9.4.1 - Information Access Restriction",
                        "C-TPAT Business Partner Requirements",
                        "ISO 28000 Supply Chain Security",
                    ],
                    discovered_by="Logistics Security Agent",
                    evidence={"endpoint": endpoint, "auth_required": False}
                ))

        return findings

    async def _check_bol_exposure(self, scan_result: Any) -> List[AgentFinding]:
        """
        Check for Bill of Lading (BoL) data exposure.

        BoL is THE most sensitive document in logistics:
        - Shipper and consignee details (customer lists)
        - Commodity descriptions (business intelligence)
        - Freight charges (pricing information)
        - Container and tracking numbers
        - Incoterms and payment terms

        Exposure risks:
        - Directory listings exposing BoL files
        - Predictable BoL URLs
        - No authentication on BoL download endpoints
        - BoL numbers in URLs (IDOR vulnerability)

        Args:
            scan_result: Scanner output

        Returns:
            List of BoL exposure findings
        """
        findings: List[AgentFinding] = []

        # Check for directory listing vulnerabilities containing shipping docs
        for vuln in scan_result.vulnerabilities:
            if 'directory' in vuln.title.lower() and 'listing' in vuln.title.lower():
                # Check if this directory likely contains shipping documents
                affected_url = vuln.affected_url.lower() if hasattr(vuln, 'affected_url') else ""

                if any(keyword in affected_url for keyword in [
                    'shipping', 'documents', 'bol', 'bill', 'manifest', 'cargo'
                ]):
                    findings.append(AgentFinding(
                        title="Bill of Lading Documents Publicly Exposed",
                        severity=FindingSeverity.HIGH,
                        category="Data Exposure",
                        description=(
                            f"Directory listing at {vuln.affected_url} exposes shipping documents "
                            f"including Bills of Lading. These documents contain highly sensitive "
                            f"commercial and customer data."
                        ),
                        affected_component=vuln.affected_url,
                        business_impact=(
                            "Exposed Bills of Lading reveal:\n"
                            "• Complete customer lists with shipping volumes\n"
                            "• Pricing structures and freight rates\n"
                            "• Supply chain routes and timing\n"
                            "• Product specifications and HS codes\n"
                            "• Shipper-consignee relationships\n"
                            "\n"
                            "Competitive intelligence value:\n"
                            "• Competitors can identify your customers and approach them\n"
                            "• Undercut your pricing based on exposed rates\n"
                            "• Map your entire supply chain network\n"
                            "\n"
                            "Compliance risks:\n"
                            "• GDPR violation (customer personal data)\n"
                            "• Contract violations (customer confidentiality clauses)\n"
                            "• ISO 27001 A.18.1.3 non-compliance"
                        ),
                        financial_impact="$250K-$2M in lost customers and competitive disadvantage",
                        remediation=(
                            "IMMEDIATE (within 24 hours):\n"
                            "1. Disable directory listing (Apache: -Indexes, Nginx: autoindex off)\n"
                            "2. Move documents outside web root\n"
                            "3. Audit access logs for unauthorized downloads\n"
                            "\n"
                            "SHORT-TERM (within 1 week):\n"
                            "4. Implement authentication for all document access\n"
                            "5. Use document IDs instead of predictable filenames\n"
                            "6. Add access control: users can only see their own BoLs\n"
                            "\n"
                            "LONG-TERM:\n"
                            "7. Encrypt documents at rest (AES-256)\n"
                            "8. Implement document watermarking\n"
                            "9. Add download tracking and expiring links\n"
                            "10. Set up DLP (Data Loss Prevention) monitoring"
                        ),
                        remediation_priority="immediate",
                        remediation_effort="hours",
                        compliance_violations=[
                            "ISO 27001 A.18.1.3 - Protection of Records",
                            "GDPR Article 32 - Security of Processing",
                            "ISO 28000 - Supply Chain Security",
                        ],
                        discovered_by="Logistics Security Agent",
                        evidence={"vulnerability": vuln.title, "url": vuln.affected_url},
                    ))

        return findings

    async def _check_customs_apis(self, scan_result: Any) -> List[AgentFinding]:
        """
        Check security of customs API integrations.

        Common customs systems:
        - SUNAT (Peru): SOL, SEE, VUCE
        - CBP (USA): ACE, e-Manifest
        - SAT (Mexico): COVE
        - SII (Chile): Portal MiPyME
        - AFIP (Argentina): SICAM

        Critical risks:
        - API keys/credentials exposed in code
        - Keys in version control (Git history)
        - Keys in log files
        - Overly permissive API scopes
        - Lack of key rotation

        Args:
            scan_result: Scanner output

        Returns:
            List of customs API security findings
        """
        findings: List[AgentFinding] = []

        # Search for exposed API keys/credentials
        # This would be in actual exposed files, error messages, etc.

        # Check vulnerabilities for exposed files
        for vuln in scan_result.vulnerabilities:
            # Check for files that might contain keys
            if hasattr(vuln, 'affected_url'):
                url_lower = vuln.affected_url.lower()

                if any(ext in url_lower for ext in ['.env', 'config', 'settings', 'credentials']):
                    # Check if it's likely customs-related
                    if any(keyword in url_lower for keyword in ['customs', 'sunat', 'cbp', 'sat', 'api']):
                        findings.append(AgentFinding(
                            title="Customs API Credentials Potentially Exposed",
                            severity=FindingSeverity.CRITICAL,
                            category="Customs Integration Security",
                            description=(
                                f"Configuration file exposed at {vuln.affected_url} likely contains "
                                f"customs API credentials. These credentials provide access to "
                                f"government customs declaration systems."
                            ),
                            affected_component=vuln.affected_url,
                            business_impact=(
                                "Compromised customs API credentials allow attackers to:\n"
                                "\n"
                                "FRAUD RISKS:\n"
                                "• Submit fraudulent customs declarations\n"
                                "• Modify existing import/export entries\n"
                                "• Access company import/export history\n"
                                "• Change payment methods for duties\n"
                                "\n"
                                "REGULATORY RISKS:\n"
                                "• Customs compliance violations (your company is liable)\n"
                                "• Automatic penalties and fines\n"
                                "• Customs audits and investigations\n"
                                "• Suspension of import/export privileges\n"
                                "\n"
                                "FINANCIAL IMPACT:\n"
                                "• Peru (SUNAT): Fines up to $50K per violation\n"
                                "• USA (CBP): $5K-$10K per false declaration\n"
                                "• Mexico (SAT): Fines + criminal charges possible\n"
                                "• Business disruption if suspended from customs system"
                            ),
                            financial_impact="$50K-$500K in fines + potential criminal liability",
                            remediation=(
                                "⚠️ CRITICAL EMERGENCY ACTIONS (NOW):\n"
                                "1. Contact customs agency immediately to revoke credentials\n"
                                "2. Generate new credentials\n"
                                "3. Review all declarations submitted in past 30 days\n"
                                "4. Notify compliance officer and legal counsel\n"
                                "\n"
                                "IMMEDIATE (24 hours):\n"
                                "5. Move credentials to HashiCorp Vault or AWS Secrets Manager\n"
                                "6. Scan Git history for exposed keys (use GitGuardian)\n"
                                "7. Rotate ALL customs API credentials\n"
                                "\n"
                                "SHORT-TERM (1 week):\n"
                                "8. Implement secret scanning in CI/CD (detect-secrets)\n"
                                "9. Set up key rotation every 90 days\n"
                                "10. Implement API usage monitoring and alerting\n"
                                "11. Use environment variables, NEVER hardcode\n"
                                "\n"
                                "LONG-TERM:\n"
                                "12. Implement just-in-time credential access\n"
                                "13. Set up anomaly detection for customs API usage\n"
                                "14. Conduct quarterly security training on secrets management"
                            ),
                            remediation_priority="immediate",
                            remediation_effort="hours",
                            compliance_violations=[
                                "SUNAT Resolution 185-2020 (Peru)",
                                "ISO 27001 A.9.4.1 - Information Access Restriction",
                                "PCI DSS 6.5.3 (if payment data involved)",
                                "Customs-Trade Partnership Against Terrorism (C-TPAT)",
                            ],
                            regulatory_risk="Criminal charges possible for fraudulent customs declarations",
                            discovered_by="Logistics Security Agent",
                            evidence={"file_type": "configuration", "url": vuln.affected_url},
                            references=[
                                "https://www.sunat.gob.pe/legislacion/procedim/normasadua/",
                                "https://www.cbp.gov/trade/ace",
                            ]
                        ))

        return findings

    async def _check_document_uploads(self, scan_result: Any) -> List[AgentFinding]:
        """Check document upload endpoint security"""
        findings: List[AgentFinding] = []

        # Check for upload vulnerabilities
        for vuln in scan_result.vulnerabilities:
            if any(keyword in vuln.title.lower() for keyword in ['upload', 'file']):
                # Logistics systems often have document uploads for:
                # - Commercial invoices
                # - Packing lists
                # - Certificates of origin
                # - BoLs

                findings.append(AgentFinding(
                    title="Insecure Document Upload in Logistics System",
                    severity=FindingSeverity.HIGH,
                    category="Document Security",
                    description=(
                        f"Document upload vulnerability found at {vuln.affected_url}. "
                        f"Logistics systems handle sensitive trade documents."
                    ),
                    affected_component=vuln.affected_url,
                    business_impact=(
                        "Insecure uploads could allow:\n"
                        "• Malware injection into document processing system\n"
                        "• Fraudulent commercial invoices\n"
                        "• Fake certificates of origin\n"
                        "• Document tampering"
                    ),
                    remediation=(
                        "1. Validate file types (whitelist: PDF, JPG, PNG only)\n"
                        "2. Scan uploads with antivirus\n"
                        "3. Store outside web root\n"
                        "4. Implement file size limits\n"
                        "5. Verify document authenticity (digital signatures)"
                    ),
                    remediation_priority="high",
                    remediation_effort="days",
                    compliance_violations=["ISO 27001 A.12.2.1"],
                    discovered_by="Logistics Security Agent",
                ))

        return findings

    async def _check_3pl_access(self, scan_result: Any) -> List[AgentFinding]:
        """Check third-party logistics partner access controls"""
        findings: List[AgentFinding] = []

        # Look for weak access control findings
        for vuln in scan_result.vulnerabilities:
            if any(keyword in vuln.title.lower() for keyword in ['access', 'auth', 'idor', 'broken']):
                findings.append(AgentFinding(
                    title="Weak Access Controls for 3PL Partner Data",
                    severity=FindingSeverity.MEDIUM,
                    category="Partner Security",
                    description=(
                        f"Access control weakness at {vuln.affected_url}. "
                        f"Third-party logistics partners may access unauthorized customer data."
                    ),
                    affected_component=vuln.affected_url,
                    business_impact=(
                        "3PL partners could access:\n"
                        "• Other customers' shipment data\n"
                        "• Pricing for competitors\n"
                        "• Full customer database"
                    ),
                    remediation=(
                        "1. Implement row-level security (partners see only their data)\n"
                        "2. Add partner_id to all queries\n"
                        "3. Use JWT with partner scope restrictions\n"
                        "4. Audit partner access monthly"
                    ),
                    remediation_priority="high",
                    remediation_effort="weeks",
                    compliance_violations=["ISO 27001 A.9.4.1", "ISO 28000"],
                    discovered_by="Logistics Security Agent",
                ))

        return findings

    async def _check_tracking_systems(self, scan_result: Any) -> List[AgentFinding]:
        """Check fleet/asset tracking system security"""
        findings: List[AgentFinding] = []

        # Look for tracking-related endpoints
        for vuln in scan_result.vulnerabilities:
            if hasattr(vuln, 'affected_url'):
                if any(keyword in vuln.affected_url.lower() for keyword in ['track', 'gps', 'location', 'fleet']):
                    findings.append(AgentFinding(
                        title="GPS Tracking Data Exposure",
                        severity=FindingSeverity.MEDIUM,
                        category="Asset Tracking",
                        description=(
                            f"Fleet tracking endpoint {vuln.affected_url} may expose vehicle locations. "
                            f"Real-time location data enables cargo theft."
                        ),
                        affected_component=vuln.affected_url,
                        business_impact=(
                            "Exposed tracking data enables:\n"
                            "• Cargo theft (criminals know exact locations)\n"
                            "• Route intelligence (competitors)\n"
                            "• Driver safety risks"
                        ),
                        remediation=(
                            "1. Require authentication for all tracking queries\n"
                            "2. Delay location updates by 15-30 minutes\n"
                            "3. Geofence high-risk areas\n"
                            "4. Implement tracking data encryption"
                        ),
                        remediation_priority="medium",
                        remediation_effort="days",
                        compliance_violations=["ISO 28000"],
                        discovered_by="Logistics Security Agent",
                    ))

        return findings

    def _endpoint_likely_unauthenticated(self, endpoint: str) -> bool:
        """Heuristic to determine if endpoint likely lacks auth"""
        # This is a placeholder - in production would actually test
        # For now, flag if it's HTTP (often correlates with weak auth)
        return endpoint.startswith('http://')

    def get_compliance_mapping(self, finding: AgentFinding) -> Dict[str, Any]:
        """Map logistics finding to regulations"""
        mapping = {
            "frameworks": [],
            "controls": {},
            "severity_per_framework": {},
        }

        # Extract frameworks from compliance violations
        for violation in finding.compliance_violations:
            if "ISO 27001" in violation:
                mapping["frameworks"].append("ISO 27001")
                if "ISO 27001" not in mapping["controls"]:
                    mapping["controls"]["ISO 27001"] = []
                mapping["controls"]["ISO 27001"].append(violation)

            if "C-TPAT" in violation or "CTPAT" in violation:
                mapping["frameworks"].append("C-TPAT")

            if "SUNAT" in violation:
                mapping["frameworks"].append("SUNAT Peru")

            if "ISO 28000" in violation:
                mapping["frameworks"].append("ISO 28000")

        # Set severity per framework
        for framework in mapping["frameworks"]:
            mapping["severity_per_framework"][framework] = finding.severity.value

        return mapping

    def calculate_business_risk_score(self, findings: List[AgentFinding]) -> float:
        """
        Calculate logistics-specific business risk score.

        Factors:
        - Customs compliance violations (highest weight)
        - Customer data exposure
        - EDI security issues
        - Supply chain disruption potential
        """
        if not findings:
            return 0.0

        score = 0.0

        for finding in findings:
            # Base severity score
            severity_scores = {
                FindingSeverity.CRITICAL: 25.0,
                FindingSeverity.HIGH: 15.0,
                FindingSeverity.MEDIUM: 8.0,
                FindingSeverity.LOW: 3.0,
                FindingSeverity.INFO: 1.0,
            }
            score += severity_scores.get(finding.severity, 0.0)

            # Extra weight for customs/regulatory issues
            if any(keyword in ' '.join(finding.compliance_violations).lower()
                   for keyword in ['sunat', 'customs', 'ctpat', 'cbp']):
                score += 20.0

            # Extra weight for EDI issues
            if finding.category == "EDI Security":
                score += 15.0

            # Extra weight for BoL exposure
            if "bill of lading" in finding.title.lower():
                score += 10.0

        # Normalize to 0-100
        return min(score, 100.0)


# Export
__all__ = ["LogisticsSecurityAgent"]
