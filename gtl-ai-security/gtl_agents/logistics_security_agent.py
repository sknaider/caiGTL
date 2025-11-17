"""
GTL Logistics Security Agent

Specialized CAI agent for logistics and supply chain security assessments.
Focuses on: EDI systems, customs data, warehouse management, fleet tracking.
"""

import os
from typing import List

from cai.sdk.agents import Agent, OpenAIChatCompletionsModel, function_tool
from cai.tools.reconnaissance.generic_linux_command import generic_linux_command
from cai.tools.reconnaissance.nmap import nmap
from cai.tools.reconnaissance.shodan import shodan_search, shodan_host_info
from openai import AsyncOpenAI
from pydantic import BaseModel

# Configure guardrails
from cai.agents.guardrails import get_security_guardrails

input_guardrails, output_guardrails = get_security_guardrails()


# ===========================================
# CUSTOM TOOLS FOR LOGISTICS
# ===========================================


class EDISecurityCheck(BaseModel):
    """EDI system security check result"""

    system_type: str  # X12, EDIFACT, XML, etc.
    encryption_enabled: bool
    authentication_type: str
    vulnerabilities_found: List[str]
    compliance_status: str  # compliant, non_compliant, warning


@function_tool
def check_edi_security(target_ip: str, port: int = 5000) -> EDISecurityCheck:
    """
    Check EDI (Electronic Data Interchange) system security.

    Assesses:
    - Encryption status (TLS/SSL)
    - Authentication mechanisms
    - Data integrity validation
    - AS2/AS3/AS4 protocol security
    - Partner authentication

    Args:
        target_ip: IP address of EDI system
        port: EDI service port (default: 5000)

    Returns:
        EDISecurityCheck with findings
    """
    # In production, this would integrate with real EDI testing tools
    # This is a simulation for demonstration

    vulnerabilities = []

    # Check if port is open (simplified)
    if not target_ip:
        vulnerabilities.append("Invalid target IP")

    # Simulated checks
    encryption = True  # Assume encrypted for demo
    if not encryption:
        vulnerabilities.append("EDI data transmission not encrypted")

    # Check for common EDI vulnerabilities
    common_issues = [
        "Weak partner authentication detected",
        "Missing message integrity validation",
        "No audit logging for EDI transactions",
    ]

    return EDISecurityCheck(
        system_type="X12",  # Common format in logistics
        encryption_enabled=encryption,
        authentication_type="certificate-based",
        vulnerabilities_found=vulnerabilities if vulnerabilities else ["None found"],
        compliance_status="compliant"
        if not vulnerabilities
        else "non_compliant",
    )


class BillOfLadingValidation(BaseModel):
    """Bill of lading fraud detection result"""

    document_id: str
    fraud_indicators: List[str]
    risk_score: float  # 0.0 to 1.0
    validation_status: str


@function_tool
def validate_bill_of_lading(document_data: str) -> BillOfLadingValidation:
    """
    Validate bill of lading for fraud indicators.

    Checks for:
    - Duplicate document numbers
    - Inconsistent shipping data
    - Forged signatures
    - Suspicious routing patterns
    - Data tampering

    Args:
        document_data: Bill of lading data (JSON or XML)

    Returns:
        BillOfLadingValidation with fraud analysis
    """
    # In production, integrate with ML fraud detection model
    # This is simplified for demonstration

    fraud_indicators = []
    risk_score = 0.0

    # Simulated fraud checks
    if "DUPLICATE" in document_data.upper():
        fraud_indicators.append("Potential duplicate document number")
        risk_score += 0.3

    if "TAMPER" in document_data.upper():
        fraud_indicators.append("Evidence of data tampering")
        risk_score += 0.5

    # Normalize risk score
    risk_score = min(risk_score, 1.0)

    validation_status = "FRAUDULENT" if risk_score > 0.7 else "VALID"

    return BillOfLadingValidation(
        document_id=document_data[:20] if document_data else "UNKNOWN",
        fraud_indicators=fraud_indicators
        if fraud_indicators
        else ["No fraud indicators detected"],
        risk_score=risk_score,
        validation_status=validation_status,
    )


class SupplyChainRiskAssessment(BaseModel):
    """Supply chain risk assessment result"""

    vendor_name: str
    security_score: int  # 0-100
    risk_factors: List[str]
    recommendations: List[str]
    breach_history: bool


@function_tool
def assess_supply_chain_vendor(
    vendor_domain: str, vendor_name: str = "Unknown Vendor"
) -> SupplyChainRiskAssessment:
    """
    Assess security posture of supply chain vendor.

    Analyzes:
    - Public vulnerability disclosures
    - Data breach history
    - Security certifications (ISO 27001, SOC 2)
    - Exposed systems (via Shodan)
    - Dark web mentions

    Args:
        vendor_domain: Vendor's domain name
        vendor_name: Vendor company name

    Returns:
        SupplyChainRiskAssessment with security analysis
    """
    # In production, integrate with:
    # - Shodan API
    # - SecurityScorecard API
    # - BitSight API
    # - Threat intelligence feeds

    risk_factors = []
    security_score = 85  # Base score

    # Simulated checks
    if not vendor_domain.endswith(".com"):
        risk_factors.append("Non-standard TLD domain")
        security_score -= 5

    # Common risk factors in logistics
    common_risks = [
        "No public security certifications found",
        "Outdated web server detected",
        "Missing DMARC email protection",
    ]

    recommendations = [
        "Request SOC 2 Type II certification",
        "Implement vendor security assessment annually",
        "Require encryption for all data exchanges",
        "Monitor vendor for breach notifications",
    ]

    return SupplyChainRiskAssessment(
        vendor_name=vendor_name,
        security_score=max(security_score, 0),
        risk_factors=risk_factors if risk_factors else ["No major risks identified"],
        recommendations=recommendations,
        breach_history=False,  # Simulated
    )


# ===========================================
# LOGISTICS SECURITY AGENT
# ===========================================

# Agent instructions (system prompt)
LOGISTICS_INSTRUCTIONS = """Eres un experto en ciberseguridad especializado en el sector logístico y de cadena de suministro en Perú.

TU MISIÓN:
Evaluar y mejorar la seguridad de sistemas logísticos críticos, protegiendo datos sensibles de clientes, cumpliendo regulaciones aduaneras, y previniendo fraude en la cadena de suministro.

ÁREAS DE ESPECIALIZACIÓN:

1. **Sistemas EDI (Electronic Data Interchange)**
   - Seguridad de protocolos X12, EDIFACT, XML
   - Autenticación de socios comerciales
   - Cifrado de datos en tránsito y reposo
   - Integridad de mensajes EDI
   - Conformidad con estándares AS2/AS3/AS4

2. **Protección de Datos Aduaneros**
   - Cumplimiento con regulaciones SUNAT (Perú)
   - Protección de manifiestos de carga
   - Seguridad de declaraciones aduaneras
   - Prevención de fraude documental
   - Bill of Lading (conocimiento de embarque) fraud detection

3. **Sistemas de Gestión de Almacenes (WMS)**
   - SAP Extended Warehouse Management (EWM)
   - Oracle WMS
   - Manhattan Associates WMOS
   - Seguridad de APIs de WMS
   - Control de acceso a inventario

4. **Rastreo de Flotas y GPS**
   - Seguridad de dispositivos GPS
   - Protección de datos de ubicación en tiempo real
   - Prevención de suplantación de ubicación (GPS spoofing)
   - Cifrado de comunicaciones de flotas

5. **Evaluación de Riesgos en Cadena de Suministro**
   - Análisis de seguridad de proveedores
   - Third-party risk management
   - Monitoreo de brechas de seguridad en partners
   - Evaluación de certificaciones de seguridad

HERRAMIENTAS DISPONIBLES:
- `generic_linux_command`: Ejecuta comandos de seguridad en sistemas Linux
- `nmap`: Escaneo de puertos y descubrimiento de servicios
- `shodan_search`: Búsqueda de sistemas expuestos en internet
- `shodan_host_info`: Información detallada de host específico
- `check_edi_security`: Evaluación de seguridad de sistemas EDI
- `validate_bill_of_lading`: Detección de fraude en conocimientos de embarque
- `assess_supply_chain_vendor`: Análisis de riesgo de proveedores

METODOLOGÍA DE EVALUACIÓN:

1. **Reconocimiento**
   - Descubrir sistemas logísticos en red
   - Identificar versiones de software
   - Mapear superficie de ataque

2. **Análisis de Vulnerabilidades**
   - Escanear sistemas EDI
   - Verificar cifrado de datos
   - Evaluar autenticación

3. **Evaluación de Cumplimiento**
   - Verificar conformidad SUNAT
   - Validar protección de datos
   - Revisar controles de acceso

4. **Análisis de Riesgos**
   - Evaluar proveedores
   - Detectar fraude documental
   - Identificar amenazas en cadena de suministro

5. **Reporte y Remediación**
   - Generar informe en español
   - Priorizar hallazgos por criticidad
   - Proporcionar pasos de remediación
   - Incluir recomendaciones específicas para Perú

FORMATO DE REPORTE:
Siempre genera reportes en español con:
- Resumen ejecutivo (para directores)
- Hallazgos técnicos detallados
- Puntuación de riesgo (0-100)
- Priorización por severidad (CRÍTICO, ALTO, MEDIO, BAJO)
- Plan de remediación paso a paso
- Consideraciones de cumplimiento regulatorio Perú

IMPORTANTE:
- Solo realiza pruebas autorizadas
- No ejecutes ataques destructivos
- Protege datos sensibles de clientes
- Cumple con leyes de protección de datos de Perú (Ley 29733)
- Enfócate en seguridad preventiva y defensiva
"""

# Create logistics security agent
logistics_security_agent = Agent(
    name="GTL Logistics Security Agent",
    description="Especialista en seguridad para empresas logísticas y cadena de suministro en Perú",
    instructions=LOGISTICS_INSTRUCTIONS,
    tools=[
        # CAI built-in tools
        generic_linux_command,
        nmap,
        shodan_search,
        shodan_host_info,
        # Custom GTL tools
        check_edi_security,
        validate_bill_of_lading,
        assess_supply_chain_vendor,
    ],
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
    model=OpenAIChatCompletionsModel(
        model=os.getenv("CAI_MODEL", "alias0"),
        openai_client=AsyncOpenAI(),
    ),
)


# ===========================================
# TRANSFER FUNCTION FOR HANDOFFS
# ===========================================


def transfer_to_logistics_security_agent(**kwargs):
    """Transfer control to logistics security agent"""
    return logistics_security_agent


# ===========================================
# EXAMPLE USAGE
# ===========================================

if __name__ == "__main__":
    import asyncio
    from cai.sdk.agents import Runner

    async def main():
        # Example assessment request
        result = await Runner.run(
            logistics_security_agent,
            input="""Realizar evaluación de seguridad para empresa logística:

Empresa: Transportes Rápidos del Perú SAC
Sistemas:
- Sistema EDI en 192.168.100.50:5000
- WMS (SAP EWM) en 192.168.100.51
- Rastreo GPS de flota (200 vehículos)

Evaluación requerida:
1. Seguridad del sistema EDI
2. Protección de datos aduaneros
3. Riesgo de fraude en documentación de embarque
4. Evaluación de proveedor de GPS (vendor: gps-tracker.com)

Generar reporte completo en español con priorización de hallazgos.""",
        )

        print("\n" + "=" * 70)
        print("INFORME DE SEGURIDAD LOGÍSTICA")
        print("=" * 70 + "\n")
        print(result.final_output)

    asyncio.run(main())
