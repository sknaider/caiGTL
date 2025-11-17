"""
Ejemplos de Inicio Rápido para el Motor de IA GTL
Ejecuta estos después de la instalación para probar que todo funciona
"""

import asyncio
import sys
sys.path.append('..')

from core.llm_client import LLMClient, LLMConfig
from analyzers.vulnerability_analyzer import AIVulnerabilityAnalyzer
from analyzers.malware_analyzer import MalwareAnalyzer


async def ejemplo_1_analisis_simple():
    """Ejemplo 1: Análisis simple de vulnerabilidad"""
    print("=" * 60)
    print("EJEMPLO 1: Análisis Simple de Vulnerabilidad")
    print("=" * 60)

    client = LLMClient(LLMConfig(model="llama3.1:70b"))

    vuln = {
        'id': 'vuln-001',
        'title': 'Inyección SQL en formulario de login',
        'description': 'El input del usuario se concatena directamente en la consulta SQL',
        'severity': 'Critical',
        'affected_url': 'https://ejemplo.com/login',
        'category': 'Injection'
    }

    print("\nAnalizando vulnerabilidad con IA...")
    result = await client.analyze_vulnerability(vuln)

    print("\n" + "=" * 60)
    print("RESULTADOS:")
    print("=" * 60)
    print(result['analysis'][:500] + "...")
    print("\n✅ ¡Ejemplo 1 completado!")


async def ejemplo_2_analisis_avanzado():
    """Ejemplo 2: Análisis avanzado de vulnerabilidad con generación de PoC"""
    print("\n" + "=" * 60)
    print("EJEMPLO 2: Análisis Avanzado con Generación de PoC")
    print("=" * 60)

    analyzer = AIVulnerabilityAnalyzer()

    vuln = {
        'id': 'vuln-002',
        'title': 'Cross-Site Scripting (XSS) en sección de comentarios',
        'description': 'Los comentarios del usuario se renderizan sin sanitización',
        'severity': 'High',
        'affected_url': 'https://ejemplo.com/post/123/comentarios',
        'category': 'XSS'
    }

    context = {
        'framework': 'React',
        'version': '18.0.0',
        'public_facing': True,
        'user_base': '50,000+'
    }

    print("\nRealizando análisis completo...")
    analysis = await analyzer.analyze(vuln, context, generate_poc=True)

    print("\n" + "=" * 60)
    print("RESULTADOS:")
    print("=" * 60)
    print(f"Score de Riesgo: {analysis.ai_risk_score}/10")
    print(f"Nivel de Riesgo: {analysis.risk_level.value.upper()}")
    print(f"Complejidad de Exploit: {analysis.exploit_complexity}")
    print(f"Explotabilidad: {analysis.exploitability_score:.1%}")
    print(f"\nImpacto de Negocio:")
    print(analysis.business_impact[:300] + "...")

    if analysis.poc_code:
        print(f"\n✅ PoC Generado ({len(analysis.poc_code)} caracteres)")

    print("\n✅ ¡Ejemplo 2 completado!")


async def ejemplo_3_analisis_codigo():
    """Ejemplo 3: Análisis de seguridad de código con IA"""
    print("\n" + "=" * 60)
    print("EJEMPLO 3: Análisis de Seguridad de Código")
    print("=" * 60)

    client = LLMClient(LLMConfig(model="codellama:34b"))

    codigo_vulnerable = """
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    return user
"""

    print("\nAnalizando código en busca de problemas de seguridad...")
    result = await client.analyze_code_security(
        code=codigo_vulnerable,
        language="python",
        context="Función de login de aplicación web"
    )

    print("\n" + "=" * 60)
    print("RESULTADOS:")
    print("=" * 60)
    print(result['analysis'][:500] + "...")
    print("\n✅ ¡Ejemplo 3 completado!")


async def ejemplo_4_asistente_red_team():
    """Ejemplo 4: Asistente de IA para red team"""
    print("\n" + "=" * 60)
    print("EJEMPLO 4: Asistente de IA para Red Team")
    print("=" * 60)

    client = LLMClient(LLMConfig(model="llama3.1:70b"))

    info_objetivo = {
        'domain': 'ejemplo.com',
        'tech_stack': ['Apache', 'PHP', 'MySQL'],
        'services': ['HTTP (80)', 'HTTPS (443)', 'SSH (22)'],
        'cms': 'WordPress 6.0',
        'hosting': 'AWS'
    }

    print("\nGenerando plan de ataque de red team...")
    print("⚠️  ADVERTENCIA: ¡Solo para pruebas autorizadas!")

    result = await client.red_team_assistant(
        objective="Obtener acceso inicial a la aplicación web",
        target_info=info_objetivo
    )

    print("\n" + "=" * 60)
    print("PLAN TÁCTICO:")
    print("=" * 60)
    print(result['plan'][:600] + "...")
    print("\n✅ ¡Ejemplo 4 completado!")
    print("⚠️  Recuerda: ¡Solo usar en objetivos autorizados!")


async def ejemplo_5_analisis_malware():
    """Ejemplo 5: Análisis de malware (sin LLM requerido)"""
    print("\n" + "=" * 60)
    print("EJEMPLO 5: Análisis de Malware")
    print("=" * 60)

    # Nota: Este ejemplo muestra la estructura pero no se ejecutará sin una muestra real de malware
    print("\nℹ️  Esta es una simulación (no se analiza archivo real)")
    print("\nEn producción, harías:")
    print("1. analyzer = MalwareAnalyzer(llm_client)")
    print("2. result = await analyzer.analyze_file('/ruta/a/sospechoso.exe')")
    print("3. Imprimir resultados: familia, comportamientos, IoCs, score de riesgo")

    print("\nEstructura de salida esperada:")
    print("""
{
    'file_hash': 'abc123...',
    'is_malicious': True,
    'family': 'RANSOMWARE',
    'malware_probability': 0.89,
    'risk_score': 9.2,
    'behaviors': ['Cifrado de archivos', 'Comunicación de red', ...],
    'iocs': {'ip_addresses': [...], 'domains': [...], ...},
    'capabilities': ['ransomware', 'crypto_wallet', ...],
    'detailed_analysis': '...'
}
    """)

    print("\n✅ ¡Ejemplo 5 completado!")


async def ejemplo_6_analisis_batch():
    """Ejemplo 6: Análisis batch de vulnerabilidades"""
    print("\n" + "=" * 60)
    print("EJEMPLO 6: Análisis Batch (Múltiples Vulnerabilidades)")
    print("=" * 60)

    analyzer = AIVulnerabilityAnalyzer()

    vulnerabilidades = [
        {
            'id': 'vuln-101',
            'title': 'Inyección SQL',
            'description': 'Input sin sanitizar en consulta',
            'severity': 'Critical'
        },
        {
            'id': 'vuln-102',
            'title': 'XSS en búsqueda',
            'description': 'Vulnerabilidad XSS reflejada',
            'severity': 'High'
        },
        {
            'id': 'vuln-103',
            'title': 'Token CSRF faltante',
            'description': 'Sin protección CSRF en formularios',
            'severity': 'Medium'
        }
    ]

    print(f"\nAnalizando {len(vulnerabilidades)} vulnerabilidades en paralelo...")
    print("(Esto tomará 30-60 segundos)\n")

    analyses = await analyzer.batch_analyze(vulnerabilidades, max_concurrent=3)

    print("\n" + "=" * 60)
    print("RESULTADOS BATCH:")
    print("=" * 60)
    for analysis in analyses:
        print(f"\n{analysis.title}")
        print(f"  Score de Riesgo: {analysis.ai_risk_score}/10")
        print(f"  Nivel de Riesgo: {analysis.risk_level.value}")
        print(f"  Explotabilidad: {analysis.exploitability_score:.0%}")

    # Priorizar
    prioritized = await analyzer.prioritize_vulnerabilities(analyses)
    print("\n" + "=" * 60)
    print("ORDEN DE PRIORIDAD:")
    print("=" * 60)
    for i, analysis in enumerate(prioritized, 1):
        print(f"{i}. {analysis.title} (Riesgo: {analysis.ai_risk_score}/10)")

    print("\n✅ ¡Ejemplo 6 completado!")


async def ejecutar_todos_ejemplos():
    """Ejecutar todos los ejemplos"""
    print("""
╔═══════════════════════════════════════════════════════════╗
║     Motor de Ciberseguridad con IA GTL - Inicio Rápido   ║
║                  Demostraciones de Ejemplos               ║
╚═══════════════════════════════════════════════════════════╝

Estos ejemplos demuestran las capacidades centrales del motor de IA.
Cada ejemplo es completamente funcional y listo para usar.

Requisitos:
- Ollama ejecutándose con el modelo llama3.1:70b
- Entorno Python con todas las dependencias instaladas

¡Comencemos! 🚀
""")

    try:
        await ejemplo_1_analisis_simple()
        await ejemplo_2_analisis_avanzado()
        await ejemplo_3_analisis_codigo()
        await ejemplo_4_asistente_red_team()
        await ejemplo_5_analisis_malware()
        await ejemplo_6_analisis_batch()

        print("\n" + "=" * 60)
        print("🎉 ¡TODOS LOS EJEMPLOS COMPLETADOS EXITOSAMENTE!")
        print("=" * 60)
        print("""
Próximos pasos:
1. Explorar la documentación de la API
2. Integrar con GTL Scanner
3. Entrenar modelos personalizados con tus datos
4. Construir analizadores personalizados para tus necesidades

¡Tu motor de seguridad con IA está listo para usar! 🔥
        """)

    except Exception as e:
        print(f"\n❌ Error ejecutando ejemplos: {e}")
        print("\nSolución de problemas:")
        print("1. Asegúrate que Ollama esté ejecutándose: ollama serve")
        print("2. Verifica que los modelos estén instalados: ollama list")
        print("3. Revisa los logs: tail -f logs/gtl_ai_engine.log")
        print("4. Revisa INSTALACION_ES.md")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("Selecciona el ejemplo a ejecutar:")
    print("=" * 60)
    print("1. Análisis simple de vulnerabilidad")
    print("2. Análisis avanzado con generación de PoC")
    print("3. Análisis de seguridad de código")
    print("4. Asistente de IA para red team")
    print("5. Análisis de malware (simulación)")
    print("6. Análisis batch de vulnerabilidades")
    print("7. Ejecutar TODOS los ejemplos (recomendado para primera vez)")
    print("=" * 60)

    choice = input("\nIngresa tu elección (1-7): ").strip()

    ejemplos = {
        '1': ejemplo_1_analisis_simple,
        '2': ejemplo_2_analisis_avanzado,
        '3': ejemplo_3_analisis_codigo,
        '4': ejemplo_4_asistente_red_team,
        '5': ejemplo_5_analisis_malware,
        '6': ejemplo_6_analisis_batch,
        '7': ejecutar_todos_ejemplos
    }

    if choice in ejemplos:
        asyncio.run(ejemplos[choice]())
    else:
        print("Elección inválida. Ejecutando todos los ejemplos...")
        asyncio.run(ejecutar_todos_ejemplos())
