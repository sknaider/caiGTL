"""
Quick Start Examples for GTL AI Engine
Run these after installation to test everything works
"""

import asyncio
import sys
sys.path.append('..')

from core.llm_client import LLMClient, LLMConfig
from analyzers.vulnerability_analyzer import AIVulnerabilityAnalyzer
from analyzers.malware_analyzer import MalwareAnalyzer


async def example_1_simple_analysis():
    """Example 1: Simple vulnerability analysis"""
    print("=" * 60)
    print("EXAMPLE 1: Simple Vulnerability Analysis")
    print("=" * 60)

    client = LLMClient(LLMConfig(model="llama3.1:70b"))

    vuln = {
        'id': 'vuln-001',
        'title': 'SQL Injection in login form',
        'description': 'User input concatenated directly into SQL query',
        'severity': 'Critical',
        'affected_url': 'https://example.com/login',
        'category': 'Injection'
    }

    print("\nAnalyzing vulnerability with AI...")
    result = await client.analyze_vulnerability(vuln)

    print("\n" + "=" * 60)
    print("RESULTS:")
    print("=" * 60)
    print(result['analysis'][:500] + "...")
    print("\n✅ Example 1 completed!")


async def example_2_advanced_analysis():
    """Example 2: Advanced vulnerability analysis with PoC"""
    print("\n" + "=" * 60)
    print("EXAMPLE 2: Advanced Analysis with PoC Generation")
    print("=" * 60)

    analyzer = AIVulnerabilityAnalyzer()

    vuln = {
        'id': 'vuln-002',
        'title': 'Cross-Site Scripting (XSS) in comment section',
        'description': 'User comments are rendered without sanitization',
        'severity': 'High',
        'affected_url': 'https://example.com/post/123/comments',
        'category': 'XSS'
    }

    context = {
        'framework': 'React',
        'version': '18.0.0',
        'public_facing': True,
        'user_base': '50,000+'
    }

    print("\nPerforming comprehensive analysis...")
    analysis = await analyzer.analyze(vuln, context, generate_poc=True)

    print("\n" + "=" * 60)
    print("RESULTS:")
    print("=" * 60)
    print(f"Risk Score: {analysis.ai_risk_score}/10")
    print(f"Risk Level: {analysis.risk_level.value.upper()}")
    print(f"Exploit Complexity: {analysis.exploit_complexity}")
    print(f"Exploitability: {analysis.exploitability_score:.1%}")
    print(f"\nBusiness Impact:")
    print(analysis.business_impact[:300] + "...")

    if analysis.poc_code:
        print(f"\n✅ PoC Generated ({len(analysis.poc_code)} characters)")

    print("\n✅ Example 2 completed!")


async def example_3_code_analysis():
    """Example 3: AI-powered code security analysis"""
    print("\n" + "=" * 60)
    print("EXAMPLE 3: Code Security Analysis")
    print("=" * 60)

    client = LLMClient(LLMConfig(model="codellama:34b"))

    vulnerable_code = """
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    return user
"""

    print("\nAnalyzing code for security issues...")
    result = await client.analyze_code_security(
        code=vulnerable_code,
        language="python",
        context="Web application login function"
    )

    print("\n" + "=" * 60)
    print("RESULTS:")
    print("=" * 60)
    print(result['analysis'][:500] + "...")
    print("\n✅ Example 3 completed!")


async def example_4_red_team_assistant():
    """Example 4: AI red team assistant"""
    print("\n" + "=" * 60)
    print("EXAMPLE 4: Red Team AI Assistant")
    print("=" * 60)

    client = LLMClient(LLMConfig(model="llama3.1:70b"))

    target_info = {
        'domain': 'example.com',
        'tech_stack': ['Apache', 'PHP', 'MySQL'],
        'services': ['HTTP (80)', 'HTTPS (443)', 'SSH (22)'],
        'cms': 'WordPress 6.0',
        'hosting': 'AWS'
    }

    print("\nGenerating red team attack plan...")
    print("⚠️  WARNING: For authorized testing only!")

    result = await client.red_team_assistant(
        objective="Gain initial access to web application",
        target_info=target_info
    )

    print("\n" + "=" * 60)
    print("TACTICAL PLAN:")
    print("=" * 60)
    print(result['plan'][:600] + "...")
    print("\n✅ Example 4 completed!")
    print("⚠️  Remember: Only use on authorized targets!")


async def example_5_malware_analysis():
    """Example 5: Malware analysis (no LLM required)"""
    print("\n" + "=" * 60)
    print("EXAMPLE 5: Malware Analysis")
    print("=" * 60)

    # Note: This example shows structure but won't run without actual malware sample
    print("\nℹ️  This is a simulation (no real file analyzed)")
    print("\nIn production, you would:")
    print("1. analyzer = MalwareAnalyzer(llm_client)")
    print("2. result = await analyzer.analyze_file('/path/to/suspicious.exe')")
    print("3. Print results: family, behaviors, IoCs, risk score")

    print("\nExpected output structure:")
    print("""
{
    'file_hash': 'abc123...',
    'is_malicious': True,
    'family': 'RANSOMWARE',
    'malware_probability': 0.89,
    'risk_score': 9.2,
    'behaviors': ['File encryption', 'Network communication', ...],
    'iocs': {'ip_addresses': [...], 'domains': [...], ...},
    'capabilities': ['ransomware', 'crypto_wallet', ...],
    'detailed_analysis': '...'
}
    """)

    print("\n✅ Example 5 completed!")


async def example_6_batch_analysis():
    """Example 6: Batch vulnerability analysis"""
    print("\n" + "=" * 60)
    print("EXAMPLE 6: Batch Analysis (Multiple Vulnerabilities)")
    print("=" * 60)

    analyzer = AIVulnerabilityAnalyzer()

    vulnerabilities = [
        {
            'id': 'vuln-101',
            'title': 'SQL Injection',
            'description': 'Unsanitized input in query',
            'severity': 'Critical'
        },
        {
            'id': 'vuln-102',
            'title': 'XSS in search',
            'description': 'Reflected XSS vulnerability',
            'severity': 'High'
        },
        {
            'id': 'vuln-103',
            'title': 'CSRF missing token',
            'description': 'No CSRF protection on forms',
            'severity': 'Medium'
        }
    ]

    print(f"\nAnalyzing {len(vulnerabilities)} vulnerabilities in parallel...")
    print("(This will take 30-60 seconds)\n")

    analyses = await analyzer.batch_analyze(vulnerabilities, max_concurrent=3)

    print("\n" + "=" * 60)
    print("BATCH RESULTS:")
    print("=" * 60)
    for analysis in analyses:
        print(f"\n{analysis.title}")
        print(f"  Risk Score: {analysis.ai_risk_score}/10")
        print(f"  Risk Level: {analysis.risk_level.value}")
        print(f"  Exploitability: {analysis.exploitability_score:.0%}")

    # Prioritize
    prioritized = await analyzer.prioritize_vulnerabilities(analyses)
    print("\n" + "=" * 60)
    print("PRIORITY ORDER:")
    print("=" * 60)
    for i, analysis in enumerate(prioritized, 1):
        print(f"{i}. {analysis.title} (Risk: {analysis.ai_risk_score}/10)")

    print("\n✅ Example 6 completed!")


async def run_all_examples():
    """Run all examples"""
    print("""
╔═══════════════════════════════════════════════════════════╗
║         GTL AI Cybersecurity Engine - Quick Start         ║
║                   Example Demonstrations                  ║
╚═══════════════════════════════════════════════════════════╝

These examples demonstrate the core capabilities of the AI engine.
Each example is fully functional and ready to use.

Requirements:
- Ollama running with llama3.1:70b model
- Python environment with all dependencies installed

Let's begin! 🚀
""")

    try:
        await example_1_simple_analysis()
        await example_2_advanced_analysis()
        await example_3_code_analysis()
        await example_4_red_team_assistant()
        await example_5_malware_analysis()
        await example_6_batch_analysis()

        print("\n" + "=" * 60)
        print("🎉 ALL EXAMPLES COMPLETED SUCCESSFULLY!")
        print("=" * 60)
        print("""
Next steps:
1. Explore the API documentation
2. Integrate with GTL Scanner
3. Train custom models on your data
4. Build custom analyzers for your needs

Your AI security engine is ready to use! 🔥
        """)

    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        print("\nTroubleshooting:")
        print("1. Make sure Ollama is running: ollama serve")
        print("2. Verify models are installed: ollama list")
        print("3. Check logs: tail -f logs/gtl_ai_engine.log")
        print("4. Review INSTALLATION.md")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("Select example to run:")
    print("=" * 60)
    print("1. Simple vulnerability analysis")
    print("2. Advanced analysis with PoC generation")
    print("3. Code security analysis")
    print("4. Red team AI assistant")
    print("5. Malware analysis (simulation)")
    print("6. Batch vulnerability analysis")
    print("7. Run ALL examples (recommended for first time)")
    print("=" * 60)

    choice = input("\nEnter choice (1-7): ").strip()

    examples = {
        '1': example_1_simple_analysis,
        '2': example_2_advanced_analysis,
        '3': example_3_code_analysis,
        '4': example_4_red_team_assistant,
        '5': example_5_malware_analysis,
        '6': example_6_batch_analysis,
        '7': run_all_examples
    }

    if choice in examples:
        asyncio.run(examples[choice]())
    else:
        print("Invalid choice. Running all examples...")
        asyncio.run(run_all_examples())
