"""
Local LLM Client for Security Analysis
Supports Ollama, LM Studio, and custom endpoints
"""

import os
import json
import asyncio
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import requests
from enum import Enum


class LLMProvider(Enum):
    """Supported LLM providers"""
    OLLAMA = "ollama"
    LM_STUDIO = "lm_studio"
    VLLM = "vllm"
    TEXT_GENERATION_WEBUI = "text_generation_webui"


@dataclass
class LLMConfig:
    """Configuration for LLM client"""
    provider: LLMProvider = LLMProvider.OLLAMA
    model: str = "llama3.1:70b"
    base_url: str = "http://localhost:11434"
    temperature: float = 0.7
    max_tokens: int = 4096
    top_p: float = 0.9
    top_k: int = 40
    repeat_penalty: float = 1.1
    context_length: int = 32768
    gpu_layers: int = -1  # -1 = all layers on GPU
    num_threads: Optional[int] = None


class LLMClient:
    """
    Client for interacting with local LLM models
    Optimized for RTX 5090 (24GB VRAM)
    """

    def __init__(self, config: Optional[LLMConfig] = None):
        self.config = config or LLMConfig()
        self._validate_setup()

    def _validate_setup(self):
        """Validate LLM setup and connectivity"""
        try:
            if self.config.provider == LLMProvider.OLLAMA:
                response = requests.get(f"{self.config.base_url}/api/tags", timeout=5)
                if response.status_code != 200:
                    raise ConnectionError("Ollama server not responding")

                models = response.json().get('models', [])
                available_models = [m['name'] for m in models]

                if self.config.model not in available_models:
                    raise ValueError(
                        f"Model {self.config.model} not found. "
                        f"Available: {', '.join(available_models)}\n"
                        f"Run: ollama pull {self.config.model}"
                    )
        except requests.exceptions.RequestException as e:
            raise ConnectionError(
                f"Cannot connect to LLM server at {self.config.base_url}. "
                f"Make sure Ollama is running: ollama serve"
            ) from e

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        stream: bool = False
    ) -> str:
        """
        Generate text from LLM

        Args:
            prompt: User prompt
            system_prompt: System instructions
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            stream: Stream response

        Returns:
            Generated text
        """
        if self.config.provider == LLMProvider.OLLAMA:
            return await self._generate_ollama(
                prompt, system_prompt, temperature, max_tokens, stream
            )
        else:
            raise NotImplementedError(f"Provider {self.config.provider} not implemented")

    async def _generate_ollama(
        self,
        prompt: str,
        system_prompt: Optional[str],
        temperature: Optional[float],
        max_tokens: Optional[int],
        stream: bool
    ) -> str:
        """Generate using Ollama"""
        url = f"{self.config.base_url}/api/generate"

        payload = {
            "model": self.config.model,
            "prompt": prompt,
            "system": system_prompt or "",
            "stream": stream,
            "options": {
                "temperature": temperature or self.config.temperature,
                "num_predict": max_tokens or self.config.max_tokens,
                "top_p": self.config.top_p,
                "top_k": self.config.top_k,
                "repeat_penalty": self.config.repeat_penalty,
                "num_gpu": self.config.gpu_layers,
                "num_thread": self.config.num_threads or os.cpu_count(),
            }
        }

        try:
            response = requests.post(url, json=payload, timeout=300)
            response.raise_for_status()

            if stream:
                return self._handle_stream(response)
            else:
                result = response.json()
                return result.get('response', '')

        except requests.exceptions.Timeout:
            raise TimeoutError("LLM request timed out after 5 minutes")
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"LLM request failed: {e}")

    def _handle_stream(self, response) -> str:
        """Handle streaming response"""
        full_response = ""
        for line in response.iter_lines():
            if line:
                try:
                    data = json.loads(line)
                    if 'response' in data:
                        chunk = data['response']
                        full_response += chunk
                        print(chunk, end='', flush=True)
                    if data.get('done', False):
                        break
                except json.JSONDecodeError:
                    continue
        print()  # New line after streaming
        return full_response

    async def analyze_vulnerability(
        self,
        vulnerability: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Analyze a vulnerability using LLM

        Args:
            vulnerability: Vulnerability details
            context: Additional context (tech stack, environment, etc.)

        Returns:
            Detailed analysis with recommendations
        """
        system_prompt = """You are an expert cybersecurity analyst with 15+ years of experience.
Your role is to analyze vulnerabilities and provide actionable, detailed recommendations.

For each vulnerability, provide:
1. Risk assessment (0-10 score with justification)
2. Exploit complexity (Low/Medium/High/Critical)
3. Realistic attack scenarios
4. Business impact analysis
5. Step-by-step remediation plan
6. Code examples where applicable
7. Related CVEs or known exploits

Be technical but clear. Assume the reader is a security professional."""

        prompt = f"""Analyze this vulnerability:

VULNERABILITY DETAILS:
Title: {vulnerability.get('title', 'Unknown')}
Description: {vulnerability.get('description', 'No description')}
Severity: {vulnerability.get('severity', 'Unknown')}
Affected URL: {vulnerability.get('affected_url', 'Unknown')}
Category: {vulnerability.get('category', 'Unknown')}

"""

        if context:
            prompt += f"""CONTEXT:
{json.dumps(context, indent=2)}

"""

        prompt += """Provide a comprehensive analysis in the following format:

## Risk Assessment
[Provide risk score and detailed justification]

## Exploit Complexity
[Assess difficulty to exploit]

## Attack Scenarios
[Describe 2-3 realistic attack scenarios]

## Business Impact
[Explain impact on business operations, data, reputation]

## Remediation Plan
[Step-by-step fix with code examples]

## Prevention
[How to prevent similar issues]

## References
[Related CVEs, exploits, documentation]
"""

        response = await self.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=0.3,  # Low temperature for factual analysis
            max_tokens=2048
        )

        return {
            'vulnerability_id': vulnerability.get('id'),
            'analysis': response,
            'analyzed_at': self._get_timestamp(),
            'model': self.config.model
        }

    async def generate_exploit_poc(
        self,
        vulnerability: Dict[str, Any]
    ) -> str:
        """
        Generate a Proof of Concept exploit

        Args:
            vulnerability: Vulnerability details

        Returns:
            Exploit PoC code
        """
        system_prompt = """You are a penetration testing expert specializing in exploit development.
Generate clean, well-documented proof-of-concept exploits.

IMPORTANT:
- Code should be for testing/educational purposes only
- Include clear warnings about authorized use
- Add comments explaining each step
- Make code production-ready with error handling"""

        prompt = f"""Generate a Proof of Concept exploit for this vulnerability:

Vulnerability: {vulnerability.get('title')}
Type: {vulnerability.get('category')}
Description: {vulnerability.get('description')}
Target: {vulnerability.get('affected_url')}

Requirements:
1. Clean, readable Python code
2. Error handling
3. Comments explaining the exploit
4. Usage instructions
5. Warning about authorized use only

Generate the exploit code:"""

        response = await self.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=0.5,
            max_tokens=2048
        )

        return response

    async def analyze_code_security(
        self,
        code: str,
        language: str,
        context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze code for security vulnerabilities

        Args:
            code: Source code to analyze
            language: Programming language
            context: Additional context

        Returns:
            Security analysis with findings
        """
        system_prompt = """You are a code security expert with deep knowledge of:
- OWASP Top 10
- CWE (Common Weakness Enumeration)
- Secure coding practices
- Language-specific vulnerabilities

Analyze code for security issues including but not limited to:
- Injection flaws (SQL, Command, XSS, etc.)
- Authentication/Authorization issues
- Sensitive data exposure
- Security misconfiguration
- Insecure dependencies
- Logic flaws
- Race conditions
- Memory issues (for C/C++/Rust)

Be thorough but practical. Focus on exploitable issues."""

        prompt = f"""Analyze this {language} code for security vulnerabilities:

```{language}
{code}
```

"""

        if context:
            prompt += f"""Additional Context:
{context}

"""

        prompt += """Provide analysis in this format:

## Security Findings

### [Severity] [Vulnerability Type]
**Location**: [Line numbers or function name]
**Description**: [What's the issue]
**Exploit Scenario**: [How an attacker could exploit this]
**Risk**: [Impact and likelihood]
**Fix**: [How to fix with code example]

## Secure Code Recommendations
[General security improvements]

## OWASP/CWE Mapping
[Map findings to OWASP Top 10 and CWE]
"""

        response = await self.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=0.2,  # Very low for code analysis
            max_tokens=3072
        )

        return {
            'code_hash': self._hash_code(code),
            'language': language,
            'analysis': response,
            'analyzed_at': self._get_timestamp(),
            'model': self.config.model
        }

    async def red_team_assistant(
        self,
        objective: str,
        target_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        AI-powered red team assistant

        Args:
            objective: What to achieve (e.g., "gain initial access")
            target_info: Information about the target

        Returns:
            Attack suggestions and strategies
        """
        system_prompt = """You are an elite penetration tester and red team operator.
Provide tactical, actionable attack strategies based on real-world techniques.

Reference MITRE ATT&CK framework where applicable.
Suggest tools, commands, and procedures.
Consider defensive measures and evasion.

IMPORTANT: Assume authorized testing engagement. Include warnings."""

        prompt = f"""Red Team Objective: {objective}

Target Information:
{json.dumps(target_info, indent=2)}

Provide a tactical plan including:

## Reconnaissance
[Information gathering steps]

## Initial Access
[Techniques to gain foothold]

## Execution
[Commands and payloads to run]

## Persistence
[How to maintain access]

## Privilege Escalation
[Escalation techniques]

## Defense Evasion
[How to avoid detection]

## Lateral Movement
[Moving through the network]

## Collection
[Data gathering techniques]

## Exfiltration
[Data exfiltration methods]

## Tools & Commands
[Specific tools and command examples]

## MITRE ATT&CK Mapping
[Map to ATT&CK tactics and techniques]

## Detection Risk
[Likelihood of detection and countermeasures]
"""

        response = await self.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=0.6,
            max_tokens=4096
        )

        return {
            'objective': objective,
            'plan': response,
            'generated_at': self._get_timestamp(),
            'model': self.config.model
        }

    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.utcnow().isoformat() + 'Z'

    def _hash_code(self, code: str) -> str:
        """Hash code for caching"""
        import hashlib
        return hashlib.sha256(code.encode()).hexdigest()[:16]

    async def chat(
        self,
        messages: List[Dict[str, str]],
        system_prompt: Optional[str] = None
    ) -> str:
        """
        Chat interface for conversational security analysis

        Args:
            messages: List of {"role": "user"/"assistant", "content": "..."}
            system_prompt: System instructions

        Returns:
            Assistant response
        """
        # Convert messages to single prompt
        conversation = ""
        for msg in messages:
            role = msg['role']
            content = msg['content']
            if role == 'user':
                conversation += f"User: {content}\n\n"
            elif role == 'assistant':
                conversation += f"Assistant: {content}\n\n"

        conversation += "Assistant: "

        return await self.generate(
            prompt=conversation,
            system_prompt=system_prompt or "You are a helpful cybersecurity expert.",
            temperature=0.7
        )


# Convenience function for quick analysis
async def quick_vulnerability_analysis(
    title: str,
    description: str,
    severity: str = "Unknown",
    model: str = "llama3.1:70b"
) -> str:
    """Quick vulnerability analysis"""
    client = LLMClient(LLMConfig(model=model))
    result = await client.analyze_vulnerability({
        'title': title,
        'description': description,
        'severity': severity
    })
    return result['analysis']


# Example usage
if __name__ == "__main__":
    import asyncio

    async def main():
        # Initialize client
        client = LLMClient(LLMConfig(
            model="llama3.1:70b",
            base_url="http://localhost:11434"
        ))

        # Test vulnerability analysis
        vuln = {
            'title': 'SQL Injection in login form',
            'description': 'User input is directly concatenated into SQL query without sanitization',
            'severity': 'Critical',
            'affected_url': 'https://example.com/login',
            'category': 'Injection'
        }

        print("Analyzing vulnerability...")
        result = await client.analyze_vulnerability(vuln)
        print(result['analysis'])

    asyncio.run(main())
