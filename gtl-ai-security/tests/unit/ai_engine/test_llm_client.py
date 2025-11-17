"""
Tests for LLM Client
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import asyncio


class TestLLMClientInitialization:
    """Tests for LLM client initialization"""

    @patch('requests.get')
    def test_llm_client_initialization(self, mock_get):
        """Test LLM client initializes correctly"""
        from gtl_ai_engine.core.llm_client import LLMClient, LLMConfig

        # Mock Ollama server response
        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: {
                "models": [
                    {"name": "llama3.1:70b"},
                    {"name": "codellama:34b"}
                ]
            }
        )

        config = LLMConfig(model="llama3.1:70b")
        client = LLMClient(config)

        assert client is not None
        assert client.config.model == "llama3.1:70b"

    @patch('requests.get')
    def test_llm_client_validation_failure(self, mock_get):
        """Test LLM client validation failure"""
        from gtl_ai_engine.core.llm_client import LLMClient, LLMConfig

        # Mock Ollama server not responding
        mock_get.side_effect = requests.exceptions.ConnectionError()

        config = LLMConfig(model="llama3.1:70b")

        with pytest.raises(ConnectionError, match="Cannot connect"):
            LLMClient(config)

    @patch('requests.get')
    def test_llm_client_model_not_found(self, mock_get):
        """Test LLM client with model not found"""
        from gtl_ai_engine.core.llm_client import LLMClient, LLMConfig

        # Mock Ollama with different models
        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: {
                "models": [
                    {"name": "llama2:7b"}
                ]
            }
        )

        config = LLMConfig(model="llama3.1:70b")

        with pytest.raises(ValueError, match="Model .* not found"):
            LLMClient(config)


class TestLLMGeneration:
    """Tests for LLM text generation"""

    @pytest.mark.asyncio
    @patch('requests.get')
    @patch('requests.post')
    async def test_generate_success(self, mock_post, mock_get):
        """Test successful text generation"""
        from gtl_ai_engine.core.llm_client import LLMClient, LLMConfig

        # Mock validation
        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: {"models": [{"name": "llama3.1:70b"}]}
        )

        # Mock generation
        mock_post.return_value = Mock(
            status_code=200,
            json=lambda: {
                "response": "This is a test response from LLM",
                "done": True
            }
        )

        config = LLMConfig(model="llama3.1:70b")
        client = LLMClient(config)

        response = await client.generate("Test prompt")

        assert response == "This is a test response from LLM"
        mock_post.assert_called_once()

    @pytest.mark.asyncio
    @patch('requests.get')
    @patch('requests.post')
    async def test_generate_with_system_prompt(self, mock_post, mock_get):
        """Test generation with system prompt"""
        from gtl_ai_engine.core.llm_client import LLMClient, LLMConfig

        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: {"models": [{"name": "llama3.1:70b"}]}
        )

        mock_post.return_value = Mock(
            status_code=200,
            json=lambda: {"response": "Response", "done": True}
        )

        config = LLMConfig(model="llama3.1:70b")
        client = LLMClient(config)

        await client.generate(
            prompt="User prompt",
            system_prompt="You are a security expert"
        )

        # Check that system prompt was included
        call_args = mock_post.call_args
        assert call_args[1]['json']['system'] == "You are a security expert"

    @pytest.mark.asyncio
    @patch('requests.get')
    @patch('requests.post')
    async def test_generate_timeout(self, mock_post, mock_get):
        """Test generation timeout handling"""
        import requests
        from gtl_ai_engine.core.llm_client import LLMClient, LLMConfig

        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: {"models": [{"name": "llama3.1:70b"}]}
        )

        # Mock timeout
        mock_post.side_effect = requests.exceptions.Timeout()

        config = LLMConfig(model="llama3.1:70b")
        client = LLMClient(config)

        with pytest.raises(TimeoutError, match="timed out"):
            await client.generate("Test prompt")


class TestVulnerabilityAnalysis:
    """Tests for vulnerability analysis"""

    @pytest.mark.asyncio
    @patch('requests.get')
    @patch('requests.post')
    async def test_analyze_vulnerability(self, mock_post, mock_get, sample_vulnerability, mock_llm_response):
        """Test vulnerability analysis"""
        from gtl_ai_engine.core.llm_client import LLMClient, LLMConfig

        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: {"models": [{"name": "llama3.1:70b"}]}
        )

        mock_post.return_value = Mock(
            status_code=200,
            json=lambda: {"response": mock_llm_response, "done": True}
        )

        config = LLMConfig(model="llama3.1:70b")
        client = LLMClient(config)

        result = await client.analyze_vulnerability(sample_vulnerability)

        assert "analysis" in result
        assert result["vulnerability_id"] == sample_vulnerability["id"]
        assert "analyzed_at" in result
        assert result["model"] == "llama3.1:70b"

    @pytest.mark.asyncio
    @patch('requests.get')
    @patch('requests.post')
    async def test_analyze_vulnerability_with_context(self, mock_post, mock_get, sample_vulnerability):
        """Test vulnerability analysis with context"""
        from gtl_ai_engine.core.llm_client import LLMClient, LLMConfig

        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: {"models": [{"name": "llama3.1:70b"}]}
        )

        mock_post.return_value = Mock(
            status_code=200,
            json=lambda: {"response": "Analysis with context", "done": True}
        )

        config = LLMConfig(model="llama3.1:70b")
        client = LLMClient(config)

        context = {
            "tech_stack": ["Python", "Django"],
            "environment": "production",
            "critical_asset": True
        }

        result = await client.analyze_vulnerability(sample_vulnerability, context)

        # Check that context was included in prompt
        call_args = mock_post.call_args
        prompt = call_args[1]['json']['prompt']
        assert "CONTEXT" in prompt or "context" in prompt.lower()


class TestCodeAnalysis:
    """Tests for code security analysis"""

    @pytest.mark.asyncio
    @patch('requests.get')
    @patch('requests.post')
    async def test_analyze_code_security(self, mock_post, mock_get):
        """Test code security analysis"""
        from gtl_ai_engine.core.llm_client import LLMClient, LLMConfig

        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: {"models": [{"name": "llama3.1:70b"}]}
        )

        mock_post.return_value = Mock(
            status_code=200,
            json=lambda: {
                "response": "## Security Findings\n### SQL Injection Risk",
                "done": True
            }
        )

        config = LLMConfig(model="llama3.1:70b")
        client = LLMClient(config)

        code = """
        def login(username, password):
            query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
            return db.execute(query)
        """

        result = await client.analyze_code_security(code, "python")

        assert "analysis" in result
        assert result["language"] == "python"
        assert "code_hash" in result


class TestRedTeamAssistant:
    """Tests for red team assistant"""

    @pytest.mark.asyncio
    @patch('requests.get')
    @patch('requests.post')
    async def test_red_team_assistant(self, mock_post, mock_get):
        """Test red team assistant"""
        from gtl_ai_engine.core.llm_client import LLMClient, LLMConfig

        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: {"models": [{"name": "llama3.1:70b"}]}
        )

        mock_post.return_value = Mock(
            status_code=200,
            json=lambda: {
                "response": "## Reconnaissance\nPerform network scanning",
                "done": True
            }
        )

        config = LLMConfig(model="llama3.1:70b")
        client = LLMClient(config)

        target_info = {
            "domain": "example.com",
            "ip_ranges": ["192.168.1.0/24"],
            "technologies": ["Apache", "PHP"]
        }

        result = await client.red_team_assistant(
            objective="gain initial access",
            target_info=target_info
        )

        assert "plan" in result
        assert result["objective"] == "gain initial access"


class TestChatInterface:
    """Tests for chat interface"""

    @pytest.mark.asyncio
    @patch('requests.get')
    @patch('requests.post')
    async def test_chat(self, mock_post, mock_get):
        """Test chat interface"""
        from gtl_ai_engine.core.llm_client import LLMClient, LLMConfig

        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: {"models": [{"name": "llama3.1:70b"}]}
        )

        mock_post.return_value = Mock(
            status_code=200,
            json=lambda: {"response": "Assistant response", "done": True}
        )

        config = LLMConfig(model="llama3.1:70b")
        client = LLMClient(config)

        messages = [
            {"role": "user", "content": "What is SQL injection?"},
            {"role": "assistant", "content": "SQL injection is..."},
            {"role": "user", "content": "How to prevent it?"}
        ]

        response = await client.chat(messages)

        assert response == "Assistant response"


class TestHelperFunctions:
    """Tests for helper functions"""

    @patch('requests.get')
    def test_hash_code(self, mock_get):
        """Test code hashing"""
        from gtl_ai_engine.core.llm_client import LLMClient, LLMConfig

        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: {"models": [{"name": "llama3.1:70b"}]}
        )

        config = LLMConfig(model="llama3.1:70b")
        client = LLMClient(config)

        code1 = "print('hello')"
        code2 = "print('hello')"
        code3 = "print('world')"

        hash1 = client._hash_code(code1)
        hash2 = client._hash_code(code2)
        hash3 = client._hash_code(code3)

        # Same code should produce same hash
        assert hash1 == hash2

        # Different code should produce different hash
        assert hash1 != hash3

        # Hash should be truncated to 16 characters
        assert len(hash1) == 16

    @patch('requests.get')
    def test_get_timestamp(self, mock_get):
        """Test timestamp generation"""
        from gtl_ai_engine.core.llm_client import LLMClient, LLMConfig

        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: {"models": [{"name": "llama3.1:70b"}]}
        )

        config = LLMConfig(model="llama3.1:70b")
        client = LLMClient(config)

        timestamp = client._get_timestamp()

        # Should be ISO format with Z suffix
        assert timestamp.endswith('Z')
        assert 'T' in timestamp  # ISO 8601 format
