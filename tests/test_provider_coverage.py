import pytest
import json
from unittest.mock import patch, MagicMock

from qwed_new.providers.openai_direct import OpenAIDirectProvider
from qwed_new.providers.openai_compat import OpenAICompatProvider
from qwed_new.providers.ollama_provider import OllamaProvider
from qwed_new.core.schemas import MathVerificationTask, LogicVerificationTask

def _create_mock_response(content: str):
    """Creates a mock completion text response."""
    mock_msg = MagicMock()
    mock_msg.content = content
    mock_choice = MagicMock()
    mock_choice.message = mock_msg
    mock_resp = MagicMock()
    mock_resp.choices = [mock_choice]
    return mock_resp

def _create_mock_tool_response(arguments: str):
    """Creates a mock completion tool call response."""
    mock_function = MagicMock()
    mock_function.arguments = arguments
    mock_tool_call = MagicMock()
    mock_tool_call.function = mock_function
    mock_msg = MagicMock()
    mock_msg.tool_calls = [mock_tool_call]
    mock_choice = MagicMock()
    mock_choice.message = mock_msg
    mock_resp = MagicMock()
    mock_resp.choices = [mock_choice]
    return mock_resp

class TestOpenAIDirectHappyPaths:
    @patch("qwed_new.providers.openai_direct.OpenAI")
    def test_translate_happy(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _create_mock_tool_response('{"expression": "2+2", "claimed_answer": "4", "reasoning": "Basic addition"}')
        provider = OpenAIDirectProvider(api_key="sk-test")
        result = provider.translate("my query")
        assert isinstance(result, MathVerificationTask)
        assert result.expression == "2+2"

    @patch("qwed_new.providers.openai_direct.OpenAI")
    def test_translate_empty_response(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _create_mock_response("")
        provider = OpenAIDirectProvider(api_key="sk-test")
        with pytest.raises(ValueError, match="OpenAI stats translation failed."):
            provider.translate_stats("my stats", ["col1"])

    @patch("qwed_new.providers.openai_direct.OpenAI")
    def test_translate_logic_happy(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _create_mock_tool_response('{"variables": {"x": "Int"}, "constraints": ["x > 0"]}')
        provider = OpenAIDirectProvider(api_key="sk-test")
        result = provider.translate_logic("my logic")
        assert isinstance(result, LogicVerificationTask)
        assert result.variables == {"x": "Int"}

    @patch("qwed_new.providers.openai_direct.OpenAI")
    def test_translate_stats_happy(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _create_mock_response("stats_translated")
        provider = OpenAIDirectProvider(api_key="sk-test")
        result = provider.translate_stats("my stats", ["col1"])
        assert result == "stats_translated"

    @patch("qwed_new.providers.openai_direct.OpenAI")
    def test_refine_logic_happy(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _create_mock_tool_response('{"variables": {"x": "Int"}, "constraints": ["x > 1"]}')
        provider = OpenAIDirectProvider(api_key="sk-test")
        result = provider.refine_logic("my logic", "error")
        assert isinstance(result, LogicVerificationTask)
        assert result.variables == {"x": "Int"}

    @patch("qwed_new.providers.openai_direct.OpenAI")
    def test_verify_fact_happy(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _create_mock_tool_response('{"verdict": "SUPPORTED", "reasoning": "it is true", "citations": []}')
        provider = OpenAIDirectProvider(api_key="sk-test")
        result = provider.verify_fact("fact", "context")
        assert result["verdict"] == "SUPPORTED"

    @patch("qwed_new.providers.openai_direct.OpenAI")
    def test_verify_image_happy(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _create_mock_response('{"verdict": "SUPPORTED", "reasoning": "it is nice", "confidence": 0.9}')
        provider = OpenAIDirectProvider(api_key="sk-test")
        jpeg_bytes = b"\xff\xd8\xff\xe0\x00\x10JFIF"
        result = provider.verify_image(jpeg_bytes, "prompt")
        assert result["verdict"] == "SUPPORTED"

class TestOpenAICompatHappyPaths:
    @patch("qwed_new.providers.openai_compat.OpenAI")
    def test_translate_happy(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _create_mock_response('```json\n{"expression": "2+2", "claimed_answer": "4", "reasoning": "Basic addition"}\n```')
        provider = OpenAICompatProvider(base_url="http://val", api_key="sk")
        result = provider.translate("query")
        assert isinstance(result, MathVerificationTask)

    @patch("qwed_new.providers.openai_compat.OpenAI")
    def test_translate_logic_happy(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _create_mock_response('```json\n{"variables": {"x": "Int"}, "constraints": ["x > 0"]}\n```')
        provider = OpenAICompatProvider(base_url="http://val", api_key="sk")
        result = provider.translate_logic("my logic")
        assert isinstance(result, LogicVerificationTask)

    @patch("qwed_new.providers.openai_compat.OpenAI")
    def test_refine_logic_happy(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _create_mock_response('```json\n{"variables": {"x": "Int"}, "constraints": ["x > 1"]}\n```')
        provider = OpenAICompatProvider(base_url="http://val", api_key="sk")
        result = provider.refine_logic("my logic", "error")
        assert isinstance(result, LogicVerificationTask)

    @patch("qwed_new.providers.openai_compat.OpenAI")
    def test_translate_stats_happy(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _create_mock_response("stats_translated")
        provider = OpenAICompatProvider(base_url="http://val", api_key="sk")
        result = provider.translate_stats("my stats", ["col1"])
        assert result == "stats_translated"

    @patch("qwed_new.providers.openai_compat.OpenAI")
    def test_verify_fact_happy(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _create_mock_response('```json\n{"verdict": "SUPPORTED", "reasoning": "true", "citations": []}\n```')
        provider = OpenAICompatProvider(base_url="http://val", api_key="sk")
        result = provider.verify_fact("fact", "context")
        assert result["verdict"] == "SUPPORTED"

    @patch("qwed_new.providers.openai_compat.OpenAI")
    def test_verify_image_fallback(self, mock_openai_cls):
        provider = OpenAICompatProvider(base_url="http://val", api_key="sk")
        result = provider.verify_image(b"abc", "prompt")
        assert result["verdict"] == "INCONCLUSIVE"

class TestOllamaHappyPaths:
    @patch("qwed_new.providers.ollama_provider.OpenAI")
    def test_translate_happy(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _create_mock_response('```json\n{"expression": "2+2", "claimed_answer": "4", "reasoning": "Basic addition"}\n```')
        provider = OllamaProvider()
        result = provider.translate("query")
        assert isinstance(result, MathVerificationTask)

    @patch("qwed_new.providers.ollama_provider.OpenAI")
    def test_translate_logic_happy(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _create_mock_response('```json\n{"variables": {"x": "Int"}, "constraints": ["x > 0"]}\n```')
        provider = OllamaProvider()
        result = provider.translate_logic("my logic")
        assert isinstance(result, LogicVerificationTask)

    @patch("qwed_new.providers.ollama_provider.OpenAI")
    def test_refine_logic_happy(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _create_mock_response('```json\n{"variables": {"x": "Int"}, "constraints": ["x > 1"]}\n```')
        provider = OllamaProvider()
        result = provider.refine_logic("my logic", "error")
        assert isinstance(result, LogicVerificationTask)

    @patch("qwed_new.providers.ollama_provider.OpenAI")
    def test_translate_stats_happy(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _create_mock_response("stats_translated")
        provider = OllamaProvider()
        result = provider.translate_stats("my stats", ["col1"])
        assert result == "stats_translated"

    @patch("qwed_new.providers.ollama_provider.OpenAI")
    def test_verify_fact_happy(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _create_mock_response('```json\n{"verdict": "SUPPORTED", "reasoning": "true", "citations": []}\n```')
        provider = OllamaProvider()
        result = provider.verify_fact("fact", "context")
        assert result["verdict"] == "SUPPORTED"

    @patch("qwed_new.providers.ollama_provider.OpenAI")
    def test_verify_image_fallback(self, mock_openai_cls):
        provider = OllamaProvider()
        result = provider.verify_image(b"abc", "prompt")
        assert result["verdict"] == "INCONCLUSIVE"
