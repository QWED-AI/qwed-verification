import json
import pytest
from unittest.mock import patch, MagicMock

# Import the provider. We'll mock google.generativeai entirely.
from qwed_new.providers.gemini_provider import GeminiProvider


class MockGenaiTypes:
    class GenerationConfig:
        def __init__(self, **kwargs):
            self.kwargs = kwargs


class MockGenai:
    def __init__(self):
        self.types = MockGenaiTypes()
        self.configure = MagicMock()
        self.GenerativeModel = MagicMock()


@pytest.fixture
def mock_genai_module(monkeypatch):
    mock = MockGenai()
    monkeypatch.setattr("qwed_new.providers.gemini_provider.genai", mock)
    return mock


@pytest.fixture
def mock_gemini_model():
    return MagicMock()


@pytest.fixture
def provider(mock_genai_module, mock_gemini_model, monkeypatch):
    mock_genai_module.GenerativeModel.return_value = mock_gemini_model
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key-123")
    return GeminiProvider()


def test_init_missing_key(mock_genai_module, monkeypatch):
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(ValueError, match="Gemini API key not found"):
        GeminiProvider()


def test_init_without_genai(monkeypatch):
    monkeypatch.setattr("qwed_new.providers.gemini_provider.genai", None)
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key-123")
    provider = GeminiProvider()
    assert provider.model is None


def test_call_text_success_with_python_fence(provider, mock_gemini_model):
    mock_response = MagicMock()
    mock_response.text = "```python\ndef test(): pass\n```"
    mock_gemini_model.generate_content.return_value = mock_response
    
    result = provider._call_text("system", "user")
    assert result == "def test(): pass"
    mock_gemini_model.generate_content.assert_called_once()


def test_call_text_success_with_generic_fence(provider, mock_gemini_model):
    mock_response = MagicMock()
    mock_response.text = "```\nsome_code()\n```"
    mock_gemini_model.generate_content.return_value = mock_response
    
    result = provider._call_text("system", "user")
    assert result == "some_code()"


def test_call_text_without_fence(provider, mock_gemini_model):
    mock_response = MagicMock()
    mock_response.text = "just regular text"
    mock_gemini_model.generate_content.return_value = mock_response
    
    result = provider._call_text("system", "user")
    assert result == "just regular text"


def test_call_text_import_error(monkeypatch):
    monkeypatch.setattr("qwed_new.providers.gemini_provider.genai", None)
    provider = GeminiProvider()
    with pytest.raises(ImportError, match="google-generativeai package required"):
        provider._call_text("sys", "user")


def test_call_json_success(provider, mock_gemini_model):
    mock_response = MagicMock()
    mock_response.text = '```json\n{"status": "ok"}\n```'
    mock_gemini_model.generate_content.return_value = mock_response
    
    result = provider._call_json("system", "user")
    assert result == {"status": "ok"}


def test_call_json_parse_error(provider, mock_gemini_model):
    mock_response = MagicMock()
    mock_response.text = "{invalid_json}"
    mock_gemini_model.generate_content.return_value = mock_response
    
    with pytest.raises(ValueError, match="Failed to parse JSON"):
        provider._call_json("sys", "user")


def test_call_json_generic_error(provider, mock_gemini_model):
    mock_gemini_model.generate_content.side_effect = RuntimeError("API down")
    with pytest.raises(ValueError, match="Gemini call failed"):
        provider._call_json("sys", "user")


def test_translate_success(provider, mock_gemini_model):
    mock_response = MagicMock()
    mock_response.text = '{"expression": "2+2", "claimed_answer": 4.0, "reasoning": "add", "confidence": 1.0}'
    mock_gemini_model.generate_content.return_value = mock_response
    
    task = provider.translate("2+2=4")
    assert task.expression == "2+2"


def test_translate_error(provider, mock_gemini_model):
    mock_gemini_model.generate_content.return_value.text = "invalid"
    with pytest.raises(ValueError, match="Gemini math translation failed"):
        provider.translate("bad")


def test_translate_logic_success(provider, mock_gemini_model):
    mock_response = MagicMock()
    mock_response.text = '{"variables": {}, "constraints": [], "goal": "SATISFIABILITY"}'
    mock_gemini_model.generate_content.return_value = mock_response
    
    task = provider.translate_logic("x > 0")
    assert task.goal == "SATISFIABILITY"


def test_translate_logic_error(provider, mock_gemini_model):
    mock_gemini_model.generate_content.return_value.text = "invalid"
    with pytest.raises(ValueError, match="Gemini logic translation failed."):
        provider.translate_logic("bad")


def test_refine_logic_success(provider, mock_gemini_model):
    mock_response = MagicMock()
    mock_response.text = '{"variables": {}, "constraints": [], "goal": "SATISFIABILITY"}'
    mock_gemini_model.generate_content.return_value = mock_response
    
    task = provider.refine_logic("x > 0", "error")
    assert task.goal == "SATISFIABILITY"


def test_refine_logic_error(provider, mock_gemini_model):
    mock_gemini_model.generate_content.return_value.text = "invalid"
    with pytest.raises(ValueError, match="Gemini logic refinement failed."):
        provider.refine_logic("bad", "err")


def test_translate_stats_success(provider, mock_gemini_model):
    mock_response = MagicMock()
    mock_response.text = "```python\nimport pandas\n```"
    mock_gemini_model.generate_content.return_value = mock_response
    
    res = provider.translate_stats("mean", ["col"])
    assert res == "import pandas"


def test_translate_stats_error(provider, mock_gemini_model):
    mock_gemini_model.generate_content.side_effect = RuntimeError("fail")
    with pytest.raises(ValueError, match="Gemini stats translation failed."):
        provider.translate_stats("bad", [])


def test_verify_fact_success(provider, mock_gemini_model):
    mock_response = MagicMock()
    mock_response.text = '{"verdict": "SUPPORTED", "reasoning": "R", "citations": []}'
    mock_gemini_model.generate_content.return_value = mock_response
    
    res = provider.verify_fact("Sky is blue", "Context")
    assert res["verdict"] == "SUPPORTED"


def test_verify_fact_error(provider, mock_gemini_model):
    mock_gemini_model.generate_content.side_effect = RuntimeError("fail")
    with pytest.raises(ValueError, match="Gemini fact verification failed."):
        provider.verify_fact("C", "C")


def test_verify_image_success(provider, mock_gemini_model):
    mock_response = MagicMock()
    mock_response.text = '```json\n{"verified": true, "reasoning": "ok", "confidence": 0.99}\n```'
    mock_gemini_model.generate_content.return_value = mock_response
    
    res = provider.verify_image(b"fake_image", "claim")
    assert res["verified"] is True
    
def test_verify_image_no_fence(provider, mock_gemini_model):
    mock_response = MagicMock()
    mock_response.text = '{"verified": true, "reasoning": "ok", "confidence": 0.99}'
    mock_gemini_model.generate_content.return_value = mock_response
    
    res = provider.verify_image(b"fake_image", "claim")
    assert res["verified"] is True

def test_verify_image_generic_fence(provider, mock_gemini_model):
    mock_response = MagicMock()
    mock_response.text = '```\n{"verified": true, "reasoning": "ok", "confidence": 0.99}\n```'
    mock_gemini_model.generate_content.return_value = mock_response
    
    res = provider.verify_image(b"fake_image", "claim")
    assert res["verified"] is True


def test_verify_image_error(provider, mock_gemini_model):
    mock_gemini_model.generate_content.side_effect = RuntimeError("fail")
    with pytest.raises(ValueError, match="Gemini image verification failed."):
        provider.verify_image(b"f", "c")


def test_verify_image_import_error(monkeypatch):
    monkeypatch.setattr("qwed_new.providers.gemini_provider.genai", None)
    provider = GeminiProvider()
    with pytest.raises(ImportError, match="google-generativeai package required"):
        provider.verify_image(b"f", "c")
