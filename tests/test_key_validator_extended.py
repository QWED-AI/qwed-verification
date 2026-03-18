from unittest.mock import patch, MagicMock
import httpx

from qwed_new.providers.key_validator import (
    _test_ollama,
    _test_openai,
    _test_anthropic,
    _test_openai_compat
)

# Replace timeout and error constants if exported from the file directly
# Or just assert directly in strings

class TestOllamaReal:
    @patch("httpx.get")
    def test_ollama_success_models(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"models": [{"name": "llama3"}, {"name": "mixtral"}]}
        mock_get.return_value = mock_resp
        
        success, msg = _test_ollama("http://localhost:11434/v1", 5.0)
        assert success
        assert "llama3, mixtral" in msg
        mock_get.assert_called_once_with("http://localhost:11434/api/tags", timeout=5.0)

    @patch("httpx.get")
    def test_ollama_success_no_models(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"models": []}
        mock_get.return_value = mock_resp
        
        success, msg = _test_ollama(None, 5.0)
        assert success
        assert "no models pulled yet" in msg

    @patch("httpx.get")
    def test_ollama_connect_error(self, mock_get):
        mock_get.side_effect = httpx.ConnectError("boom")
        success, msg = _test_ollama("http://localhost:11434/v1/", 5.0)
        assert not success
        assert "Cannot connect" in msg

    @patch("httpx.get")
    def test_ollama_timeout(self, mock_get):
        mock_get.side_effect = httpx.TimeoutException("boom")
        success, msg = _test_ollama("http://localhost:11434", 5.0)
        assert not success
        assert "timed out" in msg

    @patch("httpx.get")
    def test_ollama_bad_status(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_get.return_value = mock_resp
        success, msg = _test_ollama(None, 5.0)
        assert not success
        assert "status 500" in msg


class TestOpenAIReal:
    @patch("httpx.get")
    def test_openai_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp
        
        success, msg = _test_openai("sk-test", 5.0)
        assert success
        assert "Connected" in msg
        mock_get.assert_called_once_with(
            "https://api.openai.com/v1/models",
            headers={"Authorization": "Bearer sk-test"},
            timeout=5.0
        )

    @patch("httpx.get")
    def test_openai_auth_fail(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_get.return_value = mock_resp
        success, msg = _test_openai("sk-test", 5.0)
        assert not success
        assert "Authentication failed" in msg

    @patch("httpx.get")
    def test_openai_bad_status(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_get.return_value = mock_resp
        success, msg = _test_openai("sk-test", 5.0)
        assert not success
        assert "status 503" in msg

    @patch("httpx.get")
    def test_openai_network_errors(self, mock_get):
        mock_get.side_effect = httpx.ConnectError("boom")
        success, msg = _test_openai("sk-test", 5.0)
        assert not success
        assert "Cannot connect" in msg
        
        mock_get.side_effect = httpx.TimeoutException("boom")
        success, msg = _test_openai("sk-test", 5.0)
        assert not success
        assert "timed out" in msg


class TestAnthropicReal:
    @patch("httpx.get")
    def test_anthropic_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp
        
        success, msg = _test_anthropic("sk-ant-test", 5.0)
        assert success
        assert "Connected" in msg
        mock_get.assert_called_once_with(
            "https://api.anthropic.com/v1/models",
            headers={"x-api-key": "sk-ant-test", "anthropic-version": "2023-06-01"},
            timeout=5.0
        )

    @patch("httpx.get")
    def test_anthropic_errors(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_get.return_value = mock_resp
        success, msg = _test_anthropic("sk-ant-test", 5.0)
        assert not success
        assert "Authentication failed" in msg
        
        mock_resp.status_code = 500
        mock_get.return_value = mock_resp
        success, msg = _test_anthropic("sk-ant-test", 5.0)
        assert not success
        assert "status 500" in msg


class TestOpenAICompatReal:
    @patch("httpx.get")
    def test_compat_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp
        
        success, msg = _test_openai_compat("sk-test", "http://my.api/v1/", 5.0)
        assert success
        assert "Connected" in msg
        mock_get.assert_called_once_with(
            "http://my.api/v1/models",
            headers={"Authorization": "Bearer sk-test"},
            timeout=5.0
        )

    @patch("httpx.get")
    def test_compat_errors(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_get.return_value = mock_resp
        success, msg = _test_openai_compat("sk", "http://url", 5.0)
        assert not success
        assert "Authentication failed" in msg
        
        mock_resp.status_code = 500
        success, msg = _test_openai_compat("sk", "http://url", 5.0)
        assert not success
        assert "status 500" in msg
        
        mock_get.side_effect = httpx.ConnectError("")
        success, _ = _test_openai_compat("sk", "http://url", 5.0)
        assert not success
        
        mock_get.side_effect = httpx.TimeoutException("")
        success, _ = _test_openai_compat("sk", "http://url", 5.0)
        assert not success
