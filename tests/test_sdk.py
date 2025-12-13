import pytest
from unittest.mock import MagicMock, patch
from qwed.client import QwedClient
from qwed.models import VerificationResponse

def test_client_init():
    client = QwedClient(api_key="test_key")
    assert client.api_key == "test_key"
    assert client.base_url == "https://api.qwed.tech/v1"

@patch("requests.Session.post")
def test_verify_natural_language(mock_post):
    # Mock response
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "status": "VERIFIED",
        "final_answer": 42.0,
        "user_query": "What is 21 + 21?",
        "translation": {"confidence": 1.0},
        "verification": {"is_correct": True}
    }
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    # Test
    client = QwedClient(api_key="test_key")
    result = client.verify_natural_language("What is 21 + 21?")

    # Verify
    assert isinstance(result, VerificationResponse)
    assert result.status == "VERIFIED"
    assert result.final_answer == 42.0
    
    # Check call
    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert kwargs["json"] == {"query": "What is 21 + 21?"}
