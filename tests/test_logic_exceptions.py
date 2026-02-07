
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from qwed_new.api.main import app
from qwed_new.core.control_plane import ControlPlane

client = TestClient(app)

@pytest.mark.asyncio
async def test_verify_logic_exception_handling():
    """
    Test that verify_logic catches internal errors and returns a sanitized message.
    """
    # Mock the control plane to raise an exception, and bypass auth/rate limiting
    with patch("qwed_new.core.rate_limiter.check_rate_limit"), \
         patch("qwed_new.api.main.get_current_tenant") as mock_tenant, \
         patch("qwed_new.api.main.control_plane.process_logic_query", side_effect=Exception("SENSITIVE_LOGIC_ERROR")):
        
        mock_tenant.return_value = MagicMock(organization_id=1, api_key="test_key")  # noqa: S105 - Mock API key
        
        # Providing valid minimal input
        response = client.post(
            "/verify/logic",
            json={"query": "If A then B..."}
        )
        
        # Verify that the endpoint handled the internal error and returned a sanitized message
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ERROR"
        assert data["error"] == "Internal verification error"
        assert "SENSITIVE_LOGIC_ERROR" not in str(data)

def test_verify_logic_exception_integration():
    """
    Integration style test for verify_logic exception.
    """
    with patch("qwed_new.core.rate_limiter.check_rate_limit"), \
         patch("qwed_new.api.main.get_current_tenant") as mock_tenant, \
         patch("qwed_new.api.main.control_plane.process_logic_query", side_effect=Exception("SENSITIVE_FAILURE")):
        
        mock_tenant.return_value = MagicMock(organization_id=1, api_key="test_key")  # noqa: S105 - Mock API key
        
        response = client.post(
            "/verify/logic",
            json={"query": "test query"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ERROR"
        assert data["error"] == "Internal verification error"
        assert "SENSITIVE_FAILURE" not in str(data)

@pytest.mark.asyncio
async def test_control_plane_logic_exception():
    """
    Directly test ControlPlane.process_logic_query exception handling.
    """
    cp = ControlPlane()
    
    # Mock components to fail deep inside
    with patch.object(cp.security_gateway, 'detect_advanced_injection', return_value=(True, "")), \
         patch.object(cp.policy, 'check_policy', return_value=(True, "")), \
         patch.object(cp.router, 'route', return_value="openai"), \
         patch.object(cp.logic_verifier, 'verify_from_natural_language', side_effect=Exception("DEEP_INTERNAL_ERROR")):
             
        result = await cp.process_logic_query("test query", organization_id=123)
        
        assert result["status"] == "ERROR"
        assert result["error"] == "Internal pipeline error"
        assert "DEEP_INTERNAL_ERROR" not in result["error"]
