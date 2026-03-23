import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from qwed_new.api.main import app, get_current_tenant, get_session
from qwed_new.core.control_plane import ControlPlane

@pytest.fixture
def client():
    mock_tenant = MagicMock(organization_id=1, api_key="test_key", organization_name="Test Org")
    mock_session = MagicMock()

    app.dependency_overrides[get_current_tenant] = lambda: mock_tenant
    app.dependency_overrides[get_session] = lambda: mock_session

    yield TestClient(app)

    app.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_verify_logic_exception_handling(client):
    """
    Test that verify_logic catches internal errors and returns a sanitized message.
    """
    with patch("qwed_new.api.main.check_rate_limit"), \
         patch("qwed_new.api.main.control_plane.process_logic_query", side_effect=Exception("SENSITIVE_LOGIC_ERROR")):

        response = client.post(
            "/verify/logic",
            json={"query": "If A then B..."}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ERROR"
        assert data["error"] == "Internal verification error"
        assert "SENSITIVE_LOGIC_ERROR" not in str(data)

def test_verify_logic_exception_integration(client):
    """
    Integration style test for verify_logic exception.
    """
    with patch("qwed_new.api.main.check_rate_limit"), \
         patch("qwed_new.api.main.control_plane.process_logic_query", side_effect=Exception("SENSITIVE_FAILURE")):

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
