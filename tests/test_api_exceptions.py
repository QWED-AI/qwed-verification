from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from qwed_new.api.main import app, get_current_tenant, get_session, check_rate_limit, TenantContext
from sqlmodel import Session

# Mock dependencies
async def mock_get_current_tenant():
    # Return a dummy context
    mock_ctx = MagicMock(spec=TenantContext)
    mock_ctx.organization_id = 123
    mock_ctx.api_key = "dummy_key"
    mock_ctx.user_id = 456
    return mock_ctx

def mock_get_session():
    # Return a dummy session
    return MagicMock(spec=Session)

def mock_check_rate_limit(api_key: str):
    pass # No-op

# Apply overrides
app.dependency_overrides[get_current_tenant] = mock_get_current_tenant
app.dependency_overrides[get_session] = mock_get_session
app.dependency_overrides[check_rate_limit] = mock_check_rate_limit

client = TestClient(app)

def test_verify_math_exception_handling():
    """
    Test that verify_math catches internal errors and returns a sanitized message.
    """
    # Force an exception during parsing/processing
    with patch('sympy.parsing.sympy_parser.parse_expr', side_effect=ValueError("CRITICAL SENSITIVE STACK TRACE")):
        # Providing valid minimal input to pass Pydantic validation
        response = client.post(
            "/verify/math",
            json={"expression": "1+1"} 
        )
        
        # It should return 200 OK (soft failure) as per our logic, or handle it gracefully
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ERROR"
        assert data["error"] == "Internal verification error"
        assert "CRITICAL SENSITIVE STACK TRACE" not in str(data) # Ensure leak prevention

def test_verify_sql_exception_handling():
    """
    Test that verify_sql catches internal errors and returns a sanitized message.
    """
    with patch('qwed_new.core.sql_verifier.SQLVerifier.verify_sql', side_effect=Exception("DB_PASSWORD=secret")):
        response = client.post(
            "/verify/sql",
            json={
                "query": "SELECT *",
                "schema_ddl": "CREATE TABLE t(id int)", # Required field
                "type": "postgres" # Valid type
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ERROR"
        assert data["error"] == "Internal verification error"
        assert "DB_PASSWORD" not in str(data)

def test_verify_fact_exception_handling():
    """
    Test that verify_fact catches internal errors and returns a sanitized message.
    """
    with patch('qwed_new.core.fact_verifier.FactVerifier.verify_fact', side_effect=Exception("API_KEY_LEAK")):
        response = client.post(
            "/verify/fact",
            json={
                "claim": "Sky is blue",
                "context": "Sky is blue"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ERROR"
        assert data["error"] == "Internal verification error"
        assert "API_KEY_LEAK" not in str(data)

def test_verify_code_exception_handling():
    """
    Test that verify_code catches internal errors and returns a sanitized message.
    """
    with patch('qwed_new.core.code_verifier.CodeVerifier.verify_code', side_effect=Exception("INTERNAL_PATH_LEAK")):
        response = client.post(
            "/verify/code",
            json={"code": "print('hello')", "language": "python"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ERROR"
        assert data["error"] == "Internal verification error"
        assert "INTERNAL_PATH_LEAK" not in str(data)

def test_verify_image_exception_handling():
    """
    Test that verify_image catches internal errors and returns a sanitized message.
    """
    # Mocking UploadFile processing is tricky, so we mock the verifier
    with patch('qwed_new.core.image_verifier.ImageVerifier.verify_image', side_effect=Exception("VLM_API_KEY_LEAK")):
        # We need to send a file to pass FastAPI validation
        response = client.post(
            "/verify/image",
            files={"image": ("test.png", b"fake-content", "image/png")},
            data={"claim": "test"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ERROR"
        assert data["error"] == "Internal processing error"
        assert "VLM_API_KEY_LEAK" not in str(data)


def test_verify_stats_exception_handling():
    """
    Test that verify_stats catches internal errors and returns a sanitized message.
    """
    # Use pandas mock if needed, but here we just mock the verifier
    with patch('qwed_new.core.stats_verifier.StatsVerifier.verify_stats', side_effect=Exception("SENSITIVE_DATA_LEAK")):
        # Need to provide a dummy file and query
        response = client.post(
            "/verify/stats",
            files={"file": ("data.csv", b"col1,col2\n1,2", "text/csv")},
            data={"query": "average of col1"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ERROR"
        assert data["error"] == "Internal processing error"
        assert "SENSITIVE_DATA_LEAK" not in str(data)

def test_agent_tool_call_exception_handling():
    """
    Test that agent_tool_call logs errors without stack traces when execution fails.
    """
    # Mock all the agent registry and approval steps to get to the execution part
    with patch('qwed_new.core.agent_registry.agent_registry.authenticate_agent') as mock_auth, \
         patch('qwed_new.core.agent_registry.agent_registry.check_permission') as mock_perm, \
         patch('qwed_new.core.tool_approval.tool_approval.approve_tool_call') as mock_approve, \
         patch('qwed_new.core.tool_approval.tool_approval.execute_tool_call') as mock_exec:
        
        # Setup mocks
        mock_agent = MagicMock()
        mock_agent.id = 1
        mock_agent.organization_id = 123
        mock_auth.return_value = mock_agent
        
        mock_perm.return_value = (True, None) # Permission granted
        
        mock_tool_call = MagicMock()
        mock_tool_call.id = 999
        mock_approve.return_value = (True, None, mock_tool_call) # Approved
        
        # execution fails!
        mock_exec.return_value = (False, "CRITICAL_TOOL_FAILURE", None)
        
        response = client.post(
            "/agents/1/tools/web_search",
            json={"tool_params": {"q": "test"}},
            headers={"x-agent-token": "valid_token"}
        )
        
        # Should raise 500
        assert response.status_code == 500
        assert response.json()["detail"] == "Tool execution failed"
        # We can't easily assert the log content here without a log capture fixture,
        # but execution of properly handled code is sufficient for coverage.
