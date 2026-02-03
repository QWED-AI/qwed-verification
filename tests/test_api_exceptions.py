from fastapi.testclient import TestClient
from unittest.mock import patch
from qwed_new.api.main import app

client = TestClient(app)

# Mock dependencies to bypass auth/rate-limiting/db for pure logic testing
# Note: In a real integration test we might want these, but here we want to force localized errors.

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

