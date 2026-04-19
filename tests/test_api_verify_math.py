from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from qwed_new.api.main import app, get_current_tenant, get_session


def test_verify_math_ambiguous_expression_fails_closed_and_logs_unverified():
    mock_tenant = MagicMock(organization_id=123, api_key="dummy_key", user_id=456)
    mock_session = MagicMock()

    app.dependency_overrides[get_current_tenant] = lambda: mock_tenant
    app.dependency_overrides[get_session] = lambda: mock_session

    try:
        client = TestClient(app)

        with patch("qwed_new.api.main.check_rate_limit"):
            response = client.post(
                "/verify/math",
                json={"expression": "1/2(3+1)"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "BLOCKED"
        assert data["is_valid"] is False
        assert data["result"] is False
        assert data["warning"] == "ambiguous"
        assert "implicit multiplication after division" in data["message"]

        logged = mock_session.add.call_args[0][0]
        assert logged.is_verified is False
        assert logged.domain == "MATH"
    finally:
        app.dependency_overrides.clear()
