from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from qwed_new.api.main import app, get_current_tenant, get_session
from qwed_new.core.models import VerificationLog


def test_verify_math_ambiguous_expression_fails_closed_and_logs_unverified(isolated_audit_chain):
    mock_tenant = MagicMock(
        organization_id=123,
        api_key=MagicMock(name="tenant_api_key"),
        user_id=456,
    )
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
        assert "implicit multiplication after division" in data["agent_message"]

        # The row goes to the signed audit chain, not the request session.
        mock_session.add.assert_not_called()
        with Session(isolated_audit_chain) as session:
            (logged,) = session.exec(select(VerificationLog)).all()
        assert logged.is_verified is False
        assert logged.domain == "MATH"
        assert logged.organization_id == 123
        assert logged.entry_hash and logged.hmac_signature
    finally:
        app.dependency_overrides.clear()
