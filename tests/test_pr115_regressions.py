from unittest.mock import MagicMock, PropertyMock, patch

import pytest
from fastapi.testclient import TestClient

from qwed_new.api.main import (
    AgentVerifyRequest,
    app,
    get_current_tenant,
    get_session,
    _run_agent_security_checks,
)
from qwed_new.core.consensus_verifier import ConsensusVerifier, VerificationMode
from qwed_new.core.logic_verifier import LogicVerifier


@pytest.fixture
def client():
    mock_tenant = MagicMock(organization_id=1, api_key="placeholder", organization_name="Test Org")
    mock_session = MagicMock(add=MagicMock(), commit=MagicMock())

    app.dependency_overrides[get_current_tenant] = lambda: mock_tenant
    app.dependency_overrides[get_session] = lambda: mock_session

    yield TestClient(app)

    app.dependency_overrides.clear()


def test_logic_verifier_requires_safe_evaluator():
    verifier = LogicVerifier()

    with patch.object(LogicVerifier, "safe_evaluator", new_callable=PropertyMock, return_value=None):
        with pytest.raises(RuntimeError, match="SafeEvaluator is required"):
            verifier._parse_constraint("x > 5", {"x": 1})


def test_agent_security_checks_are_server_enforced():
    session = MagicMock()
    agent = MagicMock(id=99, organization_id=1)
    request = AgentVerifyRequest(query="Fetch recent issues", tool_schema={"name": "agent_query"})

    with (
        patch("qwed_new.api.main._run_exfiltration_check") as mock_exfiltration,
        patch("qwed_new.api.main._run_mcp_poison_check") as mock_mcp,
    ):
        _run_agent_security_checks(session, 99, agent, request)

    mock_exfiltration.assert_called_once_with(session, 99, agent, "Fetch recent issues")
    mock_mcp.assert_called_once_with(session, 99, agent, {"name": "agent_query"})


def test_consensus_endpoint_checks_rate_limit(client):
    fake_result = MagicMock(
        confidence=0.99,
        final_answer="4",
        engines_used=1,
        agreement_status="unanimous",
        verification_chain=[],
        total_latency_ms=5.0,
    )

    with (
        patch("qwed_new.api.main.check_rate_limit") as mock_rate_limit,
        patch("qwed_new.api.main.consensus_verifier.verify_with_consensus", return_value=fake_result),
    ):
        response = client.post(
            "/verify/consensus",
            json={"query": "2+2", "verification_mode": "single", "min_confidence": 0.95},
            headers={"x-api-key": "fake-key"},
        )

    assert response.status_code == 200
    mock_rate_limit.assert_called_once_with("placeholder")


def test_consensus_verifier_does_not_select_fact_engine_without_context():
    verifier = ConsensusVerifier(enable_circuit_breaker=False)

    engines = verifier._select_engines("What is the capital population?", VerificationMode.MAXIMUM)

    assert "Fact" not in [engine_name for engine_name, _ in engines]


def test_consensus_fact_engine_requires_external_context():
    verifier = ConsensusVerifier(enable_circuit_breaker=False)

    result = verifier._verify_with_fact("What is the capital of France?")

    assert result.engine_name == "Fact"
    assert result.success is False
    assert result.result is None
    assert "External fact context is required" in result.error
