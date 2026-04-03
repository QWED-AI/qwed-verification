from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from qwed_new.api import main as api_main
from qwed_new.api.main import get_optional_api_key_record, get_optional_current_user
from qwed_new.core.agent_service import ActionContext, AgentAction, AgentService
from qwed_new.core.policy import RedisSlidingWindowLimiter


@pytest.fixture
def client():
    original_overrides = api_main.app.dependency_overrides.copy()
    try:
        with patch("qwed_new.api.main._enforce_environment_integrity", return_value=None):
            with TestClient(api_main.app) as test_client:
                yield test_client
    finally:
        api_main.app.dependency_overrides = original_overrides


def _register_test_agent(service: AgentService):
    agent = service.register_agent(
        name="test-agent",
        agent_type="autonomous",
        principal_id="user-1",
    )
    return agent["agent_id"], agent["agent_token"]


def test_redis_limiter_fails_closed_on_backend_error():
    mock_client = MagicMock()
    mock_pipe = MagicMock()
    mock_client.pipeline.return_value = mock_pipe
    mock_pipe.execute.side_effect = RuntimeError("redis unavailable")

    with patch("qwed_new.core.redis_config.get_redis_client", return_value=mock_client):
        limiter = RedisSlidingWindowLimiter(rate=1, per=60)

    assert limiter.allow("tenant-1") is False
    assert limiter.get_remaining("tenant-1") == 0


def test_redis_limiter_uses_local_fallback_when_redis_missing_at_init():
    with patch("qwed_new.core.redis_config.get_redis_client", return_value=None):
        limiter = RedisSlidingWindowLimiter(rate=1, per=60)

    assert limiter.allow("tenant-1") is True
    assert limiter.allow("tenant-1") is False


def test_redis_limiter_reset_reports_failure_on_redis_error():
    mock_client = MagicMock()
    mock_client.delete.side_effect = RuntimeError("redis unavailable")

    with patch("qwed_new.core.redis_config.get_redis_client", return_value=mock_client):
        limiter = RedisSlidingWindowLimiter(rate=1, per=60)

    assert limiter.reset("tenant-1") is False


def test_agent_token_verification_uses_compare_digest():
    service = AgentService()
    agent_id, stored_token = _register_test_agent(service)
    presented_token = "not-the-stored-token"

    with patch("qwed_new.core.agent_service.hmac.compare_digest", return_value=True) as mock_compare:
        assert service.verify_agent_token(agent_id, presented_token) is True

    mock_compare.assert_called_once_with(stored_token, presented_token)


def test_verify_action_requires_context():
    service = AgentService()
    agent_id, _ = _register_test_agent(service)

    result = service.verify_action(
        agent_id,
        AgentAction(action_type="calculate", query="2+2"),
        context=None,
    )

    assert result["decision"] == "DENIED"
    assert result["error"]["code"] == "QWED-AGENT-CTX-001"


def test_verify_action_blocks_replay_steps():
    service = AgentService()
    agent_id, _ = _register_test_agent(service)
    action = AgentAction(action_type="calculate", query="2+2")

    approved = service.verify_action(
        agent_id,
        action,
        context=ActionContext(conversation_id="conv-1", step_number=1),
    )
    replayed = service.verify_action(
        agent_id,
        action,
        context=ActionContext(conversation_id="conv-1", step_number=1),
    )

    assert approved["decision"] == "APPROVED"
    assert replayed["decision"] == "DENIED"
    assert replayed["error"]["code"] == "QWED-AGENT-LOOP-002"


def test_verify_action_blocks_repetitive_loop():
    service = AgentService()
    agent_id, _ = _register_test_agent(service)
    action = AgentAction(action_type="calculate", query="2+2")

    first = service.verify_action(
        agent_id,
        action,
        context=ActionContext(conversation_id="conv-2", step_number=1),
    )
    second = service.verify_action(
        agent_id,
        action,
        context=ActionContext(conversation_id="conv-2", step_number=2),
    )
    third = service.verify_action(
        agent_id,
        action,
        context=ActionContext(conversation_id="conv-2", step_number=3),
    )

    assert first["decision"] == "APPROVED"
    assert second["decision"] == "APPROVED"
    assert third["decision"] == "DENIED"
    assert third["error"]["code"] == "QWED-AGENT-LOOP-003"


def test_verify_action_allows_different_action_after_loop_denial_same_step():
    service = AgentService()
    agent_id, _ = _register_test_agent(service)
    repeat_action = AgentAction(action_type="calculate", query="2+2")
    different_action = AgentAction(action_type="verify_logic", query="x > 1")

    service.verify_action(
        agent_id,
        repeat_action,
        context=ActionContext(conversation_id="conv-3", step_number=1),
    )
    service.verify_action(
        agent_id,
        repeat_action,
        context=ActionContext(conversation_id="conv-3", step_number=2),
    )
    state_before_denial = service._conversation_state[(agent_id, "conv-3")].copy()
    denied = service.verify_action(
        agent_id,
        repeat_action,
        context=ActionContext(conversation_id="conv-3", step_number=3),
    )
    assert service._conversation_state[(agent_id, "conv-3")] == state_before_denial
    different = service.verify_action(
        agent_id,
        different_action,
        context=ActionContext(conversation_id="conv-3", step_number=3),
    )
    step4 = service.verify_action(
        agent_id,
        AgentAction(action_type="calculate", query="3+3"),
        context=ActionContext(conversation_id="conv-3", step_number=4),
    )

    assert denied["decision"] == "DENIED"
    assert denied["error"]["code"] == "QWED-AGENT-LOOP-003"
    assert state_before_denial == {
        "last_step": 2,
        "last_fingerprint": service._action_fingerprint(repeat_action),
        "repeat_count": 2,
    }
    assert different["decision"] == "APPROVED"
    assert step4["decision"] == "APPROVED"


def test_verify_action_blocks_repetitive_pending_loop():
    service = AgentService()
    agent_id, _ = _register_test_agent(service)
    pending_action = AgentAction(action_type="file_write", query="write config")

    first = service.verify_action(
        agent_id,
        pending_action,
        context=ActionContext(conversation_id="conv-pending", step_number=1),
    )
    second = service.verify_action(
        agent_id,
        pending_action,
        context=ActionContext(conversation_id="conv-pending", step_number=2),
    )
    third = service.verify_action(
        agent_id,
        pending_action,
        context=ActionContext(conversation_id="conv-pending", step_number=3),
    )

    assert first["decision"] == "PENDING"
    assert second["decision"] == "PENDING"
    assert third["decision"] == "DENIED"
    assert third["error"]["code"] == "QWED-AGENT-LOOP-003"


def test_metrics_requires_admin_user(client):
    api_main.app.dependency_overrides[get_optional_current_user] = lambda: MagicMock(role="member", is_active=True)

    response = client.get("/metrics", headers={"Authorization": "Bearer fake"})

    assert response.status_code == 403
    assert response.json()["detail"] == "Admin access required"


def test_metrics_allows_admin_user(client):
    api_main.app.dependency_overrides[get_optional_current_user] = lambda: MagicMock(role="admin", is_active=True)

    with patch.object(api_main.metrics_collector, "get_global_metrics", return_value={"requests": 1}), patch.object(
        api_main.metrics_collector,
        "get_all_tenant_metrics",
        return_value={"1": {"requests": 1}},
    ):
        response = client.get("/metrics", headers={"Authorization": "Bearer fake"})

    assert response.status_code == 200
    assert response.json()["global"] == {"requests": 1}


def test_prometheus_metrics_requires_admin_user(client):
    api_main.app.dependency_overrides[get_optional_current_user] = lambda: MagicMock(role="member", is_active=True)

    response = client.get("/metrics/prometheus", headers={"Authorization": "Bearer fake"})

    assert response.status_code == 403
    assert response.json()["detail"] == "Admin access required"


def test_metrics_allows_api_key_client(client):
    api_main.app.dependency_overrides[get_optional_api_key_record] = lambda: MagicMock(
        organization_id=1,
        user_id=42,
    )
    mock_session = MagicMock()
    mock_session.get.return_value = MagicMock(role="admin", is_active=True)
    api_main.app.dependency_overrides[api_main.get_session] = lambda: mock_session

    with patch.object(api_main.metrics_collector, "get_global_metrics", return_value={"requests": 1}), patch.object(
        api_main.metrics_collector,
        "get_all_tenant_metrics",
        return_value={"1": {"requests": 1}},
    ):
        response = client.get("/metrics", headers={"x-api-key": "fake-key"})

    assert response.status_code == 200


def test_metrics_rejects_non_admin_api_key_client(client):
    api_main.app.dependency_overrides[get_optional_api_key_record] = lambda: MagicMock(
        organization_id=1,
        user_id=42,
    )
    mock_session = MagicMock()
    mock_session.get.return_value = MagicMock(role="member", is_active=True)
    api_main.app.dependency_overrides[api_main.get_session] = lambda: mock_session

    response = client.get("/metrics", headers={"x-api-key": "fake-key"})

    assert response.status_code == 403
    assert response.json()["detail"] == "Admin access required"


def test_get_optional_current_user_rejects_missing_sub_claim():
    session = MagicMock()

    with patch("qwed_new.api.main.get_current_user_token", return_value={}):
        with pytest.raises(api_main.HTTPException) as exc_info:
            api_main.get_optional_current_user("Bearer fake", session)

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Missing sub claim in token"


def test_metrics_rejects_inactive_admin_user(client):
    api_main.app.dependency_overrides[get_optional_current_user] = lambda: MagicMock(role="admin", is_active=False)

    response = client.get("/metrics", headers={"Authorization": "Bearer fake"})

    assert response.status_code == 403
    assert response.json()["detail"] == "Admin access required"


def test_metrics_allows_api_key_when_authorization_header_is_not_bearer(client):
    api_main.app.dependency_overrides[get_optional_api_key_record] = lambda: MagicMock(
        organization_id=1,
        user_id=42,
    )
    mock_session = MagicMock()
    mock_session.get.return_value = MagicMock(role="admin", is_active=True)
    api_main.app.dependency_overrides[api_main.get_session] = lambda: mock_session

    with patch.object(api_main.metrics_collector, "get_global_metrics", return_value={"requests": 1}), patch.object(
        api_main.metrics_collector,
        "get_all_tenant_metrics",
        return_value={"1": {"requests": 1}},
    ):
        response = client.get("/metrics", headers={"Authorization": "Basic abc", "x-api-key": "fake-key"})

    assert response.status_code == 200


def test_budget_denial_does_not_consume_conversation_step():
    service = AgentService()
    agent_id, _ = _register_test_agent(service)
    service._agents[agent_id].budget.max_requests_per_hour = 0

    denied = service.verify_action(
        agent_id,
        AgentAction(action_type="calculate", query="2+2"),
        context=ActionContext(conversation_id="conv-budget", step_number=1),
    )
    retry = service.verify_action(
        agent_id,
        AgentAction(action_type="verify_logic", query="x > 1"),
        context=ActionContext(conversation_id="conv-budget", step_number=1),
    )

    assert denied["decision"] == "BUDGET_EXCEEDED"
    assert retry["decision"] == "BUDGET_EXCEEDED"
    assert retry["error"]["code"] == "QWED-AGENT-BUDGET-002"


def test_enforce_environment_integrity_raises_on_compromise():
    with patch("qwed_sdk.guards.environment_guard.StartupHookGuard") as mock_guard_cls:
        mock_guard = mock_guard_cls.return_value
        mock_guard.verify_environment_integrity.return_value = {
            "verified": False,
            "message": "compromised",
        }

        with pytest.raises(RuntimeError, match="Environment integrity verification failed"):
            api_main._enforce_environment_integrity()


def test_on_startup_enforces_environment_before_db_init():
    calls = []
    with patch(
        "qwed_new.api.main._enforce_environment_integrity",
        side_effect=lambda: calls.append("enforce"),
    ) as mock_enforce, patch(
        "qwed_new.api.main.create_db_and_tables",
        side_effect=lambda: calls.append("create"),
    ) as mock_create_db:
        api_main.on_startup()

    mock_enforce.assert_called_once()
    mock_create_db.assert_called_once()
    assert calls == ["enforce", "create"]
