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
    provided_value = "mismatch"

    with patch("qwed_new.core.agent_service.hmac.compare_digest", return_value=True) as mock_compare:
        assert service.verify_agent_token(agent_id, provided_value) is True

    mock_compare.assert_called_once_with(stored_token, provided_value)


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


def test_verify_action_denies_unknown_action_types():
    service = AgentService()
    agent_id, _ = _register_test_agent(service)

    result = service.verify_action(
        agent_id,
        AgentAction(
            action_type="transfer_funds_internal_v2",
            query="Move funds between ledgers",
        ),
        context=ActionContext(conversation_id="conv-unknown", step_number=1),
    )

    assert result["decision"] == "DENIED"
    assert result["error"]["code"] == "QWED-AGENT-ACTION-001"
    assert "verification" not in result


def test_unknown_action_denial_releases_same_step_reservation():
    service = AgentService()
    agent_id, _ = _register_test_agent(service)

    denied = service.verify_action(
        agent_id,
        AgentAction(
            action_type="transfer_funds_internal_v2",
            query="Move funds between ledgers",
        ),
        context=ActionContext(conversation_id="conv-unknown-release", step_number=1),
    )
    approved = service.verify_action(
        agent_id,
        AgentAction(action_type="calculate", query="2+2"),
        context=ActionContext(conversation_id="conv-unknown-release", step_number=1),
    )

    assert denied["decision"] == "DENIED"
    assert denied["error"]["code"] == "QWED-AGENT-ACTION-001"
    assert approved["decision"] == "APPROVED"


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


def test_verify_action_reserves_in_flight_step_until_release():
    service = AgentService()
    agent_id, _ = _register_test_agent(service)
    action = AgentAction(action_type="calculate", query="2+2")

    error, context_state = service._enforce_action_context(
        agent_id,
        action,
        ActionContext(conversation_id="conv-race", step_number=1),
    )
    replay_error, _ = service._enforce_action_context(
        agent_id,
        action,
        ActionContext(conversation_id="conv-race", step_number=1),
    )
    service._release_action_context(context_state)
    retry_error, retry_state = service._enforce_action_context(
        agent_id,
        action,
        ActionContext(conversation_id="conv-race", step_number=1),
    )

    assert error is None
    assert replay_error["code"] == "QWED-AGENT-LOOP-002"
    assert retry_error is None
    service._release_action_context(retry_state)


def test_action_fingerprint_rejects_non_deterministic_parameters():
    action = AgentAction(action_type="calculate", query="2+2", parameters={"bad": object()})

    with pytest.raises(TypeError, match="Unsupported action parameter type"):
        AgentService._action_fingerprint(action)


def test_metrics_rejects_org_admin_when_allowlist_unset(client, monkeypatch):
    """Issue #337: org role "owner"/"admin" is NOT platform authority.

    Self-service signup mints role="owner" for every account, so with the
    operator allowlist unset the gate must fail closed.
    """
    monkeypatch.delenv("QWED_METRICS_OPERATOR_USER_IDS", raising=False)
    api_main.app.dependency_overrides[get_optional_current_user] = lambda: MagicMock(role="admin", is_active=True, id=7)

    response = client.get("/metrics", headers={"Authorization": "Bearer fake"})

    assert response.status_code == 403
    assert response.json()["detail"] == "Platform operator access required"


def test_metrics_allows_configured_operator_user(client, monkeypatch):
    monkeypatch.setenv("QWED_METRICS_OPERATOR_USER_IDS", "7")
    api_main.app.dependency_overrides[get_optional_current_user] = lambda: MagicMock(role="owner", is_active=True, id=7)

    with patch.object(api_main.metrics_collector, "get_global_metrics", return_value={"requests": 1}), patch.object(
        api_main.metrics_collector,
        "get_all_tenant_metrics",
        return_value={"1": {"requests": 1}},
    ):
        response = client.get("/metrics", headers={"Authorization": "Bearer fake"})

    assert response.status_code == 200
    assert response.json()["global"] == {"requests": 1}


def test_metrics_rejects_operator_user_not_in_allowlist(client, monkeypatch):
    monkeypatch.setenv("QWED_METRICS_OPERATOR_USER_IDS", "1,2,3")
    api_main.app.dependency_overrides[get_optional_current_user] = lambda: MagicMock(role="admin", is_active=True, id=7)

    response = client.get("/metrics", headers={"Authorization": "Bearer fake"})

    assert response.status_code == 403
    assert response.json()["detail"] == "Platform operator access required"


def test_metrics_rejects_inactive_operator_user(client, monkeypatch):
    monkeypatch.setenv("QWED_METRICS_OPERATOR_USER_IDS", "7")
    api_main.app.dependency_overrides[get_optional_current_user] = lambda: MagicMock(role="owner", is_active=False, id=7)

    response = client.get("/metrics", headers={"Authorization": "Bearer fake"})

    assert response.status_code == 403
    assert response.json()["detail"] == "Platform operator access required"


def test_prometheus_metrics_requires_operator_user(client, monkeypatch):
    monkeypatch.delenv("QWED_METRICS_OPERATOR_USER_IDS", raising=False)
    api_main.app.dependency_overrides[get_optional_current_user] = lambda: MagicMock(role="admin", is_active=True, id=7)

    response = client.get("/metrics/prometheus", headers={"Authorization": "Bearer fake"})

    assert response.status_code == 403
    assert response.json()["detail"] == "Platform operator access required"


def test_metrics_allows_api_key_of_configured_operator(client, monkeypatch):
    monkeypatch.setenv("QWED_METRICS_OPERATOR_USER_IDS", "42")
    api_main.app.dependency_overrides[get_optional_api_key_record] = lambda: MagicMock(
        organization_id=1,
        user_id=42,
    )
    mock_session = MagicMock()
    mock_session.get.return_value = MagicMock(role="member", is_active=True, id=42)
    api_main.app.dependency_overrides[api_main.get_session] = lambda: mock_session

    with patch.object(api_main.metrics_collector, "get_global_metrics", return_value={"requests": 1}), patch.object(
        api_main.metrics_collector,
        "get_all_tenant_metrics",
        return_value={"1": {"requests": 1}},
    ):
        response = client.get("/metrics", headers={"x-api-key": "fake-key"})

    assert response.status_code == 200


def test_metrics_rejects_api_key_of_non_operator_user(client, monkeypatch):
    """Issue #337: an org-admin-linked API key must not read all-tenant metrics."""
    monkeypatch.setenv("QWED_METRICS_OPERATOR_USER_IDS", "99")
    api_main.app.dependency_overrides[get_optional_api_key_record] = lambda: MagicMock(
        organization_id=1,
        user_id=42,
    )
    mock_session = MagicMock()
    mock_session.get.return_value = MagicMock(role="admin", is_active=True, id=42)
    api_main.app.dependency_overrides[api_main.get_session] = lambda: mock_session

    response = client.get("/metrics", headers={"x-api-key": "fake-key"})

    assert response.status_code == 403
    assert response.json()["detail"] == "Platform operator access required"


def test_metrics_rejects_unlinked_api_key(client, monkeypatch):
    monkeypatch.setenv("QWED_METRICS_OPERATOR_USER_IDS", "42")
    api_main.app.dependency_overrides[get_optional_api_key_record] = lambda: MagicMock(
        organization_id=1,
        user_id=None,
    )
    mock_session = MagicMock()
    api_main.app.dependency_overrides[api_main.get_session] = lambda: mock_session

    response = client.get("/metrics", headers={"x-api-key": "fake-key"})

    assert response.status_code == 403
    assert response.json()["detail"] == "Platform operator access required"
    mock_session.get.assert_not_called()


def test_get_optional_api_key_record_treats_expired_key_as_absent():
    """CodeAnt on PR #349: is_active is not a liveness check. An expired key
    resolves to None (not a raise) so a valid operator JWT in the same
    request is not preempted (Sentry on PR #349)."""
    from datetime import datetime, timedelta, timezone

    expired = MagicMock(expires_at=datetime.now(timezone.utc) - timedelta(days=1), revoked_at=None)
    mock_session = MagicMock()
    mock_session.execute.return_value.scalars.return_value.first.return_value = expired

    with patch("qwed_new.api.main.hash_api_key", return_value="h"):
        result = get_optional_api_key_record(x_api_key="k", session=mock_session)

    assert result is None


def test_get_optional_api_key_record_normalizes_naive_stored_expiry():
    """expires_at is written naive-UTC (key_rotation convention); a naive
    past value must still be interpreted as UTC-expired, not crash."""
    from datetime import datetime, timedelta, timezone

    naive_expired = MagicMock(
        expires_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=1),
        revoked_at=None,
    )
    mock_session = MagicMock()
    mock_session.execute.return_value.scalars.return_value.first.return_value = naive_expired

    with patch("qwed_new.api.main.hash_api_key", return_value="h"):
        result = get_optional_api_key_record(x_api_key="k", session=mock_session)

    assert result is None


def test_get_optional_api_key_record_treats_revoked_key_as_absent():
    """Defense-in-depth for corrupted rows (revoked_at stamped, is_active
    not flipped): not a usable credential."""
    from datetime import datetime, timedelta, timezone

    revoked = MagicMock(expires_at=None, revoked_at=datetime.now(timezone.utc) - timedelta(days=1))
    mock_session = MagicMock()
    mock_session.execute.return_value.scalars.return_value.first.return_value = revoked

    with patch("qwed_new.api.main.hash_api_key", return_value="h"):
        result = get_optional_api_key_record(x_api_key="k", session=mock_session)

    assert result is None


def test_get_optional_api_key_record_allows_unexpired_key():
    from datetime import datetime, timedelta, timezone

    live = MagicMock(
        expires_at=datetime.now(timezone.utc) + timedelta(days=30), revoked_at=None
    )
    mock_session = MagicMock()
    mock_session.execute.return_value.scalars.return_value.first.return_value = live

    with patch("qwed_new.api.main.hash_api_key", return_value="h"):
        result = get_optional_api_key_record(x_api_key="k", session=mock_session)

    assert result is live


def test_metrics_allows_operator_jwt_when_api_key_expired(client, monkeypatch):
    """Sentry on PR #349 (MEDIUM): an expired X-Api-Key header must not
    preempt a valid operator JWT — the key resolves to None and the JWT
    still authorizes the all-tenant metrics read."""
    from datetime import datetime, timedelta, timezone

    monkeypatch.setenv("QWED_METRICS_OPERATOR_USER_IDS", "7")
    api_main.app.dependency_overrides[get_optional_current_user] = lambda: MagicMock(
        role="member", is_active=True, id=7
    )

    expired = MagicMock(
        expires_at=datetime.now(timezone.utc) - timedelta(days=1), revoked_at=None
    )
    mock_session = MagicMock()
    mock_session.execute.return_value.scalars.return_value.first.return_value = expired
    api_main.app.dependency_overrides[api_main.get_session] = lambda: mock_session

    with patch("qwed_new.api.main.hash_api_key", return_value="h"), patch.object(
        api_main.metrics_collector, "get_global_metrics", return_value={"requests": 1}
    ), patch.object(
        api_main.metrics_collector, "get_all_tenant_metrics", return_value={"1": {"requests": 1}}
    ):
        response = client.get("/metrics", headers={"x-api-key": "stale-key"})

    assert response.status_code == 200
    assert response.json()["global"] == {"requests": 1}


def test_metrics_denies_expired_api_key_without_jwt(client, monkeypatch):
    """Fail-closed still holds: an expired key presented alone authorizes
    nothing (resolves to no credential -> 401)."""
    from datetime import datetime, timedelta, timezone

    monkeypatch.setenv("QWED_METRICS_OPERATOR_USER_IDS", "7")
    api_main.app.dependency_overrides[get_optional_current_user] = lambda: None

    expired = MagicMock(
        expires_at=datetime.now(timezone.utc) - timedelta(days=1), revoked_at=None
    )
    mock_session = MagicMock()
    mock_session.execute.return_value.scalars.return_value.first.return_value = expired
    api_main.app.dependency_overrides[api_main.get_session] = lambda: mock_session

    with patch("qwed_new.api.main.hash_api_key", return_value="h"):
        response = client.get("/metrics", headers={"x-api-key": "stale-key"})

    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"


def test_get_optional_current_user_rejects_missing_sub_claim():
    session = MagicMock()

    with patch("qwed_new.api.main.get_current_user_token", return_value={}):
        with pytest.raises(api_main.HTTPException) as exc_info:
            api_main.get_optional_current_user("Bearer fake", session)

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Missing sub claim in token"


def test_metrics_rejects_inactive_admin_user(client, monkeypatch):
    monkeypatch.setenv("QWED_METRICS_OPERATOR_USER_IDS", "7")
    api_main.app.dependency_overrides[get_optional_current_user] = lambda: MagicMock(role="admin", is_active=False, id=7)

    response = client.get("/metrics", headers={"Authorization": "Bearer fake"})

    assert response.status_code == 403
    assert response.json()["detail"] == "Platform operator access required"


def test_metrics_allows_api_key_when_authorization_header_is_not_bearer(client, monkeypatch):
    monkeypatch.setenv("QWED_METRICS_OPERATOR_USER_IDS", "42")
    api_main.app.dependency_overrides[get_optional_api_key_record] = lambda: MagicMock(
        organization_id=1,
        user_id=42,
    )
    mock_session = MagicMock()
    mock_session.get.return_value = MagicMock(role="admin", is_active=True, id=42)
    api_main.app.dependency_overrides[api_main.get_session] = lambda: mock_session

    with patch.object(api_main.metrics_collector, "get_global_metrics", return_value={"requests": 1}), patch.object(
        api_main.metrics_collector,
        "get_all_tenant_metrics",
        return_value={"1": {"requests": 1}},
    ):
        response = client.get("/metrics", headers={"Authorization": "Basic abc", "x-api-key": "fake-key"})

    assert response.status_code == 200


def test_metrics_operator_allowlist_parser_tolerates_whitespace_and_blanks(monkeypatch):
    monkeypatch.setenv("QWED_METRICS_OPERATOR_USER_IDS", " 7 , , 42,,")
    assert api_main._get_metrics_operator_ids() == {"7", "42"}


def test_metrics_operator_allowlist_empty_string_denies_everyone(monkeypatch):
    monkeypatch.setenv("QWED_METRICS_OPERATOR_USER_IDS", "")
    assert api_main._get_metrics_operator_ids() == set()


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
