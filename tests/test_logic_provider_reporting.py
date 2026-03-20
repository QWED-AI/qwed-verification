from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from qwed_new.api.main import VerifyRequest, verify_logic
from qwed_new.core.control_plane import ControlPlane, metrics_collector
from qwed_new.core.tenant_context import TenantContext

TEST_API_KEY = "-".join(["unit", "tenant", "placeholder"])


@pytest.mark.asyncio
async def test_verify_logic_error_uses_routed_provider(monkeypatch):
    tenant = TenantContext(organization_id=1, organization_name="demo", tier="free", api_key=TEST_API_KEY)
    session = MagicMock()

    monkeypatch.setattr("qwed_new.api.main.check_rate_limit", lambda _: None)
    monkeypatch.setattr(
        "qwed_new.api.main.control_plane.process_logic_query",
        AsyncMock(side_effect=Exception("sensitive internal failure")),
    )
    monkeypatch.setattr(
        "qwed_new.api.main.control_plane.router.route",
        lambda query, preferred_provider=None: "openai_compat",
    )

    result = await verify_logic(
        VerifyRequest(query="approval is required", provider=" OpenAI-Compatible "),
        tenant=tenant,
        session=session,
    )

    assert result["status"] == "ERROR"
    assert result["error"] == "Internal verification error"
    assert result["provider_used"] == "openai_compat"


@pytest.mark.asyncio
async def test_control_plane_logic_metrics_use_resolved_provider(monkeypatch):
    cp = ControlPlane()
    captured: dict[str, object] = {}

    monkeypatch.setattr(cp.security_gateway, "detect_advanced_injection", lambda _: (True, ""))
    monkeypatch.setattr(cp.policy, "check_policy", lambda _query, organization_id=None: (True, ""))
    monkeypatch.setattr(cp.router, "route", lambda _query, preferred_provider=None: "azure_openai")
    monkeypatch.setattr(cp.output_sanitizer, "sanitize_output", lambda result, output_type, organization_id: result)
    monkeypatch.setattr(
        cp.logic_verifier,
        "verify_from_natural_language",
        lambda query, provider: SimpleNamespace(
            status="SAT",
            model={"x": "6"},
            dsl_code="(GT x 5)",
            error=None,
            provider_used="openai_compat",
        ),
    )

    def _track_request(*, organization_id, status, latency_ms, provider):
        captured.update(
            {
                "organization_id": organization_id,
                "status": status,
                "provider": provider,
                "latency_ms": latency_ms,
            }
        )

    monkeypatch.setattr(metrics_collector, "track_request", _track_request)

    result = await cp.process_logic_query("x > 5", organization_id=42)

    assert result["status"] == "SAT"
    assert result["provider_used"] == "openai_compat"
    assert captured["organization_id"] == 42
    assert captured["status"] == "SAT"
    assert captured["provider"] == "openai_compat"


@pytest.mark.asyncio
async def test_control_plane_logic_exception_keeps_last_known_provider(monkeypatch):
    cp = ControlPlane()

    monkeypatch.setattr(cp.security_gateway, "detect_advanced_injection", lambda _: (True, ""))
    monkeypatch.setattr(cp.policy, "check_policy", lambda _query, organization_id=None: (True, ""))
    monkeypatch.setattr(cp.router, "route", lambda _query, preferred_provider=None: "openai_compat")
    def _raise_runtime_error(query, provider):
        raise RuntimeError("boom")

    monkeypatch.setattr(
        cp.logic_verifier,
        "verify_from_natural_language",
        _raise_runtime_error,
    )

    result = await cp.process_logic_query("x > 5", organization_id=42)

    assert result["status"] == "ERROR"
    assert result["error"] == "Internal pipeline error"
    assert result["provider_used"] == "openai_compat"
