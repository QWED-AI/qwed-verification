import pytest

from qwed_new.core.control_plane import ControlPlane, metrics_collector
from qwed_new.core.schemas import MathVerificationTask
from qwed_new.core.verifier import VerificationEngine


def test_verify_identity_sampling_returns_unknown_without_formal_proof():
    engine = VerificationEngine()

    result = engine.verify_identity(
        "x",
        "x + (x-0.5)*(x-1)*(x-2)*(x+1)*(x-0.1)",
    )

    assert result["status"] == "UNKNOWN"
    assert result["is_equivalent"] is None
    assert result["method"] == "numerical_sampling"


@pytest.mark.asyncio
async def test_control_plane_marks_translated_math_as_inconclusive(monkeypatch):
    cp = ControlPlane()
    captured: dict[str, object] = {}

    monkeypatch.setattr(cp.security_gateway, "detect_advanced_injection", lambda _: (True, ""))
    monkeypatch.setattr(cp.policy, "check_policy", lambda _query, organization_id=None: (True, ""))
    monkeypatch.setattr(cp.router, "route", lambda _query, preferred_provider=None: "openai_compat")
    monkeypatch.setattr(cp.output_sanitizer, "sanitize_output", lambda result, output_type, organization_id: result)
    monkeypatch.setattr(
        cp.translator,
        "translate",
        lambda query, provider=None: MathVerificationTask(
            expression="0.15 * 200",
            claimed_answer=30.0,
            reasoning="15 percent is 0.15, multiplied by 200",
            confidence=0.99,
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

    result = await cp.process_natural_language("What is 15% of 200?", organization_id=42)

    assert result["status"] == "INCONCLUSIVE"
    assert result["final_answer"] == 30.0
    assert result["verification"]["status"] == "VERIFIED"
    assert result["trust_boundary"] == {
        "query_interpretation_source": "llm_translation",
        "query_semantics_verified": False,
        "verification_scope": "translated_expression_only",
        "deterministic_expression_evaluation": True,
        "formal_proof": False,
        "translation_claim_self_consistent": True,
        "provider_used": "openai_compat",
        "overall_status": "INCONCLUSIVE",
    }
    assert captured["organization_id"] == 42
    assert captured["status"] == "INCONCLUSIVE"
    assert captured["provider"] == "openai_compat"


@pytest.mark.asyncio
async def test_control_plane_keeps_inconclusive_when_translation_claim_is_wrong(monkeypatch):
    cp = ControlPlane()

    monkeypatch.setattr(cp.security_gateway, "detect_advanced_injection", lambda _: (True, ""))
    monkeypatch.setattr(cp.policy, "check_policy", lambda _query, organization_id=None: (True, ""))
    monkeypatch.setattr(cp.router, "route", lambda _query, preferred_provider=None: "openai_compat")
    monkeypatch.setattr(cp.output_sanitizer, "sanitize_output", lambda result, output_type, organization_id: result)
    monkeypatch.setattr(
        cp.translator,
        "translate",
        lambda query, provider=None: MathVerificationTask(
            expression="0.15 * 200",
            claimed_answer=40.0,
            reasoning="Incorrectly interpreted result",
            confidence=0.99,
        ),
    )

    result = await cp.process_natural_language("What is 15% of 200?", organization_id=42)

    assert result["status"] == "INCONCLUSIVE"
    assert result["final_answer"] == 30.0
    assert result["verification"]["status"] == "CORRECTION_NEEDED"
    assert result["trust_boundary"]["translation_claim_self_consistent"] is False
