import pytest

from qwed_new.core.control_plane import ControlPlane
from qwed_new.core.observability import metrics_collector
from qwed_new.core.schemas import MathVerificationTask
from qwed_new.core.verifier import VerificationEngine


def test_verify_identity_sampling_fails_closed_without_formal_proof():
    engine = VerificationEngine()

    # This RHS is crafted to equal x at the hardcoded sample points used by
    # verify_identity (0.5, 1, 2, -1, 0.1) without being algebraically identical.
    result = engine.verify_identity(
        "x",
        "x + (x-0.5)*(x-1)*(x-2)*(x+1)*(x-0.1)",
    )

    assert result["status"] == "BLOCKED"
    assert result["is_equivalent"] is False
    assert result["method"] == "numerical_sampling_rejected"


def _build_cp(monkeypatch, claimed_answer):
    """Build a ControlPlane with all provider components mocked out."""
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
            claimed_answer=claimed_answer,
            reasoning="15 percent is 0.15, multiplied by 200",
            confidence=0.99,
        ),
    )
    return cp


@pytest.mark.asyncio
async def test_control_plane_marks_translated_math_as_verified(monkeypatch):
    """Coordinated trust enforcement marks VERIFIED results with mandatory
    attestation, proving the trust gate is no longer advisory-only (#265)."""
    cp = _build_cp(monkeypatch, claimed_answer=30.0)
    captured: dict[str, object] = {}

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

    # Mock attestation — crypto availability is a deployment concern,
    # not control plane orchestration behavior.
    from qwed_new.core.attestation import AttestationResult, AttestationStatus
    from qwed_new.core.diagnostics import DiagnosticResult
    captured_attestation_kwargs: dict = {}
    def _mock_create_attestation(**kwargs):
        captured_attestation_kwargs.update(kwargs)
        return AttestationResult(
            status=AttestationStatus.ISSUED,
            token="test-sentinel-token",
            error_code=None,
            error=None,
        )
    monkeypatch.setattr(
        "qwed_new.core.control_plane.create_verification_attestation",
        _mock_create_attestation,
    )

    captured_enforce_kwargs: dict = {}

    def _mock_enforce(result, **kwargs):
        captured_enforce_kwargs.update(kwargs)
        return DiagnosticResult.verified(
            "Expression verified successfully",
            developer_fields={"mocked": True},
            evidence={"status": "VERIFIED"},
        )

    monkeypatch.setattr("qwed_new.core.control_plane.enforce_trust_decision", _mock_enforce)

    result = await cp.process_natural_language("What is 15% of 200?", organization_id=42)

    assert result["status"] == "VERIFIED"
    assert result["final_answer"] == 30.0
    assert result["verification"]["status"] == "VERIFIED"
    trust_boundary = result["trust_boundary"]
    assert trust_boundary["overall_status"] == "VERIFIED"
    assert trust_boundary["trust_enforced"] == "VERIFIED"
    assert trust_boundary["attestation_policy"] == "mandatory"
    assert trust_boundary["query_interpretation_source"] == "llm_translation"
    assert trust_boundary["provider_used"] == "openai_compat"
    # Assert enforce_trust_decision was called with mandatory attestation args
    assert captured_enforce_kwargs["require_attestation"] is True
    assert captured_enforce_kwargs["attestation_token"] == "test-sentinel-token"
    # #279 regression: attestation and enforcement both bind to task.expression,
    # not the natural-language query (semantic scope must match)
    assert captured_attestation_kwargs["query"] == "0.15 * 200"
    assert captured_enforce_kwargs["query"] == "0.15 * 200"
    assert captured["organization_id"] == 42
    assert captured["status"] == "VERIFIED"
    assert captured["provider"] == "openai_compat"


@pytest.mark.asyncio
async def test_control_plane_returns_unverifiable_when_translation_claim_is_wrong(monkeypatch):
    cp = _build_cp(monkeypatch, claimed_answer=40.0)

    result = await cp.process_natural_language("What is 15% of 200?", organization_id=42)

    assert result["status"] == "UNVERIFIABLE"
    assert result["final_answer"] == 30.0
    assert result["verification"]["status"] == "CORRECTION_NEEDED"
    assert result["trust_boundary"]["translation_claim_self_consistent"] is False
    assert result["trust_boundary"]["trust_enforced"] == "UNVERIFIABLE"
    assert result["trust_boundary"]["attestation_policy"] == "mandatory"


@pytest.mark.asyncio
async def test_control_plane_attestation_failure_returns_blocked(monkeypatch):
    """When attestation signing fails (e.g. crypto unavailable), the VERIFIED
    result must downgrade to BLOCKED — fail-closed (#265)."""
    cp = _build_cp(monkeypatch, claimed_answer=30.0)

    from qwed_new.core.attestation import AttestationResult, AttestationStatus
    monkeypatch.setattr(
        "qwed_new.core.control_plane.create_verification_attestation",
        lambda **kwargs: AttestationResult(
            status=AttestationStatus.UNVERIFIABLE,
            token=None,
            error_code="CRYPTO_UNAVAILABLE",
            error="cryptography/PyJWT package not installed",
        ),
    )

    result = await cp.process_natural_language("What is 15% of 200?", organization_id=42)

    assert result["status"] == "BLOCKED"
    # final_answer retains the computed value for debugging,
    # but BLOCKED status indicates it cannot be trusted
    assert result["final_answer"] == 30.0
    trust_boundary = result["trust_boundary"]
    assert trust_boundary["trust_enforced"] == "BLOCKED"
    assert trust_boundary["attestation_error"] == "CRYPTO_UNAVAILABLE"
    assert trust_boundary["attestation_policy"] == "mandatory"


def test_control_plane_maps_syntax_error_to_error_status():
    result = ControlPlane._determine_math_response_status({"status": "SYNTAX_ERROR"})

    assert result == "ERROR"


def test_control_plane_defaults_missing_math_status_to_error():
    result = ControlPlane._determine_math_response_status({})

    assert result == "ERROR"


def test_control_plane_marks_failed_expression_evaluation_as_non_deterministic():
    result = ControlPlane._build_math_trust_boundary(
        "openai_compat",
        {"status": "SYNTAX_ERROR", "is_correct": False},
    )

    assert result["deterministic_expression_evaluation"] is False
    assert result["translation_claim_self_consistent"] is False
