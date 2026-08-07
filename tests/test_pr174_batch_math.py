import asyncio

from qwed_new.core.batch import BatchItem, BatchVerificationService, VerificationType


def test_batch_math_identity_verification_returns_valid(monkeypatch):
    service = BatchVerificationService()
    item = BatchItem(
        id="math-identity",
        query="x + x = 2*x",
        verification_type=VerificationType.MATH,
    )

    # Mock attestation + enforcement — crypto/JWT internals are deployment
    # concerns, not batch orchestration behavior (#271)
    from qwed_new.core.attestation import AttestationResult, AttestationStatus
    from qwed_new.core.diagnostics import DiagnosticResult
    monkeypatch.setattr(
        "qwed_new.core.batch.create_verification_attestation",
        lambda **kwargs: AttestationResult(
            status=AttestationStatus.ISSUED, token="test-sentinel-token", error_code=None, error=None,
        ),
    )
    monkeypatch.setattr(
        "qwed_new.core.batch.enforce_trust_decision",
        lambda result, **kwargs: result,
    )

    result = asyncio.run(service._verify_item(item, organization_id=1))

    # VERIFIED with proof_ref + attestation — trust boundary hit (#271)
    assert result["type"] == "math"
    assert result["is_valid"] is True
    assert result["status"] == "VERIFIED"
    assert result["agent_message"] == "Identity verified"
    assert result["proof_ref"] is not None
    assert result["is_authoritative"] is True


def test_batch_math_verified_attestation_failure_preserves_fields(monkeypatch):
    """When attestation signing fails, batch math must return UNVERIFIABLE
    while preserving type/query/is_valid/diff developer fields (#271)."""
    service = BatchVerificationService()
    item = BatchItem(
        id="math-attestation-fail",
        query="x + x = 2*x",
        verification_type=VerificationType.MATH,
    )

    from qwed_new.core.attestation import AttestationResult, AttestationStatus
    monkeypatch.setattr(
        "qwed_new.core.batch.create_verification_attestation",
        lambda **kwargs: AttestationResult(
            status=AttestationStatus.UNVERIFIABLE,
            token=None,
            error_code="CRYPTO_UNAVAILABLE",
            error="signing unavailable",
        ),
    )
    monkeypatch.setattr(
        "qwed_new.core.batch.enforce_trust_decision",
        lambda result, **kwargs: result,
    )

    result = asyncio.run(service._verify_item(item, organization_id=1))

    assert result["status"] == "UNVERIFIABLE"
    assert result["proof_ref"] is None
    # is_valid comes from the math evaluation, not the attestation outcome.
    # Signing failure marks the verdict unverifiable; the math itself was proven.
    assert result["is_valid"] is True
    assert result["type"] == "math"
    assert result["query"] == "x + x = 2*x"
    assert result["constraint_id"] == "api.attestation.signing_error"
    assert result["attestation_error"] == "CRYPTO_UNAVAILABLE"


def test_batch_math_non_identity_verification_returns_invalid():
    service = BatchVerificationService()
    item = BatchItem(
        id="math-not-equal",
        query="x + x = x",
        verification_type=VerificationType.MATH,
    )

    result = asyncio.run(service._verify_item(item, organization_id=1))

    assert result["type"] == "math"
    assert result["is_valid"] is False
    assert result["status"] == "UNVERIFIABLE"
    assert "Not equal" in result["agent_message"]
    assert result["proof_ref"] is None
    assert result["is_authoritative"] is False


def test_batch_math_simplification_only_is_not_reported_as_valid():
    service = BatchVerificationService()
    item = BatchItem(
        id="math-simplified",
        query="x + x",
        verification_type=VerificationType.MATH,
    )

    result = asyncio.run(service._verify_item(item, organization_id=1))

    assert result["type"] == "math"
    assert result["is_valid"] is False
    # SIMPLIFIED status removed — DiagnosticResult invariant: UNVERIFIABLE has no proof_ref (#271)
    assert result["status"] == "UNVERIFIABLE"
    assert result["simplified"] == "2*x"
    assert result["proof_ref"] is None
    assert "no equality or proof claim" in result["agent_message"]


def test_batch_code_item_exposes_admission_decision(monkeypatch):
    """CODE batch items expose an admission decision for VERIFIED-as-unsafe code."""
    from qwed_new.core.code_verifier import CodeVerifier
    from qwed_new.core.diagnostics import DiagnosticResult

    service = BatchVerificationService()
    item = BatchItem(
        id="code-unsafe",
        query="eval(input())",
        verification_type=VerificationType.CODE,
    )

    unsafe = DiagnosticResult.verified(
        "The code failed security verification and is not safe to use.",
        {"constraint_id": "code_verifier.code_unsafe", "is_valid": False,
         "critical_count": 1},
        {"engine": "test", "language": "python", "code": "eval(input())", "is_safe": False},
    )
    monkeypatch.setattr(
        CodeVerifier, "verify_code",
        lambda self, code, language="python": unsafe,
    )

    result = asyncio.run(service._verify_item(item, organization_id=1))

    assert result["status"] == "VERIFIED"
    assert result["developer_fields"]["is_valid"] is False
    assert result["admission"] == "BLOCKED"


def test_batch_code_safe_item_admission_is_admit(monkeypatch):
    """A safe CODE batch item is admitted via its explicit admission decision."""
    from qwed_new.core.code_verifier import CodeVerifier
    from qwed_new.core.diagnostics import DiagnosticResult

    service = BatchVerificationService()
    item = BatchItem(
        id="code-safe",
        query="result = 1 + 1",
        verification_type=VerificationType.CODE,
    )

    safe = DiagnosticResult.verified(
        "The code passed security verification and is safe to use.",
        {"constraint_id": "code_verifier.code_safe", "is_valid": True},
        {"engine": "test", "language": "python", "code": "result = 1 + 1", "is_safe": True},
    )
    monkeypatch.setattr(
        CodeVerifier, "verify_code",
        lambda self, code, language="python": safe,
    )

    result = asyncio.run(service._verify_item(item, organization_id=1))

    assert result["status"] == "VERIFIED"
    assert result["developer_fields"]["is_valid"] is True
    assert result["admission"] == "ADMIT"
