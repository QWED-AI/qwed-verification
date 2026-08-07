"""Fail-closed batch verification tests for CodeVerifier (Greptile/Sentry fixes)."""
from qwed_new.core.code_verifier import CodeVerifier
from qwed_new.core.diagnostics import DiagnosticResult


def test_code_verifier_empty_batch_is_blocked():
    """An empty batch must never produce an authoritative VERIFIED result."""
    verifier = CodeVerifier()

    result = verifier.verify_batch([])

    assert result.status.value == "BLOCKED"
    assert result.proof_ref is None
    assert result.is_verified is False
    assert result.developer_fields.get("is_valid") is False
    assert result.developer_fields.get("constraint_id") == "code_verifier.empty_batch"


def test_code_verifier_blocked_item_blocks_batch(monkeypatch):
    """A batch containing a BLOCKED item must be BLOCKED, never VERIFIED-as-unsafe."""
    verifier = CodeVerifier()
    blocked = DiagnosticResult.blocked(
        "unsupported language",
        {"constraint_id": "code_verifier.unsupported_language", "is_valid": False},
    )

    monkeypatch.setattr(verifier, "verify_code", lambda code, language="python": blocked)

    result = verifier.verify_batch([{"code": "print(1)", "language": "go"}])

    assert result.status.value == "BLOCKED"
    assert result.proof_ref is None
    assert result.developer_fields.get("is_valid") is False
    assert result.developer_fields.get("constraint_id") == "code_verifier.batch_blocked"


def test_code_verifier_all_safe_batch_is_verified():
    """A batch of all-safe, verified snippets is VERIFIED."""
    verifier = CodeVerifier()

    result = verifier.verify_batch([{"code": "result = 1", "language": "python"}])

    assert result.is_verified is True
    assert result.proof_ref is not None
    assert result.developer_fields.get("is_valid") is True
    assert result.developer_fields["summary"]["safe"] == 1


def test_code_verifier_batch_evidence_binds_full_snippets():
    """Suffix-only changes must change the proof_ref (evidence binds full code)."""
    verifier = CodeVerifier()
    base = "print(1)"
    long_a = base + (" " * 200)
    long_b = base + (" " * 200) + " # marker"

    verifier.verify_code = lambda code, language="python": DiagnosticResult.verified(
        "safe", {"constraint_id": "code_verifier.code_safe", "is_valid": True,
                 "critical_count": 0}, {}
    )

    ref_a = verifier.verify_batch([{"code": long_a, "language": "python"}]).proof_ref
    ref_b = verifier.verify_batch([{"code": long_b, "language": "python"}]).proof_ref
    assert ref_a != ref_b