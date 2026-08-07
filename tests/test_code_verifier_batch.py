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


def test_code_verifier_batch_with_unsafe_verified_item_is_verified_unsafe(monkeypatch):
    """A batch of all-verified but unsafe items is VERIFIED-as-unsafe (non-admissible)."""
    verifier = CodeVerifier()

    def _fake_verify_code(code, language="python"):
        if "eval" in code:
            return DiagnosticResult.verified(
                "The code failed security verification and is not safe to use.",
                {"constraint_id": "code_verifier.code_unsafe", "is_valid": False,
                 "critical_count": 1},
                {"engine": "test", "language": language, "code": code, "is_safe": False},
            )
        return DiagnosticResult.verified(
            "The code passed security verification and is safe to use.",
            {"constraint_id": "code_verifier.code_safe", "is_valid": True},
            {"engine": "test", "language": language, "code": code, "is_safe": True},
        )

    monkeypatch.setattr(verifier, "verify_code", _fake_verify_code)

    result = verifier.verify_batch(
        [
            {"code": "result = 1", "language": "python"},
            {"code": "eval(input())", "language": "python"},
        ]
    )

    assert result.is_verified is True
    assert result.proof_ref is not None
    assert result.developer_fields.get("is_valid") is False


def test_code_verifier_non_string_language_is_blocked():
    """A non-string language returns BLOCKED instead of raising AttributeError."""
    verifier = CodeVerifier()

    result = verifier.verify_code("print(1)", language=None)

    assert result.status.value == "BLOCKED"
    assert result.proof_ref is None
    assert result.developer_fields.get("is_valid") is False
    assert result.developer_fields.get("constraint_id") == "code_verifier.unsupported_language"


def test_code_verifier_non_string_language_batch_item_does_not_abort():
    """One malformed batch item must produce a BLOCKED batch, not raise."""
    verifier = CodeVerifier()

    result = verifier.verify_batch(
        [
            {"code": "print(1)", "language": "python"},
            {"code": "alert(1)", "language": None},
        ]
    )

    assert result.status.value == "BLOCKED"
    assert result.developer_fields.get("constraint_id") == "code_verifier.batch_blocked"


def test_verify_python_deep_propagates_fail_closed_pattern_result(monkeypatch):
    """A BLOCKED pattern result must be returned unchanged by verify_python_deep."""
    verifier = CodeVerifier()
    blocked = DiagnosticResult.blocked(
        "unsupported language",
        {"constraint_id": "code_verifier.unsupported_language", "is_valid": False},
    )
    monkeypatch.setattr(verifier, "verify_code", lambda code, language="python": blocked)

    result = verifier.verify_python_deep("print(1)")

    assert result.status.value == "BLOCKED"
    assert result.developer_fields.get("constraint_id") == "code_verifier.unsupported_language"


def test_verify_python_deep_taint_exception_is_blocked(monkeypatch):
    """A taint-analysis exception must produce a BLOCKED result, not escape."""
    verifier = CodeVerifier()

    def _fail_taint(code):
        raise RuntimeError("taint engine down")

    monkeypatch.setattr(
        verifier, "_taint_analyzer", type("FakeTaint", (), {"analyze": _fail_taint})()
    )

    result = verifier.verify_python_deep("print(1)")

    assert result.status.value == "BLOCKED"
    assert result.developer_fields.get("constraint_id") == "code_verifier.execution_error"


def test_verify_python_deep_safe_is_verified():
    """A safe snippet passes deep verification as VERIFIED."""
    verifier = CodeVerifier()

    result = verifier.verify_python_deep("x = 1\nprint(x)")

    assert result.is_verified is True
    assert result.proof_ref is not None
    assert result.developer_fields.get("is_valid") is True


def test_verify_python_deep_taint_unsafe_is_verified_unsafe(monkeypatch):
    """A taint-flagged snippet is VERIFIED-as-unsafe (not admitted)."""
    from qwed_new.core.code_verifier import CodeVerifier

    verifier = CodeVerifier()

    class _TaintUnsafe:
        def analyze(self, code):
            return {
                "is_safe": False,
                "vulnerabilities": [{"severity": "high", "description": "xss", "source": "s"}],
                "tainted_variables": ["x"],
                "sources_found": ["s"],
                "sinks_found": ["t"],
            }

    monkeypatch.setattr(verifier, "_taint_analyzer", _TaintUnsafe())

    result = verifier.verify_python_deep("x = input()\nrender(x)")

    assert result.is_verified is True
    assert result.proof_ref is not None
    assert result.developer_fields.get("is_valid") is False
    assert result.developer_fields.get("is_safe") is False