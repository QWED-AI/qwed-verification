"""Fail-closed security validation tests for StatsVerifier._validate_security."""
from unittest.mock import MagicMock

from qwed_new.core.diagnostics import DiagnosticResult
from qwed_new.core.stats_verifier import StatsVerifier


def _verifier_with(mock_code_result):
    verifier = StatsVerifier()
    verifier._code_verifier = MagicMock()
    verifier._code_verifier.verify_code.return_value = mock_code_result
    verifier._restricted_executor = MagicMock()
    verifier._restricted_executor.is_code_safe.return_value = (True, [])
    return verifier


def test_validate_security_blocked_verifier_is_fail_closed():
    """A BLOCKED verifier result must fail closed, even with no issues list."""
    blocked = DiagnosticResult.blocked(
        "unsupported language",
        {"constraint_id": "code_verifier.unsupported_language", "is_valid": False},
    )
    verifier = _verifier_with(blocked)

    report = verifier._validate_security("print(1)")

    assert report.is_safe is False
    assert any("code_verifier_unavailable" in f for f in report.checks_failed)


def test_validate_security_verified_unsafe_without_issues_fails_closed():
    """A VERIFIED-as-unsafe result with an empty/absent issues list still fails."""
    unsafe = DiagnosticResult.verified(
        "The code failed security verification and is not safe to use.",
        {"constraint_id": "code_verifier.code_unsafe", "is_valid": False},
        {"engine": "test", "language": "python", "code": "eval()", "is_safe": False},
    )
    verifier = _verifier_with(unsafe)

    report = verifier._validate_security("eval(input())")

    assert report.is_safe is False
    assert "code_verifier_invalid" in report.checks_failed


def test_validate_security_safe_verifier_passes():
    """A VERIFIED-safe result contributes a passed check."""
    safe = DiagnosticResult.verified(
        "The code passed security verification and is safe to use.",
        {"constraint_id": "code_verifier.code_safe", "is_valid": True},
        {"engine": "test", "language": "python", "code": "print(1)", "is_safe": True},
    )
    verifier = _verifier_with(safe)

    report = verifier._validate_security("print(1)")

    assert report.is_safe is True
    assert "code_verifier" in report.checks_passed


def test_validate_security_verified_unsafe_includes_issue_details():
    """Issue details from a VERIFIED-as-unsafe result are preserved."""
    unsafe = DiagnosticResult.verified(
        "The code failed security verification and is not safe to use.",
        {
            "constraint_id": "code_verifier.code_unsafe",
            "is_valid": False,
            "issues": [{"type": "command_injection", "description": "shell true"}],
        },
        {"engine": "test", "language": "python", "code": "subprocess.run", "is_safe": False},
    )
    verifier = _verifier_with(unsafe)

    report = verifier._validate_security("subprocess.run(...)")

    assert report.is_safe is False
    assert "code_verifier_invalid" in report.checks_failed
    assert any("command_injection" in f for f in report.checks_failed)


def test_validate_security_non_dict_issue_is_stringified():
    """Non-dict issues from a VERIFIED-as-unsafe result are stringified."""
    unsafe = DiagnosticResult.verified(
        "The code failed security verification and is not safe to use.",
        {
            "constraint_id": "code_verifier.code_unsafe",
            "is_valid": False,
            "issues": ["raw_issue_1"],
        },
        {"engine": "test", "language": "python", "code": "danger", "is_safe": False},
    )
    verifier = _verifier_with(unsafe)

    report = verifier._validate_security("danger")

    assert report.is_safe is False
    assert "code_verifier_invalid" in report.checks_failed
    assert any("raw_issue_1" in f for f in report.checks_failed)