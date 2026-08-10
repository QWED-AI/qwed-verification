import pytest
from importlib.metadata import PackageNotFoundError

from qwed_new.core.diagnostics import DiagnosticResult
from qwed_new.core.stats_verifier import StatsVerifier
from qwed_new.core.verification_context import (
    VerificationContextValidationError,
    resolve_document_proof_ref,
)


def _verified_result(is_valid=True):
    return DiagnosticResult.verified(
        agent_message="Statistical claim verified.",
        developer_fields={
            "is_valid": is_valid,
            "observed_result": 2.0,
        },
        evidence={"observed_result": 2.0},
    )


def test_stats_verified_context_valid_and_resolves():
    verifier = StatsVerifier()
    doc = verifier.to_verification_context(_verified_result(), "mean of a == 2")
    doc.validate()
    payload = doc.to_dict()
    assert payload["verdict"] == "VERIFIED"
    assert payload["context"]["decision"]["admission"] == "ADMIT"
    assert payload["context"]["proof"]["verifier"] == "StatsVerifier"
    assert payload["context"]["proof"]["verifier_version"]
    assert resolve_document_proof_ref(payload)


def test_stats_verified_invalid_result_fails_closed():
    verifier = StatsVerifier()
    result = _verified_result(is_valid=False)
    doc = verifier.to_verification_context(result, "mean of a == 2")
    doc.validate()
    payload = doc.to_dict()
    assert payload["verdict"] == "UNVERIFIABLE"
    assert payload["context"]["evidence"]["proof_ref"] is None
    assert payload["context"]["decision"]["admission"] == "DENY"


def test_stats_unverifiable_context_fail_closed():
    verifier = StatsVerifier()
    result = DiagnosticResult.unverifiable(
        agent_message="Claim could not be verified.",
        developer_fields={"is_valid": False},
    )
    doc = verifier.to_verification_context(result, "mean of a == 2")
    doc.validate()
    payload = doc.to_dict()
    assert payload["verdict"] == "UNVERIFIABLE"
    assert payload["context"]["evidence"]["proof_ref"] is None
    assert payload["context"]["decision"]["admission"] == "DENY"


def test_stats_blocked_context_fail_closed():
    verifier = StatsVerifier()
    result = DiagnosticResult.blocked(
        agent_message="Verification could not be attempted.",
        developer_fields={"is_valid": False},
    )
    doc = verifier.to_verification_context(result, "mean of a == 2")
    doc.validate()
    payload = doc.to_dict()
    assert payload["verdict"] == "BLOCKED"
    assert payload["context"]["evidence"]["proof_ref"] is None
    assert payload["context"]["decision"]["admission"] == "DENY"


def test_stats_context_tampering_invalidates_proof_ref():
    verifier = StatsVerifier()
    doc = verifier.to_verification_context(_verified_result(), "mean of a == 2")
    payload = doc.to_dict()
    payload["context"]["evidence"]["evidence"]["developer_fields"]["observed_result"] = 3.0
    assert not resolve_document_proof_ref(payload)


def test_stats_context_rejects_empty_query():
    verifier = StatsVerifier()
    result = _verified_result()
    with pytest.raises(VerificationContextValidationError):
        verifier.to_verification_context(result, "")


def test_stats_context_fails_closed_on_non_finite_evidence():
    verifier = StatsVerifier()
    result = DiagnosticResult.verified(
        agent_message="Statistical claim verified.",
        developer_fields={"is_valid": True, "value": float("nan")},
        evidence={"value": float("nan")},
    )
    with pytest.raises(VerificationContextValidationError):
        verifier.to_verification_context(result, "mean of a == nan")


def test_stats_verified_missing_is_valid_fails_closed():
    verifier = StatsVerifier()
    result = DiagnosticResult.verified(
        agent_message="Statistical claim verified.",
        developer_fields={"observed_result": 2.0},
        evidence={"observed_result": 2.0},
    )
    doc = verifier.to_verification_context(result, "mean of a == 2")
    doc.validate()
    payload = doc.to_dict()
    assert payload["verdict"] == "UNVERIFIABLE"
    assert payload["context"]["evidence"]["proof_ref"] is None
    assert payload["context"]["decision"]["admission"] == "DENY"


def test_stats_context_fails_closed_when_package_version_unavailable(monkeypatch):
    def _raise_package_not_found(_distribution_name):
        raise PackageNotFoundError()

    monkeypatch.setattr("qwed_new.core.stats_verifier.version", _raise_package_not_found)
    verifier = StatsVerifier()
    result = _verified_result()
    with pytest.raises(VerificationContextValidationError):
        verifier.to_verification_context(result, "mean of a == 2")
