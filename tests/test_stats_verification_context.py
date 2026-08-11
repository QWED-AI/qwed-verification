import pytest
from importlib.metadata import PackageNotFoundError

from qwed_new.core.diagnostics import DiagnosticResult
from qwed_new.core.stats_verifier import StatsVerifier
from qwed_new.core.verification_context import (
    VerificationContextValidationError,
)


def _verified_result():
    return DiagnosticResult.verified(
        agent_message="Statistical claim verified.",
        developer_fields={"is_valid": True, "observed_result": 2.0},
        evidence={"observed_result": 2.0},
    )


def _assert_fail_closed(payload, expected_verdict):
    assert payload["verdict"] == expected_verdict
    assert payload["context"]["evidence"]["proof_ref"] is None
    assert payload["context"]["decision"]["admission"] == "DENY"


def test_stats_verified_input_fails_closed_without_execution_provenance():
    verifier = StatsVerifier()
    doc = verifier.to_verification_context(_verified_result(), "mean of a == 2")
    doc.validate()
    _assert_fail_closed(doc.to_dict(), "BLOCKED")


def test_stats_verified_input_with_claim_metadata_fails_closed():
    verifier = StatsVerifier()
    result = DiagnosticResult.verified(
        agent_message="Statistical claim verified.",
        developer_fields={
            "is_valid": True,
            "claim_supported": True,
            "dataset_sha256": "a" * 64,
            "claim_sha256": "b" * 64,
            "observed_result": 2.0,
        },
        evidence={"observed_result": 2.0},
    )
    doc = verifier.to_verification_context(result, "mean of a == 2")
    doc.validate()
    _assert_fail_closed(doc.to_dict(), "BLOCKED")


def test_stats_unverifiable_context_fail_closed():
    verifier = StatsVerifier()
    result = DiagnosticResult.unverifiable(
        agent_message="Claim could not be verified.",
        developer_fields={"is_valid": False},
    )
    doc = verifier.to_verification_context(result, "mean of a == 2")
    doc.validate()
    _assert_fail_closed(doc.to_dict(), "UNVERIFIABLE")


def test_stats_blocked_context_fail_closed():
    verifier = StatsVerifier()
    result = DiagnosticResult.blocked(
        agent_message="Verification could not be attempted.",
        developer_fields={"is_valid": False},
    )
    doc = verifier.to_verification_context(result, "mean of a == 2")
    doc.validate()
    _assert_fail_closed(doc.to_dict(), "BLOCKED")


def test_stats_context_rejects_empty_query():
    verifier = StatsVerifier()
    result = DiagnosticResult.unverifiable(
        agent_message="Claim could not be verified.",
        developer_fields={"is_valid": False},
    )
    with pytest.raises(VerificationContextValidationError):
        verifier.to_verification_context(result, "")


def test_stats_context_fails_closed_when_package_version_unavailable(monkeypatch):
    def _raise_package_not_found(_distribution_name):
        raise PackageNotFoundError()

    monkeypatch.setattr("qwed_new.core.stats_verifier.version", _raise_package_not_found)
    verifier = StatsVerifier()
    with pytest.raises(
        VerificationContextValidationError,
        match="qwed package metadata is unavailable",
    ):
        verifier.to_verification_context(_verified_result(), "mean of a == 2")
