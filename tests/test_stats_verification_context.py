import hashlib
import json

import pytest
from importlib.metadata import PackageNotFoundError

from qwed_new.core.attestation import create_verification_attestation
from qwed_new.core.diagnostics import DiagnosticResult
from qwed_new.core.stats_verifier import (
    CONSTRAINT_STATS_VALID,
    StatsVerifier,
)
from qwed_new.core.verification_context import (
    VerificationContextValidationError,
    resolve_document_proof_ref,
)

DATASET_SHA256 = "a" * 64
QUERY = "mean of a == 2"
CLAIM_SHA256 = hashlib.sha256(QUERY.encode("utf-8")).hexdigest()
PROOF_DATA = json.dumps({"observed_result": 2.0}, sort_keys=True)


def _binding_fields():
    return {
        "constraint_id": CONSTRAINT_STATS_VALID,
        "is_valid": True,
        "claim_supported": True,
        "dataset_sha256": DATASET_SHA256,
        "claim_sha256": CLAIM_SHA256,
        "observed_result": 2.0,
    }


def _verified_result(is_valid=True, developer_overrides=None):
    developer_fields = _binding_fields()
    developer_fields["is_valid"] = is_valid
    if developer_overrides:
        developer_fields.update(developer_overrides)
    return DiagnosticResult.verified(
        agent_message="Statistical claim verified.",
        developer_fields=developer_fields,
        evidence={"observed_result": 2.0},
        proof_data=PROOF_DATA,
    )


def _attestation_token(query=QUERY, proof_data=PROOF_DATA):
    attestation_result = create_verification_attestation(
        status="VERIFIED",
        verified=True,
        engine="stats",
        query=query,
        proof_data=proof_data,
    )
    assert attestation_result.is_issued
    return attestation_result.token


def _assert_fail_closed(payload, expected_verdict):
    assert payload["verdict"] == expected_verdict
    assert payload["context"]["evidence"]["proof_ref"] is None
    assert payload["context"]["decision"]["admission"] == "DENY"


def test_stats_verified_context_valid_and_resolves():
    verifier = StatsVerifier()
    result = _verified_result()
    doc = verifier.to_verification_context(
        result,
        QUERY,
        attestation_token=_attestation_token(),
    )
    doc.validate()
    payload = doc.to_dict()
    assert payload["verdict"] == "VERIFIED"
    assert payload["context"]["decision"]["admission"] == "ADMIT"
    assert payload["context"]["proof"]["verifier"] == "StatsVerifier"
    assert payload["context"]["proof"]["verifier_version"]
    assert resolve_document_proof_ref(payload)


def test_stats_verified_without_attestation_fails_closed():
    verifier = StatsVerifier()
    doc = verifier.to_verification_context(_verified_result(), QUERY)
    doc.validate()
    _assert_fail_closed(doc.to_dict(), "BLOCKED")


def test_stats_verified_with_invalid_attestation_fails_closed():
    verifier = StatsVerifier()
    doc = verifier.to_verification_context(
        _verified_result(),
        QUERY,
        attestation_token="invalid",
    )
    doc.validate()
    _assert_fail_closed(doc.to_dict(), "BLOCKED")


def test_stats_verified_invalid_result_fails_closed():
    verifier = StatsVerifier()
    result = _verified_result(is_valid=False)
    doc = verifier.to_verification_context(
        result,
        QUERY,
        attestation_token=_attestation_token(),
    )
    doc.validate()
    _assert_fail_closed(doc.to_dict(), "UNVERIFIABLE")


def test_stats_verified_missing_is_valid_fails_closed():
    verifier = StatsVerifier()
    result = _verified_result(developer_overrides={"is_valid": None})
    doc = verifier.to_verification_context(
        result,
        QUERY,
        attestation_token=_attestation_token(),
    )
    doc.validate()
    _assert_fail_closed(doc.to_dict(), "UNVERIFIABLE")


def test_stats_verified_unbound_result_fails_closed():
    verifier = StatsVerifier()
    result = DiagnosticResult.verified(
        agent_message="Statistical claim verified.",
        developer_fields={"is_valid": True, "observed_result": 2.0},
        evidence={"observed_result": 2.0},
        proof_data=PROOF_DATA,
    )
    doc = verifier.to_verification_context(
        result,
        QUERY,
        attestation_token=_attestation_token(),
    )
    doc.validate()
    _assert_fail_closed(doc.to_dict(), "UNVERIFIABLE")


def test_stats_verified_malformed_dataset_digest_fails_closed():
    verifier = StatsVerifier()
    result = _verified_result(developer_overrides={"dataset_sha256": "not-a-sha256"})
    doc = verifier.to_verification_context(
        result,
        QUERY,
        attestation_token=_attestation_token(),
    )
    doc.validate()
    _assert_fail_closed(doc.to_dict(), "UNVERIFIABLE")


def test_stats_verified_malformed_claim_digest_fails_closed():
    verifier = StatsVerifier()
    result = _verified_result(developer_overrides={"claim_sha256": "not-a-sha256"})
    doc = verifier.to_verification_context(
        result,
        QUERY,
        attestation_token=_attestation_token(),
    )
    doc.validate()
    _assert_fail_closed(doc.to_dict(), "UNVERIFIABLE")


def test_stats_verified_mismatched_query_fails_closed():
    verifier = StatsVerifier()
    result = _verified_result()
    doc = verifier.to_verification_context(
        result,
        "sum of revenue == 999999",
        attestation_token=_attestation_token(),
    )
    doc.validate()
    _assert_fail_closed(doc.to_dict(), "BLOCKED")


def test_stats_unverifiable_context_fail_closed():
    verifier = StatsVerifier()
    result = DiagnosticResult.unverifiable(
        agent_message="Claim could not be verified.",
        developer_fields={"is_valid": False},
    )
    doc = verifier.to_verification_context(result, QUERY)
    doc.validate()
    _assert_fail_closed(doc.to_dict(), "UNVERIFIABLE")


def test_stats_blocked_context_fail_closed():
    verifier = StatsVerifier()
    result = DiagnosticResult.blocked(
        agent_message="Verification could not be attempted.",
        developer_fields={"is_valid": False},
    )
    doc = verifier.to_verification_context(result, QUERY)
    doc.validate()
    _assert_fail_closed(doc.to_dict(), "BLOCKED")


def test_stats_context_tampering_invalidates_proof_ref():
    verifier = StatsVerifier()
    result = _verified_result()
    doc = verifier.to_verification_context(
        result,
        QUERY,
        attestation_token=_attestation_token(),
    )
    payload = doc.to_dict()
    payload["context"]["evidence"]["evidence"]["developer_fields"]["observed_result"] = 3.0
    assert not resolve_document_proof_ref(payload)


def test_stats_context_rejects_empty_query():
    verifier = StatsVerifier()
    result = DiagnosticResult.unverifiable(
        agent_message="Claim could not be verified.",
        developer_fields={"is_valid": False},
    )
    with pytest.raises(VerificationContextValidationError):
        verifier.to_verification_context(result, "")


def test_stats_context_fails_closed_on_non_finite_evidence():
    verifier = StatsVerifier()
    nan_proof_data = json.dumps({"value": float("nan")}, sort_keys=True)
    developer_fields = _binding_fields()
    developer_fields["value"] = float("nan")
    result = DiagnosticResult.verified(
        agent_message="Statistical claim verified.",
        developer_fields=developer_fields,
        evidence={"value": float("nan")},
        proof_data=nan_proof_data,
    )
    with pytest.raises(VerificationContextValidationError):
        verifier.to_verification_context(
            result,
            QUERY,
            attestation_token=_attestation_token(proof_data=nan_proof_data),
        )


def test_stats_context_fails_closed_when_package_version_unavailable(monkeypatch):
    def _raise_package_not_found(_distribution_name):
        raise PackageNotFoundError()

    monkeypatch.setattr("qwed_new.core.stats_verifier.version", _raise_package_not_found)
    verifier = StatsVerifier()
    result = _verified_result()
    with pytest.raises(
        VerificationContextValidationError,
        match="qwed package metadata is unavailable",
    ):
        verifier.to_verification_context(result, QUERY)
