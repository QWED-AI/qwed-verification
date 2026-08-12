import json

import pytest

from qwed_new.core.attestation import create_verification_attestation
from qwed_new.core.diagnostics import DiagnosticResult, DiagnosticStatus
from qwed_new.core.verification_context import (
    VerificationContextValidationError,
    resolve_document_proof_ref,
)
from qwed_new.core.verification_context_bridge import (
    verification_context_from_diagnostic_result,
)

QUERY = "mean of a == 2"
PROOF_DATA = json.dumps({"observed_result": 2.0}, sort_keys=True)


def _verified_result(is_valid=True):
    return DiagnosticResult.verified(
        agent_message="Statistical claim verified.",
        developer_fields={"is_valid": is_valid, "observed_result": 2.0},
        evidence={"observed_result": 2.0},
        proof_data=PROOF_DATA,
    )


def _attestation_token():
    attestation_result = create_verification_attestation(
        status="VERIFIED",
        verified=True,
        engine="test",
        query=QUERY,
        proof_data=PROOF_DATA,
    )
    assert attestation_result.is_issued
    return attestation_result.token


def test_verified_without_attestation_fails_closed():
    doc = verification_context_from_diagnostic_result(
        _verified_result(),
        formal_statement=QUERY,
        verifier="TestVerifier",
    )
    doc.validate()
    payload = doc.to_dict()
    assert payload["verdict"] == "BLOCKED"
    assert payload["context"]["evidence"]["proof_ref"] is None
    assert payload["context"]["decision"]["admission"] == "DENY"


def test_verified_with_attestation_and_valid_result_admits():
    doc = verification_context_from_diagnostic_result(
        _verified_result(is_valid=True),
        formal_statement=QUERY,
        verifier="TestVerifier",
        attestation_token=_attestation_token(),
    )
    doc.validate()
    payload = doc.to_dict()
    assert payload["verdict"] == "VERIFIED"
    assert payload["context"]["decision"]["admission"] == "ADMIT"
    assert resolve_document_proof_ref(payload)


def test_verified_with_attestation_but_invalid_result_denies():
    doc = verification_context_from_diagnostic_result(
        _verified_result(is_valid=False),
        formal_statement=QUERY,
        verifier="TestVerifier",
        attestation_token=_attestation_token(),
    )
    doc.validate()
    payload = doc.to_dict()
    assert payload["verdict"] == "VERIFIED"
    assert payload["context"]["decision"]["admission"] == "DENY"
    assert resolve_document_proof_ref(payload)


def test_unverifiable_result_fails_closed():
    result = DiagnosticResult.unverifiable(
        agent_message="Claim could not be verified.",
        developer_fields={"is_valid": False},
    )
    doc = verification_context_from_diagnostic_result(
        result,
        formal_statement=QUERY,
        verifier="TestVerifier",
    )
    doc.validate()
    payload = doc.to_dict()
    assert payload["verdict"] == "UNVERIFIABLE"
    assert payload["context"]["evidence"]["proof_ref"] is None
    assert payload["context"]["decision"]["admission"] == "DENY"


def test_blocked_result_fails_closed():
    result = DiagnosticResult.blocked(
        agent_message="Verification could not be attempted.",
        developer_fields={"is_valid": False},
    )
    doc = verification_context_from_diagnostic_result(
        result,
        formal_statement=QUERY,
        verifier="TestVerifier",
    )
    doc.validate()
    payload = doc.to_dict()
    assert payload["verdict"] == "BLOCKED"
    assert payload["context"]["evidence"]["proof_ref"] is None
    assert payload["context"]["decision"]["admission"] == "DENY"


def test_empty_formal_statement_rejected():
    result = _verified_result()
    with pytest.raises(VerificationContextValidationError):
        verification_context_from_diagnostic_result(
            result,
            formal_statement="",
            verifier="TestVerifier",
        )


def test_malformed_developer_fields_fail_closed():
    result = DiagnosticResult(
        status=DiagnosticStatus.UNVERIFIABLE,
        agent_message="Claim could not be verified.",
        developer_fields=[],
        proof_ref=None,
    )
    doc = verification_context_from_diagnostic_result(
        result,
        formal_statement=QUERY,
        verifier="TestVerifier",
    )
    doc.validate()
    payload = doc.to_dict()
    assert payload["verdict"] == "BLOCKED"
    assert payload["context"]["evidence"]["proof_ref"] is None
    assert payload["context"]["decision"]["admission"] == "DENY"
