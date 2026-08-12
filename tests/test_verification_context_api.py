from qwed_new.api.verification_context_routes import (
    DiagnosticVerificationContextRequest,
    VerificationContextDocumentRequest,
    create_verification_context_from_diagnostic,
    resolve_verification_context,
    validate_verification_context,
)
from qwed_new.core.tenant_context import TenantContext

_TENANT = TenantContext(
    organization_id=1,
    organization_name="test",
    tier="free",
    api_key="test",
)


def test_from_diagnostic_malformed_diagnostic_fails_closed():
    payload = DiagnosticVerificationContextRequest(
        query="mean of a == 2",
        verifier="TestVerifier",
        diagnostic={"status": "VERIFIED"},
    )
    document = create_verification_context_from_diagnostic(
        payload,
        tenant=_TENANT,
        session=None,
    )
    assert document["verdict"] == "BLOCKED"
    assert document["context"]["evidence"]["proof_ref"] is None
    assert document["context"]["decision"]["admission"] == "DENY"
    assert validate_verification_context(
        VerificationContextDocumentRequest(document=document),
        tenant=_TENANT,
        session=None,
    ) == {"valid": True}


def test_from_diagnostic_verified_without_attestation_fails_closed():
    payload = DiagnosticVerificationContextRequest(
        query="mean of a == 2",
        verifier="TestVerifier",
        diagnostic={
            "status": "VERIFIED",
            "agent_message": "Statistical claim verified.",
            "developer_fields": {"is_valid": True},
            "proof_ref": "sha256:" + "a" * 64,
        },
    )
    document = create_verification_context_from_diagnostic(
        payload,
        tenant=_TENANT,
        session=None,
    )
    assert document["verdict"] == "BLOCKED"
    assert document["context"]["evidence"]["proof_ref"] is None
    assert document["context"]["decision"]["admission"] == "DENY"


def test_validate_and_resolve_fail_closed_for_invalid_document():
    document = {"spec_version": "1.0"}
    validation = validate_verification_context(
        VerificationContextDocumentRequest(document=document),
        tenant=_TENANT,
        session=None,
    )
    assert validation["valid"] is False
    assert "error" in validation
    resolution = resolve_verification_context(
        VerificationContextDocumentRequest(document=document),
        tenant=_TENANT,
        session=None,
    )
    assert resolution == {"resolved": False}


def test_from_diagnostic_non_dict_developer_fields_fails_closed():
    payload = DiagnosticVerificationContextRequest(
        query="mean of a == 2",
        verifier="TestVerifier",
        diagnostic={
            "status": "UNVERIFIABLE",
            "agent_message": "Claim could not be verified.",
            "developer_fields": [],
        },
    )
    document = create_verification_context_from_diagnostic(
        payload,
        tenant=_TENANT,
        session=None,
    )
    assert document["verdict"] == "BLOCKED"
    assert document["context"]["evidence"]["proof_ref"] is None
    assert document["context"]["decision"]["admission"] == "DENY"
