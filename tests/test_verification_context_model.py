import pytest

from qwed_new.core.verification_context import (
    Admission,
    Decision,
    Evidence,
    Formalization,
    Interpretation,
    Proof,
    Verdict,
    VerificationContext,
    VerificationContextDocument,
    VerificationContextValidationError,
    VerifiedObject,
    is_valid_document,
    validate_document,
)

PROOF_REF = "sha256:" + "a" * 64


def _interpretation():
    return Interpretation(theory="real-closed fields", logic="first-order")


def _proof():
    return Proof(
        verifier="SymPy",
        verifier_version="1.14.0",
        configuration={"timeout_ms": 5000},
        theory_scope="real-closed fields",
        trusted_dependencies=["sympy"],
        outcome_treatment="unknown/timeout/error resolve to UNVERIFIABLE or BLOCKED",
    )


def _context(admission=Admission.ADMIT, proof_ref=PROOF_REF):
    return VerificationContext(
        interpretation=_interpretation(),
        proof=_proof(),
        evidence=Evidence(evidence={"roots": [-2, 2]}, proof_ref=proof_ref),
        decision=Decision(admission=admission),
    )


def _formalization():
    return Formalization(
        source_query="Is x squared minus four zero?",
        translator="qwed-translator",
        translation_confidence=0.9,
    )


def test_verified_document_valid():
    doc = VerificationContextDocument.verified(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
        proof_ref=PROOF_REF,
        formalization=_formalization(),
    )
    doc.validate()
    payload = doc.to_dict()
    assert payload["spec_version"] == "1.0"
    assert payload["verdict"] == "VERIFIED"
    assert payload["context"]["evidence"]["proof_ref"] == PROOF_REF


def test_unverifiable_factory_forces_fail_closed_defaults():
    doc = VerificationContextDocument.unverifiable(
        formal_statement="x**2 - 4 = 0",
        context=_context(admission=Admission.ADMIT, proof_ref=PROOF_REF),
    )
    doc.validate()
    payload = doc.to_dict()
    assert payload["verdict"] == "UNVERIFIABLE"
    assert payload["context"]["evidence"]["proof_ref"] is None
    assert payload["context"]["decision"]["admission"] == "DENY"


def test_blocked_factory_forces_fail_closed_defaults():
    doc = VerificationContextDocument.blocked(
        formal_statement="x**2 - 4 = 0",
        context=_context(admission=Admission.ADMIT, proof_ref=PROOF_REF),
    )
    doc.validate()
    payload = doc.to_dict()
    assert payload["verdict"] == "BLOCKED"
    assert payload["context"]["evidence"]["proof_ref"] is None
    assert payload["context"]["decision"]["admission"] == "DENY"


def test_verified_allows_deny_admission():
    doc = VerificationContextDocument.verified(
        formal_statement="x**2 - 4 = 0",
        context=_context(admission=Admission.DENY),
        proof_ref=PROOF_REF,
    )
    doc.validate()
    assert doc.to_dict()["context"]["decision"]["admission"] == "DENY"


def test_verified_requires_proof_ref():
    with pytest.raises(VerificationContextValidationError):
        VerificationContextDocument(
            verified_object=VerifiedObject(formal_statement="x**2 - 4 = 0"),
            context=_context(proof_ref=None),
            verdict=Verdict.VERIFIED,
        )


def test_fail_closed_requires_null_proof_ref():
    with pytest.raises(VerificationContextValidationError):
        VerificationContextDocument(
            verified_object=VerifiedObject(formal_statement="x**2 - 4 = 0"),
            context=_context(admission=Admission.DENY, proof_ref=PROOF_REF),
            verdict=Verdict.UNVERIFIABLE,
        )


def test_fail_closed_requires_deny_admission():
    with pytest.raises(VerificationContextValidationError):
        VerificationContextDocument(
            verified_object=VerifiedObject(formal_statement="x**2 - 4 = 0"),
            context=_context(admission=Admission.ADMIT, proof_ref=None),
            verdict=Verdict.BLOCKED,
        )


def test_formalization_verified_must_be_false():
    with pytest.raises(VerificationContextValidationError):
        Formalization(verified=True)


def test_empty_interpretation_rejected():
    with pytest.raises(VerificationContextValidationError):
        Interpretation()


def test_malformed_proof_ref_rejected_by_model():
    with pytest.raises(VerificationContextValidationError):
        Evidence(evidence={}, proof_ref="sha256:zzz")


def test_schema_rejects_unknown_top_level_field():
    doc = VerificationContextDocument.verified(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
        proof_ref=PROOF_REF,
    )
    payload = doc.to_dict()
    payload["unexpected"] = True
    with pytest.raises(VerificationContextValidationError):
        validate_document(payload)
    assert not is_valid_document(payload)


def test_schema_rejects_wrong_spec_version():
    doc = VerificationContextDocument.verified(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
        proof_ref=PROOF_REF,
    )
    payload = doc.to_dict()
    payload["spec_version"] = "2.0"
    with pytest.raises(VerificationContextValidationError):
        validate_document(payload)


def test_schema_rejects_malformed_proof_ref():
    doc = VerificationContextDocument.verified(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
        proof_ref=PROOF_REF,
    )
    payload = doc.to_dict()
    payload["context"]["evidence"]["proof_ref"] = "sha256:zzz"
    with pytest.raises(VerificationContextValidationError):
        validate_document(payload)


def test_schema_rejects_verified_with_null_proof_ref():
    doc = VerificationContextDocument.verified(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
        proof_ref=PROOF_REF,
    )
    payload = doc.to_dict()
    payload["context"]["evidence"]["proof_ref"] = None
    with pytest.raises(VerificationContextValidationError):
        validate_document(payload)


def test_schema_rejects_unverifiable_with_admit():
    doc = VerificationContextDocument.unverifiable(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
    )
    payload = doc.to_dict()
    payload["context"]["decision"]["admission"] = "ADMIT"
    with pytest.raises(VerificationContextValidationError):
        validate_document(payload)


def test_validate_document_rejects_non_mapping():
    with pytest.raises(VerificationContextValidationError):
        validate_document([])
