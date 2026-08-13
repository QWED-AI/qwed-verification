"""Coverage for qwed_sdk/__init__.py re-exports."""

import pytest


def test_sdk_init_exports_verdict_enum():
    from qwed_sdk import Verdict
    assert Verdict.VERIFIED.value == "VERIFIED"
    assert Verdict.UNVERIFIABLE.value == "UNVERIFIABLE"
    assert Verdict.BLOCKED.value == "BLOCKED"
    assert len(Verdict) == 3


def test_sdk_init_exports_admission_enum():
    from qwed_sdk import Admission
    assert Admission.ADMIT.value == "ADMIT"
    assert Admission.DENY.value == "DENY"
    assert len(Admission) == 2


def test_sdk_init_exports_model_classes():
    from qwed_sdk import (
        VerificationContext,
        VerificationContextDocument,
        Formalization,
        VerifiedObject,
        Interpretation,
        Proof,
        Evidence,
        Decision,
    )
    assert VerificationContext is not None
    assert VerificationContextDocument is not None
    assert Formalization is not None
    assert VerifiedObject is not None
    assert Interpretation is not None
    assert Proof is not None
    assert Evidence is not None
    assert Decision is not None


def test_sdk_init_exports_validation_error():
    from qwed_sdk import VerificationContextValidationError
    assert issubclass(VerificationContextValidationError, ValueError)
    err = VerificationContextValidationError("test")
    assert str(err) == "test"


def test_sdk_init_exports_proof_functions():
    from qwed_sdk import (
        compute_context_proof_ref,
        compute_document_proof_ref,
        resolve_document_proof_ref,
        resolve_context_proof_ref,
        validate_document,
        is_valid_document,
    )
    assert callable(compute_context_proof_ref)
    assert callable(compute_document_proof_ref)
    assert callable(resolve_document_proof_ref)
    assert callable(resolve_context_proof_ref)
    assert callable(validate_document)
    assert callable(is_valid_document)


def test_sdk_init_all_list_complete():
    import qwed_sdk
    expected = [
        "QWEDClient",
        "QWEDAsyncClient",
        "QWEDLocal",
        "VerificationResult",
        "BatchResult",
        "VerificationType",
        "Verdict",
        "Admission",
        "VerificationContext",
        "VerificationContextDocument",
        "VerificationContextValidationError",
        "Formalization",
        "VerifiedObject",
        "Interpretation",
        "Proof",
        "Evidence",
        "Decision",
        "compute_context_proof_ref",
        "compute_document_proof_ref",
        "resolve_document_proof_ref",
        "resolve_context_proof_ref",
        "validate_document",
        "is_valid_document",
    ]
    for name in expected:
        assert name in qwed_sdk.__all__, f"{name} missing from __all__"
        assert hasattr(qwed_sdk, name), f"{name} not accessible on qwed_sdk"


def test_sdk_init_is_valid_document_returns_false_for_invalid():
    from qwed_sdk import is_valid_document
    assert is_valid_document({}) is False
    assert is_valid_document({"spec_version": "99.0"}) is False


def test_sdk_init_resolve_document_proof_ref_returns_false_for_invalid():
    from qwed_sdk import resolve_document_proof_ref
    assert resolve_document_proof_ref({}) is False
    assert resolve_document_proof_ref({"verdict": "BLOCKED"}) is False
