"""Coverage for qwed_sdk/__init__.py re-exports."""

import importlib
import sys

import pytest


def test_sdk_init_module_executes():
    """Force re-execution of qwed_sdk/__init__.py module-level code for coverage."""
    if "qwed_sdk" in sys.modules:
        importlib.reload(sys.modules["qwed_sdk"])
    else:
        from qwed_sdk import __version__ as _  # noqa: F401
    from qwed_sdk import __all__ as sdk_all, __version__ as sdk_version
    assert sdk_all is not None
    assert sdk_version == "7.1.0"


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
        VerificationContextValidationError,
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
    with pytest.raises(VerificationContextValidationError):
        validate_document({})


def test_sdk_init_all_list_complete():
    from qwed_sdk import __all__ as sdk_all
    from qwed_sdk import (
        QWEDClient,
        QWEDAsyncClient,
        QWEDLocal,
        VerificationResult,
        BatchResult,
        VerificationType,
        Verdict,
        Admission,
        VerificationContext,
        VerificationContextDocument,
        VerificationContextValidationError,
        Formalization,
        VerifiedObject,
        Interpretation,
        Proof,
        Evidence,
        Decision,
        compute_context_proof_ref,
        compute_document_proof_ref,
        resolve_document_proof_ref,
        resolve_context_proof_ref,
        validate_document,
        is_valid_document,
    )
    exported = {
        "QWEDClient": QWEDClient,
        "QWEDAsyncClient": QWEDAsyncClient,
        "QWEDLocal": QWEDLocal,
        "VerificationResult": VerificationResult,
        "BatchResult": BatchResult,
        "VerificationType": VerificationType,
        "Verdict": Verdict,
        "Admission": Admission,
        "VerificationContext": VerificationContext,
        "VerificationContextDocument": VerificationContextDocument,
        "VerificationContextValidationError": VerificationContextValidationError,
        "Formalization": Formalization,
        "VerifiedObject": VerifiedObject,
        "Interpretation": Interpretation,
        "Proof": Proof,
        "Evidence": Evidence,
        "Decision": Decision,
        "compute_context_proof_ref": compute_context_proof_ref,
        "compute_document_proof_ref": compute_document_proof_ref,
        "resolve_document_proof_ref": resolve_document_proof_ref,
        "resolve_context_proof_ref": resolve_context_proof_ref,
        "validate_document": validate_document,
        "is_valid_document": is_valid_document,
    }
    for name, obj in exported.items():
        assert name in sdk_all, f"{name} missing from __all__"
        assert obj is not None, f"{name} is None"


def test_sdk_init_is_valid_document_returns_false_for_invalid():
    from qwed_sdk import is_valid_document
    assert is_valid_document({}) is False
    assert is_valid_document({"spec_version": "99.0"}) is False


def test_sdk_init_resolve_document_proof_ref_returns_false_for_invalid():
    from qwed_sdk import resolve_document_proof_ref
    assert resolve_document_proof_ref({}) is False
    assert resolve_document_proof_ref({"verdict": "BLOCKED"}) is False


def test_sdk_init_get_langchain_tools():
    from qwed_sdk import get_langchain_tools
    try:
        tools = get_langchain_tools()
        assert "QWEDTool" in tools
    except ImportError as exc:
        pytest.skip(f"langchain is optional: {exc}")


def test_sdk_init_get_llamaindex_tools():
    from qwed_sdk import get_llamaindex_tools
    try:
        tools = get_llamaindex_tools()
        assert "QWEDQueryEngine" in tools
    except ImportError as exc:
        pytest.skip(f"llamaindex is optional: {exc}")


def test_sdk_init_get_crewai_tools():
    from qwed_sdk import get_crewai_tools
    try:
        tools = get_crewai_tools()
        assert "QWEDVerificationTool" in tools
    except ImportError as exc:
        pytest.skip(f"crewai is optional: {exc}")