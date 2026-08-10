import json
from pathlib import Path

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
    _canonical_json,
    _es_number_to_string,
    compute_context_proof_ref,
    compute_document_proof_ref,
    is_valid_document,
    load_schema,
    resolve_context_proof_ref,
    resolve_document_proof_ref,
    validate_document,
)

DUMMY_PROOF_REF = "sha256:" + "a" * 64


def _interpretation():
    return Interpretation(theory="real-closed fields", logic="first-order")


def _proof():
    return Proof(
        verifier="SymPy",
        verifier_version="1.14.0",
        configuration={"timeout_ms": 5000},
        theory_scope="real-closed fields",
        trusted_dependencies=("sympy",),
        outcome_treatment="unknown/timeout/error resolve to UNVERIFIABLE or BLOCKED",
    )


def _context(admission=Admission.ADMIT, proof_ref=None, payload=None):
    if payload is None:
        payload = {"roots": [-2, 2]}
    return VerificationContext(
        interpretation=_interpretation(),
        proof=_proof(),
        evidence=Evidence(payload=payload, proof_ref=proof_ref),
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
        formalization=_formalization(),
    )
    doc.validate()
    assert doc.is_valid()
    payload = doc.to_dict()
    assert payload["spec_version"] == "1.0"
    assert payload["verdict"] == "VERIFIED"
    expected = compute_context_proof_ref("x**2 - 4 = 0", doc.context)
    assert payload["context"]["evidence"]["proof_ref"] == expected


def test_verified_factory_rejects_mismatched_proof_ref():
    context = _context()
    with pytest.raises(VerificationContextValidationError):
        VerificationContextDocument.verified(
            formal_statement="x**2 - 4 = 0",
            context=context,
            proof_ref=DUMMY_PROOF_REF,
        )


def test_unverifiable_factory_forces_fail_closed_defaults():
    doc = VerificationContextDocument.unverifiable(
        formal_statement="x**2 - 4 = 0",
        context=_context(admission=Admission.ADMIT, proof_ref=DUMMY_PROOF_REF),
    )
    doc.validate()
    payload = doc.to_dict()
    assert payload["verdict"] == "UNVERIFIABLE"
    assert payload["context"]["evidence"]["proof_ref"] is None
    assert payload["context"]["decision"]["admission"] == "DENY"


def test_blocked_factory_forces_fail_closed_defaults():
    doc = VerificationContextDocument.blocked(
        formal_statement="x**2 - 4 = 0",
        context=_context(admission=Admission.ADMIT, proof_ref=DUMMY_PROOF_REF),
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
    )
    doc.validate()
    assert doc.to_dict()["context"]["decision"]["admission"] == "DENY"


def test_verified_requires_proof_ref():
    verified_object = VerifiedObject(formal_statement="x**2 - 4 = 0")
    context = _context(proof_ref=None)
    with pytest.raises(VerificationContextValidationError):
        VerificationContextDocument(
            verified_object=verified_object,
            context=context,
            verdict=Verdict.VERIFIED,
        )


def test_verified_rejects_unresolved_proof_ref():
    verified_object = VerifiedObject(formal_statement="x**2 - 4 = 0")
    context = _context(proof_ref=DUMMY_PROOF_REF)
    with pytest.raises(VerificationContextValidationError):
        VerificationContextDocument(
            verified_object=verified_object,
            context=context,
            verdict=Verdict.VERIFIED,
        )


def test_fail_closed_requires_null_proof_ref():
    verified_object = VerifiedObject(formal_statement="x**2 - 4 = 0")
    context = _context(admission=Admission.DENY, proof_ref=DUMMY_PROOF_REF)
    with pytest.raises(VerificationContextValidationError):
        VerificationContextDocument(
            verified_object=verified_object,
            context=context,
            verdict=Verdict.UNVERIFIABLE,
        )


def test_fail_closed_requires_deny_admission():
    verified_object = VerifiedObject(formal_statement="x**2 - 4 = 0")
    context = _context(admission=Admission.ADMIT, proof_ref=None)
    with pytest.raises(VerificationContextValidationError):
        VerificationContextDocument(
            verified_object=verified_object,
            context=context,
            verdict=Verdict.BLOCKED,
        )


def test_formalization_verified_must_be_false():
    with pytest.raises(VerificationContextValidationError):
        Formalization(verified=True)


def test_formalization_verified_rejects_non_boolean_falsy_values():
    with pytest.raises(VerificationContextValidationError):
        Formalization(verified=0)


def test_empty_interpretation_rejected():
    with pytest.raises(VerificationContextValidationError):
        Interpretation()


def test_interpretation_rejects_empty_string():
    with pytest.raises(VerificationContextValidationError):
        Interpretation(theory="")


def test_verified_object_requires_formal_statement():
    with pytest.raises(VerificationContextValidationError):
        VerifiedObject(formal_statement="")


def test_proof_requires_verifier():
    with pytest.raises(VerificationContextValidationError):
        Proof(verifier="", verifier_version="1.14.0")


def test_proof_requires_verifier_version():
    with pytest.raises(VerificationContextValidationError):
        Proof(verifier="SymPy", verifier_version="")


def test_proof_rejects_non_object_configuration():
    with pytest.raises(VerificationContextValidationError):
        Proof(verifier="SymPy", verifier_version="1.14.0", configuration=[1])


def test_proof_rejects_invalid_trusted_dependency():
    with pytest.raises(VerificationContextValidationError):
        Proof(
            verifier="SymPy",
            verifier_version="1.14.0",
            trusted_dependencies=("sympy", ""),
        )


def test_formalization_rejects_non_numeric_confidence():
    with pytest.raises(VerificationContextValidationError):
        Formalization(translation_confidence="0.9")


def test_formalization_rejects_out_of_range_confidence():
    with pytest.raises(VerificationContextValidationError):
        Formalization(translation_confidence=1.5)


def test_formalization_rejects_non_finite_confidence():
    with pytest.raises(VerificationContextValidationError):
        Formalization(translation_confidence=float("nan"))


def test_malformed_proof_ref_rejected_by_model():
    with pytest.raises(VerificationContextValidationError):
        Evidence(payload={}, proof_ref="sha256:zzz")


def test_proof_ref_with_trailing_newline_rejected():
    with pytest.raises(VerificationContextValidationError):
        Evidence(payload={}, proof_ref=DUMMY_PROOF_REF + "\n")


def test_verified_rejects_non_roundtrip_integer_evidence():
    context = _context(payload={"value": 2**53 + 1})
    with pytest.raises(VerificationContextValidationError):
        VerificationContextDocument.verified(
            formal_statement="x**2 - 4 = 0",
            context=context,
        )


def test_verified_rejects_non_string_evidence_key():
    context = _context(payload={1: "x"})
    with pytest.raises(VerificationContextValidationError):
        VerificationContextDocument.verified(
            formal_statement="x**2 - 4 = 0",
            context=context,
        )


def test_verified_rejects_unpaired_surrogate_evidence():
    context = _context(payload={"value": chr(0xD800)})
    with pytest.raises(VerificationContextValidationError):
        VerificationContextDocument.verified(
            formal_statement="x**2 - 4 = 0",
            context=context,
        )


def test_to_dict_returns_independent_evidence_copy():
    doc = VerificationContextDocument.verified(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
    )
    payload = doc.to_dict()
    payload["context"]["evidence"]["evidence"]["roots"].append(3)
    assert doc.to_dict()["context"]["evidence"]["evidence"] == {"roots": [-2, 2]}


def test_constructor_copies_evidence_input():
    evidence_payload = {"roots": [-2, 2]}
    context = _context(payload=evidence_payload)
    doc = VerificationContextDocument.verified(
        formal_statement="x**2 - 4 = 0",
        context=context,
    )
    evidence_payload["roots"].append(3)
    assert doc.to_dict()["context"]["evidence"]["evidence"] == {"roots": [-2, 2]}


def test_constructor_copies_configuration_input():
    configuration = {"timeout_ms": 5000}
    proof = Proof(
        verifier="SymPy",
        verifier_version="1.14.0",
        configuration=configuration,
    )
    context = VerificationContext(
        interpretation=_interpretation(),
        proof=proof,
        evidence=Evidence(payload={}, proof_ref=None),
        decision=Decision(admission=Admission.ADMIT),
    )
    doc = VerificationContextDocument.verified(
        formal_statement="x**2 - 4 = 0",
        context=context,
    )
    configuration["timeout_ms"] = 1
    assert doc.to_dict()["context"]["proof"]["configuration"] == {"timeout_ms": 5000}


def test_to_dict_returns_independent_configuration_copy():
    doc = VerificationContextDocument.verified(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
    )
    payload = doc.to_dict()
    payload["context"]["proof"]["configuration"]["timeout_ms"] = 1
    assert doc.to_dict()["context"]["proof"]["configuration"] == {"timeout_ms": 5000}


def test_schema_rejects_unknown_top_level_field():
    doc = VerificationContextDocument.verified(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
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
    )
    payload = doc.to_dict()
    payload["spec_version"] = "2.0"
    with pytest.raises(VerificationContextValidationError):
        validate_document(payload)


def test_schema_rejects_malformed_proof_ref():
    doc = VerificationContextDocument.verified(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
    )
    payload = doc.to_dict()
    payload["context"]["evidence"]["proof_ref"] = "sha256:zzz"
    with pytest.raises(VerificationContextValidationError):
        validate_document(payload)


def test_schema_rejects_verified_with_null_proof_ref():
    doc = VerificationContextDocument.verified(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
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


def test_packaged_schema_matches_spec():
    spec_path = (
        Path(__file__).resolve().parents[1]
        / "spec"
        / "v1.0"
        / "schemas"
        / "verification-context.schema.json"
    )
    if not spec_path.exists():
        pytest.skip("spec schema not present")
    assert load_schema() == json.loads(spec_path.read_text(encoding="utf-8"))


def test_validate_document_rejects_forged_proof_ref():
    doc = VerificationContextDocument.verified(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
    )
    payload = doc.to_dict()
    payload["context"]["evidence"]["proof_ref"] = DUMMY_PROOF_REF
    with pytest.raises(VerificationContextValidationError):
        validate_document(payload)
    assert not is_valid_document(payload)


def test_validate_document_rejects_nan_in_evidence():
    doc = VerificationContextDocument.unverifiable(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
    )
    payload = doc.to_dict()
    payload["context"]["evidence"]["evidence"]["value"] = float("nan")
    with pytest.raises(VerificationContextValidationError):
        validate_document(payload)


def test_validate_document_rejects_positive_infinity_in_evidence():
    doc = VerificationContextDocument.unverifiable(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
    )
    payload = doc.to_dict()
    payload["context"]["evidence"]["evidence"]["value"] = float("inf")
    with pytest.raises(VerificationContextValidationError):
        validate_document(payload)


def test_validate_document_rejects_negative_infinity_in_evidence():
    doc = VerificationContextDocument.unverifiable(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
    )
    payload = doc.to_dict()
    payload["context"]["evidence"]["evidence"]["value"] = float("-inf")
    with pytest.raises(VerificationContextValidationError):
        validate_document(payload)


def test_validate_document_rejects_nan_translation_confidence():
    doc = VerificationContextDocument.unverifiable(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
        formalization=_formalization(),
    )
    payload = doc.to_dict()
    payload["object"]["formalization"]["translation_confidence"] = float("nan")
    with pytest.raises(VerificationContextValidationError):
        validate_document(payload)


def test_evidence_rejects_integer_proof_ref():
    with pytest.raises(VerificationContextValidationError):
        Evidence(payload={}, proof_ref=1)


def test_evidence_rejects_list_proof_ref():
    with pytest.raises(VerificationContextValidationError):
        Evidence(payload={}, proof_ref=[])


def test_evidence_rejects_dict_proof_ref():
    with pytest.raises(VerificationContextValidationError):
        Evidence(payload={}, proof_ref={})


def test_canonical_number_1e21_uses_exponential_form():
    assert _es_number_to_string(1e21) == "1e+21"
    assert _canonical_json(10**21) == "1e+21"


def test_evidence_payload_is_immutable():
    doc = VerificationContextDocument.verified(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
    )
    with pytest.raises(TypeError):
        doc.context.evidence.payload["roots"] = [3]


def test_configuration_is_immutable():
    doc = VerificationContextDocument.verified(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
    )
    with pytest.raises(TypeError):
        doc.context.proof.configuration["timeout_ms"] = 1


def test_document_proof_ref_producer_resolver_parity():
    doc = VerificationContextDocument.verified(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
    )
    payload = doc.to_dict()
    stored = payload["context"]["evidence"]["proof_ref"]
    assert compute_document_proof_ref(payload) == stored
    assert resolve_document_proof_ref(payload)


def test_resolver_rejects_tampered_formal_statement():
    doc = VerificationContextDocument.verified(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
    )
    payload = doc.to_dict()
    payload["object"]["formal_statement"] = "x**2 - 9 = 0"
    assert not resolve_document_proof_ref(payload)
    with pytest.raises(VerificationContextValidationError):
        validate_document(payload)


def test_resolver_rejects_tampered_admission():
    doc = VerificationContextDocument.verified(
        formal_statement="x**2 - 4 = 0",
        context=_context(admission=Admission.ADMIT),
    )
    payload = doc.to_dict()
    payload["context"]["decision"]["admission"] = "DENY"
    assert not resolve_document_proof_ref(payload)
    with pytest.raises(VerificationContextValidationError):
        validate_document(payload)


def test_resolver_rejects_tampered_evidence():
    doc = VerificationContextDocument.verified(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
    )
    payload = doc.to_dict()
    payload["context"]["evidence"]["evidence"]["roots"] = [-3, 3]
    assert not resolve_document_proof_ref(payload)
    with pytest.raises(VerificationContextValidationError):
        validate_document(payload)


def test_resolver_rejects_tampered_proof_layer():
    doc = VerificationContextDocument.verified(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
    )
    payload = doc.to_dict()
    payload["context"]["proof"]["verifier"] = "Z3"
    assert not resolve_document_proof_ref(payload)
    with pytest.raises(VerificationContextValidationError):
        validate_document(payload)


def test_document_proof_ref_fails_closed_on_non_roundtrip_integer():
    doc = VerificationContextDocument.verified(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
    )
    payload = doc.to_dict()
    payload["context"]["evidence"]["evidence"]["value"] = 2**53 + 1
    with pytest.raises(VerificationContextValidationError):
        compute_document_proof_ref(payload)
    assert not resolve_document_proof_ref(payload)


def test_document_proof_ref_fails_closed_on_non_string_key():
    doc = VerificationContextDocument.verified(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
    )
    payload = doc.to_dict()
    payload["context"]["evidence"]["evidence"] = {1: "x"}
    with pytest.raises(VerificationContextValidationError):
        compute_document_proof_ref(payload)
    assert not resolve_document_proof_ref(payload)


def test_document_proof_ref_fails_closed_on_unpaired_surrogate():
    doc = VerificationContextDocument.verified(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
    )
    payload = doc.to_dict()
    payload["context"]["evidence"]["evidence"] = {"value": chr(0xD800)}
    with pytest.raises(VerificationContextValidationError):
        compute_document_proof_ref(payload)
    assert not resolve_document_proof_ref(payload)


def test_document_proof_ref_fails_closed_on_missing_bound_fields():
    doc = VerificationContextDocument.verified(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
    )
    payload = doc.to_dict()
    del payload["context"]["evidence"]
    with pytest.raises(VerificationContextValidationError):
        compute_document_proof_ref(payload)
    assert not resolve_document_proof_ref(payload)


def test_resolver_returns_false_for_fail_closed_verdicts():
    doc = VerificationContextDocument.unverifiable(
        formal_statement="x**2 - 4 = 0",
        context=_context(),
    )
    assert not resolve_document_proof_ref(doc.to_dict())


def test_resolver_returns_false_for_non_mapping():
    assert not resolve_document_proof_ref([])


def test_context_proof_ref_resolver():
    context = _context()
    expected = compute_context_proof_ref("x**2 - 4 = 0", context)
    assert resolve_context_proof_ref("x**2 - 4 = 0", context, expected)
    assert not resolve_context_proof_ref("x**2 - 4 = 0", context, DUMMY_PROOF_REF)
    assert not resolve_context_proof_ref("x**2 - 4 = 0", context, None)


def test_context_resolver_rejects_non_string_proof_ref():
    class AlwaysEqual:
        def __eq__(self, other):
            return True

    context = _context()
    assert not resolve_context_proof_ref("x**2 - 4 = 0", context, AlwaysEqual())
    assert not resolve_context_proof_ref("x**2 - 4 = 0", context, 123)
    assert not resolve_context_proof_ref("x**2 - 4 = 0", context, [])


def test_context_resolver_rejects_malformed_context():
    assert not resolve_context_proof_ref("x", {}, DUMMY_PROOF_REF)


def test_compute_document_proof_ref_rejects_non_mapping():
    with pytest.raises(VerificationContextValidationError):
        compute_document_proof_ref([])


def test_resolver_rejects_schema_invalid_document_even_if_commitment_matches():
    minimal = {
        "spec_version": "1.0",
        "object": {"formal_statement": "x"},
        "context": {"evidence": {"evidence": {}, "proof_ref": None}},
        "verdict": "VERIFIED",
    }
    minimal["context"]["evidence"]["proof_ref"] = compute_document_proof_ref(minimal)
    assert not resolve_document_proof_ref(minimal)
    with pytest.raises(VerificationContextValidationError):
        validate_document(minimal)


def test_context_resolver_rejects_non_string_formal_statement():
    context = _context()
    expected = compute_context_proof_ref("x**2 - 4 = 0", context)
    assert not resolve_context_proof_ref(1, context, expected)
