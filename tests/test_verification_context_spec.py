"""Conformance tests for the QWED Verification Context Specification v1.0.

Validates example Verification Context documents against the normative JSON
Schema (spec/v1.0/schemas/verification-context.schema.json), proving the schema
is machine-checkable and that the load-bearing invariants hold:

  - VERIFIED      -> proof_ref present and matches ^sha256:[a-f0-9]{64}$
  - UNVERIFIABLE  -> proof_ref is null
  - BLOCKED       -> proof_ref is null
  - admission     in {ADMIT, DENY}
  - object.formal_statement required
  - object.formalization.verified is always false
"""

import copy
import hashlib
import json
from pathlib import Path

import jsonschema
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "spec" / "v1.0" / "schemas" / "verification-context.schema.json"


@pytest.fixture(scope="module")
def schema():
    with open(SCHEMA_PATH, encoding="utf-8") as f:
        return json.load(f)


def _validated(schema, doc):
    """Return True if doc validates against the schema, else False."""
    try:
        jsonschema.validate(instance=doc, schema=schema)
        return True
    except jsonschema.ValidationError:
        return False


def _canonicalize_numbers(value):
    """Normalize numbers so equivalent values commit identically.

    JSON does not distinguish ``1`` and ``1.0`` semantically, but they serialize
    to different bytes. Normalizing integer-valued floats to integers gives a
    unique canonical form (spec section 3.3, canonical encoding).
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, dict):
        return {k: _canonicalize_numbers(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonicalize_numbers(v) for v in value]
    return value


def _canonical_proof_ref(doc):
    """Compute proof_ref per the spec (verification-context.md, section 3.3).

    The bound payload is the formal statement + the complete Verification Context,
    with ``context.evidence.proof_ref`` itself EXCLUDED (the commitment cannot
    include itself). Note ``object.formalization`` is deliberately NOT part of the
    bound payload — the commitment binds the formal statement, not how it was
    derived. Producers and resolvers must both apply this payload definition.
    """
    bound = {
        "formal_statement": doc["object"]["formal_statement"],
        "context": copy.deepcopy(doc["context"]),
    }
    bound["context"]["evidence"].pop("proof_ref", None)
    bound = _canonicalize_numbers(bound)
    payload = json.dumps(bound, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _verified_doc():
    doc = {
        "spec_version": "1.0",
        "object": {
            "formal_statement": "x**2 - 4 = 0",
            "formalization": {
                "source_query": "Is x squared minus four zero?",
                "translator": "qwed-translator",
                "translation_confidence": 0.9,
                "verified": False,
            },
        },
        "context": {
            "interpretation": {"theory": "real-closed fields", "logic": "first-order"},
            "proof": {
                "verifier": "SymPy",
                "verifier_version": "1.14.0",
                "configuration": {"timeout_ms": 5000},
                "theory_scope": "real-closed fields",
                "trusted_dependencies": ["sympy"],
                "outcome_treatment": "unknown/timeout/error resolve to UNVERIFIABLE or BLOCKED",
            },
            "evidence": {
                "evidence": {"roots": [-2, 2]},
            },
            "decision": {"admission": "ADMIT"},
        },
        "verdict": "VERIFIED",
    }
    # Derive proof_ref from the canonical payload (content-bound), not a constant.
    doc["context"]["evidence"]["proof_ref"] = _canonical_proof_ref(doc)
    return doc


def test_schema_is_valid_json_schema(schema):
    # The schema itself must be a valid JSON Schema document.
    jsonschema.Draft202012Validator.check_schema(schema)


def test_verified_document_valid(schema):
    assert _validated(schema, _verified_doc())


def test_unverifiable_document_valid(schema):
    doc = _verified_doc()
    doc["verdict"] = "UNVERIFIABLE"
    doc["context"]["evidence"]["proof_ref"] = None
    doc["context"]["decision"]["admission"] = "DENY"
    assert _validated(schema, doc)


def test_blocked_document_valid(schema):
    doc = _verified_doc()
    doc["verdict"] = "BLOCKED"
    doc["context"]["evidence"]["proof_ref"] = None
    doc["context"]["decision"]["admission"] = "DENY"
    assert _validated(schema, doc)


def test_verified_without_proof_ref_rejected(schema):
    doc = _verified_doc()
    doc["context"]["evidence"]["proof_ref"] = None
    assert not _validated(schema, doc)


def test_verified_with_missing_proof_ref_rejected(schema):
    doc = _verified_doc()
    del doc["context"]["evidence"]["proof_ref"]
    assert not _validated(schema, doc)


def test_unverifiable_with_nonnull_proof_ref_rejected(schema):
    doc = _verified_doc()
    doc["verdict"] = "UNVERIFIABLE"
    # proof_ref left non-null -> must be rejected
    assert not _validated(schema, doc)


def test_malformed_proof_ref_rejected(schema):
    doc = _verified_doc()
    doc["context"]["evidence"]["proof_ref"] = "sha256:zzz"  # not 64 hex chars
    assert not _validated(schema, doc)


def test_missing_formal_statement_rejected(schema):
    doc = _verified_doc()
    del doc["object"]["formal_statement"]
    assert not _validated(schema, doc)


def test_formalization_marked_verified_rejected(schema):
    doc = _verified_doc()
    doc["object"]["formalization"]["verified"] = True
    assert not _validated(schema, doc)


def test_invalid_admission_rejected(schema):
    doc = _verified_doc()
    doc["context"]["decision"]["admission"] = "MAYBE"
    assert not _validated(schema, doc)


def test_invalid_verdict_rejected(schema):
    doc = _verified_doc()
    doc["verdict"] = "PROBABLY"
    assert not _validated(schema, doc)


def test_missing_context_layer_rejected(schema):
    doc = _verified_doc()
    del doc["context"]["decision"]
    assert not _validated(schema, doc)


def test_unknown_top_level_field_rejected(schema):
    doc = _verified_doc()
    doc["unexpected"] = True
    assert not _validated(schema, doc)


def test_wrong_spec_version_rejected(schema):
    doc = _verified_doc()
    doc["spec_version"] = "2.0"
    assert not _validated(schema, doc)


# --- proof_ref is content-bound (spec section 3.3) ---------------------------

def test_verified_proof_ref_is_content_bound(schema):
    """The fixture's proof_ref must resolve against its own payload."""
    doc = _verified_doc()
    assert doc["context"]["evidence"]["proof_ref"] == _canonical_proof_ref(doc)
    assert _validated(schema, doc)


def test_verified_proof_ref_mismatch_detected(schema):
    """Tampering with the bound payload must change the commitment (mismatch)."""
    doc = _verified_doc()
    stored = doc["context"]["evidence"]["proof_ref"]
    # Tamper with a bound field after the commitment was made.
    doc["object"]["formal_statement"] = "x**2 - 9 = 0"
    assert _canonical_proof_ref(doc) != stored


# --- fail-closed verdicts must carry an explicit null proof_ref --------------

def test_unverifiable_missing_proof_ref_rejected(schema):
    doc = _verified_doc()
    doc["verdict"] = "UNVERIFIABLE"
    doc["context"]["decision"]["admission"] = "DENY"
    del doc["context"]["evidence"]["proof_ref"]
    assert not _validated(schema, doc)


def test_blocked_missing_proof_ref_rejected(schema):
    doc = _verified_doc()
    doc["verdict"] = "BLOCKED"
    doc["context"]["decision"]["admission"] = "DENY"
    del doc["context"]["evidence"]["proof_ref"]
    assert not _validated(schema, doc)


# --- fail-closed verdicts must DENY admission --------------------------------

def test_unverifiable_with_admit_rejected(schema):
    doc = _verified_doc()
    doc["verdict"] = "UNVERIFIABLE"
    doc["context"]["evidence"]["proof_ref"] = None
    doc["context"]["decision"]["admission"] = "ADMIT"
    assert not _validated(schema, doc)


def test_blocked_with_admit_rejected(schema):
    doc = _verified_doc()
    doc["verdict"] = "BLOCKED"
    doc["context"]["evidence"]["proof_ref"] = None
    doc["context"]["decision"]["admission"] = "ADMIT"
    assert not _validated(schema, doc)


# --- interpretation must be non-empty ----------------------------------------

def test_empty_interpretation_rejected(schema):
    doc = _verified_doc()
    doc["context"]["interpretation"] = {}
    assert not _validated(schema, doc)


def test_empty_string_interpretation_rejected(schema):
    """An interpretation field present but empty must not satisfy the layer."""
    doc = _verified_doc()
    doc["context"]["interpretation"] = {"theory": ""}
    assert not _validated(schema, doc)


# --- canonical number representation -----------------------------------------

def test_numeric_canonicalization_equal_values_commit_identically():
    """Equivalent numbers (1 and 1.0) must commit identically (spec 3.3)."""
    doc_int = _verified_doc()
    doc_int["context"]["evidence"]["evidence"] = {"value": 1}
    doc_float = _verified_doc()
    doc_float["context"]["evidence"]["evidence"] = {"value": 1.0}
    assert _canonical_proof_ref(doc_int) == _canonical_proof_ref(doc_float)


def test_distinct_numbers_commit_differently():
    doc_one = _verified_doc()
    doc_one["context"]["evidence"]["evidence"] = {"value": 1}
    doc_two = _verified_doc()
    doc_two["context"]["evidence"]["evidence"] = {"value": 2}
    assert _canonical_proof_ref(doc_one) != _canonical_proof_ref(doc_two)


# --- commitment binds the formal statement, not the formalization ------------

def test_formalization_excluded_from_commitment():
    """Changing object.formalization must not change the commitment (spec 3.3)."""
    doc_a = _verified_doc()
    doc_b = _verified_doc()
    doc_b["object"]["formalization"]["translator"] = "a-different-translator"
    assert _canonical_proof_ref(doc_a) == _canonical_proof_ref(doc_b)


# --- documented engine-specific interpretation fields ------------------------

def test_code_interpretation_fields_accepted(schema):
    """Code contexts use language + policy_version (spec 3.1)."""
    doc = _verified_doc()
    doc["context"]["interpretation"] = {"language": "python", "policy_version": "1.0"}
    assert _validated(schema, doc)


def test_sql_interpretation_fields_accepted(schema):
    """SQL contexts use dialect + parser_version (spec 3.1)."""
    doc = _verified_doc()
    doc["context"]["interpretation"] = {"dialect": "postgres", "parser_version": "0.21"}
    assert _validated(schema, doc)


def test_undocumented_interpretation_field_rejected(schema):
    doc = _verified_doc()
    doc["context"]["interpretation"] = {"theory": "arithmetic", "bogus_field": "x"}
    assert not _validated(schema, doc)
