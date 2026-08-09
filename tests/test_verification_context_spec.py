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
import json
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "spec" / "v1.0" / "schemas" / "verification-context.schema.json"

PROOF = "sha256:" + "a" * 64


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


def _verified_doc():
    return {
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
                "proof_ref": PROOF,
            },
            "decision": {"admission": "ADMIT"},
        },
        "verdict": "VERIFIED",
    }


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
