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
import math
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


def _es_number_to_string(value):
    """Serialize a finite IEEE-754 double per ECMAScript Number::toString."""
    neg = value < 0
    ax = abs(value)
    r = repr(ax)  # shortest round-trip decimal for the double
    if "e" in r:
        mant, exp_s = r.split("e")
        e10 = int(exp_s)
    else:
        mant = r
        e10 = 0
    if "." in mant:
        ip, fp = mant.split(".")
        coeff = int(ip + fp) if (ip + fp).lstrip("0") else 0
        e10 -= len(fp)
    else:
        coeff = int(mant)
    # Strip trailing zeros from the coefficient, adjusting the exponent.
    while coeff > 0 and coeff % 10 == 0:
        coeff //= 10
        e10 += 1
    if coeff == 0:
        return "0"
    s_digits = str(coeff)
    k = len(s_digits)
    n = e10 + k  # value == coeff * 10**(n - k)
    if k <= n <= 21:
        out = s_digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = s_digits[:n] + "." + s_digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + s_digits
    else:
        exp = n - 1
        sign = "+" if exp >= 0 else "-"
        if k == 1:
            out = s_digits + "e" + sign + str(abs(exp))
        else:
            out = s_digits[0] + "." + s_digits[1:] + "e" + sign + str(abs(exp))
    return ("-" if neg else "") + out


def _reject_unpaired_surrogates(value):
    for ch in value:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise ValueError(
                f"unpaired UTF-16 surrogate not allowed in proof_ref payload: {value!r}"
            )


def _canonical_json(value):
    """Serialize a value to canonical JSON per RFC 8785 (JCS)."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        try:
            as_float = float(value)
        except OverflowError as exc:
            raise ValueError(
                f"integer not representable as IEEE-754 double: {value!r}"
            ) from exc
        if int(as_float) != value:
            raise ValueError(
                f"integer not representable as IEEE-754 double: {value!r}"
            )
        return _es_number_to_string(as_float)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(
                f"non-finite number not allowed in proof_ref payload: {value!r}"
            )
        return _es_number_to_string(value)
    if isinstance(value, str):
        _reject_unpaired_surrogates(value)
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical_json(v) for v in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise ValueError(
                    f"non-string object key not allowed in proof_ref payload: {key!r}"
                )
            _reject_unpaired_surrogates(key)
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return (
            "{"
            + ",".join(
                json.dumps(k, ensure_ascii=False) + ":" + _canonical_json(v)
                for k, v in items
            )
            + "}"
        )
    raise ValueError(f"unsupported type in proof_ref payload: {type(value).__name__}")


def _canonical_proof_ref(doc):
    """Compute proof_ref per the spec (verification-context.md, section 3.3).

    The bound payload is the formal statement + the complete Verification Context,
    with ``context.evidence.proof_ref`` itself EXCLUDED (the commitment cannot
    include itself). Note ``object.formalization`` is deliberately NOT part of the
    bound payload — the commitment binds the formal statement, not how it was
    derived. Producers and resolvers must both apply this payload definition. The
    payload is serialized with the RFC 8785 canonical encoding.
    """
    bound = {
        "formal_statement": doc["object"]["formal_statement"],
        "context": copy.deepcopy(doc["context"]),
    }
    bound["context"]["evidence"].pop("proof_ref", None)
    payload = _canonical_json(bound)
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


def test_negative_zero_canonicalizes_to_zero():
    """0 and -0 must commit identically (negative zero normalizes to 0)."""
    assert _canonical_json(-0.0) == _canonical_json(0) == "0"
    doc_pos = _verified_doc()
    doc_pos["context"]["evidence"]["evidence"] = {"value": 0.0}
    doc_neg = _verified_doc()
    doc_neg["context"]["evidence"]["evidence"] = {"value": -0.0}
    assert _canonical_proof_ref(doc_pos) == _canonical_proof_ref(doc_neg)


def test_large_integer_canonical_form():
    """Representable integer doubles serialize per ECMAScript Number::toString."""
    assert _canonical_json(1e21) == _canonical_json(10**21) == "1e+21"
    doc_float = _verified_doc()
    doc_float["context"]["evidence"]["evidence"] = {"value": 1e21}
    doc_int = _verified_doc()
    doc_int["context"]["evidence"]["evidence"] = {"value": 10**21}
    assert _canonical_proof_ref(doc_float) == _canonical_proof_ref(doc_int)


def test_precision_sensitive_decimal_deterministic():
    """A non-integer float commits deterministically (golden vector)."""
    doc = _verified_doc()
    doc["context"]["evidence"]["evidence"] = {"value": 3.141592653589793}
    first = _canonical_proof_ref(doc)
    second = _canonical_proof_ref(doc)
    assert first == second
    assert first.startswith("sha256:")


def test_canonical_proof_ref_rejects_nan():
    doc = _verified_doc()
    doc["context"]["evidence"]["evidence"] = {"value": float("nan")}
    with pytest.raises(ValueError):
        _canonical_proof_ref(doc)


def test_canonical_proof_ref_rejects_infinity():
    doc = _verified_doc()
    doc["context"]["evidence"]["evidence"] = {"value": float("inf")}
    with pytest.raises(ValueError):
        _canonical_proof_ref(doc)


def test_canonical_proof_ref_rejects_negative_infinity():
    doc = _verified_doc()
    doc["context"]["evidence"]["evidence"] = {"value": float("-inf")}
    with pytest.raises(ValueError):
        _canonical_proof_ref(doc)


# --- RFC 8785 / ECMAScript number encoding golden vectors --------------------

def test_canonical_json_exponent_golden_vectors():
    """Non-integer floats use ECMAScript Number::toString, not Python repr.

    Python's json.dumps emits 1e-07 / 1e-06; RFC 8785 requires 1e-7 / 0.000001.
    These byte-level vectors pin the cross-language canonical form.
    """
    assert _canonical_json(1e-7) == "1e-7"
    assert _canonical_json(1e-6) == "0.000001"
    assert _canonical_json(3.141592653589793) == "3.141592653589793"
    assert _canonical_json(-1e-7) == "-1e-7"
    assert _canonical_json(1.5e-7) == "1.5e-7"


def test_canonical_json_integer_golden_vectors():
    """Finite IEEE-754 numbers serialize per ECMAScript Number::toString."""
    assert _canonical_json(1) == "1"
    assert _canonical_json(1.0) == "1"
    assert _canonical_json(0) == "0"
    assert _canonical_json(-0.0) == "0"
    assert _canonical_json(10**21) == "1e+21"
    assert _canonical_json(1e21) == "1e+21"


def test_canonical_json_equivalent_floats_commit_identically():
    """1e-6 and 0.000001 (the same double) commit identically."""
    doc_a = _verified_doc()
    doc_a["context"]["evidence"]["evidence"] = {"value": 1e-6}
    doc_b = _verified_doc()
    doc_b["context"]["evidence"]["evidence"] = {"value": 0.000001}
    assert _canonical_proof_ref(doc_a) == _canonical_proof_ref(doc_b)


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


def test_canonical_json_rejects_non_roundtrip_integer():
    with pytest.raises(ValueError):
        _canonical_json(2**53 + 1)


def test_canonical_json_rejects_overflowing_integer():
    with pytest.raises(ValueError):
        _canonical_json(10**400)


def test_canonical_json_rejects_non_string_keys():
    with pytest.raises(ValueError):
        _canonical_json({1: 1})


def test_canonical_json_key_order_utf16():
    high = chr(0x10000)
    low = chr(0xE000)
    value = {low: 1, high: 2}
    expected = (
        "{"
        + json.dumps(high, ensure_ascii=False)
        + ":2,"
        + json.dumps(low, ensure_ascii=False)
        + ":1}"
    )
    assert _canonical_json(value) == expected


def test_verified_proof_ref_binds_admission():
    doc = _verified_doc()
    stored = doc["context"]["evidence"]["proof_ref"]
    doc["context"]["decision"]["admission"] = "DENY"
    assert _canonical_proof_ref(doc) != stored


def test_canonical_json_rejects_unpaired_surrogate_string():
    with pytest.raises(ValueError):
        _canonical_json(chr(0xD800))


def test_canonical_json_rejects_unpaired_surrogate_key():
    with pytest.raises(ValueError):
        _canonical_json({chr(0xD800): 1})


def test_canonical_json_accepts_valid_supplementary_character():
    ch = chr(0x1F600)
    assert _canonical_json(ch) == json.dumps(ch, ensure_ascii=False)


def test_evidence_with_non_roundtrip_integer_rejected(schema):
    doc = _verified_doc()
    doc["context"]["evidence"]["evidence"] = {"value": 2**53 + 1}
    assert not _validated(schema, doc)


def test_evidence_with_nested_non_roundtrip_integer_rejected(schema):
    doc = _verified_doc()
    doc["context"]["evidence"]["evidence"] = {"nested": {"value": 2**53 + 1}}
    assert not _validated(schema, doc)


def test_proof_configuration_with_non_roundtrip_integer_rejected(schema):
    doc = _verified_doc()
    doc["context"]["proof"]["configuration"] = {"value": 2**53 + 1}
    assert not _validated(schema, doc)


def test_evidence_with_representable_integer_accepted(schema):
    doc = _verified_doc()
    doc["context"]["evidence"]["evidence"] = {"value": 2**53}
    assert _validated(schema, doc)
