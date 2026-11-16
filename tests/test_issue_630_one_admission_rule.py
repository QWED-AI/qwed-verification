"""#630: admission was decided by four rules, and the general one ignored translation scope.

- ``admission_decision`` admitted any VERIFIED result with ``is_valid`` true,
  so a natural-language maths result (VERIFIED, ``is_valid`` true,
  ``query_semantics_verified`` false) was admitted by every caller that used
  it: the Verification Context bridge, and the SDK's fallback rule for a
  response without its ``admission`` key.
- ``claim_verified`` read a missing ``query_semantics_verified`` as true, so a
  translation route that forgot to set it would be verified and admitted.
- The natural-language result set ``is_valid: true`` for the model's
  translated expression, which reads as a valid claim to anything that looks
  at ``is_valid``.

Now ``admission_decision`` is ``claim_verified`` plus authority, every
translation engine's VERIFIED result records its scope before it is signed,
and the natural-language result carries no ``is_valid`` when the expression
holds.
"""

import json

import pytest

from qwed_new.core.attestation import create_verification_attestation, get_attestation_service
from qwed_new.core.control_plane import ControlPlane, natural_language_admission
from qwed_new.core.diagnostics import (
    AdmissionDecision,
    DiagnosticResult,
    admission_decision,
    claim_verified,
)
from qwed_new.core.trust import attest_and_enforce
from qwed_new.core.verification_context_bridge import verification_context_from_diagnostic_result
from qwed_sdk.models import VerificationResult, is_admitted

EXPRESSION = "2+3"
PROOF_DATA = json.dumps({"expression": EXPRESSION, "calculated_value": 5}, sort_keys=True)


def _verified(fields):
    return DiagnosticResult.verified(
        "verified",
        developer_fields=fields,
        evidence={"expression": EXPRESSION, "calculated_value": 5},
        proof_data=PROOF_DATA,
    )


def _translated(**extra):
    """The shape a natural-language maths verdict had on main."""
    return _verified({
        "is_valid": True,
        "translated_expression": EXPRESSION,
        "verification_scope": "translated_expression_only",
        "query_semantics_verified": False,
        **extra,
    })


@pytest.mark.parametrize(
    ("fields", "decision"),
    [
        # A verdict on the model's translation: never admitted.
        ({"is_valid": True, "query_semantics_verified": False}, AdmissionDecision.BLOCKED),
        # Only a real True counts.
        ({"is_valid": True, "query_semantics_verified": "true"}, AdmissionDecision.BLOCKED),
        ({"is_valid": True, "query_semantics_verified": 1}, AdmissionDecision.BLOCKED),
        ({"is_valid": True, "query_semantics_verified": None}, AdmissionDecision.BLOCKED),
        # A result that says it covers a translation must say its meaning was
        # checked: the missing field is not read as true (CodeRabbit).
        ({"is_valid": True, "verification_scope": "translated_expression_only"}, AdmissionDecision.BLOCKED),
        (
            {"is_valid": True, "verification_scope": "translated_expression_only", "query_semantics_verified": True},
            AdmissionDecision.ADMIT,
        ),
        # The meaning was checked: admitted.
        ({"is_valid": True, "query_semantics_verified": True}, AdmissionDecision.ADMIT),
        # A direct engine on the caller's own input: unchanged.
        ({"is_valid": True}, AdmissionDecision.ADMIT),
        ({"is_valid": False}, AdmissionDecision.BLOCKED),
        ({}, AdmissionDecision.BLOCKED),
    ],
)
def test_admission_decision_is_claim_verified_plus_authority(fields, decision):
    dr = _verified(fields)

    assert admission_decision(dr) is decision
    assert (decision is AdmissionDecision.ADMIT) is claim_verified(dr)


def test_admission_decision_agrees_with_the_translation_rule():
    dr = _translated()

    assert admission_decision(dr) is natural_language_admission(dr) is AdmissionDecision.BLOCKED


def test_the_verification_context_bridge_does_not_admit_a_translated_verdict():
    token = create_verification_attestation(
        status="VERIFIED",
        verified=False,
        engine="natural_language",
        query=EXPRESSION,
        proof_data=PROOF_DATA,
    )
    assert token.is_issued

    payload = verification_context_from_diagnostic_result(
        _translated(),
        formal_statement=EXPRESSION,
        verifier="SymPy",
        attestation_token=token.token,
    ).to_dict()

    assert payload["verdict"] == "VERIFIED"
    assert payload["context"]["decision"]["admission"] == "DENY"


@pytest.mark.parametrize(
    ("data", "admitted"),
    [
        ({"status": "VERIFIED", "is_valid": True, "query_semantics_verified": False}, False),
        ({"status": "VERIFIED", "is_valid": True, "query_semantics_verified": "true"}, False),
        ({"status": "VERIFIED", "is_valid": True, "query_semantics_verified": True}, True),
        ({"status": "VERIFIED", "is_valid": True, "verification_scope": "translated_expression_only"}, False),
        (
            {"status": "VERIFIED", "is_valid": True, "verification_scope": "translated_expression_only",
             "query_semantics_verified": True},
            True,
        ),
        ({"status": "VERIFIED", "is_valid": True}, True),
        # The route's own admission still decides when it is present.
        ({"status": "VERIFIED", "is_valid": True, "query_semantics_verified": False, "admission": "BLOCKED"}, False),
    ],
)
def test_the_sdk_fallback_reads_the_translation_scope(data, admitted):
    assert is_admitted(data) is admitted
    assert VerificationResult.from_dict(data).is_verified is admitted


@pytest.mark.parametrize("engine", ["natural_language", "logic", "consensus"])
def test_a_translation_verdict_without_its_scope_is_not_verified(engine):
    # The shape a translation route would build if it forgot its scope.
    dr = _verified({"is_valid": True})

    signed = attest_and_enforce(dr, engine=engine, query="What is 2+3?", admission=admission_decision)

    assert signed.status.value == "VERIFIED"
    assert signed.developer_fields["query_semantics_verified"] is False
    assert claim_verified(signed) is False
    assert admission_decision(signed) is AdmissionDecision.BLOCKED
    claims = get_attestation_service().verify_attestation(signed.attestation)[1]["qwed"]
    assert claims["result"]["verified"] is False
    assert claims["admission"] == "BLOCKED"


@pytest.mark.parametrize("engine", ["natural_language", "logic", "consensus"])
def test_a_recorded_scope_is_kept_as_produced(engine):
    signed = attest_and_enforce(
        _verified({"is_valid": True, "query_semantics_verified": True}),
        engine=engine,
        query="What is 2+3?",
        admission=admission_decision,
    )

    assert signed.developer_fields["query_semantics_verified"] is True
    assert admission_decision(signed) is AdmissionDecision.ADMIT


@pytest.mark.parametrize("engine", ["math", "code", "sql", "image"])
def test_a_direct_engine_verdict_is_not_given_a_translation_scope(engine):
    signed = attest_and_enforce(_verified({"is_valid": True}), engine=engine, query="2+3 = 5", admission=admission_decision)

    assert "query_semantics_verified" not in signed.developer_fields
    assert admission_decision(signed) is AdmissionDecision.ADMIT


def test_a_held_translated_expression_carries_no_is_valid():
    dr, _ = ControlPlane._math_diagnostic(
        EXPRESSION,
        {
            "status": "VERIFIED",
            "is_correct": True,
            "calculated_value": 5,
            "claimed_value": 5,
            "query_semantics_verified": False,
        },
    )

    assert dr.status.value == "VERIFIED"
    assert "is_valid" not in dr.developer_fields
    assert claim_verified(dr) is False
    assert admission_decision(dr) is AdmissionDecision.BLOCKED


def test_a_disproven_translated_expression_is_still_proven_false():
    dr, _ = ControlPlane._math_diagnostic(
        EXPRESSION,
        {
            "status": "DISPROVEN",
            "is_correct": False,
            "calculated_value": 5,
            "claimed_value": 4,
            "query_semantics_verified": False,
        },
    )

    assert dr.status.value == "VERIFIED"
    assert dr.developer_fields["is_valid"] is False
    assert admission_decision(dr) is AdmissionDecision.BLOCKED
