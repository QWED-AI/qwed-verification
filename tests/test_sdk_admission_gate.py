"""The SDK and the Action admit only what the server admitted (GHSA-jppc-7r58-7pjh).

``VerificationResult.from_dict`` read ``is_verified`` from the response's bare
``is_valid``. The server flattens the engine's fields into the response, so a
result a gate blocked could still carry ``is_valid: true`` and became
``is_verified=True``; the Action then emitted ``admission=ADMIT`` and passed
the CI gate. Now ``is_verified`` is the server's admission where the route
decides one, and otherwise the server's own rule (VERIFIED with ``is_valid``
true); the Action gates on it and reports the server's verdict.
"""

import sys
import types

import pytest

import action_entrypoint as entry
from qwed_new.core.diagnostics import DiagnosticResult, admission_decision, merge_diagnostic_result
from qwed_sdk import client as client_module
from qwed_sdk.models import VerificationResult, is_admitted


def _body(dr):
    body = merge_diagnostic_result(dr)
    body["admission"] = admission_decision(dr).value
    return body


@pytest.mark.parametrize("make", [DiagnosticResult.blocked, DiagnosticResult.unverifiable])
def test_a_fail_closed_result_carrying_is_valid_is_not_verified(make):
    # The advisory's proof of concept: BLOCKED (or UNVERIFIABLE) with the
    # engine's is_valid: true left in the body.
    body = _body(make("blocked by gate", {"constraint_id": "c", "is_valid": True}))

    assert (body["status"], body["admission"], body["is_valid"]) == (body["status"], "BLOCKED", True)
    assert VerificationResult.from_dict(body).is_verified is False


@pytest.mark.parametrize(
    ("data", "admitted"),
    [
        ({"status": "VERIFIED", "is_valid": True, "admission": "ADMIT"}, True),
        ({"status": "VERIFIED", "is_valid": True, "admission": "BLOCKED"}, False),
        ({"status": "VERIFIED", "is_valid": False, "admission": "BLOCKED"}, False),  # disproven
        ({"status": "BLOCKED", "is_valid": True}, False),
        ({"status": "UNVERIFIABLE", "is_valid": True}, False),
        # A route that decides no admission: the server's own rule.
        ({"status": "VERIFIED", "is_valid": True}, True),
        ({"status": "VERIFIED", "is_valid": False}, False),
        ({"status": "VERIFIED"}, False),
        ({"status": "VERIFIED", "is_valid": "true"}, False),
        # A bare is_verified or is_valid never admits on its own.
        ({"is_verified": True}, False),
        ({"is_valid": True}, False),
        ({"status": "BLOCKED", "is_verified": True, "admission": "ADMIT "}, False),
        ({}, False),
    ],
)
def test_is_verified_follows_the_servers_admission(data, admitted):
    assert is_admitted(data) is admitted
    assert VerificationResult.from_dict(data).is_verified is admitted


def test_a_verified_admitted_answer_is_still_verified():
    body = _body(DiagnosticResult.verified("2+2=4", {"is_valid": True}, evidence={"lhs": 4, "rhs": 4}))

    assert body["admission"] == "ADMIT"
    assert VerificationResult.from_dict(body).is_verified is True


@pytest.mark.parametrize(
    ("data", "status", "verified"),
    [
        ({"status": "VERIFIED", "meets_requirement": True}, "VERIFIED", True),
        ({"status": "VERIFIED", "meets_requirement": False}, "VERIFIED", False),
        ({"status": "BLOCKED", "meets_requirement": False}, "BLOCKED", False),
        ({"meets_requirement": "yes"}, "UNVERIFIED", False),
        ({"meets_requirement": 1}, "UNVERIFIED", False),
    ],
)
def test_a_consensus_answer_takes_the_servers_status_and_an_exact_requirement(monkeypatch, data, status, verified):
    client = client_module.QWEDClient(api_key="k", base_url="http://qwed.test")
    monkeypatch.setattr(client, "_request", lambda *args, **kwargs: dict(data))

    result = client.verify_consensus("2+2=4")

    assert (result.status, result.is_verified) == (status, verified)


# ---------------------------------------------------------------- the Action

def _run_verify(monkeypatch, body, fail_on_findings="true"):
    outputs = {}

    class FakeClient:
        def __init__(self, api_key):
            pass

        def verify_math(self, expression):
            return VerificationResult.from_dict(body)

    monkeypatch.setitem(sys.modules, "qwed_sdk.client", types.SimpleNamespace(QWEDClient=FakeClient))
    monkeypatch.setattr(entry, "set_output", outputs.__setitem__)
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    monkeypatch.setenv("INPUT_ACTION", "verify")
    monkeypatch.setenv("INPUT_ENGINE", "math")
    monkeypatch.setenv("INPUT_QUERY", "2+2=4")
    monkeypatch.setenv("INPUT_API_KEY", "k")
    monkeypatch.setenv("INPUT_FAIL_ON_FINDINGS", fail_on_findings)

    exit_code = 0
    try:
        entry.action_verify()
    except SystemExit as exc:
        exit_code = exc.code
    return exit_code, outputs


@pytest.mark.parametrize("make", [DiagnosticResult.blocked, DiagnosticResult.unverifiable])
def test_the_action_denies_a_blocked_result_carrying_is_valid(monkeypatch, make):
    body = _body(make("blocked by gate", {"constraint_id": "c", "is_valid": True}))

    exit_code, outputs = _run_verify(monkeypatch, body)

    assert exit_code == 1
    assert outputs["verified"] == "false"
    assert outputs["admission"] == "DENY"
    assert outputs["verdict"] == body["status"]


def test_the_action_reports_a_disproven_claim_as_verified_and_denied(monkeypatch):
    body = {"status": "VERIFIED", "is_valid": False, "admission": "BLOCKED"}

    exit_code, outputs = _run_verify(monkeypatch, body)

    assert exit_code == 1
    assert (outputs["verdict"], outputs["admission"], outputs["verified"]) == ("VERIFIED", "DENY", "false")


def test_the_action_admits_only_an_admitted_answer(monkeypatch):
    body = _body(DiagnosticResult.verified("2+2=4", {"is_valid": True}, evidence={"lhs": 4, "rhs": 4}))

    exit_code, outputs = _run_verify(monkeypatch, body)

    assert exit_code == 0
    assert (outputs["verdict"], outputs["admission"], outputs["verified"]) == ("VERIFIED", "ADMIT", "true")


def test_an_unknown_status_is_reported_as_unverifiable(monkeypatch):
    exit_code, outputs = _run_verify(monkeypatch, {"status": "SAT", "is_valid": True}, fail_on_findings="false")

    assert exit_code == 0  # fail_on_findings is off
    assert (outputs["verdict"], outputs["admission"]) == ("UNVERIFIABLE", "DENY")
