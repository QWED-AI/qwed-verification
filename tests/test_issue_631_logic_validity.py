"""#631: /verify/logic decided satisfiability, never validity.

Every question was translated into constraints with the goal
``SATISFIABILITY``, and a satisfiable set was VERIFIED: "Prove x > 5 implies
x > 10" came back VERIFIED with x = 11, though the claim fails for x = 6.

The translation now separates what the question takes as given (the
constraints) from what it asks to prove (the claim), and the route decides
the claim for every value of the variables:

- VALID (the claim follows) is VERIFIED;
- INVALID is proven false, with the counterexample;
- VACUOUS (constraints that cannot hold together) and constraints with no
  claim are UNVERIFIABLE: one satisfying assignment proves nothing.

Admission is unchanged: a logic verdict is reached on a model's translation,
so it is not admitted (#320, #585).
"""

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from qwed_new.core.dsl_logic_verifier import DSLLogicVerifier, DSLVerificationResult
from qwed_new.core.schemas import LogicVerificationTask
from qwed_new.providers.base import LOGIC_CLAIM_RULE, translation_request
from tests.test_issue_320_logic_route_admission import client  # noqa: F401  (fixture)
from tests.test_issue_582_translation_prompts import PROVIDERS, _provider, _system_and_user

X = [{"name": "x", "type": "Int"}]


@pytest.mark.parametrize("premises, claim, status, counterexample", [
    # The issue's case: x = 6 meets the premise and fails the claim.
    ("(GT x 5)", "(GT x 10)", "INVALID", lambda x: 5 < x <= 10),
    ("(GT x 5)", "(GT x 3)", "VALID", None),
    ("", "(EQ x x)", "VALID", None),
    ("", "(GT x 5)", "INVALID", lambda x: x <= 5),
    # Premises that cannot hold prove every claim, so they prove none.
    ("(AND (GT x 5) (LT x 3))", "(EQ x 100)", "VACUOUS", None),
])
def test_a_claim_is_decided_for_every_value(premises, claim, status, counterexample):
    result = DSLLogicVerifier().prove_from_dsl(premises, claim, X)

    assert result.status == status
    assert result.dsl_code == (f"(IMPLIES {premises} {claim})" if premises else claim)
    if counterexample is not None:
        assert counterexample(int(result.model["x"]))


@pytest.mark.parametrize("premises, claim", [("(AND)", "(GT x 3)"), ("(GT x 5)", "(AND)"), ("", "(AND)")])
def test_a_step_the_solver_does_not_decide_reports_the_statement(premises, claim):
    # Not the internal refutation query (CodeAnt).
    result = DSLLogicVerifier().prove_from_dsl(premises, claim, X)

    assert result.status == "BLOCKED"
    assert result.dsl_code == (f"(IMPLIES {premises} {claim})" if premises else claim)


def test_undecided_premises_after_no_counterexample_are_returned(monkeypatch):
    # Z3 finds no counterexample, then cannot decide the premises alone.
    verifier = DSLLogicVerifier()
    answers = iter([DSLVerificationResult(status="UNSAT"), DSLVerificationResult(status="UNKNOWN", error="timeout")])
    monkeypatch.setattr(verifier, "verify_from_dsl", lambda dsl_code, variables=None: next(answers))

    result = verifier.prove_from_dsl("(GT x 5)", "(GT x 3)", X)

    assert (result.status, result.dsl_code) == ("UNKNOWN", "(IMPLIES (GT x 5) (GT x 3))")


def test_a_claim_beside_a_satisfiability_goal_is_one_more_condition():
    # "Is there an x > 5?": a witness, never a claim refuted for every value (CodeAnt).
    task = LogicVerificationTask(variables={"x": "Int"}, constraints=["x > 0"], claim="x > 5", goal="SATISFIABILITY")

    assert DSLLogicVerifier()._logic_task_to_dsl(task) == ("(AND (GT x 0) (GT x 5))", X, None)


def test_the_translation_keeps_the_claim_apart_from_the_constraints():
    task = LogicVerificationTask(variables={"x": "Int"}, constraints=["x > 5"], claim="x > 10", goal="VALIDITY")

    assert DSLLogicVerifier()._logic_task_to_dsl(task) == ("(GT x 5)", X, "(GT x 10)")


def test_a_claim_needs_no_constraints():
    task = LogicVerificationTask(variables={"x": "Int"}, constraints=[], claim="x == x", goal="VALIDITY")

    assert DSLLogicVerifier()._logic_task_to_dsl(task) == ("", X, "(EQ x x)")


@pytest.mark.parametrize("text", ["And(x > 3, **{'c': x > 10})", "Or(x > 3, **{})"])
def test_a_helper_call_with_keyword_arguments_is_refused(text):
    # The keyword part was dropped, deciding less than was written (CodeRabbit).
    with pytest.raises(ValueError, match="does not accept keyword arguments"):
        DSLLogicVerifier()._constraint_to_dsl(text)


@pytest.mark.parametrize("text", ["x / 2 == 1", "x % -2 == 1", "x % y == 1", "x % 0 == 1"])
def test_division_and_remainder_outside_python_semantics_are_refused(text):
    # DSL DIV and MOD are Z3's integer division and Euclidean remainder: with
    # x = 3, x / 2 == 1 held, and with x = -7, x % -2 == 1 (CodeRabbit).
    with pytest.raises(ValueError, match="Unsupported arithmetic operator: Div|only with a positive"):
        DSLLogicVerifier()._constraint_to_dsl(text)


def test_a_remainder_by_a_positive_whole_number_matches_python():
    verifier = DSLLogicVerifier()
    claim = verifier._constraint_to_dsl("x % 2 == 1")

    assert claim == "(EQ (MOD x 2) 1)"
    assert verifier.prove_from_dsl("(EQ x -7)", claim, X).status == "VALID"  # -7 % 2 == 1 in Python


def test_a_division_claim_is_not_decided(client):  # noqa: F811
    task = LogicVerificationTask(variables={"x": "Int"}, constraints=["x == 3"], claim="x / 2 == 1", goal="VALIDITY")
    body = _logic(client, task)

    assert (body["status"], body["admission"]) == ("BLOCKED", "BLOCKED")


def test_a_claim_with_keyword_arguments_is_not_decided(client):  # noqa: F811
    task = LogicVerificationTask(
        variables={"x": "Int"}, constraints=["x > 5"], claim="And(x > 3, **{'c': x > 10})", goal="VALIDITY"
    )
    body = _logic(client, task)

    assert (body["status"], body["admission"]) == ("BLOCKED", "BLOCKED")


def test_a_claim_without_a_goal_is_not_decided():
    # Fail closed: a claim with no stated goal is not proven or refuted.
    # The tool schemas require the goal, and the prompt states it.
    task = LogicVerificationTask(variables={"x": "Int"}, constraints=["x > 5"], claim="x > 3")

    assert DSLLogicVerifier()._logic_task_to_dsl(task) == ("(AND (GT x 5) (GT x 3))", X, None)


def test_an_unknown_goal_is_refused():
    task = LogicVerificationTask(variables={"x": "Int"}, constraints=["x > 5"], goal="MAXIMIZE")

    with pytest.raises(ValueError, match="Unsupported logic goal: MAXIMIZE"):
        DSLLogicVerifier()._logic_task_to_dsl(task)


def _translates_to(task):
    """The model's translation is ``task``; the bridge and Z3 run for real."""
    translator = SimpleNamespace(
        translate_logic=lambda query, provider=None: task,
        last_resolved_provider="mock",
        translation_model=lambda provider_key=None: None,
    )
    return patch("qwed_new.core.dsl_logic_verifier.TranslationLayer", return_value=translator)


def _logic(client, task, route="/verify/logic"):  # noqa: F811
    question = "x is greater than 5. Is x greater than 10?"
    with _translates_to(task):
        if route == "/verify/batch":
            body = client.post(route, json={"items": [{"query": question, "type": "logic"}]}).json()
            return body["items"][0]["result"]
        return client.post(route, json={"query": question}).json()


def test_the_library_pipeline_proves_a_claim_as_the_route_does():
    # verify_from_natural_language, the synchronous wrapper, takes the same claim path.
    task = LogicVerificationTask(variables={"x": "Int"}, constraints=["x > 5"], claim="x > 10", goal="VALIDITY")
    with _translates_to(task):
        result = DSLLogicVerifier().verify_from_natural_language("x is greater than 5. Is x greater than 10?")

    assert (result.status, result.dsl_code, result.provider_used) == ("INVALID", "(IMPLIES (GT x 5) (GT x 10))", "mock")
    assert 5 < int(result.model["x"]) <= 10


@pytest.mark.parametrize("route", ["/verify/logic", "/verify/batch"])
def test_a_claim_with_a_counterexample_is_proven_false(client, route):  # noqa: F811
    body = _logic(client, LogicVerificationTask(variables={"x": "Int"}, constraints=["x > 5"], claim="x > 10", goal="VALIDITY"), route)

    assert (body["status"], body["is_valid"], body["admission"]) == ("VERIFIED", False, "BLOCKED")
    assert 5 < int(body["model"]["x"]) <= 10
    assert body["developer_fields"]["translated_expression"] == "(VAR x Int) (IMPLIES (GT x 5) (GT x 10))"


@pytest.mark.parametrize("route", ["/verify/logic", "/verify/batch"])
def test_a_claim_that_follows_is_verified_for_the_translation_only(client, route):  # noqa: F811
    body = _logic(client, LogicVerificationTask(variables={"x": "Int"}, constraints=["x > 5"], claim="x > 3", goal="VALIDITY"), route)

    assert (body["status"], body["admission"]) == ("VERIFIED", "BLOCKED")
    # It proves the model's translation, not the question (#630).
    assert "is_valid" not in body
    assert body["developer_fields"]["query_semantics_verified"] is False
    assert body["developer_fields"]["translated_expression"] == "(VAR x Int) (IMPLIES (GT x 5) (GT x 3))"


@pytest.mark.parametrize("route", ["/verify/logic", "/verify/batch"])
def test_satisfiable_constraints_with_no_claim_prove_nothing(client, route):  # noqa: F811
    # What main returned VERIFIED for: the question translated into
    # constraints alone.
    body = _logic(client, LogicVerificationTask(variables={"x": "Int"}, constraints=["x > 5", "x > 10"]), route)

    assert (body["status"], body["admission"]) == ("UNVERIFIABLE", "BLOCKED")
    assert body["developer_fields"]["constraint_id"] == "logic.satisfiable_not_proven"
    assert body.get("proof_ref") is None


def test_an_existential_claim_is_not_proven_false(client):  # noqa: F811
    task = LogicVerificationTask(variables={"x": "Int"}, constraints=[], claim="x > 5", goal="SATISFIABILITY")
    body = _logic(client, task)

    assert (body["status"], body["admission"]) == ("UNVERIFIABLE", "BLOCKED")
    assert body["developer_fields"]["constraint_id"] == "logic.satisfiable_not_proven"
    assert body.get("is_valid") is not False


def test_contradictory_constraints_prove_no_claim(client):  # noqa: F811
    task = LogicVerificationTask(variables={"x": "Int"}, constraints=["x > 5", "x < 3"], claim="x == 100", goal="VALIDITY")
    body = _logic(client, task)

    assert (body["status"], body["admission"]) == ("UNVERIFIABLE", "BLOCKED")
    assert body["developer_fields"]["constraint_id"] == "dsl_logic_verifier.vacuous_premises"


@pytest.mark.parametrize("name", list(PROVIDERS))
def test_every_logic_translation_asks_for_the_claim(name, monkeypatch):
    provider, client_ = _provider(name, monkeypatch)
    question = "x is greater than 5. Is x greater than 10?"

    with pytest.raises(Exception):
        provider.translate_logic(question)

    (request,) = client_.requests
    system, _ = _system_and_user(request, translation_request(question))
    assert LOGIC_CLAIM_RULE in system
    assert '"goal": "SATISFIABILITY".' not in system
    tools = request.get("tools") or []
    for tool in tools:
        schema = tool.get("input_schema") or tool["function"]["parameters"]
        assert "claim" in schema["properties"]
        assert "goal" in schema["required"]
        assert schema["properties"]["goal"]["enum"] == ["VALIDITY", "SATISFIABILITY"]

