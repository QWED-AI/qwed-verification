"""#579: logic inputs that state nothing were VERIFIED.

1. ``prove_theorem`` proved any conclusion from premises that cannot all hold
   (ex falso): from ``x > 5`` and ``x < 3`` it "proved" ``x == 100``. That is
   valid logic, but the proof says nothing about the conclusion, and it almost
   always means the premises were written or translated wrongly. The premises
   are now checked first: premises that contradict each other give
   UNVERIFIABLE with ``logic_verifier.vacuous_premises`` and the premises that
   conflict (``unsat_core``); premises the solver cannot decide give
   UNVERIFIABLE with ``logic_verifier.premises_undecided``.
2. A DSL program of declarations only, such as ``(VAR x Int)``, compiled to no
   constraint, and an empty set of constraints is satisfiable, so
   ``/verify/logic`` returned VERIFIED. It is now BLOCKED with
   ``dsl_logic_verifier.no_constraint``.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from qwed_new.api import main as api_main
from qwed_new.core.diagnostics import DiagnosticStatus
from qwed_new.core.dsl_logic_verifier import DSLLogicVerifier
from qwed_new.core.logic_verifier import LogicVerifier
from qwed_new.core.route_diagnostics import logic_diagnostic
from qwed_new.core.tenant_context import TenantContext

INT_X = {"x": "Int"}


# ---------------------------------------------------------------- prove_theorem

@pytest.mark.parametrize("premises", [
    ["x > 5", "x < 3"],
    ["x == 1", "x == 2"],
    ["1 == 2"],  # a premise that is false on its own
    ["Not(x == x)"],
])
@pytest.mark.parametrize("conclusion", ["x == 100", "x == x", "x > 1000"])
def test_premises_that_cannot_all_hold_prove_nothing(premises, conclusion):
    result = LogicVerifier().prove_theorem(INT_X, premises, conclusion)

    assert result.status is DiagnosticStatus.UNVERIFIABLE
    fields = result.developer_fields
    assert fields["constraint_id"] == "logic_verifier.vacuous_premises"
    assert fields["deterministic_verdict"] == "VACUOUS_PREMISES"
    assert fields["unsat_core"]
    assert set(fields["unsat_core"]) <= set(fields["premises"])


def test_the_unsat_core_names_the_premises_that_conflict():
    result = LogicVerifier().prove_theorem({"x": "Int", "y": "Int"}, ["y > 0", "x > 5", "x < 3"], "x == 100")

    assert result.status is DiagnosticStatus.UNVERIFIABLE
    assert {"x > 5", "x < 3"} <= set(result.developer_fields["unsat_core"])


def test_an_implication_from_an_antecedent_that_cannot_hold_is_not_proved():
    result = LogicVerifier().check_implication(INT_X, "And(x > 5, x < 3)", "x == 1")

    assert result.status is DiagnosticStatus.UNVERIFIABLE
    assert result.developer_fields["constraint_id"] == "logic_verifier.vacuous_premises"


@pytest.mark.parametrize("variables, premises, conclusion", [
    (INT_X, ["x > 5"], "x > 3"),
    (INT_X, [], "x == x"),  # no premises: a conclusion that always holds is still proved
    ({"p": "Bool", "q": "Bool"}, ["Implies(p, q)", "p"], "q"),
    ({"x": "Int", "y": "Int"}, ["x > y", "y > 0"], "x > 1"),
])
def test_premises_that_can_all_hold_still_prove_what_follows(variables, premises, conclusion):
    result = LogicVerifier().prove_theorem(variables, premises, conclusion)

    assert result.status is DiagnosticStatus.VERIFIED
    assert result.proof_ref
    assert result.developer_fields["deterministic_verdict"] == "contradiction_confirmed"
    assert "constraint_id" not in result.developer_fields


def test_a_false_theorem_from_premises_that_can_hold_is_still_disproved():
    result = LogicVerifier().prove_theorem(INT_X, ["x > 3"], "x > 5")

    assert result.status is DiagnosticStatus.BLOCKED
    assert result.developer_fields["deterministic_verdict"] == "counterexample_found"


def test_premises_the_solver_cannot_decide_stop_the_proof():
    # x^3 + y^3 = z^3 has no solution in positive integers, and Z3 cannot
    # prove that, so the real solver gives up when its time runs out.
    variables = {"x": "Int", "y": "Int", "z": "Int"}
    premises = ["x > 0", "y > 0", "z > 0", "x*x*x + y*y*y == z*z*z"]

    result = LogicVerifier(timeout_ms=200).prove_theorem(variables, premises, "x == x")

    assert result.status is DiagnosticStatus.UNVERIFIABLE
    assert result.developer_fields["constraint_id"] == "logic_verifier.premises_undecided"
    assert result.developer_fields["deterministic_verdict"] == "UNKNOWN"
    assert "unsat_core" not in result.developer_fields


@pytest.mark.parametrize("premise", [
    # A premise can name any constant, also one shaped like a label.
    "Not(Bool('_' + '_qwed_premise_0'))",
    "Not(Bool('qwed_premise_0'))",
    "Not(Bool('_qwed_premise_0'))",
])
def test_a_premise_cannot_name_a_label_of_the_premises_check(premise):
    result = LogicVerifier().prove_theorem(INT_X, [premise, "x > 1"], "x > 0")

    assert result.status is DiagnosticStatus.VERIFIED
    assert result.developer_fields["deterministic_verdict"] == "contradiction_confirmed"


def test_the_proof_gets_what_the_premises_check_left_of_the_timeout(monkeypatch):
    from qwed_new.core import logic_verifier

    # A fixed clock for the module only, so the test does not depend on how
    # long it runs.
    monkeypatch.setattr(logic_verifier, "time", SimpleNamespace(monotonic=lambda: 10.0))
    verifier = LogicVerifier(timeout_ms=1000)

    # Started 250 ms ago: 750 ms are left.
    assert verifier._remaining_ms(9.75) == 750
    # All spent: the proof still gets a positive limit.
    assert verifier._remaining_ms(5.0) == 1


# ---------------------------------------------------------------- the DSL

@pytest.mark.parametrize("dsl", ["(VAR x Int)", "(VAR flag Bool)", "(VAR r Real)"])
def test_a_program_of_declarations_only_is_blocked(dsl):
    result = DSLLogicVerifier().verify_from_dsl(dsl)

    assert result.status == "BLOCKED"
    assert result.constraint_id == "dsl_logic_verifier.no_constraint"
    assert result.model is None
    diagnostic = logic_diagnostic({
        "status": result.status, "error": result.error, "dsl_code": result.dsl_code,
        "constraint_id": result.constraint_id,
    })
    assert diagnostic.status is DiagnosticStatus.BLOCKED
    assert diagnostic.constraint_id == "dsl_logic_verifier.no_constraint"


@pytest.mark.parametrize("dsl, status", [
    ("(GT x 5)", "SAT"),
    ("(AND (GT x 5) (LT x 3))", "UNSAT"),
])
def test_a_program_with_a_constraint_is_still_decided(dsl, status):
    result = DSLLogicVerifier().verify_from_dsl(dsl)

    assert result.status == status
    assert result.constraint_id is None


# ---------------------------------------------------------------- the route

@pytest.fixture
def client(isolated_audit_chain):
    tenant = TenantContext(organization_id=1, organization_name="Org", tier="free", api_key="k")

    def _mock_session():
        # A plain function, not MagicMock itself: FastAPI would read MagicMock's
        # constructor parameters as query parameters.
        return MagicMock()

    api_main.app.dependency_overrides[api_main.get_current_tenant] = lambda: tenant
    api_main.app.dependency_overrides[api_main.get_session] = _mock_session
    try:
        with patch("qwed_new.api.main.check_rate_limit"):
            yield TestClient(api_main.app)
    finally:
        api_main.app.dependency_overrides.clear()


def test_verify_logic_blocks_a_translation_that_states_no_constraint(client):
    translated = ("(VAR x Int)", None, "mock", None)
    with patch.object(api_main.control_plane.logic_verifier, "translate_to_dsl", return_value=translated):
        body = client.post("/verify/logic", json={"query": "Is there an integer x?"}).json()

    assert body["status"] == "BLOCKED"
    assert body["admission"] == "BLOCKED"
    assert body["constraint_id"] == "dsl_logic_verifier.no_constraint"
    assert body["proof_ref"] is None
    assert "attestation" not in body
