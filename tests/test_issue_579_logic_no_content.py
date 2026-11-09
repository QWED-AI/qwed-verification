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
3. The same held in the library: ``verify_logic``, ``verify_bitvector``,
   ``verify_array`` and ``verify_with_quantifiers`` returned VERIFIED when
   no constraint was asserted. They are now BLOCKED with
   ``logic_verifier.no_constraint``.
4. A constraint that is not a Boolean formula, such as ``"[]"``, counted as a
   constraint while it asserted nothing. Every check now takes only True,
   False and Z3 Boolean expressions, and BLOCKS anything else.
5. ``verify_logic(..., prove_unsat=True)`` labelled constraints ``c0``,
   ``c1``, ..., the names of constants a constraint can declare, so a
   satisfiable set came back UNSAT. Its labels, like those of the premises
   check, now avoid every constant of the constraints.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from qwed_new.api import main as api_main
from qwed_new.core.diagnostics import DiagnosticStatus
from qwed_new.core.dsl_logic_verifier import DSLLogicVerifier
from qwed_new.core.logic_verifier import LogicVerifier, QuantifiedFormula
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
    now_ns = 10_000_000_000
    monkeypatch.setattr(logic_verifier, "time", SimpleNamespace(monotonic_ns=lambda: now_ns))
    verifier = LogicVerifier(timeout_ms=1000)

    # Started 250 ms ago: 750 ms are left.
    assert verifier._remaining_ms(now_ns - 250_000_000) == 750
    # All spent: the proof still gets a positive limit.
    assert verifier._remaining_ms(now_ns - 5_000_000_000) == 1


# ---------------------------------------------------------------- the other checks

ARRAY = {"a": ("Int", "Int")}
SQUARES = QuantifiedFormula("forall", [("y", "Int")], "y * y >= 0")

NO_CONSTRAINT = {
    "verify_logic": lambda v: v.verify_logic(INT_X, []),
    "verify_logic, prove_unsat": lambda v: v.verify_logic(INT_X, [], prove_unsat=True),
    "verify_bitvector": lambda v: v.verify_bitvector({"x": 8}, []),
    "verify_array": lambda v: v.verify_array(ARRAY, {"i": "Int"}, []),
    "verify_with_quantifiers": lambda v: v.verify_with_quantifiers(INT_X, [], []),
}
WITH_A_CONSTRAINT = {
    "verify_logic": lambda v: v.verify_logic(INT_X, ["x > 5"]),
    "verify_bitvector": lambda v: v.verify_bitvector({"x": 8}, ["x > 1"]),
    "verify_array": lambda v: v.verify_array(ARRAY, {"i": "Int"}, ["Select(a, i) == 3"]),
    "verify_with_quantifiers": lambda v: v.verify_with_quantifiers({}, [SQUARES]),
}


@pytest.mark.parametrize("check", NO_CONSTRAINT.values(), ids=NO_CONSTRAINT.keys())
def test_a_check_with_no_constraint_is_blocked(check):
    result = check(LogicVerifier())

    assert result.status is DiagnosticStatus.BLOCKED
    assert result.developer_fields["constraint_id"] == "logic_verifier.no_constraint"
    assert result.proof_ref is None


@pytest.mark.parametrize("check", WITH_A_CONSTRAINT.values(), ids=WITH_A_CONSTRAINT.keys())
def test_a_check_with_a_constraint_is_still_decided(check):
    result = check(LogicVerifier())

    assert result.status is DiagnosticStatus.VERIFIED
    assert result.proof_ref


# The evaluator also yields lists, tuples and numbers. Z3's add takes a list
# apart, so "[]" stood for a constraint while it asserted nothing.
NOT_A_FORMULA = ["[]", "()", "[[]]", "1", "[x > 5]"]
CHECKS_OF_ONE_FORMULA = {
    "verify_logic": lambda v, c: v.verify_logic(INT_X, [c]),
    "verify_logic, prove_unsat": lambda v, c: v.verify_logic(INT_X, [c], prove_unsat=True),
    "verify_bitvector": lambda v, c: v.verify_bitvector({"x": 8}, [c]),
    "verify_array": lambda v, c: v.verify_array(ARRAY, {"i": "Int"}, [c]),
    "verify_with_quantifiers": lambda v, c: v.verify_with_quantifiers(INT_X, [], [c]),
    "verify_optimization": lambda v, c: v.verify_optimization(INT_X, [c], "x", maximize=False),
    "check_vacuity": lambda v, c: v.check_vacuity(INT_X, c),
    "check_equivalence": lambda v, c: v.check_equivalence(INT_X, c, c),
    "prove_theorem, premise": lambda v, c: v.prove_theorem(INT_X, [c], "x == x"),
    "prove_theorem, conclusion": lambda v, c: v.prove_theorem(INT_X, ["x > 0"], c),
}


@pytest.mark.parametrize("value", NOT_A_FORMULA)
@pytest.mark.parametrize("check", CHECKS_OF_ONE_FORMULA.values(), ids=CHECKS_OF_ONE_FORMULA.keys())
def test_a_constraint_that_is_not_a_boolean_formula_is_blocked(check, value):
    result = check(LogicVerifier(), value)

    assert result.status is DiagnosticStatus.BLOCKED
    assert result.proof_ref is None


def test_verify_logic_names_a_constraint_that_is_not_a_formula():
    result = LogicVerifier().verify_logic(INT_X, ["x > 5", "[]"])

    assert result.developer_fields["constraint_id"] == "logic_verifier.invalid_constraint"
    assert result.developer_fields["constraint"] == "[]"


@pytest.mark.parametrize("value", ["True", "1 == 1"])
def test_a_constant_formula_is_still_a_formula(value):
    assert LogicVerifier().verify_logic(INT_X, [value]).status is DiagnosticStatus.VERIFIED


# ---------------------------------------------------------------- prove_unsat labels

@pytest.mark.parametrize("variables, constraints", [
    ({"c0": "Bool"}, ["Not(c0)"]),
    ({"c1": "Bool", "x": "Int"}, ["x > 0", "Not(c1)"]),
    ({"x": "Int"}, ["x > 0", "Not(Bool('c' + '0'))"]),
])
def test_prove_unsat_labels_cannot_name_a_constant_of_the_constraints(variables, constraints):
    # Satisfiable: each constraint can hold. A label named like one of their
    # constants made Z3 assume that constant true, and reported UNSAT.
    result = LogicVerifier().verify_logic(variables, constraints, prove_unsat=True)

    assert result.status is DiagnosticStatus.VERIFIED


def test_prove_unsat_still_names_the_constraints_that_conflict():
    result = LogicVerifier().verify_logic(INT_X, ["x > 5", "x < 3"], prove_unsat=True)

    assert result.status is DiagnosticStatus.UNVERIFIABLE
    explanation = result.developer_fields["explanation"]
    # Z3 lists the core in no fixed order.
    assert explanation.startswith("Conflicting constraints: ")
    assert "'c0'" in explanation and "'c1'" in explanation


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
