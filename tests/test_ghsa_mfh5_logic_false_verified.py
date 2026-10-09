"""Regression tests for GHSA-mfh5-3c8f-975p.

Two root causes let logic verification return VERIFIED without the verdict
following from the input:

1. SafeEvaluator allowed Python `and`/`or`/`not` and chained comparisons on Z3
   objects. These do not build a Z3 formula (Python evaluates them with
   bool()/structural ==), so the constraint changed silently and false theorems
   were "proved".
2. The DSL compiler auto-created an Int variable for every string atom,
   including quoted string literals, so contradictory string constraints such as
   (AND (EQ color "red") (EQ color "blue")) were reported SAT.
"""
import pytest

from qwed_new.core.diagnostics import DiagnosticStatus
from qwed_new.core.logic_verifier import LogicVerifier
from qwed_new.core.dsl_logic_verifier import DSLLogicVerifier


@pytest.fixture
def logic():
    return LogicVerifier()


@pytest.fixture
def dsl():
    return DSLLogicVerifier()


# --- Root cause 1: Python boolean operators / chained comparisons ------------

def test_not_operator_does_not_prove_false_theorem(logic):
    # "not (x == 5)" is not a theorem (x=5 is a counterexample).
    result = logic.prove_theorem({"x": "Int"}, [], "not (x == 5)")
    assert result.status is not DiagnosticStatus.VERIFIED


def test_and_operator_does_not_prove_false_equivalence(logic):
    result = logic.check_equivalence({"x": "Int"}, "x == 1 and x == 2", "x == 1")
    assert result.status is not DiagnosticStatus.VERIFIED


def test_and_operator_constraint_is_not_verified(logic):
    # "not (x == 1)" AND "x == 1" is UNSAT; the Python-operator path used to
    # mangle this into a satisfiable model.
    result = logic.verify_logic({"x": "Int"}, ["not (x == 1)", "x == 1"])
    assert result.status is not DiagnosticStatus.VERIFIED


def test_chained_comparison_is_rejected(logic):
    result = logic.prove_theorem({"x": "Int"}, ["x == 10"], "0 < x < 5")
    assert result.status is DiagnosticStatus.BLOCKED


# --- Controls: the Z3 builders must keep working -----------------------------

def test_z3_builtins_still_prove_true_theorem(logic):
    result = logic.prove_theorem({"x": "Int"}, ["x > 10"], "x > 5")
    assert result.status is DiagnosticStatus.VERIFIED


def test_z3_and_builder_sat(logic):
    result = logic.verify_logic({"x": "Int"}, ["And(x > 3, x < 10)", "x == 5"])
    assert result.status is DiagnosticStatus.VERIFIED


def test_contradiction_is_unverifiable(logic):
    result = logic.verify_logic({"x": "Int"}, ["x > 5", "x < 3"])
    assert result.status is DiagnosticStatus.UNVERIFIABLE


# --- Root cause 2: DSL string literals ---------------------------------------

def test_dsl_string_literals_do_not_produce_sat(dsl):
    result = dsl.verify_from_dsl('(AND (EQ color "red") (EQ color "blue"))')
    assert result.status != "SAT"


def test_dsl_integer_contradiction_is_unsat(dsl):
    result = dsl.verify_from_dsl('(AND (EQ color 1) (EQ color 2))')
    assert result.status == "UNSAT"


def test_dsl_bare_variable_still_sat(dsl):
    result = dsl.verify_from_dsl('(AND (GT x 5) (LT x 10))')
    assert result.status == "SAT"
