"""A Boolean compared with a non-Boolean is a compile error, not a coercion.

Python ``True``/``False`` are ints and an undeclared name is auto-created as an
Int, so ``(EQ flag True)`` compiled to ``flag == 1`` and came back SAT with
``flag = 1``: a VERIFIED verdict on a constraint that does not mean what was
asked. z3 also coerced an Int compared with a Bool variable to
``x == If(b, 1, 0)``. Both now fail closed; Bool-to-Bool comparisons still work.
"""

import pytest

from qwed_new.core.dsl.compiler import compile_to_z3
from qwed_new.core.dsl.parser import parse_and_validate
from qwed_new.core.dsl_logic_verifier import DSLLogicVerifier
from qwed_new.core.schemas import LogicVerificationTask

_ORDERING = ["GT", "LT", "GTE", "LTE"]


def _compile(code: str, **types: str):
    parsed = parse_and_validate(code)
    assert parsed["status"] == "SUCCESS", parsed
    return compile_to_z3(parsed["ast"], {name: {"type": t} for name, t in types.items()})


@pytest.mark.parametrize("op", ["EQ", "NEQ"])
@pytest.mark.parametrize("literal", [True, False])
@pytest.mark.parametrize("literal_first", [False, True])
def test_undeclared_name_vs_bool_literal_is_rejected(op, literal, literal_first):
    args = [literal, "z"] if literal_first else ["z", literal]
    result = compile_to_z3([op, *args])
    assert not result.success
    assert result.compiled is None
    assert f"{op} compares a Boolean literal with a non-Boolean value" in result.error


@pytest.mark.parametrize("op", _ORDERING)
@pytest.mark.parametrize("literal", [True, False])
@pytest.mark.parametrize("literal_first", [False, True])
def test_ordering_with_bool_literal_is_rejected(op, literal, literal_first):
    args = [literal, "z"] if literal_first else ["z", literal]
    result = compile_to_z3([op, *args])
    assert not result.success
    assert f"{op} compares a Boolean value, which has no ordering" in result.error


@pytest.mark.parametrize("var_type", ["Int", "Real"])
def test_declared_numeric_vs_bool_literal_is_rejected(var_type):
    result = _compile("(EQ z True)", z=var_type)
    assert not result.success
    assert "Boolean literal with a non-Boolean value" in result.error


def test_int_literal_vs_bool_literal_is_rejected():
    result = compile_to_z3(["EQ", 1, True])
    assert not result.success
    assert "Boolean literal with a non-Boolean value" in result.error


def test_int_vs_bool_variable_is_rejected():
    # z3 would otherwise build x == If(b, 1, 0).
    result = _compile("(EQ x b)", b="Bool")
    assert not result.success
    assert "EQ compares a Boolean value with a non-Boolean value" in result.error


def test_ordering_bool_variables_is_rejected():
    result = _compile("(GT b c)", b="Bool", c="Bool")
    assert not result.success
    assert "no ordering" in result.error


@pytest.mark.parametrize(
    "code",
    [
        "(EQ b True)",
        "(EQ False b)",
        "(NEQ b False)",
        "(EQ b c)",
        "(EQ (GT x 1) b)",
        "(EQ (GT x 1) True)",
        "(EQ True True)",
    ],
)
def test_boolean_comparisons_still_compile(code):
    result = _compile(code, b="Bool", c="Bool")
    assert result.success, result.error


def test_numeric_comparisons_unaffected():
    for op in ["EQ", "NEQ", *_ORDERING]:
        assert _compile(f"({op} (PLUS x 1) 2)").success


@pytest.mark.parametrize("variables", [None, [{"name": "flag", "type": "Int"}]])
def test_verifier_returns_error_not_sat(variables):
    result = DSLLogicVerifier().verify_from_dsl("(EQ flag True)", variables)
    assert result.status == "ERROR"
    assert result.model is None
    assert "Boolean literal with a non-Boolean value" in result.error


def test_verifier_bool_declared_keeps_working():
    result = DSLLogicVerifier().verify_from_dsl(
        "(AND (EQ flag True) (EQ flag False))", [{"name": "flag", "type": "Bool"}]
    )
    assert result.status == "UNSAT"
    result = DSLLogicVerifier().verify_from_dsl(
        "(EQ flag True)", [{"name": "flag", "type": "Bool"}]
    )
    assert result.status == "SAT"
    assert result.model == {"flag": "True"}


class _StubTranslator:
    """Stands in for the LLM provider only: parser, compiler and Z3 run for real."""

    def __init__(self, task):
        self.task = task
        self.calls = []
        self.last_resolved_provider = None

    def translate_logic(self, user_query, provider=None):
        self.calls.append((user_query, provider))
        self.last_resolved_provider = provider
        return self.task


def _verify_nl(monkeypatch, variables, constraints):
    task = LogicVerificationTask(variables=variables, constraints=constraints, goal="SATISFIABILITY")
    stub = _StubTranslator(task)
    monkeypatch.setattr("qwed_new.core.dsl_logic_verifier.TranslationLayer", lambda: stub)
    result = DSLLogicVerifier().verify_from_natural_language("flag must be true", provider="anthropic")
    assert stub.calls == [("flag must be true", "anthropic")]
    assert result.provider_used == "anthropic"
    return result


@pytest.mark.parametrize("variables", [{}, {"flag": "Int"}])
def test_bridge_bool_literal_on_non_bool_variable_is_error(monkeypatch, variables):
    result = _verify_nl(monkeypatch, variables, ["flag == True"])
    assert result.dsl_code == "(EQ flag True)"
    assert result.status == "ERROR"
    assert result.model is None
    assert result.error == (
        "Z3 compilation error: EQ compares a Boolean literal with a non-Boolean "
        "value: flag vs True. Declare Boolean variables with (VAR name Bool)."
    )


def test_bridge_bool_variable_still_verifies(monkeypatch):
    result = _verify_nl(monkeypatch, {"flag": "Bool"}, ["flag == True", "not (flag == False)"])
    assert result.dsl_code == "(AND (EQ flag True) (NOT (EQ flag False)))"
    assert result.status == "SAT"
    assert result.error is None
    assert result.model == {"flag": "True"}


def test_bridge_contradictory_bool_constraints_are_unsat(monkeypatch):
    result = _verify_nl(monkeypatch, {"flag": "Bool"}, ["flag == True", "flag == False"])
    assert result.dsl_code == "(AND (EQ flag True) (EQ flag False))"
    assert result.status == "UNSAT"
    assert result.error is None
    assert result.model is None


def test_bridge_required_phrase_on_int_variable_unaffected(monkeypatch):
    # "is required" on a non-Bool variable deliberately emits 1/0, not True/False.
    result = _verify_nl(monkeypatch, {"approval": "Int"}, ["approval is required"])
    assert result.dsl_code == "(EQ approval 1)"
    assert result.status == "SAT"
    assert result.model == {"approval": "1"}


# --- Arithmetic must not coerce Booleans either --------------------------------

_ARITHMETIC = ["PLUS", "MINUS", "MULT", "DIV", "POW", "MOD"]


@pytest.mark.parametrize(
    "code",
    [
        "(EQ x (PLUS True 0))",
        "(EQ (PLUS True 0) 1)",
        "(EQ (PLUS False 0) 0)",
        "(GT (PLUS (GT x 1) 0) 0)",
    ],
)
def test_bool_literal_or_comparison_in_arithmetic_is_rejected(code):
    result = _compile(code)
    assert not result.success
    assert result.compiled is None
    assert "PLUS applies arithmetic to a Boolean value" in result.error


def test_declared_bool_in_arithmetic_is_rejected():
    # z3 would otherwise build If(b, 1, 0) + 0 == 1.
    result = _compile("(EQ (PLUS b 0) 1)", b="Bool")
    assert not result.success
    assert result.error == "Z3 compilation error: PLUS applies arithmetic to a Boolean value: b"


@pytest.mark.parametrize("op", _ARITHMETIC)
@pytest.mark.parametrize("operand", ["True", "False", "b"])
@pytest.mark.parametrize("bool_first", [False, True])
def test_each_arithmetic_operator_rejects_booleans(op, operand, bool_first):
    args = f"{operand} x" if bool_first else f"x {operand}"
    result = _compile(f"(EQ ({op} {args}) 1)", b="Bool")
    assert not result.success
    assert f"{op} applies arithmetic to a Boolean value: {operand}" in result.error


@pytest.mark.parametrize("op", _ARITHMETIC)
def test_numeric_arithmetic_unaffected(op):
    result = _compile(f"(EQ ({op} x 2) 1)")
    assert result.success, result.error


def test_verifier_bool_arithmetic_is_error_not_sat():
    result = DSLLogicVerifier().verify_from_dsl("(EQ x (PLUS True 0))", [{"name": "x", "type": "Int"}])
    assert result.status == "ERROR"
    assert result.model is None
    assert result.error == "Z3 compilation error: PLUS applies arithmetic to a Boolean value: True"
