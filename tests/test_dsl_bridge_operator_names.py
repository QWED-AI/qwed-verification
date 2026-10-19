"""The natural-language bridge must emit the DSL parser's operator names.

``_compare_to_dsl`` / ``_binop_to_dsl`` used to emit ``NE``, ``GE``, ``LE`` and
``MUL`` while the parser whitelist only knows ``NEQ``, ``GTE``, ``LTE`` and
``MULT``, so every bridged constraint using ``!=``, ``>=``, ``<=`` or ``*`` came
back BLOCKED ("Unknown operator"). That failed closed but rejected valid
constraints. These tests pin the bridge to the whitelist and run each operator
through the real parser, compiler and Z3.
"""

import ast
import re

import pytest

from qwed_new.core.dsl.parser import QWEDLogicDSL
from qwed_new.core.dsl_logic_verifier import DSLLogicVerifier
from qwed_new.core.schemas import LogicVerificationTask

_HEAD = re.compile(r"\((\w+)")


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


def _verify_nl(monkeypatch, constraints, variables=None):
    variables = {"x": "Int"} if variables is None else variables
    task = LogicVerificationTask(variables=variables, constraints=constraints, goal="SATISFIABILITY")
    stub = _StubTranslator(task)
    monkeypatch.setattr("qwed_new.core.dsl_logic_verifier.TranslationLayer", lambda: stub)
    result = DSLLogicVerifier().verify_from_natural_language("bridge query", provider="anthropic")
    assert stub.calls == [("bridge query", "anthropic")]
    assert result.provider_used == "anthropic"
    return result


# Every Python operator the bridge accepts, as a constraint that exercises it.
_EVERY_BRIDGE_OPERATOR = [
    "x + 1 == 2",
    "x - 1 == 2",
    "x * 2 == 4",
    "x / 2 == 3",
    "x % 3 == 1",
    "x ** 2 == 9",
    "-x == 3",
    "x == 1",
    "x != 1",
    "x > 1",
    "x < 1",
    "x >= 1",
    "x <= 1",
    "1 < x < 3",
    "x > 1 and x < 3",
    "x > 1 or x < 3",
    "not x > 1",
    "Not(x > 1)",
]


def test_bridge_operator_names_are_in_parser_whitelist():
    whitelist = set(QWEDLogicDSL().operators)
    assert DSLLogicVerifier.BRIDGE_OPERATORS <= whitelist, (
        DSLLogicVerifier.BRIDGE_OPERATORS - whitelist
    )


@pytest.mark.parametrize("constraint", _EVERY_BRIDGE_OPERATOR)
def test_every_emitted_operator_is_declared_and_whitelisted(constraint):
    dsl = DSLLogicVerifier()._constraint_to_dsl(constraint)
    heads = set(_HEAD.findall(dsl))
    assert heads, dsl
    assert heads <= DSLLogicVerifier.BRIDGE_OPERATORS, (dsl, heads - DSLLogicVerifier.BRIDGE_OPERATORS)
    assert heads <= set(QWEDLogicDSL().operators), dsl


def test_bridge_maps_cover_every_python_operator_it_translates():
    # Each AST operator class the bridge maps resolves to a whitelisted name,
    # so a future entry cannot reintroduce a non-parser spelling.
    whitelist = set(QWEDLogicDSL().operators)
    for table in (DSLLogicVerifier._BINOP_DSL, DSLLogicVerifier._COMPARE_DSL):
        for node_type, name in table.items():
            assert issubclass(node_type, (ast.operator, ast.cmpop))
            assert name in whitelist, (node_type.__name__, name)


@pytest.mark.parametrize(
    ("constraints", "dsl", "status"),
    [
        # NEQ (was NE)
        (["x != 3"], "(NEQ x 3)", "SAT"),
        (["x != 3", "x == 3"], "(AND (NEQ x 3) (EQ x 3))", "UNSAT"),
        # GTE (was GE)
        (["x >= 5"], "(GTE x 5)", "SAT"),
        (["x >= 5", "x < 5"], "(AND (GTE x 5) (LT x 5))", "UNSAT"),
        # LTE (was LE)
        (["x <= 5"], "(LTE x 5)", "SAT"),
        (["x <= 5", "x > 5"], "(AND (LTE x 5) (GT x 5))", "UNSAT"),
        # MULT (was MUL)
        (["x * 2 <= 10"], "(LTE (MULT x 2) 10)", "SAT"),
        (["x * 2 <= 10", "x > 5"], "(AND (LTE (MULT x 2) 10) (GT x 5))", "UNSAT"),
        (["x * 3 == 7"], "(EQ (MULT x 3) 7)", "UNSAT"),
        # Names that were already right stay right.
        (["x + 1 == 2"], "(EQ (PLUS x 1) 2)", "SAT"),
        (["x + 1 == 2", "x != 1"], "(AND (EQ (PLUS x 1) 2) (NEQ x 1))", "UNSAT"),
        (["x - 1 == 2"], "(EQ (MINUS x 1) 2)", "SAT"),
        (["x - 1 == 2", "x > 3"], "(AND (EQ (MINUS x 1) 2) (GT x 3))", "UNSAT"),
        (["-x > 0"], "(GT (MINUS 0 x) 0)", "SAT"),
        (["-x > 0", "x >= 0"], "(AND (GT (MINUS 0 x) 0) (GTE x 0))", "UNSAT"),
        (["x == -3"], "(EQ x -3)", "SAT"),
        (["x / 2 == 3"], "(EQ (DIV x 2) 3)", "SAT"),
        (["x / 2 == 3", "x > 7"], "(AND (EQ (DIV x 2) 3) (GT x 7))", "UNSAT"),
        (["x % 3 == 1"], "(EQ (MOD x 3) 1)", "SAT"),
        (["x % 2 == 1", "x % 4 == 0"], "(AND (EQ (MOD x 2) 1) (EQ (MOD x 4) 0))", "UNSAT"),
        (["x ** 2 == 9"], "(EQ (POW x 2) 9)", "SAT"),
        (["x ** 2 == 9", "x > 3"], "(AND (EQ (POW x 2) 9) (GT x 3))", "UNSAT"),
        (["1 < x < 3"], "(AND (LT 1 x) (LT x 3))", "SAT"),
        (["1 < x < 2"], "(AND (LT 1 x) (LT x 2))", "UNSAT"),
        (["1 <= x <= 1"], "(AND (LTE 1 x) (LTE x 1))", "SAT"),
        (["1 <= x != 1"], "(AND (LTE 1 x) (NEQ x 1))", "SAT"),
        (["1 >= x >= 2"], "(AND (GTE 1 x) (GTE x 2))", "UNSAT"),
        (["x > 1 and x < 3"], "(AND (GT x 1) (LT x 3))", "SAT"),
        (["x > 3 or x < 1", "x == 2"], "(AND (OR (GT x 3) (LT x 1)) (EQ x 2))", "UNSAT"),
        (["not x >= 1", "x == 0"], "(AND (NOT (GTE x 1)) (EQ x 0))", "SAT"),
        (["not x <= 1", "x == 0"], "(AND (NOT (LTE x 1)) (EQ x 0))", "UNSAT"),
        (["x >= 1 and x * 2 != 4", "x <= 2"], "(AND (AND (GTE x 1) (NEQ (MULT x 2) 4)) (LTE x 2))", "SAT"),
        (["x != x or x * 0 >= 1"], "(OR (NEQ x x) (GTE (MULT x 0) 1))", "UNSAT"),
        (["Not(x >= 1)", "x >= 1"], "(AND (NOT (GTE x 1)) (GTE x 1))", "UNSAT"),
    ],
)
def test_bridge_operator_runs_through_z3(monkeypatch, constraints, dsl, status):
    result = _verify_nl(monkeypatch, constraints)
    assert result.dsl_code == dsl
    assert result.error is None, result.error
    assert result.status == status
    if status == "SAT":
        model = {name: int(value) for name, value in result.model.items()}
        for constraint in constraints:
            # Python's / is true division and ** on the model is exact; check the
            # witness against Z3's integer semantics only where they agree.
            if "/" not in constraint:
                assert eval(constraint, {"Not": _not}, model), (constraint, model)
    else:
        assert result.model is None


def _not(arg):
    return not arg


@pytest.mark.parametrize("constraint", ["x // 2 == 1", "x << 1 == 2", "x & 1 == 1", "x in (1, 2)", "x is 1", "~x == 1"])
def test_unsupported_python_operator_still_fails_closed(monkeypatch, constraint):
    result = _verify_nl(monkeypatch, [constraint])
    assert result.status == "ERROR"
    assert result.model is None
    assert result.error == "LLM translation failed"


def test_unknown_dsl_operator_is_still_blocked():
    result = DSLLogicVerifier().verify_from_dsl("(GE x 5)")
    assert result.status == "BLOCKED"
    assert result.model is None
    assert "Unknown operator 'GE'" in result.error
