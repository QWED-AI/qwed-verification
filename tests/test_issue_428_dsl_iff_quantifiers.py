"""#428: the DSL grammar the parser accepts is the grammar the compiler proves.

The parser whitelisted IFF, FORALL and EXISTS, and the provider prompts told
the LLM to emit them, but Z3Compiler had no branch for any of the three, so
every such program failed with "Unknown operator".
"""

import itertools
import pathlib
import re

import pytest

from qwed_new.core.dsl.compiler import compile_to_z3
from qwed_new.core.dsl.parser import QWEDLogicDSL, parse_and_validate
from qwed_new.core.dsl_logic_verifier import DSLLogicVerifier

ROOT = pathlib.Path(__file__).resolve().parents[1]

# One minimal, well-typed program per whitelisted operator.
_OPERATOR_SAMPLES = {
    "AND": "(AND (GT x 1) (LT x 5))",
    "OR": "(OR (GT x 1) (LT x 5))",
    "NOT": "(NOT (GT x 1))",
    "IMPLIES": "(IMPLIES (GT x 1) (GT x 0))",
    "IFF": "(IFF (GT x 1) (GTE x 2))",
    "XOR": "(XOR (GT x 1) (LT x 5))",
    "FORALL": "(FORALL n (GTE (MULT n n) 0))",
    "EXISTS": "(EXISTS n (GT n 0))",
    "EQ": "(EQ x 1)",
    "NEQ": "(NEQ x 1)",
    "GT": "(GT x 1)",
    "LT": "(LT x 1)",
    "GTE": "(GTE x 1)",
    "LTE": "(LTE x 1)",
    "PLUS": "(EQ (PLUS x 1) 2)",
    "MINUS": "(EQ (MINUS x 1) 2)",
    "MULT": "(EQ (MULT x 2) 4)",
    "DIV": "(EQ (DIV x 2) 1)",
    "POW": "(EQ (POW x 2) 4)",
    "MOD": "(EQ (MOD x 2) 1)",
    "VAR": "(VAR x Int)",
}


def _verify(dsl_code, variables=None):
    return DSLLogicVerifier().verify_from_dsl(dsl_code, variables)


def _bools(*names):
    return [{"name": name, "type": "Bool"} for name in names]


def test_every_whitelisted_operator_has_a_sample():
    assert set(_OPERATOR_SAMPLES) == set(QWEDLogicDSL().operators)


@pytest.mark.parametrize("operator", sorted(_OPERATOR_SAMPLES))
def test_every_whitelisted_operator_compiles(operator):
    parsed = parse_and_validate(_OPERATOR_SAMPLES[operator])
    assert parsed["status"] == "SUCCESS", parsed

    compiled = compile_to_z3(parsed["ast"])
    assert compiled.success, compiled.error


@pytest.mark.parametrize("a, b", list(itertools.product([True, False], repeat=2)))
def test_iff_truth_table(a, b):
    result = _verify(f"(AND (IFF p q) (EQ p {a}) (EQ q {b}))", _bools("p", "q"))

    assert result.status == ("SAT" if a == b else "UNSAT")


def test_iff_of_comparisons_from_the_issue():
    # x > 5 iff x < 3 holds where both are false, e.g. x = 3, 4 or 5.
    result = _verify("(IFF (GT x 5) (LT x 3))")

    assert result.status == "SAT"
    assert 3 <= int(result.model["x"]) <= 5


def test_iff_rejects_non_boolean_operands():
    # A biconditional of two Ints must not silently become x == y.
    result = _verify("(IFF x y)")

    assert result.status == "ERROR"
    assert "IFF operand must be Boolean" in result.error


@pytest.mark.parametrize(
    "dsl_code, status",
    [
        ("(FORALL x (GT x 0))", "UNSAT"),
        ("(EXISTS x (GT x 0))", "SAT"),
        ("(FORALL n (IMPLIES (GT n 5) (GT n 3)))", "SAT"),
        ("(FORALL n (IMPLIES (GT n 3) (GT n 5)))", "UNSAT"),
        ("(NOT (FORALL x (GT x 0)))", "SAT"),
        ("(EXISTS x (AND (GT x 0) (LT x 1)))", "UNSAT"),  # Int by default
    ],
)
def test_quantifiers_are_decided(dsl_code, status):
    assert _verify(dsl_code).status == status


@pytest.mark.parametrize("sort, status", [("Int", "UNSAT"), ("Real", "SAT")])
def test_bound_variable_takes_the_declared_sort(sort, status):
    result = _verify("(EXISTS r (EQ (MULT 2 r) 1))", [{"name": "r", "type": sort}])

    assert result.status == status


def test_bound_variable_does_not_capture_a_free_one():
    # The x inside FORALL is bound; the x outside is free and set to 3.
    result = _verify("(AND (FORALL x (GTE (MULT x x) 0)) (EQ x 3))")

    assert result.status == "SAT"
    assert result.model == {"x": "3"}


def test_bound_variable_is_not_reported_as_free():
    compiled = compile_to_z3(parse_and_validate("(FORALL n (GT (PLUS n y) n))")["ast"])

    assert compiled.success
    assert set(compiled.variables) == {"y"}


@pytest.mark.parametrize(
    "dsl_code",
    [
        "(FORALL 5 (GT x 0))",
        "(FORALL AND (GT x 0))",
        "(FORALL True (GT x 0))",
        "(EXISTS (GT x 0) (GT x 1))",
        '(EXISTS "x" (GT x 0))',
    ],
)
def test_quantifier_must_bind_a_variable_name(dsl_code):
    result = _verify(dsl_code)

    assert result.status == "BLOCKED"
    assert "must bind a variable name" in result.error


def test_quantifier_body_must_be_boolean():
    result = _verify("(FORALL x (PLUS x 1))")

    assert result.status == "ERROR"
    assert "FORALL body must be Boolean" in result.error


def test_quantifier_body_is_still_whitelisted():
    result = _verify("(FORALL x (IMPORT os))")

    assert result.status == "BLOCKED"


def _prompt_examples(path):
    """Every ``Output: (...)`` S-expression in a provider's logic prompt."""
    examples = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.search(r"Output: (\(.*)", line)
        if not match:
            continue
        text, depth = match.group(1), 0
        for end, char in enumerate(text):
            depth += {"(": 1, ")": -1}.get(char, 0)
            if depth == 0:
                examples.append(text[: end + 1])
                break
    return examples


@pytest.mark.parametrize("provider", ["anthropic.py", "azure_openai.py"])
def test_provider_prompt_examples_are_valid_dsl(provider):
    examples = _prompt_examples(ROOT / "src" / "qwed_new" / "providers" / provider)

    assert any(example.startswith("(IFF") for example in examples)
    assert any(example.startswith("(FORALL") for example in examples)
    for example in examples:
        parsed = parse_and_validate(example)
        assert parsed["status"] == "SUCCESS", (example, parsed)
        # Bare names in a Boolean position are declared Bool in the prompt.
        compiled = compile_to_z3(
            parsed["ast"], {"access_denied": {"type": "Bool"}, "is_admin": {"type": "Bool"}}
        )
        assert compiled.success, (example, compiled.error)
