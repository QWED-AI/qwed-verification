import ast
from typing import Optional

import pytest

from qwed_new.core.dsl_logic_verifier import DSLLogicVerifier
from qwed_new.core.schemas import LogicVerificationTask


class _StubTranslator:
    def __init__(self, task: LogicVerificationTask, resolved_provider: Optional[str] = None):
        self.task = task
        self.calls = []
        self.last_resolved_provider = resolved_provider

    def translate_logic(self, user_query: str, provider: Optional[str] = None):
        self.calls.append((user_query, provider))
        if self.last_resolved_provider is None:
            self.last_resolved_provider = provider
        return self.task


def test_verify_from_natural_language_uses_requested_provider(monkeypatch):
    task = LogicVerificationTask(
        variables={"x": "Int"},
        constraints=["x > 5", "x < 3"],
        goal="SATISFIABILITY",
    )
    stub = _StubTranslator(task)
    monkeypatch.setattr(
        "qwed_new.core.dsl_logic_verifier.TranslationLayer",
        lambda: stub,
    )

    verifier = DSLLogicVerifier()
    result = verifier.verify_from_natural_language(
        query="x should be greater than 5 and less than 3",
        provider="anthropic",
    )

    assert stub.calls == [("x should be greater than 5 and less than 3", "anthropic")]
    assert result.provider_used == "anthropic"
    assert result.dsl_code == "(AND (GT x 5) (LT x 3))"
    assert result.status == "UNSAT"


def test_verify_from_natural_language_handles_required_phrases(monkeypatch):
    task = LogicVerificationTask(
        variables={"approval": "Bool"},
        constraints=["approval is required", "approval is not required"],
        goal="SATISFIABILITY",
    )
    stub = _StubTranslator(task)
    monkeypatch.setattr(
        "qwed_new.core.dsl_logic_verifier.TranslationLayer",
        lambda: stub,
    )

    verifier = DSLLogicVerifier()
    result = verifier.verify_from_natural_language(
        query="approval is required and approval is not required",
        provider="azure_openai",
    )

    assert "(EQ approval True)" in (result.dsl_code or "")
    assert "(EQ approval False)" in (result.dsl_code or "")
    assert result.status == "UNSAT"


def test_verify_from_natural_language_empty_constraints_returns_error(monkeypatch):
    task = LogicVerificationTask(variables={"x": "Int"}, constraints=[], goal="SATISFIABILITY")
    stub = _StubTranslator(task)
    monkeypatch.setattr(
        "qwed_new.core.dsl_logic_verifier.TranslationLayer",
        lambda: stub,
    )

    verifier = DSLLogicVerifier()
    result = verifier.verify_from_natural_language(query="just test", provider="azure_openai")

    assert result.status == "ERROR"
    assert result.provider_used == "azure_openai"
    assert "No constraints generated" in (result.error or "")


def test_logic_task_to_dsl_rejects_non_satisfiability_goal():
    verifier = DSLLogicVerifier()
    task = LogicVerificationTask(
        variables={"x": "Int"},
        constraints=["x > 5"],
        goal="MAXIMIZE",
    )

    with pytest.raises(ValueError, match="Unsupported logic goal: MAXIMIZE"):
        verifier._logic_task_to_dsl(task)


def test_constraint_to_dsl_uses_canonical_operators():
    verifier = DSLLogicVerifier()

    assert verifier._constraint_to_dsl("x * y == 10") == "(EQ (MUL x y) 10)"
    assert verifier._constraint_to_dsl("x != y") == "(NE x y)"
    assert verifier._constraint_to_dsl("x >= 5") == "(GE x 5)"
    assert verifier._constraint_to_dsl("x <= 5") == "(LE x 5)"


def test_constraint_to_dsl_rejects_float_literals():
    verifier = DSLLogicVerifier()

    with pytest.raises(ValueError, match="Floating-point literals are not allowed"):
        verifier._constraint_to_dsl("x > 0.1")

    with pytest.raises(ValueError, match="Floating-point literals are not allowed"):
        verifier._constraint_to_dsl("x > -0.1")


def test_verify_from_natural_language_uses_resolved_provider(monkeypatch):
    task = LogicVerificationTask(
        variables={"x": "Int"},
        constraints=["x > 5", "x < 3"],
        goal="SATISFIABILITY",
    )
    stub = _StubTranslator(task=task, resolved_provider="openai_compat")
    monkeypatch.setattr("qwed_new.core.dsl_logic_verifier.TranslationLayer", lambda: stub)

    verifier = DSLLogicVerifier()
    result = verifier.verify_from_natural_language(
        query="x should be greater than 5 and less than 3",
        provider="openai-compatible",
    )

    assert result.provider_used == "openai_compat"
    assert result.status == "UNSAT"


def test_verify_from_natural_language_sanitizes_translation_error(monkeypatch):
    class _FailingTranslator:
        last_resolved_provider = "openai_compat"

        def translate_logic(self, user_query: str, provider: Optional[str] = None):
            raise RuntimeError("sensitive upstream details")

    monkeypatch.setattr("qwed_new.core.dsl_logic_verifier.TranslationLayer", lambda: _FailingTranslator())

    verifier = DSLLogicVerifier()
    result = verifier.verify_from_natural_language(query="test", provider="openai_compat")

    assert result.status == "ERROR"
    assert result.error == "LLM translation failed"
    assert result.provider_used == "openai_compat"


def test_verify_from_natural_language_preserves_unsupported_goal_error(monkeypatch):
    task = LogicVerificationTask(
        variables={"x": "Int"},
        constraints=["x > 5"],
        goal="MAXIMIZE",
    )
    stub = _StubTranslator(task=task, resolved_provider="openai_compat")
    monkeypatch.setattr("qwed_new.core.dsl_logic_verifier.TranslationLayer", lambda: stub)

    verifier = DSLLogicVerifier()
    result = verifier.verify_from_natural_language(query="maximize x", provider="openai_compat")

    assert result.status == "ERROR"
    assert result.error == "Unsupported logic goal: MAXIMIZE"
    assert result.provider_used == "openai_compat"


def test_verify_from_natural_language_masks_non_goal_value_errors(monkeypatch):
    task = LogicVerificationTask(
        variables={"x": "Int"},
        constraints=["x > 0.1"],
        goal="SATISFIABILITY",
    )
    stub = _StubTranslator(task=task, resolved_provider="openai_compat")
    monkeypatch.setattr("qwed_new.core.dsl_logic_verifier.TranslationLayer", lambda: stub)

    verifier = DSLLogicVerifier()
    result = verifier.verify_from_natural_language(query="x > 0.1", provider="openai_compat")

    assert result.status == "ERROR"
    assert result.error == "LLM translation failed"
    assert result.provider_used == "openai_compat"


def test_provider_label_normalization():
    verifier = DSLLogicVerifier()

    assert verifier._provider_label(None) == "unknown"
    assert verifier._provider_label(" OpenAI_Compat ") == "openai_compat"


def test_ast_to_dsl_handles_bool_ops_calls_and_not():
    verifier = DSLLogicVerifier()

    expr = ast.parse("x > 1 and y < 2", mode="eval").body
    assert verifier._ast_to_dsl(expr) == "(AND (GT x 1) (LT y 2))"

    call_expr = ast.parse("And(x > 1, y < 2)", mode="eval").body
    assert verifier._ast_to_dsl(call_expr) == "(AND (GT x 1) (LT y 2))"

    not_expr = ast.parse("Not(x > 1)", mode="eval").body
    assert verifier._ast_to_dsl(not_expr) == "(NOT (GT x 1))"


def test_ast_to_dsl_handles_unary_minus_and_string_constant():
    verifier = DSLLogicVerifier()

    minus_expr = ast.parse("-7", mode="eval").body
    assert verifier._ast_to_dsl(minus_expr) == "-7"

    complex_minus_expr = ast.parse("-(x + 1)", mode="eval").body
    assert verifier._ast_to_dsl(complex_minus_expr) == "(MINUS 0 (PLUS x 1))"

    string_expr = ast.parse("'approval required'", mode="eval").body
    assert verifier._ast_to_dsl(string_expr) == "approval_required"


def test_ast_to_dsl_not_call_requires_one_argument():
    verifier = DSLLogicVerifier()
    bad_not = ast.parse("Not(x > 1, y > 2)", mode="eval").body

    with pytest.raises(ValueError, match="Not\\(\\.\\.\\.\\) requires one argument"):
        verifier._ast_to_dsl(bad_not)


def test_constraint_to_dsl_rejects_empty_input():
    verifier = DSLLogicVerifier()

    with pytest.raises(ValueError, match="Empty constraint"):
        verifier._constraint_to_dsl("   ")
