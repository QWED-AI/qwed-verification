import pytest
from z3 import Array, Int, IntSort

from src.qwed_new.core.schemas import MathVerificationTask
from src.qwed_new.core.safe_evaluator import SafeEvaluator
from src.qwed_new.core.translator import TranslationLayer
from src.qwed_new.core.validator import SemanticValidator
from src.qwed_new.core.verifier import VerificationEngine, INVALID_TEMPERATURE_UNIT_ERROR


def test_translation_layer_allows_hyperbolic_and_variable_names():
    translator = TranslationLayer()
    task = MathVerificationTask(
        expression="sinh(y) + z",
        claimed_answer=0.0,
        reasoning="test",
        confidence=0.5,
    )

    translator._validate_math_output(task)


def test_semantic_validator_accepts_basic_expression():
    validator = SemanticValidator()

    result = validator.validate("2 + 2")

    assert result["is_valid"] is True
    assert result["checks_failed"] == []


def test_invalid_temperature_unit_returns_error():
    engine = VerificationEngine()

    result = engine._verify_temperature_conversion(32, "rankine", "celsius", 0, 0.1)

    assert result["status"] == "ERROR"
    assert result["error"] == INVALID_TEMPERATURE_UNIT_ERROR


def test_safe_evaluator_allows_valid_z3_comparison():
    evaluator = SafeEvaluator()

    result = evaluator.safe_eval("x > 5", {"x": Int("x")})

    assert str(result) == "x > 5"


def test_safe_evaluator_rejects_unsafe_calls():
    evaluator = SafeEvaluator()

    with pytest.raises(ValueError, match="Unsafe"):
        evaluator.safe_eval("__import__('os').system('echo unsafe')", {"x": Int("x")})


def test_safe_evaluator_allows_quantifiers_and_array_theory_helpers():
    evaluator = SafeEvaluator()
    x = Int("x")
    arr = Array("A", IntSort(), IntSort())

    quantified = evaluator.safe_eval("ForAll([x], x >= 0)", {"x": x})
    existential = evaluator.safe_eval("Exists([x], x >= 0)", {"x": x})
    stored = evaluator.safe_eval("Select(Store(A, x, 7), x)", {"A": arr, "x": x})

    assert str(quantified).startswith("ForAll")
    assert str(existential).startswith("Exists")
    assert str(stored) == "Store(A, x, 7)[x]"


def test_safe_evaluator_allows_bitvec_constructor():
    evaluator = SafeEvaluator()

    result = evaluator.safe_eval("BitVec('bv', 8)", {})

    assert str(result) == "bv"
    assert result.size() == 8


def test_safe_evaluator_rejects_unsupported_ast_nodes():
    evaluator = SafeEvaluator()

    with pytest.raises(ValueError, match="Unsafe expression node detected: Dict"):
        evaluator.safe_eval("{'x': x}", {"x": Int("x")})


def test_safe_evaluator_rejects_unknown_names():
    evaluator = SafeEvaluator()

    with pytest.raises(ValueError, match="Unsafe expression name detected: y"):
        evaluator.safe_eval("y > 5", {"x": Int("x")})


def test_safe_evaluator_rejects_non_name_call_targets():
    evaluator = SafeEvaluator()

    with pytest.raises(ValueError, match="Unsafe call target detected"):
        evaluator.safe_eval("Int('x')(1)", {})


def test_safe_evaluator_rejects_calls_to_context_variables():
    evaluator = SafeEvaluator()

    with pytest.raises(ValueError, match="Unsafe function call detected: x"):
        evaluator.safe_eval("x(1)", {"x": Int("x")})


def test_safe_evaluator_reports_invalid_syntax():
    evaluator = SafeEvaluator()

    with pytest.raises(ValueError, match="Invalid expression syntax"):
        evaluator.safe_eval("x >", {"x": Int("x")})


def test_safe_evaluator_wraps_runtime_errors():
    evaluator = SafeEvaluator()

    with pytest.raises(ValueError, match="Safe evaluation failed"):
        evaluator.safe_eval("Int()", {})
