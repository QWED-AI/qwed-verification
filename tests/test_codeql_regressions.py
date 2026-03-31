import pytest
from z3 import Int

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
