from unittest.mock import patch

from qwed_new.core.dsl_logic_verifier import DSLLogicVerifier
from qwed_new.core.schemas import LogicVerificationTask


def test_verify_from_natural_language_uses_requested_provider():
    verifier = DSLLogicVerifier()
    logic_task = LogicVerificationTask(
        variables={"x": "Int"},
        constraints=["x > 5", "x < 3"],
        goal="SATISFIABILITY",
    )

    with patch("qwed_new.core.translator.TranslationLayer") as mock_layer:
        instance = mock_layer.return_value
        instance.translate_logic.return_value = logic_task
        result = verifier.verify_from_natural_language(
            query="x should be greater than 5 and less than 3",
            provider="openai_compat",
        )

    instance.translate_logic.assert_called_once_with(
        "x should be greater than 5 and less than 3",
        provider="openai_compat",
    )
    assert result.provider_used == "openai_compat"
    assert result.dsl_code == "(AND (GT x 5) (LT x 3))"
    assert result.status == "UNSAT"


def test_verify_from_natural_language_handles_required_phrases():
    verifier = DSLLogicVerifier()
    logic_task = LogicVerificationTask(
        variables={"approval": "Int"},
        constraints=["approval is required", "approval is not required"],
        goal="SATISFIABILITY",
    )

    with patch("qwed_new.core.translator.TranslationLayer") as mock_layer:
        instance = mock_layer.return_value
        instance.translate_logic.return_value = logic_task
        result = verifier.verify_from_natural_language(
            query="approval is required and approval is not required",
            provider="openai_compat",
        )

    assert result.dsl_code == "(AND (EQ approval 1) (EQ approval 0))"
    assert result.status == "UNSAT"
