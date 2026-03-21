from unittest.mock import patch

from click.testing import CliRunner

from qwed_sdk.cli import _run_full_engine_tests, cli


@patch(
    "qwed_sdk.cli._run_full_engine_tests",
    return_value=[
        {"group": "Math", "label": "2+2=4", "passed": True, "result": "VALID"},
        {"group": "Logic", "label": "x>5 AND x<3", "passed": True, "result": "UNSAT"},
        {"group": "SQL", "label": "Valid SELECT", "passed": True, "result": "SAFE"},
        {"group": "Code", "label": "Safe function", "passed": True, "result": "SAFE"},
    ],
)
def test_test_command_success(_mock_results):
    runner = CliRunner()
    result = runner.invoke(cli, ["test"])

    assert result.exit_code == 0
    assert "4/4 tests passed" in result.output


@patch(
    "qwed_sdk.cli._run_full_engine_tests",
    return_value=[
        {"group": "Math", "label": "2+2=4", "passed": True, "result": "VALID"},
        {"group": "Logic", "label": "x>5 AND x<3", "passed": False, "result": "UNSAT"},
        {"group": "SQL", "label": "Valid SELECT", "passed": True, "result": "SAFE"},
        {"group": "Code", "label": "Safe function", "passed": True, "result": "SAFE"},
    ],
)
def test_test_command_failure_exit_nonzero(_mock_results):
    runner = CliRunner()
    result = runner.invoke(cli, ["test", "--verbose"])

    assert result.exit_code == 1
    assert "3/4 tests passed" in result.output


@patch("qwed_new.core.code_verifier.CodeVerifier")
@patch("qwed_new.core.sql_verifier.SQLVerifier")
@patch("qwed_new.core.logic_verifier.LogicVerifier")
@patch("qwed_new.core.verifier.VerificationEngine")
def test_run_full_engine_tests_returns_expected_shape(
    mock_math_cls,
    mock_logic_cls,
    mock_sql_cls,
    mock_code_cls,
):
    mock_math = mock_math_cls.return_value
    mock_logic = mock_logic_cls.return_value
    mock_sql = mock_sql_cls.return_value
    mock_code = mock_code_cls.return_value

    mock_math.verify_math.side_effect = [
        {"status": "VERIFIED", "calculated_value": 4.0},
        {"status": "CORRECTION_NEEDED", "calculated_value": 4.0},
        {"status": "VERIFIED", "calculated_value": 994010994.0},
    ]
    mock_logic.verify_logic.side_effect = [
        type("LogicResult", (), {"status": "UNSAT", "model": None})(),
        type("LogicResult", (), {"status": "SAT", "model": {"x": "4"}})(),
        type("LogicResult", (), {"status": "UNSAT", "model": None})(),
    ]
    mock_sql.verify_sql.side_effect = [
        {"status": "SAFE"},
        {"status": "BLOCKED"},
        {"status": "BLOCKED"},
    ]
    mock_code.verify_code.side_effect = [
        {"status": "SAFE"},
        {"status": "BLOCKED"},
        {"status": "BLOCKED"},
    ]

    results = _run_full_engine_tests()

    assert len(results) == 12
    assert results[0]["group"] == "Math"
    assert any(item["label"] == "curl | bash" and item["passed"] for item in results)
    assert sum(1 for item in results if item["passed"]) == 12
