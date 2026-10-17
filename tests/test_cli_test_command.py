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
        {"group": "Math", "label": "2+2=4", "passed": True, "result": "VALID", "detail": "computed=4"},
        {"group": "Logic", "label": "x>5 AND x<3", "passed": False, "result": "UNSAT", "detail": "status=UNSAT"},
        {"group": "SQL", "label": "Valid SELECT", "passed": True, "result": "SAFE", "detail": "status=SAFE"},
        {"group": "Code", "label": "Safe function", "passed": True, "result": "SAFE", "detail": "status=SAFE"},
    ],
)
def test_test_command_failure_exit_nonzero(_mock_results):
    runner = CliRunner()
    result = runner.invoke(cli, ["test", "--verbose"])

    assert result.exit_code == 1
    assert "3/4 tests passed" in result.output
    assert "status=UNSAT" in result.output


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
        {"status": "DISPROVEN", "calculated_value": 4.0},
        {"status": "VERIFIED", "calculated_value": 994010994.0},
    ]
    from qwed_new.core.diagnostics import DiagnosticResult

    mock_logic.verify_logic.side_effect = [
        DiagnosticResult.unverifiable("UNSAT", {"constraint_id": "test.mock"}),
        DiagnosticResult.verified("SAT", {"model": {"x": "4"}}, {"model": {"x": "4"}}, proof_data="proof"),
        DiagnosticResult.unverifiable("UNSAT", {"constraint_id": "test.mock"}),
    ]
    mock_sql.verify_sql.side_effect = [
        DiagnosticResult.verified(
            "The SQL query passed verification and is safe to execute.",
            {
                "constraint_id": "sql_verifier.sql_valid",
                "is_valid": True,
                "malicious_classification": False,
                "critical_count": 0,
            },
            {"query": "q"},
        ),
        DiagnosticResult.verified(
            "The SQL query failed security verification and is not safe to execute.",
            {
                "constraint_id": "sql_verifier.malicious",
                "is_valid": False,
                "malicious_classification": True,
                "critical_count": 1,
            },
            {"query": "q"},
        ),
        DiagnosticResult.verified(
            "The SQL query failed security verification and is not safe to execute.",
            {
                "constraint_id": "sql_verifier.malicious",
                "is_valid": False,
                "malicious_classification": True,
                "critical_count": 1,
            },
            {"query": "q"},
        ),
    ]
    from qwed_new.core.diagnostics import DiagnosticResult

    mock_code.verify_code.side_effect = [
        DiagnosticResult.verified(
            "The code passed security verification and is safe to use.",
            {"constraint_id": "code_verifier.code_safe", "is_valid": True, "is_safe": True, "critical_count": 0},
            {"engine": "test"},
        ),
        DiagnosticResult.verified(
            "The code failed security verification and is not safe to use.",
            {"constraint_id": "code_verifier.code_unsafe", "is_valid": False, "is_safe": False, "critical_count": 1},
            {"engine": "test"},
        ),
        DiagnosticResult.verified(
            "The code failed security verification and is not safe to use.",
            {"constraint_id": "code_verifier.code_unsafe", "is_valid": False, "is_safe": False, "critical_count": 1},
            {"engine": "test"},
        ),
    ]

    results = _run_full_engine_tests()

    assert len(results) == 12
    assert results[0]["group"] == "Math"
    assert any(item["label"] == "curl | bash" and item["passed"] for item in results)
    assert sum(1 for item in results if item["passed"]) == 12
    assert all("detail" in item and item["detail"] for item in results)


@patch("qwed_new.core.code_verifier.CodeVerifier", side_effect=RuntimeError("code engine down"))
@patch("qwed_new.core.sql_verifier.SQLVerifier", side_effect=RuntimeError("sql engine down"))
@patch("qwed_new.core.logic_verifier.LogicVerifier", side_effect=RuntimeError("logic engine down"))
@patch("qwed_new.core.verifier.VerificationEngine", side_effect=RuntimeError("math engine down"))
def test_run_full_engine_tests_engine_construction_failures(
    _mock_math_cls,
    _mock_logic_cls,
    _mock_sql_cls,
    _mock_code_cls,
):
    results = _run_full_engine_tests()

    assert len(results) == 12
    assert all(item["result"] == "ERROR" for item in results)
    assert all(item["passed"] is False for item in results)
    assert all(item["detail"] for item in results)


def test_run_full_engine_tests_prints_verdict_with_admission():
    """#438: every decided case shows its verdict and admission; VERIFIED is
    never printed alone and BLOCKED is never printed for a decided case."""
    results = _run_full_engine_tests()

    assert all(item["passed"] for item in results)
    by_label = {item["label"]: item["result"] for item in results}
    assert by_label["2+2=4"] == "VERIFIED | ADMIT"
    assert by_label["2+2=5"] == "VERIFIED (false) | DENY"
    assert by_label["OR 1=1 injection"] == "VERIFIED (unsafe) | DENY"
    assert by_label["eval(input)"] == "VERIFIED (unsafe, critical) | DENY"
    for item in results:
        assert not item["result"].startswith("BLOCKED")
        if "VERIFIED" in item["result"]:
            assert item["result"].endswith(("| ADMIT", "| DENY"))


@patch("qwed_new.core.verifier.VerificationEngine")
def test_failed_check_prints_failed_not_blocked(mock_math_cls):
    """A self-check whose engine answer does not match is reported FAILED,
    and the engine's own status is kept in the detail for diagnosis."""
    mock_math_cls.return_value.verify_math.return_value = {
        "status": "BLOCKED",
        "calculated_value": None,
    }

    results = {item["label"]: item for item in _run_full_engine_tests() if item["group"] == "Math"}

    # The engine was really driven with each self-check input.
    calls = [c.args for c in mock_math_cls.return_value.verify_math.call_args_list]
    assert calls == [("2+2", 4), ("2+2", 5), ("997*998*999", 994010994)]
    # Each Math branch failed with FAILED, never with a verdict word.
    assert {label: item["passed"] for label, item in results.items()} == {
        "2+2=4": False,
        "2+2=5": False,
        "997*998*999": False,
    }
    assert {item["result"] for item in results.values()} == {"FAILED"}
    # Branch-specific detail fields carry what the engine actually returned.
    assert results["2+2=4"]["detail"] == "computed=None"
    assert results["2+2=5"]["detail"] == "computed=None"
    assert results["997*998*999"]["detail"] == "status=BLOCKED"


@patch(
    "qwed_sdk.cli._run_full_engine_tests",
    return_value=[{"group": "Math", "label": "2+2=4", "passed": True, "result": "VERIFIED | ADMIT"}],
)
def test_test_command_success_says_ready(_mock_results):
    result = CliRunner().invoke(cli, ["test"])

    assert result.exit_code == 0
    assert "All engines ready." in result.output
