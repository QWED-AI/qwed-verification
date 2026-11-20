import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import call, patch

import pytest
from click.testing import CliRunner

from qwed_new.core.diagnostics import DiagnosticStatus
from qwed_new.core.dsl_logic_verifier import DSLLogicVerifier, DSLVerificationResult
from qwed_sdk.cli import (
    LOGIC_CLAIM_INVALID_DSL,
    LOGIC_CLAIM_VALID_DSL,
    LOGIC_LABEL_INVALID,
    LOGIC_LABEL_UNSAT,
    LOGIC_LABEL_VALID,
    LOGIC_PREMISE_DSL,
    _prove_logic_claim,
    _run_full_engine_tests,
    cli,
)

README = Path(__file__).resolve().parent.parent / "README.md"


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
@patch("qwed_new.core.dsl_logic_verifier.DSLLogicVerifier")
@patch("qwed_new.core.logic_verifier.LogicVerifier")
@patch("qwed_new.core.verifier.VerificationEngine")
def test_run_full_engine_tests_returns_expected_shape(
    mock_math_cls,
    mock_logic_cls,
    mock_dsl_cls,
    mock_sql_cls,
    mock_code_cls,
):
    mock_math = mock_math_cls.return_value
    mock_logic = mock_logic_cls.return_value
    mock_dsl = mock_dsl_cls.return_value
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
    ]
    mock_dsl.prove_from_dsl.side_effect = [
        DSLVerificationResult(status="VALID"),
        DSLVerificationResult(status="INVALID", model={"x": "6"}),
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
    # The engine is asked for exactly what each label says (#660): the premise
    # and the one claim, never a constraint the label leaves out.
    variables = [{"name": "x", "type": "Int"}]
    assert mock_dsl.prove_from_dsl.call_args_list == [
        call(LOGIC_PREMISE_DSL, LOGIC_CLAIM_VALID_DSL, variables),
        call(LOGIC_PREMISE_DSL, LOGIC_CLAIM_INVALID_DSL, variables),
    ]
    assert (LOGIC_PREMISE_DSL, LOGIC_CLAIM_VALID_DSL, LOGIC_CLAIM_INVALID_DSL) == ("(GT x 5)", "(GT x 3)", "(GT x 10)")
    assert (LOGIC_LABEL_VALID, LOGIC_LABEL_INVALID) == ("x>5 => x>3", "x>5 => x>10")


@patch("qwed_new.core.code_verifier.CodeVerifier", side_effect=RuntimeError("code engine down"))
@patch("qwed_new.core.sql_verifier.SQLVerifier", side_effect=RuntimeError("sql engine down"))
@patch("qwed_new.core.dsl_logic_verifier.DSLLogicVerifier", side_effect=RuntimeError("dsl logic engine down"))
@patch("qwed_new.core.logic_verifier.LogicVerifier", side_effect=RuntimeError("logic engine down"))
@patch("qwed_new.core.verifier.VerificationEngine", side_effect=RuntimeError("math engine down"))
def test_run_full_engine_tests_engine_construction_failures(
    _mock_math_cls,
    _mock_logic_cls,
    _mock_dsl_cls,
    _mock_sql_cls,
    _mock_code_cls,
):
    results = _run_full_engine_tests()

    assert len(results) == 12
    assert all(item["result"] == "ERROR" for item in results)
    assert all(item["passed"] is False for item in results)
    assert all(item["detail"] for item in results)
    # Every logic case is still listed, in the order a passing run prints them.
    logic_labels = [item["label"] for item in results if item["group"] == "Logic"]
    assert logic_labels == [LOGIC_LABEL_UNSAT, LOGIC_LABEL_VALID, LOGIC_LABEL_INVALID]


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
    # Logic proves a claim: it follows, or the engine finds a counterexample.
    # A satisfiable set of constraints is never shown as VERIFIED (#660).
    assert by_label[LOGIC_LABEL_UNSAT] == "UNVERIFIABLE (contradiction) | DENY"
    assert by_label[LOGIC_LABEL_VALID] == "VERIFIED | ADMIT"
    assert by_label[LOGIC_LABEL_INVALID] == "VERIFIED (false) | DENY"
    assert [item["label"] for item in results if item["group"] == "Logic"] == [
        LOGIC_LABEL_UNSAT,
        LOGIC_LABEL_VALID,
        LOGIC_LABEL_INVALID,
    ]
    assert len(results) == 12
    for item in results:
        assert not item["result"].startswith("BLOCKED")
        if "VERIFIED" in item["result"]:
            assert item["result"].endswith(("| ADMIT", "| DENY"))


def test_failed_check_prints_failed_not_blocked(monkeypatch):
    """A self-check whose engine answer does not match is reported FAILED,
    and the engine's own status is kept in the detail for diagnosis.

    The real engine runs; only the self-check input changes, so the claimed
    994010994 no longer matches what the engine computes.
    """
    monkeypatch.setattr("qwed_sdk.cli.MATH_LABEL_LARGE", "997*998*998")

    results = {item["label"]: item for item in _run_full_engine_tests() if item["group"] == "Math"}

    failed = results["997*998*998"]
    assert failed["passed"] is False
    assert failed["result"] == "FAILED"
    # Branch-specific detail: the engine decided the claim is false.
    assert failed["detail"] == "status=DISPROVEN"
    # The other Math checks are untouched and still decided.
    assert results["2+2=4"]["result"] == "VERIFIED | ADMIT"
    assert results["2+2=5"]["result"] == "VERIFIED (false) | DENY"


@patch(
    "qwed_sdk.cli._run_full_engine_tests",
    return_value=[{"group": "Math", "label": "2+2=4", "passed": True, "result": "VERIFIED | ADMIT"}],
)
def test_test_command_success_says_ready(_mock_results):
    result = CliRunner().invoke(cli, ["test"])

    assert result.exit_code == 0
    assert "All engines ready." in result.output


# ---------------------------------------------------------------------------
# #660: the logic lines prove a claim; a satisfiable set is never VERIFIED.
#
# `qwed test` printed `x>3 AND x<10 -> VERIFIED (x=4) | ADMIT` for a satisfiable
# set of three constraints, under a label that named two. The cases below are
# the ways a check of that shape could still pass something it should refuse.
# ---------------------------------------------------------------------------

VALID_ANSWER = DSLVerificationResult(status="VALID")
INVALID_ANSWER = DSLVerificationResult(status="INVALID", model={"x": "6"})


def _lookalikes(status):
    """The status with its case, spacing, invisible characters and look-alike
    letters changed: none of them is the status."""
    fullwidth = "".join(chr(ord(char) + 0xFEE0) for char in status)
    variants = [
        status.lower(),
        status.title(),
        f" {status}",
        f"{status} ",
        f"{status}\n",
        f"{status}\t",
        f"{status}​",
        f"{status[:2]}​{status[2:]}",
        fullwidth,
        status.replace("A", "А"),  # Cyrillic A
        status.replace("I", "Ι"),  # Greek capital iota
    ]
    # A replacement that leaves the status unchanged would put the real status
    # among the refused ones: every variant must differ from it and from the others.
    assert status not in variants
    assert len(set(variants)) == len(variants)
    return variants


OTHER_STATUSES = ["SAT", "UNSAT", "VACUOUS", "UNKNOWN", "ERROR", "BLOCKED", "", None]
NOT_A_PROOF = OTHER_STATUSES + ["INVALID"] + _lookalikes("VALID")
NOT_A_REFUTATION = OTHER_STATUSES + ["VALID"] + _lookalikes("INVALID")

COUNTEREXAMPLES_ACCEPTED = ["6", "7", "8", "9", "10"]
COUNTEREXAMPLES_REFUSED = [
    "5",  # the premise x > 5 does not hold
    "11",  # the claim x > 10 holds
    "3",
    "0",
    "-6",
    "06",
    "+7",
    " 7",
    "7 ",
    "7\n",
    "7.0",
    "7e0",
    "1_0",
    "0x7",
    "٧",  # Arabic-Indic digit seven
    "７",  # fullwidth digit seven
    "7​",
    "",
    "x",
    "None",
    7,
    6.0,
    True,
    None,
    ["7"],
    {"v": 7},
]


def _logic_cases(monkeypatch, valid_answer, invalid_answer):
    """Run the self-check with the DSL engine answering the first claim with
    valid_answer and the second with invalid_answer (an exception is raised)."""

    def fake_prove(self, premises, claim, variables=None):
        answer = valid_answer if claim == LOGIC_CLAIM_VALID_DSL else invalid_answer
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(DSLLogicVerifier, "prove_from_dsl", fake_prove)
    return {item["label"]: item for item in _run_full_engine_tests() if item["group"] == "Logic"}


def test_logic_cases_pass_with_the_real_engines():
    cases = {item["label"]: item for item in _run_full_engine_tests() if item["group"] == "Logic"}

    assert list(cases) == [LOGIC_LABEL_UNSAT, LOGIC_LABEL_VALID, LOGIC_LABEL_INVALID]
    assert all(item["passed"] for item in cases.values())
    assert cases[LOGIC_LABEL_INVALID]["detail"].startswith("status=INVALID, counterexample x=")


@pytest.mark.parametrize("status", NOT_A_PROOF, ids=repr)
def test_valid_case_fails_unless_the_engine_proves_the_claim(monkeypatch, status):
    cases = _logic_cases(monkeypatch, DSLVerificationResult(status=status, model={"x": "4"}), INVALID_ANSWER)

    assert cases[LOGIC_LABEL_VALID]["passed"] is False
    assert cases[LOGIC_LABEL_VALID]["result"] == "FAILED"
    assert cases[LOGIC_LABEL_VALID]["detail"]
    # The other logic cases are decided on their own.
    assert cases[LOGIC_LABEL_INVALID]["passed"] is True
    assert cases[LOGIC_LABEL_UNSAT]["passed"] is True


@pytest.mark.parametrize("status", NOT_A_REFUTATION, ids=repr)
def test_invalid_case_fails_unless_the_engine_refutes_the_claim(monkeypatch, status):
    cases = _logic_cases(monkeypatch, VALID_ANSWER, DSLVerificationResult(status=status, model={"x": "7"}))

    assert cases[LOGIC_LABEL_INVALID]["passed"] is False
    assert cases[LOGIC_LABEL_INVALID]["result"] == "FAILED"
    assert cases[LOGIC_LABEL_INVALID]["detail"]
    assert cases[LOGIC_LABEL_VALID]["passed"] is True


@pytest.mark.parametrize("value", COUNTEREXAMPLES_ACCEPTED)
def test_invalid_case_accepts_any_counterexample_in_range(monkeypatch, value):
    """Z3 may return any x with 5 < x <= 10; the check must not need one value."""
    cases = _logic_cases(monkeypatch, VALID_ANSWER, DSLVerificationResult(status="INVALID", model={"x": value}))

    assert cases[LOGIC_LABEL_INVALID]["passed"] is True
    assert cases[LOGIC_LABEL_INVALID]["result"] == "VERIFIED (false) | DENY"


@pytest.mark.parametrize("value", COUNTEREXAMPLES_REFUSED, ids=repr)
def test_invalid_case_fails_on_a_model_that_is_not_a_counterexample(monkeypatch, value):
    cases = _logic_cases(monkeypatch, VALID_ANSWER, DSLVerificationResult(status="INVALID", model={"x": value}))

    assert cases[LOGIC_LABEL_INVALID]["passed"] is False
    assert cases[LOGIC_LABEL_INVALID]["result"] == "FAILED"


@pytest.mark.parametrize("model", [None, {}, {"y": "7"}, {"X": "7"}], ids=repr)
def test_invalid_case_fails_without_a_value_for_x(monkeypatch, model):
    cases = _logic_cases(monkeypatch, VALID_ANSWER, DSLVerificationResult(status="INVALID", model=model))

    assert cases[LOGIC_LABEL_INVALID]["passed"] is False
    assert cases[LOGIC_LABEL_INVALID]["result"] == "FAILED"


@pytest.mark.parametrize(
    ("valid_answer", "invalid_answer", "passing", "failing"),
    [
        (VALID_ANSWER, VALID_ANSWER, LOGIC_LABEL_VALID, LOGIC_LABEL_INVALID),
        (INVALID_ANSWER, INVALID_ANSWER, LOGIC_LABEL_INVALID, LOGIC_LABEL_VALID),
    ],
    ids=["same-answer-valid", "same-answer-invalid"],
)
def test_an_engine_with_one_answer_for_both_claims_fails_one_case(
    monkeypatch, valid_answer, invalid_answer, passing, failing
):
    cases = _logic_cases(monkeypatch, valid_answer, invalid_answer)

    assert cases[passing]["passed"] is True
    assert cases[failing]["passed"] is False
    assert cases[failing]["result"] == "FAILED"


def test_logic_proof_cases_report_error_when_the_engine_raises(monkeypatch):
    cases = _logic_cases(monkeypatch, RuntimeError("solver crashed"), ValueError("bad claim"))

    assert cases[LOGIC_LABEL_VALID]["result"] == "ERROR"
    assert cases[LOGIC_LABEL_VALID]["passed"] is False
    assert cases[LOGIC_LABEL_VALID]["detail"] == "RuntimeError: solver crashed"
    assert cases[LOGIC_LABEL_INVALID]["result"] == "ERROR"
    assert cases[LOGIC_LABEL_INVALID]["passed"] is False
    assert cases[LOGIC_LABEL_INVALID]["detail"] == "ValueError: bad claim"
    assert cases[LOGIC_LABEL_UNSAT]["passed"] is True


def test_a_satisfiability_only_engine_cannot_pass_qwed_test(monkeypatch):
    """The old framing: a model exists, so the claim is VERIFIED. No logic line
    may pass on it, and `qwed test` exits 1."""
    sat_only = DSLVerificationResult(status="SAT", model={"x": "4"})
    monkeypatch.setattr(DSLLogicVerifier, "prove_from_dsl", lambda self, *args, **kwargs: sat_only)

    result = CliRunner().invoke(cli, ["test"])

    assert result.exit_code == 1
    proof_lines = [line for line in result.output.splitlines() if "=>" in line]
    assert len(proof_lines) == 2
    assert all(line.lstrip().startswith("[x]") and line.rstrip().endswith("FAILED") for line in proof_lines)
    assert "VERIFIED" not in "\n".join(proof_lines)


@patch("qwed_new.core.dsl_logic_verifier.DSLLogicVerifier", side_effect=RuntimeError("dsl logic engine down"))
def test_dsl_engine_down_errors_only_its_two_cases(_mock_dsl_cls):
    results = _run_full_engine_tests()
    cases = {item["label"]: item for item in results if item["group"] == "Logic"}

    assert len(results) == 12
    assert cases[LOGIC_LABEL_UNSAT]["passed"] is True
    for label in (LOGIC_LABEL_VALID, LOGIC_LABEL_INVALID):
        assert cases[label]["result"] == "ERROR"
        assert cases[label]["detail"] == "RuntimeError: dsl logic engine down"
    assert sum(1 for item in results if item["passed"]) == 10


@patch("qwed_new.core.logic_verifier.LogicVerifier", side_effect=RuntimeError("logic engine down"))
def test_logic_engine_down_errors_only_its_case(_mock_logic_cls):
    results = _run_full_engine_tests()
    cases = {item["label"]: item for item in results if item["group"] == "Logic"}

    assert len(results) == 12
    assert cases[LOGIC_LABEL_UNSAT]["result"] == "ERROR"
    assert cases[LOGIC_LABEL_VALID]["passed"] is True
    assert cases[LOGIC_LABEL_INVALID]["passed"] is True
    assert sum(1 for item in results if item["passed"]) == 11


def test_each_run_asks_the_engine_again(monkeypatch):
    """No cache or earlier answer decides a run: when the engine's answer changes
    between two runs, the second run shows the new answer."""
    answers = {"valid": VALID_ANSWER}
    asked = []

    def fake_prove(self, premises, claim, variables=None):
        asked.append(claim)
        return answers["valid"] if claim == LOGIC_CLAIM_VALID_DSL else INVALID_ANSWER

    monkeypatch.setattr(DSLLogicVerifier, "prove_from_dsl", fake_prove)

    def valid_line():
        return next(item for item in _run_full_engine_tests() if item["label"] == LOGIC_LABEL_VALID)

    first = valid_line()
    answers["valid"] = DSLVerificationResult(status="SAT", model={"x": "4"})
    second = valid_line()

    assert (first["passed"], first["result"]) == (True, "VERIFIED | ADMIT")
    assert (second["passed"], second["result"]) == (False, "FAILED")
    # Both claims were put to the engine on both runs.
    assert asked == [LOGIC_CLAIM_VALID_DSL, LOGIC_CLAIM_INVALID_DSL] * 2


def _verdict(status, proof_ref, developer_fields=None):
    return SimpleNamespace(status=status, proof_ref=proof_ref, developer_fields=developer_fields or {})


@pytest.mark.parametrize("proof_ref", [None, "", 0], ids=repr)
def test_a_proof_line_needs_a_proof_ref(monkeypatch, proof_ref):
    """VERIFIED is printed only with a proof_ref bound to the evidence (QWED_RULES.md):
    a verdict that is VERIFIED without one passes neither proof line."""
    monkeypatch.setattr(
        "qwed_new.core.route_diagnostics.logic_diagnostic",
        lambda result: _verdict(DiagnosticStatus.VERIFIED, proof_ref, {"is_valid": False}),
    )
    cases = _logic_cases(monkeypatch, VALID_ANSWER, INVALID_ANSWER)

    for label in (LOGIC_LABEL_VALID, LOGIC_LABEL_INVALID):
        assert cases[label]["passed"] is False
        assert cases[label]["result"] == "FAILED"


@pytest.mark.parametrize("status", [DiagnosticStatus.UNVERIFIABLE, DiagnosticStatus.BLOCKED], ids=lambda s: s.value)
def test_a_proof_line_needs_a_verified_verdict(monkeypatch, status):
    """A proof_ref on a verdict that is not VERIFIED does not make the line VERIFIED."""
    monkeypatch.setattr(
        "qwed_new.core.route_diagnostics.logic_diagnostic",
        lambda result: _verdict(status, "a" * 64, {"is_valid": False}),
    )
    cases = _logic_cases(monkeypatch, VALID_ANSWER, INVALID_ANSWER)

    for label in (LOGIC_LABEL_VALID, LOGIC_LABEL_INVALID):
        assert cases[label]["passed"] is False
        assert cases[label]["result"] == "FAILED"


def test_the_false_claim_needs_the_proven_false_verdict(monkeypatch):
    """A VERIFIED verdict with a proof_ref but without is_valid False is the
    verdict for a claim that holds, not for one with a counterexample."""
    monkeypatch.setattr(
        "qwed_new.core.route_diagnostics.logic_diagnostic",
        lambda result: _verdict(DiagnosticStatus.VERIFIED, "a" * 64, {}),
    )
    cases = _logic_cases(monkeypatch, VALID_ANSWER, INVALID_ANSWER)

    assert cases[LOGIC_LABEL_VALID]["passed"] is True
    assert cases[LOGIC_LABEL_INVALID]["passed"] is False
    assert cases[LOGIC_LABEL_INVALID]["result"] == "FAILED"


@pytest.mark.parametrize("status", NOT_A_PROOF, ids=repr)
def test_the_valid_line_reads_the_engines_status_beside_the_verdict(monkeypatch, status):
    """A verdict that looks right does not make another engine status a proof."""
    monkeypatch.setattr(
        "qwed_new.core.route_diagnostics.logic_diagnostic",
        lambda result: _verdict(DiagnosticStatus.VERIFIED, "a" * 64, {"is_valid": False}),
    )
    cases = _logic_cases(monkeypatch, DSLVerificationResult(status=status, model={"x": "4"}), INVALID_ANSWER)

    assert cases[LOGIC_LABEL_VALID]["passed"] is False
    assert cases[LOGIC_LABEL_VALID]["result"] == "FAILED"


@pytest.mark.parametrize("status", NOT_A_REFUTATION, ids=repr)
def test_the_false_line_reads_the_engines_status_beside_the_verdict(monkeypatch, status):
    monkeypatch.setattr(
        "qwed_new.core.route_diagnostics.logic_diagnostic",
        lambda result: _verdict(DiagnosticStatus.VERIFIED, "a" * 64, {"is_valid": False}),
    )
    cases = _logic_cases(monkeypatch, VALID_ANSWER, DSLVerificationResult(status=status, model={"x": "7"}))

    assert cases[LOGIC_LABEL_INVALID]["passed"] is False
    assert cases[LOGIC_LABEL_INVALID]["result"] == "FAILED"


def test_proof_lines_carry_a_proof_ref_with_the_real_engine():
    engine = DSLLogicVerifier()
    follows = _prove_logic_claim(engine, LOGIC_CLAIM_VALID_DSL)
    refuted = _prove_logic_claim(engine, LOGIC_CLAIM_INVALID_DSL)

    assert follows.verdict.status == DiagnosticStatus.VERIFIED
    assert follows.verdict.proof_ref
    assert refuted.verdict.status == DiagnosticStatus.VERIFIED
    assert refuted.verdict.proof_ref
    assert refuted.verdict.developer_fields["is_valid"] is False


def test_a_failed_line_keeps_the_engines_own_words(monkeypatch):
    """A returned ERROR is a failed check, not a verdict (#438); what the engine
    said stays in the detail, so it can be told from a line that just did not match."""
    error = DSLVerificationResult(status="ERROR", error="parse failed", constraint_id="dsl.test_rule")
    cases = _logic_cases(monkeypatch, error, INVALID_ANSWER)

    valid = cases[LOGIC_LABEL_VALID]
    assert valid["passed"] is False
    assert valid["result"] == "FAILED"
    assert valid["detail"] == "status=ERROR, error=parse failed, constraint_id=dsl.test_rule"


def test_readme_sample_matches_qwed_test_output():
    """The README shows what `qwed test` prints; the two must not drift (#660)."""
    block = re.search(
        r"deterministic checks and needs no model or server:\n\n```text\n(.*?)\n```",
        README.read_text(encoding="utf-8"),
        re.DOTALL,
    )
    assert block, "README no longer shows a qwed test sample"
    result_line = re.compile(r"^[ \t]+\[(?:ok|x)\] .+$", re.MULTILINE)
    expected = [line.rstrip() for line in result_line.findall(block.group(1))]

    result = CliRunner().invoke(cli, ["test"])
    actual = [line.rstrip() for line in result_line.findall(result.output)]

    assert result.exit_code == 0
    assert len(expected) == 12
    assert actual == expected
