"""#602: the Action's verify-process mode reported VERIFIED and ADMIT from
keyword matching.

ProcessVerifier looks for the IRAC words (issue, rule, application,
conclusion, or a few synonyms) and for milestone keywords the workflow passes.
When all were found, the mode set ``verified`` to true, the verdict to
VERIFIED and the admission to ADMIT, with a ``proof_ref``, and logged "Reasoning
Process Verified": the text "issue rule application conclusion" passed as a
verified reasoning process. Keyword matching cannot show that the reasoning is
right, so the result is now UNVERIFIABLE and DENY whatever the keywords show,
as /verify/process returns since #601. The mode stays a lint gate: a missing
step or milestone is a finding and fails the step.
"""

import json

import pytest

import action_entrypoint as entry
from tests.test_action_github_output import _parse_github_output, _read, output_file  # noqa: F401  (fixture)

KEYWORDS_ONLY = "issue rule application conclusion"


@pytest.fixture
def run(output_file, monkeypatch):  # noqa: F811  (the imported fixture)
    def _run(llm_output, *, milestones=None, output_format=None, fail_on_findings=None):
        monkeypatch.setenv("INPUT_LLM_OUTPUT", llm_output)
        for name, value in (
            ("MILESTONES", milestones),
            ("OUTPUT_FORMAT", output_format),
            ("FAIL_ON_FINDINGS", fail_on_findings),
        ):
            if value is None:
                monkeypatch.delenv(f"INPUT_{name}", raising=False)
            else:
                monkeypatch.setenv(f"INPUT_{name}", value)
        code = None
        try:
            entry.action_verify_process()
        except SystemExit as exc:
            code = exc.code
        return code, _parse_github_output(_read(output_file))

    return _run


@pytest.mark.parametrize("milestones", [None, "issue, conclusion"])
def test_the_four_irac_words_are_not_verified_or_admitted(run, capsys, milestones):
    code, outputs = run(KEYWORDS_ONLY, milestones=milestones)

    assert code is None  # the lint passed, so the step does not fail
    assert outputs["verdict"] == "UNVERIFIABLE"
    assert outputs["admission"] == "DENY"
    assert outputs["proof_ref"] == ""
    assert outputs["verified"] == "false"
    assert "failed" in outputs["badge_url"]
    assert json.loads(outputs["findings"]) == []
    assert outputs["irac_score"] == "1.0000"
    log = capsys.readouterr().out
    assert "Reasoning Process Verified" not in log
    assert "keyword matching does not verify the reasoning" in log


def test_missing_irac_steps_still_fail_the_step(run):
    code, outputs = run("issue and rule only")

    assert code == 1
    assert outputs["verdict"] == "UNVERIFIABLE"
    assert outputs["admission"] == "DENY"
    assert outputs["proof_ref"] == ""
    (finding,) = json.loads(outputs["findings"])
    assert finding["type"] == "MISSING_STRUCTURE"
    assert "application" in finding["message"]
    assert "conclusion" in finding["message"]


def test_a_missed_milestone_still_fails_the_step(run):
    code, outputs = run(KEYWORDS_ONLY, milestones="statute of limitations")

    assert code == 1
    assert outputs["verdict"] == "UNVERIFIABLE"
    (finding,) = json.loads(outputs["findings"])
    assert finding["type"] == "MISSED_MILESTONE"
    assert outputs["process_rate"] == "0.0000"


def test_with_fail_on_findings_off_a_missing_step_does_not_fail_the_step(run):
    code, outputs = run("issue and rule only", fail_on_findings="false")

    assert code is None
    assert outputs["admission"] == "DENY"
    assert json.loads(outputs["findings"])


def test_the_verification_context_says_why_it_is_not_admitted(run, capsys):
    code, outputs = run(KEYWORDS_ONLY, output_format="json")

    assert code is None
    context = json.loads(outputs["verification_context"])
    assert context["verdict"] == "UNVERIFIABLE"
    assert context["context"]["decision"]["admission"] == "DENY"
    assert context["context"]["evidence"]["proof_ref"] is None
    assert context["object"]["formal_statement"] == (
        "QWED process verification was not admitted: keyword matching does not verify the reasoning"
    )
    evidence = context["context"]["evidence"]["evidence"]
    assert evidence["markers_found"] is True
    assert evidence["findings_count"] == 0

    printed = json.loads(capsys.readouterr().out.split("\n", 1)[1])
    assert printed["verified"] is False
    assert printed["verdict"] == "UNVERIFIABLE"
    assert printed["admission"] == "DENY"
    assert printed["markers_found"] is True
