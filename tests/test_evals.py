"""Soundness gate for evals/: no claim that does not hold may be accepted.

Each case in evals/cases is a claim with a known answer. A "false accept" is a
claim that does not hold but that an engine reported as verified. One is
enough to fail the build; add the case that exposed it to evals/cases so it
stays covered once fixed.
"""

import pytest

from evals.run import OUTCOMES, _engines, load_cases, run

REQUIRED = {"id", "check", "claim", "holds", "input"}


@pytest.fixture(scope="module")
def result():
    return run(load_cases())


def test_cases_are_well_formed():
    cases = load_cases()
    assert cases, "evals/cases holds no cases"
    for case in cases:
        missing = REQUIRED - case.keys()
        assert not missing, f"{case.get('id')}: missing {sorted(missing)}"
        assert isinstance(case["holds"], bool), f"{case['id']}: holds must be true or false"
    # Every engine call the runner knows is tested both ways, so no check can
    # drop out of the eval unnoticed.
    for check in _engines():
        answers = {c["holds"] for c in cases if c["check"] == check}
        assert answers == {True, False}, f"{check}: needs claims that hold and claims that do not"


def test_no_engine_raises(result):
    errors = [f"{r['id']}: {r['error']}" for r in result["cases"] if r["outcome"] == "error"]
    assert not errors, "engines raised instead of returning a result:\n" + "\n".join(errors)


def test_no_false_accepts(result):
    false = [f"{r['id']} ({r['check']}): {r['claim']} -> {r['status']}" for r in result["cases"] if r["outcome"] == "false_accept"]
    assert not false, "claims that do not hold were accepted:\n" + "\n".join(false)


def test_outcomes_add_up(result):
    totals = result["totals"]
    assert sum(totals[name] for name in set(OUTCOMES.values()) | {"error"}) == totals["cases"]
