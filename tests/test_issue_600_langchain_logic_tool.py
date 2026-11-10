"""#600: the LangChain QWEDLogicTool reported UNSAT for every /verify/logic
result, satisfiable ones too.

The tool chose its message by ``result.is_verified`` alone, which is the
server's admission. /verify/logic admits no result while the translation of
the query into constraints is unverified (#599, #585), so every result took
the UNSAT branch: an agent was told "No valid assignment exists" for a query
with a model in the response. The tool now follows the status, and says why a
satisfiable result is not admitted.

The responses here come from the real route, with the translation patched and
Z3 deciding the constraints.
"""

from unittest.mock import patch

import pytest

from qwed_new.api import main as api_main
from qwed_sdk import langchain
from qwed_sdk.models import VerificationResult
from tests.test_issue_320_logic_route_admission import _translated_to, client  # noqa: F401  (fixture)


def _answer(monkeypatch, response):
    tool = langchain.QWEDLogicTool(api_key="x")
    result = VerificationResult.from_dict(response)
    monkeypatch.setattr(tool._client, "verify_logic", lambda query: result)
    return tool._run("query")


def _route(client, dsl):  # noqa: F811
    route_patch, _ = _translated_to(dsl)
    with route_patch:
        return client.post("/verify/logic", json={"query": "Is there such an x?"}).json()


def test_a_satisfiable_query_is_reported_with_its_model_and_why_it_is_not_admitted(client, monkeypatch):  # noqa: F811
    response = _route(client, "(GT x 5)")
    assert (response["status"], response["admission"]) == ("VERIFIED", "BLOCKED")

    answer = _answer(monkeypatch, response)

    assert answer.startswith("⚠️ SAT, NOT ADMITTED")
    assert "UNSAT" not in answer
    assert "{'x': '6'}" in answer
    assert "translation is not verified" in answer


def test_an_unsatisfiable_query_is_unsat(client, monkeypatch):  # noqa: F811
    response = _route(client, "(AND (GT x 5) (LT x 3))")
    assert response["status"] == "UNVERIFIABLE"

    answer = _answer(monkeypatch, response)

    assert answer.startswith("❌ UNSAT: no assignment satisfies the translated constraints")
    assert "translation is not verified" in answer


def test_a_blocked_query_gives_the_servers_message(client, monkeypatch):  # noqa: F811
    response = _route(client, "(AND)")
    assert response["status"] == "BLOCKED"

    answer = _answer(monkeypatch, response)

    assert answer.startswith("⛔ BLOCKED: ")
    assert "requires at least 2 arguments" in answer
    assert "UNSAT" not in answer


def test_a_failed_translation_is_blocked_not_unsat(client, monkeypatch):  # noqa: F811
    async def failed(query, organization_id=None, preferred_provider=None):
        return {"status": "ERROR", "error": "LLM translation failed"}

    with patch.object(api_main.control_plane, "process_logic_query", failed):
        response = client.post("/verify/logic", json={"query": "Is there such an x?"}).json()

    assert _answer(monkeypatch, response) == "⛔ BLOCKED: LLM translation failed"


def test_an_admitted_satisfiable_result_is_sat(monkeypatch):
    # Once #585 verifies the translation, the server may admit one.
    response = {"status": "VERIFIED", "admission": "ADMIT", "model": {"x": "6"}, "query_semantics_verified": True}

    assert _answer(monkeypatch, response) == "✅ SAT: Satisfying assignment: {'x': '6'}"


@pytest.mark.parametrize("response, expected", [
    ({"status": "UNVERIFIABLE", "admission": "BLOCKED", "agent_message": "Solver timed out"},
     "⚠️ UNVERIFIABLE: Solver timed out"),
    ({"status": "UNVERIFIABLE", "admission": "BLOCKED"},
     "⚠️ UNVERIFIABLE: the constraints could not be decided"),
    ({"status": "BLOCKED", "admission": "BLOCKED"}, "⛔ BLOCKED: logic verification failed"),
])
def test_an_undecided_result_is_not_called_unsat(monkeypatch, response, expected):
    assert _answer(monkeypatch, response) == expected
