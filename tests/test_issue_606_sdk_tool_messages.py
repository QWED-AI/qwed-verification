"""#606: the LangChain and CrewAI tools called every result the server did not
admit incorrect, unsafe or failed.

They chose their message by ``result.is_verified`` alone, which is the
server's admission, and read ``message``, ``corrected`` and ``vulnerabilities``,
which no route sends. So:

- a maths result QWED did not decide (``x/x = 1``, ``2+2`` with no claim, input
  that does not parse) was "INCORRECT";
- code or SQL that does not parse was "security vulnerabilities" or "possible
  injection", and the LangChain code tool listed no issues even for unsafe code;
- the generic tools, on /verify/natural_language, said "FAILED" for a correct
  claim, because that route admits nothing while the translation is unverified.

Now "incorrect" and "unsafe" mean decided against (``VERIFIED``, not admitted),
an undecided result gives its status and the server's message, and a
natural-language result says what holds for the translated expression. The
responses come from the real routes; the natural-language translation is
patched.
"""

from unittest.mock import patch

import httpx
import pytest

from qwed_new.api import main as api_main
from qwed_new.core.schemas import MathVerificationTask
from qwed_sdk import crewai, langchain
from qwed_sdk.models import VerificationResult
from tests.test_issue_320_logic_route_admission import client  # noqa: F401  (fixture)

WRONG_WORDS = ("INCORRECT", "UNSAFE", "SECURITY ISSUES", "injection", "vulnerabilities", "FAILED")
SCHEMA = "CREATE TABLE t (id INT, a INT)"


def _tool(tool_class):
    # The SQL tool checks a query against the schema it runs on (#608).
    if tool_class is crewai.QWEDSQLTool:
        return tool_class(api_key="x", schema_ddl=SCHEMA)
    return tool_class(api_key="x")


def _answer(monkeypatch, tool_class, method, response):
    tool = _tool(tool_class)
    result = VerificationResult.from_dict(response)
    monkeypatch.setattr(tool._client, method, lambda *args, **kwargs: result)
    return tool._run("input")


def _math(client, expression):  # noqa: F811
    return client.post("/verify/math", json={"expression": expression}).json()


def _code(client, code):  # noqa: F811
    return client.post("/verify/code", json={"code": code, "language": "python"}).json()


def _sql(client, query):  # noqa: F811
    return client.post("/verify/sql", json={"query": query, "schema_ddl": SCHEMA, "dialect": "sqlite"}).json()


def _natural_language(client, claimed):  # noqa: F811
    task = MathVerificationTask(expression="0.15 * 200", claimed_answer=claimed, reasoning="15% of 200", confidence=0.95)
    with patch.object(api_main.control_plane.translator, "translate", return_value=task):
        return client.post("/verify/natural_language", json={"query": "What is 15% of 200?"}).json()


MATH_TOOLS = [(langchain.QWEDMathTool, "verify_math"), (crewai.QWEDMathTool, "verify_math")]
CODE_TOOLS = [(langchain.QWEDCodeTool, "verify_code"), (crewai.QWEDCodeTool, "verify_code")]
GENERIC_TOOLS = [(langchain.QWEDTool, "verify"), (crewai.QWEDVerificationTool, "verify")]


# ---------------------------------------------------------------- maths

@pytest.mark.parametrize("tool_class, method", MATH_TOOLS)
@pytest.mark.parametrize("expression, status, message", [
    ("x/x = 1", "⚠️ UNVERIFIABLE", "Identity holds only where both sides are defined"),
    ("2+2", "⚠️ UNVERIFIABLE", "no equality or proof claim was provided"),
    ("sinc(0) = 0", "⛔ BLOCKED", "Expression could not be parsed"),
])
def test_a_maths_result_qwed_did_not_decide_is_not_incorrect(client, monkeypatch, tool_class, method, expression, status, message):  # noqa: F811
    answer = _answer(monkeypatch, tool_class, method, _math(client, expression))

    assert answer.startswith(status)
    assert message in answer
    assert not any(word in answer for word in WRONG_WORDS)


@pytest.mark.parametrize("tool_class, method", MATH_TOOLS)
def test_a_false_claim_is_still_incorrect(client, monkeypatch, tool_class, method):  # noqa: F811
    answer = _answer(monkeypatch, tool_class, method, _math(client, "2+2=5"))

    assert answer.startswith("❌ INCORRECT")
    assert "Identity is false" in answer


@pytest.mark.parametrize("tool_class, method", MATH_TOOLS)
def test_a_true_claim_is_still_verified(client, monkeypatch, tool_class, method):  # noqa: F811
    assert _answer(monkeypatch, tool_class, method, _math(client, "2+2=4")).startswith("✅ VERIFIED")


# ---------------------------------------------------------------- code

@pytest.mark.parametrize("tool_class, method", CODE_TOOLS)
def test_code_that_does_not_parse_is_blocked_not_unsafe(client, monkeypatch, tool_class, method):  # noqa: F811
    answer = _answer(monkeypatch, tool_class, method, _code(client, "def f(:\n  pass"))

    assert answer.startswith("⛔ BLOCKED")
    assert "does not parse" in answer
    assert not any(word in answer for word in WRONG_WORDS)


@pytest.mark.parametrize("tool_class, method", CODE_TOOLS)
def test_unsafe_code_lists_the_issues_the_server_sends(client, monkeypatch, tool_class, method):  # noqa: F811
    # The LangChain tool read "vulnerabilities", which /verify/code does not
    # send, so it listed nothing.
    answer = _answer(monkeypatch, tool_class, method, _code(client, "import os\nos.system(input())"))

    assert answer.startswith("⚠️ SECURITY ISSUES")
    assert "CRITICAL: Shell or process execution" in answer


@pytest.mark.parametrize("tool_class, method", CODE_TOOLS)
def test_safe_code_is_still_safe(client, monkeypatch, tool_class, method):  # noqa: F811
    assert _answer(monkeypatch, tool_class, method, _code(client, "x = 1")).startswith("✅ SAFE")


@pytest.mark.parametrize("tool_class, expected", [
    (langchain.QWEDCodeTool, "⚠️ SECURITY ISSUES: Code is not safe"),
    (crewai.QWEDCodeTool, "❌ UNSAFE: Code is not safe"),
])
def test_unsafe_code_with_no_issues_listed_is_still_unsafe(monkeypatch, tool_class, expected):
    response = {"status": "VERIFIED", "admission": "BLOCKED", "is_valid": False, "agent_message": "Code is not safe"}

    assert _answer(monkeypatch, tool_class, "verify_code", response) == expected


# ---------------------------------------------------------------- server unreachable

def _unreachable(monkeypatch, tool_class):
    tool = _tool(tool_class)

    def refuse(*args, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(tool._client, "_request", refuse)
    return tool._run("input")


@pytest.mark.parametrize("tool_class", [langchain.QWEDCodeTool, crewai.QWEDCodeTool, crewai.QWEDSQLTool])
def test_a_server_that_cannot_be_reached_is_named_as_the_reason(monkeypatch, tool_class):
    # The client's own UNVERIFIABLE result for an unreachable server keeps its
    # reason in "message" and "error", not "agent_message". Without it the
    # agent could not tell an outage, worth a retry, from an input QWED could
    # not decide.
    answer = _unreachable(monkeypatch, tool_class)

    assert answer.startswith("⚠️ UNVERIFIABLE: The QWED server could not be reached")
    assert not any(word in answer for word in WRONG_WORDS)


def test_the_clients_error_is_the_reason_when_there_is_no_message(monkeypatch):
    tool = _tool(crewai.QWEDSQLTool)
    result = VerificationResult(status="UNVERIFIABLE", result={}, error="server unreachable")
    monkeypatch.setattr(tool._client, "verify_sql", lambda *args, **kwargs: result)

    assert tool._run("SELECT 1") == "⚠️ UNVERIFIABLE: server unreachable"


# ---------------------------------------------------------------- SQL (CrewAI)

def test_sql_that_does_not_parse_is_blocked_not_an_injection(client, monkeypatch):  # noqa: F811
    response = _sql(client, "SELEC * FRM")
    answer = _answer(monkeypatch, crewai.QWEDSQLTool, "verify_sql", response)

    assert answer.startswith("⛔ BLOCKED")
    assert response["agent_message"]
    assert response["agent_message"] in answer
    assert not any(word in answer for word in WRONG_WORDS)


@pytest.mark.parametrize("query", ["SELECT * FROM t WHERE id = 1 OR 1=1", "DROP TABLE t"])
def test_unsafe_sql_is_unsafe_with_the_servers_reason(client, monkeypatch, query):  # noqa: F811
    answer = _answer(monkeypatch, crewai.QWEDSQLTool, "verify_sql", _sql(client, query))

    assert answer == "❌ UNSAFE: The SQL query failed security verification and is not safe to execute."


def test_safe_sql_is_still_safe(client, monkeypatch):  # noqa: F811
    assert _answer(monkeypatch, crewai.QWEDSQLTool, "verify_sql", _sql(client, "SELECT a FROM t")).startswith("✅ SAFE")


# ---------------------------------------------------------------- natural language (generic tools)

@pytest.mark.parametrize("tool_class, method", GENERIC_TOOLS)
def test_a_correct_claim_is_not_reported_as_failed(client, monkeypatch, tool_class, method):  # noqa: F811
    response = _natural_language(client, 30.0)
    assert (response["status"], response["admission"]) == ("VERIFIED", "BLOCKED")

    answer = _answer(monkeypatch, tool_class, method, response)

    assert answer.startswith("⚠️ HOLDS, NOT ADMITTED: the claim holds for the translated expression")
    assert "0.15 * 200" in answer
    assert "translation is not verified" in answer
    assert not any(word in answer for word in WRONG_WORDS)


@pytest.mark.parametrize("tool_class, method", GENERIC_TOOLS)
def test_a_false_claim_is_incorrect_with_the_value(client, monkeypatch, tool_class, method):  # noqa: F811
    answer = _answer(monkeypatch, tool_class, method, _natural_language(client, 40.0))

    assert answer.startswith("❌ INCORRECT for the translated expression")
    assert "Claimed value is proven false" in answer
    assert "Its value is 30.0" in answer
    assert "translation is not verified" in answer


@pytest.mark.parametrize("tool_class, method", GENERIC_TOOLS)
def test_a_blocked_natural_language_result_gives_the_servers_message(client, monkeypatch, tool_class, method):  # noqa: F811
    with patch.object(api_main.control_plane, "process_natural_language", side_effect=RuntimeError("engine down")):
        response = client.post("/verify/natural_language", json={"query": "What is 15% of 200?"}).json()

    answer = _answer(monkeypatch, tool_class, method, response)

    assert answer.startswith("⛔ BLOCKED")
    assert response["agent_message"]
    assert response["agent_message"] in answer
    assert not any(word in answer for word in WRONG_WORDS)


@pytest.mark.parametrize("tool_class, method", GENERIC_TOOLS)
def test_an_admitted_natural_language_result_is_verified(monkeypatch, tool_class, method):
    # Once #585 verifies the translation, the server may admit one.
    response = {"status": "VERIFIED", "admission": "ADMIT", "is_valid": True, "agent_message": "Expression verified successfully"}

    assert _answer(monkeypatch, tool_class, method, response).startswith("✅ VERIFIED")
