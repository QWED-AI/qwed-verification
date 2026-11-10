"""#608: the CrewAI SQL tool and the LangChain callback sent an empty schema.

/verify/sql checks a query against the schema it runs on, and answers HTTP 400
without one. So against a real server the CrewAI ``QWEDSQLTool`` answered
"ERROR" for every query, and the ``QWEDVerificationCallback`` SQL check never
ran: its ``except`` swallowed the 400, recorded nothing, and ``get_summary``
counted the output as verified. The callback also counted code issues from
``vulnerabilities``, which /verify/code does not send.

The tool tests mocked ``verify_sql``, so they never sent the request the tool
built. These tests send it, through the client, to the real route.
"""

import httpx
import pytest

from qwed_sdk import crewai, langchain
from tests.test_issue_320_logic_route_admission import client  # noqa: F401  (fixture)

SCHEMA = "CREATE TABLE t (id INT, a INT)"
NO_SCHEMA = "no schema was given, so QWED cannot verify the query"


def _through_the_route(client, monkeypatch, owner):  # noqa: F811
    """Send *owner*'s requests to the app, and return the JSON bodies sent."""
    sent = []
    send = client.request

    def request(method, url, **kwargs):
        sent.append(kwargs.get("json"))
        return send(method, url, **kwargs)

    monkeypatch.setattr(client, "request", request)
    owner._client._client = client
    owner._client.base_url = ""
    return sent


def _sql_tool(client, monkeypatch, **kwargs):  # noqa: F811
    tool = crewai.QWEDSQLTool(api_key="x", **kwargs)
    return tool, _through_the_route(client, monkeypatch, tool)


def _callback(client, monkeypatch, **kwargs):  # noqa: F811
    options = {"verify_math": False, "verify_code": False, "log_results": False, **kwargs}
    callback = langchain.QWEDVerificationCallback(api_key="x", **options)
    return callback, _through_the_route(client, monkeypatch, callback)


# ---------------------------------------------------------------- CrewAI SQL tool

def test_the_sql_tool_sends_its_schema_and_dialect(client, monkeypatch):  # noqa: F811
    tool, sent = _sql_tool(client, monkeypatch, schema_ddl=SCHEMA, dialect="postgres")

    tool._run("SELECT a FROM t")

    assert sent == [{"query": "SELECT a FROM t", "schema_ddl": SCHEMA, "dialect": "postgres"}]


@pytest.mark.parametrize("query, expected", [
    ("SELECT a FROM t", "✅ SAFE"),
    ("DROP TABLE t", "❌ UNSAFE"),
    ("SELECT * FROM t WHERE id = 1 OR 1=1", "❌ UNSAFE"),
    ("SELEC * FRM", "⛔ BLOCKED"),
])
def test_the_sql_tool_reports_what_the_route_decides(client, monkeypatch, query, expected):  # noqa: F811
    tool, _ = _sql_tool(client, monkeypatch, schema_ddl=SCHEMA)

    answer = tool._run(query)

    assert answer.startswith(expected)
    assert "ERROR" not in answer


@pytest.mark.parametrize("kwargs", [{}, {"schema_ddl": ""}, {"schema_ddl": "   "}])
def test_the_sql_tool_without_a_schema_is_unverifiable_and_sends_nothing(client, monkeypatch, kwargs):  # noqa: F811
    tool, sent = _sql_tool(client, monkeypatch, **kwargs)

    answer = tool._run("SELECT a FROM t")

    assert answer.startswith(f"⚠️ UNVERIFIABLE: {NO_SCHEMA}")
    assert "schema_ddl" in answer
    assert sent == []


# ---------------------------------------------------------------- LangChain callback

@pytest.mark.parametrize("output, verified", [
    ("Run: SELECT a FROM t;", True),
    ("Run: SELECT * FROM t WHERE id = 1 OR 1=1;", False),
])
def test_the_callback_checks_sql_against_its_schema(client, monkeypatch, output, verified):  # noqa: F811
    callback, sent = _callback(client, monkeypatch, sql_schema_ddl=SCHEMA)

    record = callback._verify_output(output)

    assert [body["schema_ddl"] for body in sent] == [SCHEMA]
    assert sent[0]["dialect"] == "sqlite"
    assert record["verifications"] == [{"type": "sql", "verified": verified, "status": "VERIFIED"}]


def test_the_callback_without_a_schema_records_sql_as_unverifiable(client, monkeypatch):  # noqa: F811
    # The 400 was swallowed and nothing recorded, so get_summary counted the
    # output as verified.
    callback, sent = _callback(client, monkeypatch)

    record = callback._verify_output("SELECT a FROM t;")

    assert sent == []
    assert record["verifications"] == [
        {"type": "sql", "verified": False, "status": "UNVERIFIABLE", "reason": NO_SCHEMA}
    ]
    assert callback.get_summary()["verified"] == 0


def test_the_callback_counts_the_code_issues_the_route_sends(client, monkeypatch):  # noqa: F811
    callback, _ = _callback(client, monkeypatch, verify_code=True, verify_sql=False)

    record = callback._verify_output("```python\nimport os\nos.system(input())\n```")

    (check,) = record["verifications"]
    assert check["type"] == "code"
    assert check["verified"] is False
    assert check["vulnerabilities"] > 0


def test_a_check_that_cannot_run_is_not_counted_as_verified(monkeypatch):
    callback = langchain.QWEDVerificationCallback(api_key="x", verify_code=False, verify_sql=False, log_results=False)

    def refuse(*args, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(callback._client, "_request", refuse)

    record = callback._verify_output("2 + 2 = 4")

    assert record["verifications"] == [{
        "type": "math",
        "verified": False,
        "status": "UNVERIFIABLE",
        "reason": "the check could not be run (ConnectError)",
    }]
    assert callback.get_summary()["verified"] == 0
