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


def _refused(*args, **kwargs):
    raise httpx.ConnectError("connection refused")


def _server_error(*args, **kwargs):
    request = httpx.Request("POST", "http://qwed.test/verify")
    raise httpx.HTTPStatusError("500 Internal Server Error", request=request, response=httpx.Response(500, request=request))


@pytest.mark.parametrize("output, kind, options, failure, error", [
    ("2 + 2 = 4", "math", {"verify_code": False, "verify_sql": False}, _refused, "ConnectError"),
    ("```python\nx = 1\n```", "code", {"verify_math": False, "verify_sql": False}, _server_error, "HTTPStatusError"),
    ("SELECT a FROM t;", "sql", {"verify_math": False, "verify_code": False, "sql_schema_ddl": SCHEMA},
     _server_error, "HTTPStatusError"),
])
def test_a_check_that_cannot_run_is_not_counted_as_verified(monkeypatch, output, kind, options, failure, error):
    callback = langchain.QWEDVerificationCallback(api_key="x", log_results=False, **options)
    monkeypatch.setattr(callback._client, "_request", failure)

    record = callback._verify_output(output)

    assert record["verifications"] == [{
        "type": kind,
        "verified": False,
        "status": "UNVERIFIABLE",
        "reason": f"the check could not be run ({error})",
    }]
    assert callback.get_summary()["verified"] == 0


@pytest.mark.parametrize("output", [
    "Please select an option and send an update on the project.",
    "We will delete the old notes and create a table of the results.",
])
def test_prose_with_sql_words_is_not_sql(client, monkeypatch, output):  # noqa: F811
    # The callback matched the words anywhere, so it sent prose to /verify/sql
    # and recorded a failed SQL check.
    callback, sent = _callback(client, monkeypatch, sql_schema_ddl=SCHEMA)

    assert callback._verify_output(output)["verifications"] == []
    assert sent == []


@pytest.mark.parametrize("output, statement", [
    ("Run select a from t; to see it.", "select a from t;"),
    ("Then UPDATE t SET a = 1 WHERE id = 2;", "UPDATE t SET a = 1 WHERE id = 2;"),
    ("INSERT INTO t (id, a) VALUES (1, 2)", "INSERT INTO t (id, a) VALUES (1, 2)"),
])
def test_a_sql_statement_is_found_by_its_shape(client, monkeypatch, output, statement):  # noqa: F811
    callback, sent = _callback(client, monkeypatch, sql_schema_ddl=SCHEMA)

    callback._verify_output(output)

    assert [body["query"] for body in sent] == [statement]


# ---------------------------------------------------------------- CrewAI agent

class _Agent:
    """Stands in for crewai.Agent, keeping the tools it is given."""

    def __init__(self, **kwargs):
        self.tools = kwargs["tools"]


def test_the_agents_sql_tool_checks_against_the_configured_schema(client, monkeypatch):  # noqa: F811
    # QWEDVerifiedAgent built its SQL tool without a schema.
    monkeypatch.setattr(crewai, "CREWAI_AVAILABLE", True)
    monkeypatch.setattr(crewai, "Agent", _Agent)
    config = crewai.VerificationConfig(sql_schema_ddl=SCHEMA, sql_dialect="sqlite")
    agent = crewai.QWEDVerifiedAgent(role="Analyst", goal="Query data", api_key="x", verification_config=config)

    (tool,) = [tool for tool in agent.agent.tools if isinstance(tool, crewai.QWEDSQLTool)]
    sent = _through_the_route(client, monkeypatch, tool)

    assert tool._run("SELECT a FROM t").startswith("✅ SAFE")
    assert sent == [{"query": "SELECT a FROM t", "schema_ddl": SCHEMA, "dialect": "sqlite"}]
