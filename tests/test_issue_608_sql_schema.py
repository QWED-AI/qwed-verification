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

import logging
import time
from types import SimpleNamespace

import httpx
import pytest

from qwed_sdk import crewai, langchain
from tests.test_issue_320_logic_route_admission import client  # noqa: F401  (fixture)

SCHEMA = "CREATE TABLE t (id INT, a INT)"
NO_SCHEMA = "no schema was given, so QWED cannot verify the query"
OUTSIDE_A_BLOCK = {
    "type": "sql",
    "verified": False,
    "status": "UNVERIFIABLE",
    "reason": "the SQL is not in a ```sql block, so QWED cannot tell where it starts and ends",
}


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


def _sql_block(sql):
    return f"```sql\n{sql}\n```"


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

@pytest.mark.parametrize("sql, verified", [
    ("SELECT a FROM t", True),
    ("SELECT * FROM t WHERE id = 1 OR 1=1", False),
])
def test_the_callback_checks_a_sql_block_against_its_schema(client, monkeypatch, sql, verified):  # noqa: F811
    callback, sent = _callback(client, monkeypatch, sql_schema_ddl=SCHEMA)

    record = callback._verify_output(f"Run this:\n{_sql_block(sql)}\nIt reads the table.")

    assert sent == [{"query": sql, "schema_ddl": SCHEMA, "dialect": "sqlite"}]
    assert record["verifications"] == [{"type": "sql", "verified": verified, "status": "VERIFIED"}]


@pytest.mark.parametrize("output", ["SELECT a FROM t;", _sql_block("SELECT a FROM t")])
def test_the_callback_without_a_schema_records_sql_as_unverifiable(client, monkeypatch, output):  # noqa: F811
    # The 400 was swallowed and nothing recorded, so get_summary counted the
    # output as verified.
    callback, sent = _callback(client, monkeypatch)

    record = callback._verify_output(output)

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


def test_the_callback_records_the_math_checks_status(monkeypatch):
    callback = langchain.QWEDVerificationCallback(api_key="x", log_results=False, verify_code=False, verify_sql=False)
    monkeypatch.setattr(callback._client, "verify", lambda text: SimpleNamespace(is_verified=True, status="VERIFIED"))

    record = callback._verify_output("2 + 2 = 4")

    assert record["verifications"] == [{"type": "math", "verified": True, "status": "VERIFIED"}]
    assert callback.get_summary()["verified"] == 1


def _refused(*args, **kwargs):
    raise httpx.ConnectError("connection refused")


def _server_error(*args, **kwargs):
    request = httpx.Request("POST", "http://qwed.test/verify")
    raise httpx.HTTPStatusError("500 Internal Server Error", request=request, response=httpx.Response(500, request=request))


@pytest.mark.parametrize("output, kind, options, failure, error", [
    ("2 + 2 = 4", "math", {"verify_code": False, "verify_sql": False}, _refused, "ConnectError"),
    ("```python\nx = 1\n```", "code", {"verify_math": False, "verify_sql": False}, _server_error, "HTTPStatusError"),
    (_sql_block("SELECT a FROM t"), "sql", {"verify_math": False, "verify_code": False, "sql_schema_ddl": SCHEMA},
     _server_error, "HTTPStatusError"),
])
def test_a_check_that_cannot_run_is_not_counted_as_verified(monkeypatch, caplog, output, kind, options, failure, error):
    callback = langchain.QWEDVerificationCallback(api_key="x", log_results=False, **options)
    monkeypatch.setattr(callback._client, "_request", failure)

    with caplog.at_level(logging.WARNING, logger="qwed_sdk.langchain"):
        record = callback._verify_output(output)

    assert record["verifications"] == [{
        "type": kind,
        "verified": False,
        "status": "UNVERIFIABLE",
        "reason": f"the check could not be run ({error})",
    }]
    assert callback.get_summary()["verified"] == 0
    # Logged with its traceback, so a bug in a check stays visible.
    (logged,) = [entry for entry in caplog.records if entry.name == "qwed_sdk.langchain"]
    assert logged.getMessage() == f"QWED {kind} check could not be run"
    assert logged.exc_info[0].__name__ == error


def test_sql_in_a_long_output_is_found_in_linear_time_with_no_length_limit(client, monkeypatch):  # noqa: F811
    # A pattern that rescanned the rest of the text from each SELECT took
    # quadratic time on the first of these; read in pieces, each takes well
    # under a second.
    callback, sent = _callback(client, monkeypatch, verify_code=True, sql_schema_ddl=SCHEMA)
    long_statement = "SELECT a" + ", a" * 200_000 + " FROM t;"

    began = time.perf_counter()
    for no_statement in ("SELECT " * 200_000, "WITH " * 200_000, "```\n" * 200_000):
        assert callback._verify_output(no_statement)["verifications"] == []
    assert callback._verify_output(f"Run: {long_statement} Done.")["verifications"] == [OUTSIDE_A_BLOCK]
    assert time.perf_counter() - began < 10
    assert sent == []


@pytest.mark.parametrize("output", [
    "Please select an option and send an update on the project.",
    "We will delete the old notes and create a table of the results.",
    "I'll select a few items from your list.",
    "Select a plan. Data from the report is ready.",
    "Sent WITH THANKS to the team.",
])
def test_prose_with_sql_words_is_not_sql(client, monkeypatch, output):  # noqa: F811
    # The callback matched the words anywhere, so it sent prose to /verify/sql
    # and recorded a failed SQL check.
    callback, sent = _callback(client, monkeypatch, sql_schema_ddl=SCHEMA)

    assert callback._verify_output(output)["verifications"] == []
    assert sent == []


@pytest.mark.parametrize("output", [
    "Run: SELECT a FROM t;",
    "SELECT a FROM t\n\nThis returns every row.",
    "Then UPDATE t SET a = 1 WHERE id = 2;",
    "INSERT INTO t (id, a) VALUES (1, 2)",
    "WITH x AS (SELECT a FROM t) SELECT a FROM x;",
    "UPDATE on the project; then DELETE FROM t WHERE id = 1;",
    # Taken from the text, each of these was cut short, and the part sent
    # passed where the whole statement would not.
    "SELECT a FROM t\n\nWHERE id = 1 OR 1=1;",
    "SELECT a FROM t -- checked;\nWHERE id = 1 OR 1=1",
    "DROP TABLE t; SELECT a FROM t;",
])
def test_sql_outside_a_sql_block_is_unverifiable_and_sends_nothing(client, monkeypatch, output):  # noqa: F811
    callback, sent = _callback(client, monkeypatch, sql_schema_ddl=SCHEMA)

    assert callback._verify_output(output)["verifications"] == [OUTSIDE_A_BLOCK]
    assert sent == []
    assert callback.get_summary()["verified"] == 0


def test_each_sql_block_is_checked(client, monkeypatch):  # noqa: F811
    # Only the first block was checked, so a DELETE in the second was not,
    # and the output counted as verified.
    callback, sent = _callback(client, monkeypatch, sql_schema_ddl=SCHEMA)

    record = callback._verify_output(
        f"First:\n{_sql_block('SELECT a FROM t')}\nThen:\n{_sql_block('DELETE FROM t')}"
    )

    assert [body["query"] for body in sent] == ["SELECT a FROM t", "DELETE FROM t"]
    assert [check["verified"] for check in record["verifications"]] == [True, False]
    assert callback.get_summary()["verified"] == 0


def test_a_sql_block_is_sent_whole_and_more_than_one_statement_is_not_verified(client, monkeypatch):  # noqa: F811
    callback, sent = _callback(client, monkeypatch, sql_schema_ddl=SCHEMA)

    record = callback._verify_output(_sql_block("SELECT a FROM t;\nDELETE FROM t;"))

    assert [body["query"] for body in sent] == ["SELECT a FROM t;\nDELETE FROM t;"]
    assert record["verifications"] == [{"type": "sql", "verified": False, "status": "VERIFIED"}]


def test_sql_outside_a_block_is_recorded_beside_a_sql_block(client, monkeypatch):  # noqa: F811
    # The SQL block was checked instead of the statement before it, so the
    # output counted as verified.
    callback, sent = _callback(client, monkeypatch, sql_schema_ddl=SCHEMA)

    record = callback._verify_output(
        f"SELECT * FROM t WHERE id = 1 OR 1=1;\n{_sql_block('SELECT a FROM t')}"
    )

    assert [body["query"] for body in sent] == ["SELECT a FROM t"]
    assert record["verifications"] == [
        {"type": "sql", "verified": True, "status": "VERIFIED"},
        OUTSIDE_A_BLOCK,
    ]
    assert callback.get_summary()["verified"] == 0


def test_sql_in_another_block_is_checked_as_that_code(client, monkeypatch):  # noqa: F811
    # The query in the Python block was taken as SQL with the Python after it,
    # and sent to /verify/sql.
    callback, sent = _callback(client, monkeypatch, verify_code=True, sql_schema_ddl=SCHEMA)

    record = callback._verify_output('```python\ncur.execute("SELECT a FROM t")\n```')

    assert [check["type"] for check in record["verifications"]] == ["code"]
    assert [body.get("query") for body in sent] == [None]


def test_each_code_block_is_checked(client, monkeypatch):  # noqa: F811
    # Only the first block was checked, so unsafe code in the second was not.
    callback, sent = _callback(client, monkeypatch, verify_code=True, verify_sql=False)

    record = callback._verify_output("```python\nx = 1\n```\nand\n```python\nimport os\nos.system(input())\n```")

    assert [body["code"] for body in sent] == ["x = 1", "import os\nos.system(input())"]
    assert [check["verified"] for check in record["verifications"]] == [True, False]
    assert callback.get_summary()["verified"] == 0


def test_a_sql_block_is_not_checked_as_code(client, monkeypatch):  # noqa: F811
    # The code check took the first fenced block, so it sent SQL to
    # /verify/code as Python, and recorded it as failed.
    callback, sent = _callback(client, monkeypatch, verify_code=True, sql_schema_ddl=SCHEMA)

    record = callback._verify_output("```sql\nSELECT a FROM t\n```")

    assert [body["query"] for body in sent] == ["SELECT a FROM t"]
    assert record["verifications"] == [{"type": "sql", "verified": True, "status": "VERIFIED"}]
    assert callback.get_summary()["verified"] == 1


@pytest.mark.parametrize("output", ["SELECT 1;", "Nothing to check here."])
def test_an_output_with_no_check_is_not_counted_as_verified(client, monkeypatch, output):  # noqa: F811
    # all() of no checks is true, so get_summary counted an output no check
    # ran on, such as SQL the callback did not recognise, as verified.
    callback, sent = _callback(client, monkeypatch, verify_math=True, verify_code=True)

    assert callback._verify_output(output)["verifications"] == []
    assert sent == []
    assert callback.get_summary() == {"total_outputs": 1, "verified": 0, "verification_rate": 0}


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
