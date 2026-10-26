"""SQLGuard checks the whole query, and verify_sql asks the server (GHSA-45jv-2j44-4c2q).

``QWEDClient.verify_sql`` used the local ``SQLGuard`` whenever ``qwed_new`` was
importable. The guard parsed only the first statement and checked it against
a short mutation denylist, so stacked statements, ``COPY ... TO PROGRAM``,
``ATTACH``, ``SELECT INTO`` and file or extension functions passed as
verified read-only SQL. The server's SQLVerifier blocked most of these but
not the functions. Now:

- verify_sql always calls ``/verify/sql`` and admits only what the server
  admits; an unreachable server is UNVERIFIABLE;
- the server blocks calls to functions that reach files, code, the OS or
  another server (``DANGEROUS_SQL_FUNCTIONS``);
- SQLGuard allows exactly one statement, a read-only root, no mutation or
  administrative node anywhere, and none of those functions.
"""

import httpx
import pytest

from qwed_new.core.diagnostics import admission_decision, merge_diagnostic_result
from qwed_new.core.sql_verifier import DANGEROUS_SQL_FUNCTIONS, SQLVerifier
from qwed_new.guards.sql_guard import SQLGuard
from qwed_sdk.client import QWEDClient

SCHEMA = "CREATE TABLE users (id INT, name TEXT); CREATE TABLE orders (uid INT, total INT); CREATE TABLE t (a INT);"

PAYLOADS = [
    "SELECT 1; DROP TABLE users",
    "COPY users TO PROGRAM 'id'",
    "ATTACH DATABASE 'x' AS y",
    "SELECT load_extension('x')",
    "SELECT pg_read_file('/etc/passwd')",
    "SELECT lo_import('/etc/passwd')",
    "SELECT * INTO newt FROM users",
    "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d",
    "SELECT 1 /*!50000 ; DROP TABLE users */",
]

BENIGN = "SELECT name FROM users JOIN orders ON users.id = orders.uid WHERE orders.total > 5 GROUP BY name"


@pytest.mark.parametrize("query", PAYLOADS)
def test_the_guard_refuses_the_advisorys_payloads(query):
    assert SQLGuard().verify_query(query, "sqlite")["verified"] is False


@pytest.mark.parametrize("query", PAYLOADS)
def test_the_server_blocks_them_too(query):
    assert admission_decision(SQLVerifier().verify_sql(query, SCHEMA, "sqlite")).value == "BLOCKED"


def test_a_plain_select_still_passes_both():
    assert SQLGuard().verify_query(BENIGN, "sqlite")["verified"] is True
    assert admission_decision(SQLVerifier().verify_sql(BENIGN, SCHEMA, "sqlite")).value == "ADMIT"


@pytest.mark.parametrize("name", ["load_extension", "pg_read_file", "xp_cmdshell", "dblink", "load_file"])
@pytest.mark.parametrize("shape", [
    "SELECT name FROM users WHERE name = {call}",
    "WITH x AS (SELECT {call} AS v) SELECT v FROM x",
])
def test_a_dangerous_function_is_blocked_where_it_hides(name, shape):
    query = shape.format(call=f"{name}('x')")

    assert name in DANGEROUS_SQL_FUNCTIONS
    assert SQLGuard().verify_query(query, "sqlite")["verified"] is False
    dr = SQLVerifier().verify_sql(query, SCHEMA, "sqlite")
    assert admission_decision(dr).value == "BLOCKED"
    assert any(issue["type"] == "dangerous_function" for issue in dr.developer_fields["issues"])


def test_the_guard_refuses_a_function_even_when_mutation_is_allowed():
    assert SQLGuard(allow_mutation=True).verify_query("SELECT load_extension('x')", "sqlite")["verified"] is False


def test_the_guard_still_allows_a_mutation_when_asked():
    assert SQLGuard(allow_mutation=True).verify_query("UPDATE t SET a = 1", "sqlite")["verified"] is True


def test_the_guard_refuses_an_admin_statement_even_when_mutation_is_allowed():
    assert SQLGuard(allow_mutation=True).verify_query("ATTACH DATABASE 'x' AS y", "sqlite")["verified"] is False


@pytest.mark.parametrize("query", ["", ";", "SELEC FROM"])
def test_the_guard_refuses_what_is_not_one_statement(query):
    assert SQLGuard().verify_query(query, "sqlite")["verified"] is False


# ---------------------------------------------------------------- verify_sql

def _client(monkeypatch, respond):
    client = QWEDClient(api_key="k", base_url="http://qwed.test")
    calls = []

    def request(method, endpoint, **kwargs):
        calls.append((method, endpoint, kwargs.get("json")))
        return respond(kwargs["json"])

    monkeypatch.setattr(client, "_request", request)
    return client, calls


def _server_body(payload):
    dr = SQLVerifier().verify_sql(payload["query"], payload["schema_ddl"], payload["dialect"])
    body = merge_diagnostic_result(dr)
    body["admission"] = admission_decision(dr).value
    return body


@pytest.mark.parametrize("query", PAYLOADS + [BENIGN])
def test_verify_sql_admits_only_what_the_server_admits(monkeypatch, query):
    client, calls = _client(monkeypatch, _server_body)

    result = client.verify_sql(query, schema_ddl=SCHEMA)

    assert calls == [("POST", "/verify/sql", {"query": query, "schema_ddl": SCHEMA, "dialect": "sqlite"})]
    assert result.is_verified is (query == BENIGN)


def test_verify_sql_never_runs_the_local_guard(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("SQLGuard must not decide verify_sql")

    monkeypatch.setattr(SQLGuard, "verify_query", refuse)
    client, calls = _client(monkeypatch, lambda payload: {"status": "VERIFIED", "is_valid": True, "admission": "ADMIT"})

    assert client.verify_sql("SELECT 1").is_verified is True
    assert len(calls) == 1


@pytest.mark.parametrize("error", [httpx.ConnectError("refused"), httpx.TimeoutException("slow")])
def test_verify_sql_is_unverifiable_without_the_server(monkeypatch, error):
    client = QWEDClient(api_key="k", base_url="http://qwed.test")

    def request(*args, **kwargs):
        raise error

    monkeypatch.setattr(client, "_request", request)

    assert (client.verify_sql("SELECT 1").status, client.verify_sql("SELECT 1").is_verified) == ("UNVERIFIABLE", False)
