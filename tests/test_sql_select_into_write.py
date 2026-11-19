"""SQLVerifier does not admit SELECT ... INTO as a read-only query (GHSA-6m2h-98rq-4f53).

``SELECT ... INTO`` creates a table and writes the selected rows into it.
sqlglot parses it as a Select holding an Into node, so the verifier, which
looked for Create, Insert and the other destructive statements, admitted it:
without a schema, and with one when the target was a declared table, a
qualified name or a CTE name. SQLGuard already refused it. The verifier now
treats Into as destructive, so it is refused unless destructive statements
are allowed.
"""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from qwed_new.core.diagnostics import admission_decision
from qwed_new.core.sql_verifier import SQLVerifier
from qwed_new.guards.sql_guard import SQLGuard

INTO = [
    ("postgres", "SELECT id, name INTO newtab FROM users"),
    ("postgres", "SELECT id INTO TEMP t FROM users"),
    ("postgres", "SELECT id INTO TEMPORARY TABLE t FROM users"),
    ("postgres", "SELECT id INTO UNLOGGED t FROM users"),
    ("postgres", "SELECT * FROM (SELECT id INTO t2 FROM users) s"),
    ("postgres", "WITH c AS (SELECT 1 AS a) SELECT a INTO t3 FROM c"),
    ("postgres", "SELECT id INTO t4 FROM users UNION SELECT id FROM users"),
    ("postgres", "select id into NewTab from users"),
    ("tsql", "SELECT id INTO #tmp FROM users"),
    ("tsql", "SELECT id INTO dbo.newtab FROM users"),
    ("duckdb", "SELECT id INTO newtab FROM users"),
    ("snowflake", "SELECT id INTO newtab FROM users"),
    ("redshift", "SELECT id INTO newtab FROM users"),
    ("mysql", "SELECT id INTO @v FROM users LIMIT 1"),
    # From the review: every position, spelling and separator.
    ("postgres", "SELECT * FROM users WHERE EXISTS (SELECT id INTO t5 FROM users)"),
    ("postgres", "SELECT * FROM users WHERE id IN (SELECT id INTO t6 FROM users)"),
    ("postgres", "SELECT (SELECT id INTO t7 FROM users LIMIT 1) AS x"),
    ("postgres", "SELECT id INTO t8 FROM users INTERSECT SELECT id FROM users"),
    ("postgres", "SELECT id INTO t9 FROM users EXCEPT SELECT id FROM users"),
    ("postgres", "SELECT * FROM users u, LATERAL (SELECT id INTO t14 FROM users) l"),
    ("postgres", "((SELECT id INTO t10 FROM users))"),
    ("postgres", "SELECT\tid\nINTO /* c */ t11\nFROM users"),
    ("postgres", "SELECT id\u00a0INTO t13 FROM users"),
    ("postgres", "SELECT id INTO TEMP t12 FROM users;"),
    ("postgres", "SeLeCt id InTo t15 FrOm users"),
    ("postgres", 'SELECT id INTO "New Tab" FROM users'),
    ("tsql", "SELECT id INTO ##t FROM users"),
    ("tsql", "SELECT id INTO db.dbo.t FROM users"),
    ("oracle", "SELECT id INTO v FROM users"),
    ("oracle", "SELECT id BULK COLLECT INTO ids FROM users"),
    ("mysql", "SELECT id /*! INTO @v */ FROM users LIMIT 1"),
]


def _refused_as_into(result):
    issues = result.developer_fields["issues"]
    return admission_decision(result).value == "BLOCKED" and any(
        issue.get("type") == "destructive_command" and "Into" in issue.get("description", "")
        for issue in issues
    )


@pytest.mark.parametrize("dialect, query", INTO)
def test_select_into_is_refused_as_a_write(dialect, query):
    assert _refused_as_into(SQLVerifier().verify_sql(query, None, dialect=dialect))
    assert SQLGuard().verify_query(query, dialect=dialect)["verified"] is False


SCHEMA = "CREATE TABLE users (id INT, name TEXT); CREATE TABLE t (id INT);"


@pytest.mark.parametrize("dialect, query", [
    # /verify/sql needs a schema. With one, these are refused as writes too.
    ("postgres", "SELECT id INTO t FROM users"),
    ("postgres", "SELECT id INTO TEMP t FROM users"),
    ("postgres", "SELECT id INTO scratch.users FROM users"),
    ("postgres", "WITH n AS (SELECT 1 AS id) SELECT id INTO n FROM users"),
    ("tsql", "SELECT id INTO t FROM users"),
    ("tsql", "SELECT id INTO dbo.users FROM users"),
    ("oracle", "SELECT id INTO t FROM users"),
])
def test_select_into_is_refused_with_a_schema(dialect, query):
    assert _refused_as_into(SQLVerifier().verify_sql(query, SCHEMA, dialect=dialect))


def test_select_into_is_allowed_where_destructive_statements_are():
    # As CREATE TABLE ... AS SELECT is: the setting decides, not the parser.
    query = "SELECT id, name INTO newtab FROM users"
    into = SQLVerifier(allow_destructive=True).verify_sql(query, None, dialect="postgres")
    create = SQLVerifier(allow_destructive=True).verify_sql(
        "CREATE TABLE newtab AS SELECT id, name FROM users", None, dialect="postgres"
    )
    assert admission_decision(into).value == admission_decision(create).value


_WRAPPERS = [
    "SELECT id{s}{into}{s}{name}{s}FROM users",
    "SELECT * FROM (SELECT id{s}{into}{s}{name}{s}FROM users) s",
    "WITH c AS (SELECT id FROM users) SELECT id{s}{into}{s}{name}{s}FROM c",
    "SELECT id{s}{into}{s}{name}{s}FROM users UNION SELECT id FROM users",
]


@settings(max_examples=80, deadline=None)
@given(
    wrapper=st.sampled_from(_WRAPPERS),
    into=st.sampled_from(["INTO", "into", "Into", "iNtO"]),
    # sqlglot reads each of these as whitespace, Unicode ones included.
    separator=st.sampled_from(
        [" ", "\t", "\n", "  ", " /* c */ ", "\u00a0", "\u2003", "\u3000", "\u2028", "\u0085", "\x0b", "\x0c"]
    ),
    # A prefix keeps the name from being a keyword, which would be a parse
    # error and so refused for another reason.
    name=st.from_regex(r"[a-z0-9_]{0,10}", fullmatch=True).map(lambda tail: "t_" + tail),
    dialect=st.sampled_from(["postgres", "tsql", "duckdb", "snowflake", "redshift", "oracle", "mysql"]),
)
def test_select_into_is_refused_whatever_its_spelling(wrapper, into, separator, name, dialect):
    target = "@" + name if dialect == "mysql" else name
    query = wrapper.format(s=separator, into=into, name=target)
    assert _refused_as_into(SQLVerifier().verify_sql(query, None, dialect=dialect))


@pytest.mark.parametrize("dialect, query", [
    ("postgres", "SELECT id, name FROM users WHERE id = 5"),
    ("postgres", "WITH c AS (SELECT id FROM users) SELECT id FROM c"),
    ("tsql", "SELECT TOP 5 id FROM users"),
    ("mysql", "SELECT id FROM users LIMIT 1"),
])
def test_a_read_only_select_is_still_admitted(dialect, query):
    assert admission_decision(SQLVerifier().verify_sql(query, None, dialect=dialect)).value == "ADMIT"
