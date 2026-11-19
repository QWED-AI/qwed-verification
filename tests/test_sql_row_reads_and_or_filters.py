"""SQLVerifier no longer admits column tautologies, whole-row reads or MySQL "--x" (GHSA-xpfc).

Three gaps made /verify/sql return VERIFIED \u00b7 ADMIT for queries that read
every row or a protected column:

- An OR operand that reads a column and is always true (``name LIKE '%'``,
  ``id = id + 0``, ``abs(id) >= 0``) passed, since only constant predicates
  were folded. Each operand of an OR (or XOR) in a filter must now restrict
  a column of a table of the database to values from outside it: equal to,
  IN, or LIKE without a wildcard, a literal or a parameter, or IS NULL, on a
  column the schema declares for a table in the same SELECT, all operands
  on the same table. NOT (a AND b) is NOT a OR NOT b and is refused.
- A table or its alias used as a column (``row_to_json(u)``, ``SELECT u``) is
  the whole row, protected columns included, and passed because protected
  columns were matched by name. So do a name after an alias that is not a
  column (``u.row_to_json``), a column list after an alias, and DuckDB's
  ``COLUMNS()``. They are now refused where the schema declares a protected
  column.
- MySQL reads ``--1 OR 1=1`` as code (``--`` starts a comment only before
  whitespace), sqlglot as a comment. A query that sqlglot and a database can
  split into tokens differently is now refused outright, and so is one where
  sqlglot misreads the TABLE statement.
"""

import time

import pytest
from sqlglot import exp

from qwed_new.core.diagnostics import admission_decision
from qwed_new.core.sql_verifier import SQLVerifier

CONSTRAINT_AMBIGUOUS_TOKENIZATION = "sql_verifier.ambiguous_tokenization"
CONSTRAINT_MALICIOUS = "sql_verifier.malicious"
CONSTRAINT_UNRESTRICTED_OR = "sql_verifier.unrestricted_or"

DDL = (
    "CREATE TABLE users (id INT, name TEXT, password TEXT, active BOOLEAN, price INT, user_id INT);"
    " CREATE TABLE orders (id INT, user_id INT, total INT);"
)
UNRESTRICTED_VERDICT = ("BLOCKED", "BLOCKED", CONSTRAINT_UNRESTRICTED_OR)


def _verdict(query, dialect="sqlite", schema=DDL):
    result = SQLVerifier().verify_sql(query, schema, dialect=dialect)
    return result.status.value, admission_decision(result).value, result.developer_fields.get("constraint_id")


UNRESTRICTED = [
    "SELECT id, name FROM users WHERE id = 5 OR name LIKE '%'",
    "SELECT id, name FROM users WHERE id = 5 OR id = id + 0",
    "SELECT id, name FROM users WHERE id = 5 OR abs(id) >= 0",
    "SELECT id FROM users WHERE id = 5 or name like '%%'",
    "SELECT id FROM users WHERE name LIKE '_%' OR id = 1",
    "SELECT id FROM users WHERE id = 5 OR id <> 5",
    "SELECT id FROM users WHERE id < 5 OR id >= 5",
    "SELECT id FROM users WHERE id = 5 OR id BETWEEN -2147483648 AND 2147483647",
    "SELECT id FROM users WHERE active = TRUE OR active = FALSE",
    "SELECT id FROM users WHERE active IN (TRUE) OR active IN (FALSE)",
    "SELECT id FROM users WHERE NOT (id = 5) OR id = 5",
    "SELECT id FROM users WHERE id IS NULL OR id IS NOT NULL",
    "SELECT id FROM users WHERE id IN (SELECT id FROM users) OR id = 1",
    "SELECT id FROM users WHERE id = 5 OR name GLOB '*'",
    "SELECT id FROM users WHERE id = 5 OR (name LIKE '%')",
    "SELECT u.id FROM users u WHERE u.id = 5 OR u.name LIKE '%'",
    "SELECT users.id FROM users JOIN users v ON users.id = v.id OR v.name LIKE '%'",
    "SELECT id FROM users WHERE id IN (SELECT id FROM users WHERE id = 1 OR name LIKE '%')",
    # A pattern with a wildcard matches values the query does not list.
    "SELECT id FROM users WHERE id = 5 OR name LIKE '%a%'",
    "SELECT id FROM users WHERE name LIKE '%bob%' OR name LIKE 'a%'",
    "SELECT id FROM users WHERE id = 5 OR name LIKE ?",
    # A column that is the same on every row: another source, an alias.
    "SELECT u.id, u.name FROM users u CROSS JOIN (SELECT 1 AS k) c WHERE u.id = 5 OR c.k = 1",
    "WITH c AS (SELECT 1 AS k) SELECT id, name FROM users, c WHERE id = 5 OR k = 1",
    "SELECT a.id FROM users a JOIN users b ON b.id = 5 WHERE a.id = 7 OR b.id = 5",
    "SELECT id, name, 1 AS k FROM users WHERE id = 5 OR k = 1",
    'SELECT id FROM users WHERE id = 5 OR "zz" = \'zz\'',
    # NOT (a AND b) is NOT a OR NOT b.
    "SELECT id FROM users WHERE NOT (id <> 5 AND NOT name LIKE '%')",
    # Both values of a boolean column, however they are written.
    'SELECT id FROM users WHERE active = TRUE OR "active" = FALSE',
    "SELECT u.id FROM users u WHERE active = TRUE OR u.active = FALSE",
    "SELECT id FROM users WHERE active = 1 OR active = 0",
    # TRIM with characters to remove makes many values equal ''.
    "SELECT id FROM users WHERE id = 5 OR RTRIM(name, 'abcdefghijklmnopqrstuvwxyz') = ''",
    # The folder reads decimals exactly, SQLite as doubles.
    "SELECT id FROM users WHERE id = 5 OR 0.1 + 0.2 = 0.30000000000000004",
    "SELECT id FROM users WHERE id = 5 OR 1e16 + 1 = 1e16",
]


@pytest.mark.parametrize("query", UNRESTRICTED)
def test_an_or_operand_that_restricts_no_column_is_refused(query):
    assert _verdict(query) == UNRESTRICTED_VERDICT


@pytest.mark.parametrize("query, dialect", [
    ("SELECT id FROM users WHERE id = 5 OR name ILIKE '%'", "postgres"),
    ("SELECT id FROM users WHERE id = 5 OR name REGEXP '.*'", "mysql"),
    ("SELECT id FROM users WHERE id = 5 XOR name LIKE '%'", "mysql"),
    ("SELECT id FROM users WHERE !(id <> 5 && name NOT LIKE '%')", "mysql"),
    ("SELECT id FROM users WHERE id = 5 OR id IS NOT NULL", "postgres"),
    ("SELECT id FROM users WHERE name LIKE 'a%' OR name NOT LIKE 'a%'", "postgres"),
    ("SELECT u.id FROM users u, (VALUES (1)) AS c(k) WHERE u.id = 5 OR c.k = 1", "postgres"),
    ("SELECT id, 1 AS k FROM users GROUP BY id HAVING id = 5 OR k = 1", "mysql"),
    ("SELECT id FROM users WHERE active = TRUE OR active = 'f'", "postgres"),
    ("SELECT id FROM users WHERE id = 5 OR TRIM(BOTH 'abc' FROM name) = ''", "postgres"),
    # MySQL compares 'abc' = 0 as numbers: true for every name that is not a number.
    ("SELECT id FROM users WHERE id = 5 OR name = 0", "mysql"),
    ("SELECT id FROM users WHERE id = 5 OR name IN (0, 1)", "mysql"),
    ("SELECT id FROM users WHERE id = 5 OR name = FALSE", "mysql"),
    # In T-SQL [^~] is a character class, not three characters.
    ("SELECT id FROM users WHERE id = 5 OR name LIKE '%[^~]%'", "tsql"),
    # In Oracle '' is NULL.
    ("SELECT id FROM users WHERE id = 5 OR '' IS NULL", "oracle"),
    ("SELECT id FROM users WHERE id = 5 OR current_role = 'app'", "postgres"),
    ("SELECT id FROM users WHERE id = 5 OR user = 'SCOTT'", "oracle"),
    # Filters outside WHERE, HAVING and ON.
    ("SELECT id FROM users PREWHERE id = 5 OR name LIKE '%'", "clickhouse"),
    ("SELECT id FROM users QUALIFY id = 5 OR name LIKE '%'", "snowflake"),
    ("SELECT id FROM users START WITH id = 5 OR name LIKE '%' CONNECT BY PRIOR id = user_id", "oracle"),
])
def test_other_dialects_forms_are_refused(query, dialect):
    assert _verdict(query, dialect) == UNRESTRICTED_VERDICT


@pytest.mark.parametrize("node", [
    exp.Like(this=exp.column("name"), expression=exp.Literal.string("bob"), negate=True),
    exp.Is(this=exp.column("name"), expression=exp.Null(), negate=True),
    exp.In(this=exp.column("id"), expressions=[exp.Literal.number(5)], negate=True),
])
def test_a_negated_predicate_restricts_nothing(node):
    # sqlglot 30 writes NOT LIKE and IS NOT NULL as one node with negate=True.
    from qwed_new.core.sql_filter_check import _FilterContext, _always_false, _point_restriction

    query = exp.select("id").from_("users").where(node)
    ctx = _FilterContext(query, "postgres", None)
    assert _point_restriction(node, query, ctx) is None
    assert _always_false(node) is False


@pytest.mark.parametrize("query, dialect", [
    ('SELECT id FROM users WHERE id = 5 OR "zz" = \'zz\'', "sqlite"),
    ("SELECT id FROM users WHERE id = 5 OR current_role = 'app'", "postgres"),
    ("SELECT id FROM users WHERE id = 5 OR user = 'SCOTT'", "oracle"),
    ("SELECT id FROM users WHERE id = 1 OR sessiontimezone = '+00:00'", "oracle"),
    ("SELECT id FROM users WHERE id = 5 OR name = 'x'", "sqlite"),
    ("SELECT id FROM users WHERE id = 5 OR id = id + 0", "sqlite"),
    # A name from an outer query, a lateral, an alias anywhere in the query.
    ("SELECT (SELECT group_concat(name) FROM users WHERE id = 1 OR c = 5) FROM (SELECT 5 AS c) k", "sqlite"),
    ("SELECT name FROM users LATERAL VIEW explode(array(5)) t AS c WHERE id = 1 OR c = 5", "hive"),
    ("SELECT name, toString(5 AS c) FROM users WHERE id = 1 OR c = 5", "clickhouse"),
])
def test_without_a_schema_operands_must_restrict_one_same_column(query, dialect):
    # Without a schema a name cannot be told from a column, so every
    # operand must restrict the same one: the query then reads no more than
    # listing values for that one expression would.
    assert _verdict(query, dialect, None) == UNRESTRICTED_VERDICT


@pytest.mark.parametrize("query, dialect", [
    ("SELECT id FROM users u, orders o WHERE u.id = 5 OR u.id = 6", "postgres"),
    ("SELECT id FROM users WHERE id = 5 OR id = 6", "mysql"),
    ("SELECT id FROM users WHERE id = 5 OR id IS NULL OR LOWER(id) = '7'", "sqlite"),
])
def test_without_a_schema_operands_on_one_same_column_are_still_admitted(query, dialect):
    assert _verdict(query, dialect, None)[1] == "ADMIT"


ENUM_DDL = "CREATE TABLE users (id INT, name TEXT, password TEXT, status ENUM('a','b'));"


@pytest.mark.parametrize("query, dialect, schema", [
    # A restriction beside the OR on another table, or one that covers.
    ("SELECT u.name FROM users u, users v WHERE v.id = 1 AND (u.id = 5 OR u.name LIKE '%')", "sqlite", DDL),
    ("SELECT u.name FROM users u, users v WHERE v.id = 1 AND (u.id = 5 OR u.name LIKE '%')", "sqlite", None),
    ("SELECT u.name FROM users u LEFT JOIN users v ON v.id = -1 WHERE v.id IS NULL AND (u.id = 5 OR u.name LIKE '%')",
     "postgres", DDL),
    ("SELECT u.name FROM users u CROSS JOIN orders o WHERE o.id = 1 AND (u.id = 5 OR u.name LIKE '%')", "postgres", DDL),
    ("SELECT u.name FROM users u JOIN orders o ON o.id = 1 AND (u.id = 5 OR u.name LIKE '%')", "postgres", DDL),
    ("SELECT name FROM users WHERE active IN (TRUE, FALSE) AND (id = 5 OR name LIKE '%')", "postgres", DDL),
    ("SELECT name FROM users WHERE id = 5 AND (price > 5 OR price < 1)", "sqlite", None),
    # Aliases that shadow a declared column.
    ("SELECT name, toString(5 AS id) FROM users WHERE id = 1 OR id = 5", "clickhouse", DDL),
    ("WITH 5 AS id SELECT name FROM users WHERE id = 1 OR id = 5", "clickhouse", DDL),
    # A value that comes from the row: MySQL's @x is a variable.
    ("SELECT name FROM users WHERE (@x := name) IS NOT NULL AND (id = 5 OR name = @x)", "mysql", DDL),
    # MySQL compares 'abc' = 0 as numbers, whatever the dialect string says.
    ("SELECT name FROM users WHERE name = 0 OR name = 1", "mysql", DDL),
    ("SELECT name FROM users WHERE name = 0 OR name = 1", "mysql, normalization_strategy = lowercase", DDL),
    ("SELECT name FROM users WHERE name IN (0, 1)", "mysql", DDL),
    # Every value of a boolean or an ENUM.
    ("SELECT name FROM users WHERE active = 't' OR active = 'f'", "postgres", DDL),
    ("SELECT name FROM users WHERE status = 'a' OR status = 'b'", "mysql", ENUM_DDL),
    ("SELECT name FROM users WHERE status IN ('A', 'b')", "mysql", ENUM_DDL),
    # An IN list is an OR of equalities.
    ("SELECT name FROM users WHERE id IN (5, id)", "sqlite", DDL),
    ("SELECT name FROM users WHERE id IN (5, id)", "sqlite", None),
    ("SELECT name FROM users WHERE 5 IN (id, 5)", "sqlite", None),
    ("SELECT name FROM users WHERE id = 5 OR id IN (6, id)", "sqlite", None),
])
def test_a_widening_found_in_review_is_refused(query, dialect, schema):
    assert _verdict(query, dialect, schema) == UNRESTRICTED_VERDICT


@pytest.mark.parametrize("query", [
    "SELECT name FROM users WHERE id = 5 OR name = $2",
    "SELECT name FROM users WHERE id = 5 OR name IN ($2)",
])
def test_snowflakes_dollar_number_is_a_column_not_a_value(query):
    # $2 is the second column of the row: it restricts nothing, and it
    # reads a column by position.
    result = SQLVerifier().verify_sql(query, DDL, dialect="snowflake")
    types = {issue["type"] for issue in result.developer_fields["issues"]}
    assert {"unrestricted_or_operand", "sensitive_column_access"} <= types
    assert admission_decision(result).value == "BLOCKED"


@pytest.mark.parametrize("query, dialect, schema", [
    ("SELECT id FROM users WHERE id = $1 OR id = $2", "postgres", DDL),
    ("SELECT id FROM users WHERE id = :a OR id = :b", "oracle", DDL),
    ("SELECT id FROM users WHERE id = 1 OR id = 2", "mysql", DDL),
    ("SELECT id FROM users WHERE name = 'x' OR name = 'y'", "mysql", DDL),
    ("SELECT name FROM users WHERE status = 'a' OR id = 1", "mysql", ENUM_DDL),
    ("SELECT id FROM users WHERE id IN (1)", "postgres", DDL),
    ("SELECT id FROM users WHERE id IN (5, 6)", "mysql", None),
])
def test_restrictions_near_those_are_still_admitted(query, dialect, schema):
    assert _verdict(query, dialect, schema)[1] == "ADMIT"


RESTRICTED = [
    "SELECT id, name FROM users WHERE id = 5 OR id = 6",
    "SELECT id, name FROM users WHERE id IN (1, 2) OR name = 'bob'",
    "SELECT id, name FROM users WHERE (price > 5 AND name = 'x') OR id = ?",
    "SELECT id, name FROM users WHERE lower(name) = 'bob' OR upper(name) = 'BOB'",
    "SELECT id, name FROM users WHERE name IS NULL OR id = -1",
    "SELECT id, name FROM users WHERE id = 1 OR 1 = 0",
    "SELECT id, name FROM users WHERE id = 1 OR FALSE",
    "SELECT id, name FROM users WHERE id = 1 OR NULL",
    "SELECT id, name FROM users WHERE id = 1 OR 2 > 3",
    "SELECT id, name FROM users WHERE id = 1 OR 1 IN (2, 3)",
    "SELECT id, name FROM users WHERE name LIKE 'bob' OR id = 3",
    "SELECT id, name FROM users WHERE active = TRUE OR id = 3",
    "SELECT id, name FROM users WHERE id = 5",
    "SELECT id, name FROM users WHERE price > 10",
    "SELECT CASE WHEN id = 1 OR name LIKE '%' THEN 1 END FROM users",
    "SELECT u.id FROM users u WHERE u.id = 5 OR u.name = 'bob'",
    "SELECT u.id, o.total FROM users u JOIN orders o ON o.user_id = u.id WHERE u.id = 5 OR u.id = 6",
    "SELECT id FROM users WHERE id IN (SELECT user_id FROM orders WHERE total = 5 OR total = 6)",
    # Beside a restriction in an AND, an OR reads no more than the restriction.
    "SELECT id, name FROM users WHERE id = 5 AND (price > 5 OR price < 1)",
    "SELECT id, name FROM users WHERE id = 5 AND NOT (price > 5 AND price < 9)",
    "SELECT id, name FROM users WHERE NOT (name = 'a' OR name = 'b')",
]


@pytest.mark.parametrize("query", RESTRICTED)
def test_a_filter_whose_or_operands_restrict_is_still_admitted(query):
    assert _verdict(query) == ("VERIFIED", "ADMIT", "sql_verifier.sql_valid")


@pytest.mark.parametrize("query, dialect", [
    ("SELECT id FROM users WHERE name = N'Bob' OR id = 5", "tsql"),
    ("SELECT id FROM users WHERE id = 5 OR id = 6", "mysql"),
    ("SELECT id FROM users WHERE active = TRUE OR id = 6", "mysql"),
    ("SELECT id FROM users WHERE id = 5 OR id = 6", "postgres"),
])
def test_other_dialects_restrictions_are_still_admitted(query, dialect):
    assert _verdict(query, dialect)[1] == "ADMIT"


def test_without_a_schema_a_plain_restriction_is_still_admitted():
    assert _verdict("SELECT id FROM users WHERE id = 5 OR id = 6", "sqlite", None)[1] == "ADMIT"


@pytest.mark.serial
@pytest.mark.timeout(60)
def test_a_long_or_chain_is_read_once():
    query = "SELECT id FROM users WHERE " + " OR ".join(f"id = {i}" for i in range(230))
    started = time.perf_counter()
    assert _verdict(query)[1] == "ADMIT"
    assert time.perf_counter() - started < 10


WHOLE_ROW = [
    "SELECT row_to_json(u) FROM users u",
    "SELECT u FROM users u",
    "SELECT to_json(users) FROM users",
    "SELECT hstore(u) FROM users u",
    "SELECT json_agg(u) FROM users u",
    "SELECT u::text FROM users u",
    'SELECT "u" FROM users u',
    "SELECT U FROM users u",
    "SELECT id FROM users AS u WHERE u IS NOT NULL",
    # A quoted alias that differs from a column only in case is the row.
    'SELECT row_to_json("Name") FROM users AS "Name"',
    # An alias that is also a column of a table in a subquery.
    "SELECT row_to_json(user_id) FROM users AS user_id WHERE id IN (SELECT user_id FROM orders)",
    # A name after the alias that is not a column: row_to_json(u).
    "SELECT u.row_to_json FROM users u",
    "SELECT u.to_jsonb FROM users u",
    # A column list after the alias renames password.
    "SELECT t.c FROM users AS t(a, b, c)",
    "SELECT c FROM users AS t(a, b, c, d, e, f)",
    # An alias used again for another table in a subquery stands for both.
    "SELECT row_to_json(x) FROM users x WHERE EXISTS (SELECT 1 FROM orders x)",
    "SELECT x.row_to_json FROM users x WHERE EXISTS (SELECT 1 FROM orders x)",
    "SELECT x FROM users x WHERE EXISTS (SELECT 1 FROM orders x)",
    "SELECT to_json(x) FROM users x WHERE x.id IN (SELECT x.user_id FROM orders x)",
]


@pytest.mark.parametrize("query", [
    "SELECT * FROM users x WHERE EXISTS (SELECT 1 FROM orders x)",
    "SELECT x.* FROM users x WHERE EXISTS (SELECT 1 FROM orders x)",
])
def test_a_star_over_a_reused_alias_is_refused(query):
    assert _verdict(query, "postgres") == ("VERIFIED", "BLOCKED", CONSTRAINT_MALICIOUS)


@pytest.mark.parametrize("query, dialect", [("SELECT $3 FROM users", "snowflake"), ("SELECT #3 FROM users", "duckdb")])
def test_a_column_by_position_on_a_table_with_a_protected_column_is_refused(query, dialect):
    assert _verdict(query, dialect) == ("VERIFIED", "BLOCKED", CONSTRAINT_MALICIOUS)


def test_a_correlated_subquery_with_its_own_alias_is_still_admitted():
    query = "SELECT x.id FROM users x WHERE EXISTS (SELECT 1 FROM orders o WHERE o.user_id = x.id)"
    assert _verdict(query, "postgres")[1] == "ADMIT"


@pytest.mark.parametrize("query", WHOLE_ROW)
def test_a_whole_row_reference_to_a_table_with_a_protected_column_is_refused(query):
    assert _verdict(query, "postgres") == ("VERIFIED", "BLOCKED", CONSTRAINT_MALICIOUS)
    issues = SQLVerifier().verify_sql(query, DDL, dialect="postgres").developer_fields["issues"]
    assert any("sensitive column 'password' of 'users'" in issue["description"] for issue in issues)


def test_columns_by_pattern_on_a_table_with_a_protected_column_is_refused():
    assert _verdict("SELECT COLUMNS('pass.*') FROM users", "duckdb") == ("VERIFIED", "BLOCKED", CONSTRAINT_MALICIOUS)


@pytest.mark.parametrize("query", ["TABLE users", "WITH c AS (TABLE users) SELECT * FROM c"])
def test_the_table_statement_is_not_admitted(query):
    # Read as written it returns every column; some sqlglot versions read it
    # as a column named TABLE, so the parse is not the query.
    assert _verdict(query, "postgres")[1] == "BLOCKED"


def test_a_whole_row_reference_to_a_table_without_one_is_admitted():
    schema = "CREATE TABLE notes (id INT, body TEXT);"
    assert _verdict("SELECT row_to_json(n) FROM notes n", "postgres", schema)[1] == "ADMIT"


def test_a_name_that_is_a_column_and_an_alias_is_refused():
    # PostgreSQL reads the column here, but a quoted alias that differs only
    # in case would be the row, so the name is not trusted either way.
    schema = "CREATE TABLE notes (id INT, n TEXT, password TEXT);"
    assert _verdict("SELECT n FROM notes n", "postgres", schema)[1] == "BLOCKED"


@pytest.mark.parametrize("query, dialect", [
    ("SELECT id FROM users WHERE id = 1 --1 OR 1=1", "mysql"),
    ("SELECT id FROM users WHERE id = 1 --1 OR 1=1", "postgres"),
    ("SELECT id FROM users WHERE name = 'a\\' OR 1=1 -- '", "mysql"),
    ("SELECT id FROM users WHERE id = 1 /* a /* b */ OR 1=1 */", "postgres"),
    ("SELECT id FROM users WHERE id = 1 -- x\r OR 1=1", "postgres"),
    ("SELECT id FROM users /*!50000 WHERE id = 1 --1 OR 1=1 */", "mysql"),
    # With PIPES_AS_CONCAT, || is a concatenation.
    ("SELECT id FROM users WHERE id = 5 || name LIKE '%'", "mysql"),
])
def test_a_query_that_can_be_split_into_tokens_two_ways_is_refused(query, dialect):
    assert _verdict(query, dialect) == ("BLOCKED", "BLOCKED", CONSTRAINT_AMBIGUOUS_TOKENIZATION)


@pytest.mark.parametrize("query", [
    "SELECT id FROM users WHERE id = 1 -- x",
    "SELECT id FROM users WHERE id = 1 --\tx",
    "SELECT id FROM users WHERE id = 1 /* note */",
])
def test_an_ordinary_comment_is_not_ambiguous(query):
    assert _verdict(query, "mysql") == ("VERIFIED", "ADMIT", "sql_verifier.sql_valid")


# Found in review, round 2.

USER_DDL = 'CREATE TABLE users (id INT, name TEXT, "user" TEXT, uid INT, current_role TEXT, session_user TEXT);'
JOIN_DDL = (
    "CREATE TABLE users (id INT, name TEXT, active BOOLEAN, status ENUM('a','b'));"
    " CREATE TABLE orders (oid INT, total INT);"
)
CLICKHOUSE_ENUM_DDL = (
    "CREATE TABLE users (id Int32, name String, status Enum8('a' = 1, 'b' = 2), s16 Enum16('x' = -1, 'y' = 5));"
)
TYPE_DDL = "CREATE TABLE users (id INT, name TEXT, status mood);"


@pytest.mark.parametrize("query, dialect", [
    # The OR is beside a restriction of the subquery's table but filters the
    # outer query's rows: EXISTS is then true for every outer row.
    ("SELECT id, name FROM users u WHERE EXISTS "
     "(SELECT 1 FROM orders o WHERE o.id = 1 AND (u.id = 5 OR u.name LIKE '%'))", "sqlite"),
    ("SELECT u.id FROM users u, LATERAL "
     "(SELECT 1 FROM orders o WHERE o.id = 1 AND (u.id = 5 OR u.name LIKE '%')) l", "postgres"),
    ("SELECT id FROM users u WHERE EXISTS (SELECT 1 FROM orders o WHERE o.id = 1 AND (u.id = 5 OR name LIKE '%'))",
     "sqlite"),
    ("SELECT id FROM users u WHERE EXISTS "
     "(SELECT 1 FROM orders o WHERE o.id = 1 AND NOT (u.id <> 5 AND u.name NOT LIKE '%'))", "sqlite"),
    ("SELECT id FROM users u WHERE EXISTS (SELECT 1 FROM orders o WHERE o.id = 1 AND u.id IN (5, u.id))", "sqlite"),
    ("SELECT id FROM users u WHERE EXISTS "
     "(SELECT 1 FROM orders o WHERE o.id = 1 AND (u.active = TRUE OR u.active = FALSE))", "postgres"),
    ("SELECT id FROM users u WHERE EXISTS (SELECT 1 FROM orders o WHERE o.id = 1 AND (u.id = 5 OR u.name = 0))",
     "mysql"),
    ("SELECT id FROM users u WHERE EXISTS "
     "(SELECT 1 FROM orders o WHERE o.id = 1 AND u.active = ANY(ARRAY[TRUE, FALSE]))", "postgres"),
    ("SELECT u.id FROM users u WHERE EXISTS (SELECT o.user_id FROM orders o GROUP BY o.user_id "
     "HAVING o.user_id = 1 AND (u.id = 5 OR u.name LIKE '%'))", "sqlite"),
])
def test_an_or_on_an_outer_querys_columns_is_checked(query, dialect):
    assert _verdict(query, dialect) == UNRESTRICTED_VERDICT


def test_an_or_on_the_subquerys_own_table_beside_a_restriction_is_still_admitted():
    query = (
        "SELECT id FROM users u WHERE EXISTS "
        "(SELECT 1 FROM orders o WHERE o.user_id = u.id AND (o.total = 5 OR o.total = 6))"
    )
    assert _verdict(query)[1] == "ADMIT"
    assert _verdict("SELECT id, name FROM users WHERE id = 5 AND (price > 5 OR price < 1)", "postgres")[1] == "ADMIT"


@pytest.mark.parametrize("query, dialect, schema", [
    # MySQL finds 'abc' = -0 true, as 'abc' = 0.
    ("SELECT id FROM users WHERE id = 5 OR name = -0", "mysql", DDL),
    ("SELECT id FROM users WHERE id = 5 OR name = -0.0", "mysql", DDL),
    ("SELECT id FROM users WHERE id = 5 OR name = -(0)", "mysql", DDL),
    ("SELECT id FROM users WHERE id = 5 OR name IN (-0)", "mysql", DDL),
    ("SELECT id FROM users WHERE name IN (-0, 'x')", "mysql", DDL),
    ("SELECT id FROM users WHERE id = 5 OR LOWER(name) = -0", "mysql", DDL),
    ("SELECT id FROM users WHERE id = 5 OR name = -0", "doris", DDL),
    ("SELECT id FROM users WHERE id = 5 OR name = -0", "starrocks", DDL),
    # Zero or FALSE for a column whose type is not known.
    ("SELECT name FROM users WHERE name = 'bob' OR name = 0", "mysql", None),
    ("SELECT name FROM users WHERE name = 'bob' OR name = FALSE", "mysql", None),
    # An unqualified column of a SELECT with several sources.
    ("SELECT u.id FROM users u JOIN orders o ON o.oid = u.id WHERE name = 'bob' OR name = 0", "mysql", JOIN_DDL),
    ("SELECT u.id FROM users u JOIN orders o ON o.oid = u.id WHERE name IN ('bob', 0)", "mysql", JOIN_DDL),
    ("SELECT u.id FROM users u JOIN orders o ON o.oid = u.id WHERE active = 't' OR active = 'f'", "postgres", JOIN_DDL),
    ("SELECT u.id FROM users u JOIN orders o ON o.oid = u.id WHERE status IN ('a', 'b')", "mysql", JOIN_DDL),
    # Every member of an ENUM, as a collation compares them, or by number.
    ("SELECT id FROM users WHERE status = 'A' OR status = 'b '", "mysql", ENUM_DDL),
    ("SELECT id FROM users WHERE status = '\u00e1' OR status = 'b'", "mysql", ENUM_DDL),
    ("SELECT id FROM users WHERE status = 1 OR status = 2", "mysql", ENUM_DDL),
    ("SELECT id FROM users WHERE status = 'a' OR status = 'b'", "clickhouse", CLICKHOUSE_ENUM_DDL),
    ("SELECT id FROM users WHERE s16 IN ('x', 5)", "clickhouse", CLICKHOUSE_ENUM_DDL),
    # A type the schema defines elsewhere, such as an enumerated type.
    ("SELECT id FROM users WHERE status = 'happy' OR status = 'sad'", "postgres", TYPE_DDL),
    # A name the engine reads as a value, though the schema declares it.
    ("SELECT id FROM users WHERE id = 5 OR user = 'app'", "postgres", USER_DDL),
    ("SELECT id FROM users WHERE id = 5 OR current_role = 'app'", "postgres", USER_DDL),
    ("SELECT id FROM users WHERE id = 5 OR session_user = 'app'", "postgres", USER_DDL),
    ("SELECT id FROM users WHERE id = 5 OR user = 'APP'", "oracle", USER_DDL),
    ("SELECT id FROM users WHERE id = 5 OR uid = 1", "oracle", USER_DDL),
    ("SELECT id FROM users WHERE id = 5 OR user = 'dbo'", "tsql", USER_DDL),
    # A name in double quotes may be a string (QUOTED_IDENTIFIER OFF, or a
    # SQLite name no column has).
    ("SELECT id FROM users WHERE name = 'bob' OR \"name\" = 'name'", "tsql", None),
    ("SELECT id FROM users WHERE name = 'bob' OR \"name\" = 'name'", "tsql", DDL),
    ("SELECT id FROM users WHERE \"nosuch\" = 'a' OR \"nosuch\" = 'nosuch'", "sqlite", None),
    # ClickHouse's {p:Identifier} binds a column name.
    ("SELECT id FROM users WHERE id = 5 OR name = {p:Identifier}", "clickhouse", DDL),
])
def test_a_widening_found_in_the_second_review_is_refused(query, dialect, schema):
    # sqlglot 30 reads session_user as a function, so the operand is also a
    # predicate it cannot work out, which names the constraint first.
    result = SQLVerifier().verify_sql(query, schema, dialect=dialect)
    assert admission_decision(result).value == "BLOCKED"
    assert "unrestricted_or_operand" in {issue["type"] for issue in result.developer_fields["issues"]}


@pytest.mark.parametrize("query, dialect", [
    # A negated or compared AND or XOR is an OR of negations.
    ("SELECT id FROM users WHERE (id <> 5 AND name NOT LIKE '%') IS FALSE", "postgres"),
    ("SELECT id FROM users WHERE (id <> 5 AND name NOT LIKE '%') = FALSE", "postgres"),
    ("SELECT id FROM users WHERE (id <> 5 AND name NOT LIKE '%') IS NOT TRUE", "postgres"),
    ("SELECT id FROM users WHERE NOT (id = 5 XOR name LIKE '%')", "mysql"),
    # A list written another way holds the column itself, or covers it.
    ("SELECT id FROM users WHERE id = ANY(ARRAY[5, id])", "postgres"),
    ("SELECT id FROM users WHERE id IN UNNEST([5, id])", "bigquery"),
    ("SELECT id FROM users WHERE id IN (SELECT 5 UNION ALL SELECT id)", "postgres"),
    ("SELECT id FROM users WHERE id IN (VALUES (5), (id))", "postgres"),
    ("SELECT id FROM users WHERE active = ANY(ARRAY[TRUE, FALSE])", "postgres"),
    # <> ANY of two values is true for every row.
    ("SELECT id FROM users WHERE id <> ANY(ARRAY[5, 6])", "postgres"),
])
def test_an_or_written_another_way_is_refused(query, dialect):
    assert _verdict(query, dialect) == UNRESTRICTED_VERDICT


@pytest.mark.parametrize("query, dialect, schema", [
    ("SELECT id FROM users WHERE id = 1 OR id = 2", "mysql", DDL),
    ("SELECT id FROM users WHERE id = 0 OR id = 1", "mysql", DDL),
    ("SELECT name FROM users WHERE name = 'x' OR name = 'y'", "mysql", None),
    ("SELECT id FROM users WHERE status = 'a' OR id = 1", "mysql", ENUM_DDL),
    ('SELECT id FROM users WHERE "user" = \'a\' OR "user" = \'b\'', "postgres", USER_DDL),
    ("SELECT id FROM users WHERE [name] = 'a' OR [name] = 'b'", "tsql", DDL),
    ("SELECT id FROM users WHERE id = ANY(ARRAY[5, 6])", "postgres", DDL),
    ("SELECT id FROM users WHERE id = ANY($1)", "postgres", DDL),
    ("SELECT id FROM users WHERE id IN UNNEST([5, 6])", "bigquery", DDL),
    ("SELECT id FROM users WHERE id IN (SELECT user_id FROM orders)", "postgres", DDL),
    ("SELECT id FROM users WHERE id IN (VALUES (5), (6))", "postgres", DDL),
    ("SELECT id FROM users WHERE id = 5 OR id = {p:Int32}", "clickhouse", DDL),
])
def test_restrictions_near_the_second_reviews_are_still_admitted(query, dialect, schema):
    assert _verdict(query, dialect, schema)[1] == "ADMIT"


@pytest.mark.parametrize("query, dialect", [
    # A bracketed join's alias, or a subquery's that selects a star, stands
    # for every table in it.
    ("SELECT j.* FROM (users JOIN orders USING (user_id)) AS j", "postgres"),
    ("SELECT j.* FROM (users JOIN orders USING (user_id)) AS j", "duckdb"),
    ("SELECT to_jsonb(j) FROM (users CROSS JOIN orders) j", "postgres"),
    ("SELECT j.row_to_json FROM (users CROSS JOIN orders) j", "postgres"),
    ("SELECT k.* FROM ((users JOIN orders USING (user_id)) AS j) AS k", "postgres"),
    # An alias used again for another table: the star covers both, as on main.
    ("SELECT * FROM orders u WHERE EXISTS (SELECT 1 FROM users u WHERE u.id = 1)", "postgres"),
    # In Hive, Spark and Databricks a quoted name may be a pattern of names.
    ("SELECT `pass.*` FROM users", "hive"),
    ("SELECT `pas+word` FROM users", "spark"),
    ("SELECT `(id)?+.+` FROM users", "databricks"),
])
def test_a_protected_column_read_through_another_name_is_refused(query, dialect):
    assert _verdict(query, dialect) == ("VERIFIED", "BLOCKED", CONSTRAINT_MALICIOUS)


@pytest.mark.parametrize("query, dialect", [
    ("SELECT s.* FROM (SELECT id, name FROM users) s", "postgres"),
    ("SELECT row_to_json(s) FROM (SELECT id, name FROM users) s", "postgres"),
    ("SELECT j.id FROM (users JOIN orders USING (user_id)) AS j", "postgres"),
    ("SELECT `id`, name FROM users", "hive"),
])
def test_named_columns_through_another_name_are_still_admitted(query, dialect):
    assert _verdict(query, dialect)[1] == "ADMIT"


@pytest.mark.parametrize("query, dialect", [
    # With ANSI_QUOTES (MySQL) or double-quoted identifiers (Spark,
    # Databricks), "name" is a column.
    ('SELECT id FROM users WHERE id = 5 OR name = "name"', "mysql"),
    ('SELECT "password" FROM users', "mysql"),
    ('SELECT id FROM users WHERE id = 5 OR name = "name"', "spark"),
    ('SELECT "password" FROM users', "databricks"),
    ('SELECT id FROM users /*! WHERE name = "name" */', "mysql"),
])
def test_a_token_a_server_setting_changes_is_refused(query, dialect):
    assert _verdict(query, dialect) == ("BLOCKED", "BLOCKED", CONSTRAINT_AMBIGUOUS_TOKENIZATION)


def test_double_quotes_inside_a_string_are_not_a_token():
    assert _verdict("SELECT id FROM users WHERE name = 'say \"hi\"'", "mysql")[1] == "ADMIT"


@pytest.mark.parametrize("query", [
    # MySQL reads --1 as code, so the DROP is a second statement there.
    "SELECT id FROM users WHERE id = 1 --1; DROP TABLE users",
    'SELECT "password" FROM users',
    "SELECT id FROM users WHERE name = 'a\\' OR 1=1 -- '",
])
def test_sql_guard_refuses_a_query_it_can_split_into_tokens_two_ways(query):
    from qwed_new.guards.sql_guard import SQLGuard

    result = SQLGuard().verify_query(query, dialect="mysql")
    assert result["verified"] is False
    assert result["risk"] == "AMBIGUOUS_TOKENS"


def test_sql_guard_still_verifies_an_ordinary_query():
    from qwed_new.guards.sql_guard import SQLGuard

    assert SQLGuard().verify_query("SELECT id FROM users WHERE id = 1 -- note", dialect="mysql")["verified"] is True
