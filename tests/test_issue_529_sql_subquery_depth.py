"""#529: SQLVerifier no longer blocks every query with a parenthesised subquery.

``_calculate_subquery_depth`` walked ``find_all(exp.Subquery)`` from a
Subquery node, which yields that node first, so it called itself on the
same node until RecursionError. ``verify_sql`` turned that into
BLOCKED ``sql_verifier.execution_error`` for any valid ``IN (SELECT ...)``,
scalar subquery or subquery in FROM, and ``max_subquery_depth`` was never
checked for them. The depth is now the number of SELECTs a SELECT is nested
in, found by walking its parents.
"""

import pytest

from qwed_new.core.sql_verifier import SQLVerifier

DDL = "CREATE TABLE users (id INT, name TEXT); CREATE TABLE orders (id INT, user_id INT)"


def _verify(query):
    result = SQLVerifier().verify_sql(query, DDL, "sqlite")
    complexity = result.developer_fields.get("complexity") or {}
    return result.status.value, result.developer_fields["constraint_id"], complexity.get("subquery_depth")


def _nested(levels):
    """A query whose innermost SELECT is nested in ``levels`` others."""
    query = "SELECT user_id FROM orders"
    for _ in range(levels - 1):
        query = f"SELECT user_id FROM orders WHERE user_id IN ({query})"
    return f"SELECT name FROM users WHERE id IN ({query})"


@pytest.mark.parametrize(("query", "depth"), [
    ("SELECT name FROM users WHERE id IN (SELECT user_id FROM orders)", 1),
    ("SELECT name FROM users WHERE id = (SELECT MAX(user_id) FROM orders)", 1),
    ("SELECT t.id FROM (SELECT id FROM users) AS t", 1),
    ("SELECT name FROM users WHERE EXISTS (SELECT 1 FROM orders WHERE orders.user_id = users.id)", 1),
    ("WITH o AS (SELECT user_id FROM orders) SELECT name FROM users WHERE id IN (SELECT user_id FROM o)", 1),
    ("SELECT name FROM users WHERE id IN (1, 2)", 0),
    ("SELECT id FROM users UNION SELECT id FROM orders", 0),
])
def test_a_valid_query_with_a_subquery_is_verified_with_its_depth(query, depth):
    assert _verify(query) == ("VERIFIED", "sql_verifier.sql_valid", depth)


def test_subqueries_side_by_side_count_once():
    query = (
        "SELECT name FROM users WHERE id IN (SELECT user_id FROM orders) "
        "AND id = (SELECT MAX(user_id) FROM orders)"
    )

    assert _verify(query) == ("VERIFIED", "sql_verifier.sql_valid", 1)


def test_nesting_at_the_limit_is_verified():
    assert _verify(_nested(3)) == ("VERIFIED", "sql_verifier.sql_valid", 3)


@pytest.mark.parametrize("levels", [4, 10])
def test_nesting_past_the_limit_is_blocked_by_the_depth_check(levels):
    status, constraint, depth = _verify(_nested(levels))

    assert (status, constraint, depth) == ("BLOCKED", "sql_verifier.complexity_limit_exceeded", levels)


def test_the_depth_issue_names_the_depth_and_the_limit():
    result = SQLVerifier().verify_sql(_nested(4), DDL, "sqlite")

    (issue,) = [i for i in result.developer_fields["issues"] if i["type"] == "complexity_subqueries"]
    assert issue["description"] == "Query has 4 levels of subqueries (limit: 3)."
