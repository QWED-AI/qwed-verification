"""#529: SQLVerifier no longer blocks every query with a parenthesised subquery.

``_calculate_subquery_depth`` walked ``find_all(exp.Subquery)`` from a
Subquery node, which yields that node first, so it called itself on the
same node until RecursionError. ``verify_sql`` turned that into
BLOCKED ``sql_verifier.execution_error`` for any valid ``IN (SELECT ...)``,
scalar subquery or subquery in FROM, and ``max_subquery_depth`` was never
checked for them. The depth is now the number of SELECT, UPDATE, DELETE,
INSERT or MERGE nodes a SELECT is nested in, found in one pass over the tree.
"""

import pytest

from qwed_new.core.sql_verifier import SQLVerifier

DDL = "CREATE TABLE users (id INT, name TEXT); CREATE TABLE orders (id INT, user_id INT)"
INNERMOST = "SELECT user_id FROM orders"
# The test only builds query text for the verifier to parse; nothing runs it.
LEVEL = "SELECT user_id FROM orders WHERE user_id IN (INNER)"
OUTER = "SELECT name FROM users WHERE id IN (INNER)"


def _depth_of(result):
    return (result.developer_fields.get("complexity") or {}).get("subquery_depth")


def _verify(query, verifier=None):
    result = (verifier or SQLVerifier()).verify_sql(query, DDL, "sqlite")
    return result.status.value, result.developer_fields["constraint_id"], _depth_of(result)


def _nested(levels):
    """A query whose innermost SELECT is nested in ``levels`` others."""
    query = INNERMOST
    for _ in range(levels - 1):
        query = LEVEL.replace("INNER", query)
    return OUTER.replace("INNER", query)


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


# ---------------------------------------------------- DML and long UNION chains

@pytest.mark.parametrize(("query", "depth"), [
    ("UPDATE users SET name = 'x' WHERE id IN (SELECT user_id FROM orders)", 1),
    ("DELETE FROM users WHERE id IN (SELECT user_id FROM orders)", 1),
    ("UPDATE users SET name = 'x' WHERE id = 1", 0),
])
def test_a_subquery_of_a_permitted_dml_statement_counts_as_a_level(query, depth):
    # Review on #554: a SELECT under UPDATE or DELETE has no enclosing SELECT,
    # but it is still a subquery, so max_subquery_depth must see it.
    verifier = SQLVerifier(allow_destructive=True, complexity_limits={"max_subquery_depth": 0})

    status, constraint, reported = _verify(query, verifier)

    assert reported == depth
    expected = ("BLOCKED", "sql_verifier.complexity_limit_exceeded") if depth else ("VERIFIED", "sql_verifier.sql_valid")
    assert (status, constraint) == expected


def test_a_long_union_chain_is_walked_once(monkeypatch):
    # sqlglot nests a UNION ALL chain to the left. Each node is visited once,
    # so the walk is linear in the chain (review on #554), and no level is
    # added: a union is not a subquery.
    from sqlglot import exp, parse_one

    operands = 500
    tree = parse_one("SELECT 1" + " UNION ALL SELECT 1" * (operands - 1), read="sqlite")
    nodes = sum(1 for _ in tree.walk())
    visits = []
    real = exp.Expression.iter_expressions
    monkeypatch.setattr(
        exp.Expression, "iter_expressions", lambda self, *a, **k: visits.append(self) or real(self, *a, **k)
    )
    # Count reads of each node's parent: walking every SELECT's ancestors, as
    # the first fix did, reads about operands**2 / 2 of them.
    slot = exp.Expression.__dict__["parent"]
    parent_reads = []

    def _read_parent(node):
        parent_reads.append(node)
        return slot.__get__(node)

    monkeypatch.setattr(exp.Expression, "parent", property(_read_parent, slot.__set__))

    assert SQLVerifier()._calculate_subquery_depth(tree) == 0
    assert len(visits) == nodes
    assert len(parent_reads) <= nodes
