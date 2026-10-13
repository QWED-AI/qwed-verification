"""SQL hidden in executable comments, and tables outside the schema (GHSA-q5g6-6cw2-cjm3).

1. MySQL and MariaDB run the body of /*! ... */ comments, but the verifier
   treated it as a comment, so "WHERE id = 1 /*!50000 OR 1=1 */" was admitted
   while the same query without the comment was caught as a tautology.
2. A table outside the declared schema was a WARNING, so the query was still
   admitted.
"""

import pytest

from qwed_new.core.diagnostics import admission_decision
from qwed_new.core.sql_verifier import SQLVerifier, expand_executable_comments

SCHEMA = "CREATE TABLE users (id INT, name TEXT, role TEXT); CREATE TABLE orders (id INT, user_id INT, total INT)"


def verify(query, dialect="mysql", schema=SCHEMA):
    result = SQLVerifier().verify_sql(query, schema, dialect)
    issues = {i["type"] for i in result.developer_fields.get("issues", [])}
    return result, issues


@pytest.mark.parametrize("query", [
    "SELECT * FROM users WHERE id = 1 /*!50000 OR 1=1 */",
    "SELECT * FROM users WHERE id = 1 /*! OR 1=1 */",
    "SELECT * FROM users WHERE id = 1 /*!500000 OR 1=1 */",
    "SELECT * FROM users WHERE id = 1 /*M! OR 1=1 */",
    "SELECT * FROM users WHERE id = 1 /*!50000\n OR 1=1 */",
])
def test_tautology_in_an_executable_comment_is_caught(query):
    result, issues = verify(query)
    assert result.developer_fields["is_valid"] is False
    assert admission_decision(result).value == "BLOCKED"
    assert "injection_tautology" in issues
    assert result.developer_fields["executable_comments_expanded"] is True


def test_executable_comments_are_expanded_whatever_the_dialect():
    result, issues = verify("SELECT * FROM users WHERE id = 1 /*!50000 OR 1=1 */", dialect="postgres")
    assert admission_decision(result).value == "BLOCKED"
    assert "injection_tautology" in issues


def test_table_hidden_in_an_executable_comment_is_caught():
    result, issues = verify("SELECT id FROM users /*!50000 , secrets */")
    assert admission_decision(result).value == "BLOCKED"
    assert "schema_table_missing" in issues


def test_ordinary_comments_are_unchanged():
    result, _ = verify("SELECT id FROM users /* the active ones */ WHERE id = 1")
    assert result.developer_fields["is_valid"] is True
    assert result.developer_fields["executable_comments_expanded"] is False
    assert admission_decision(result).value == "ADMIT"


def test_expand_executable_comments():
    assert expand_executable_comments("a /*!50000 b */ c").split() == ["a", "b", "c"]
    assert expand_executable_comments("a /* b */ c") == "a /* b */ c"


@pytest.mark.parametrize("query", [
    "SELECT id FROM secrets",
    "SELECT id FROM users WHERE id = 1 UNION SELECT id FROM secrets",
    "SELECT u.id FROM users u JOIN secrets s ON s.id = u.id",
])
def test_table_outside_the_schema_is_not_admitted(query):
    result, issues = verify(query, dialect="postgres")
    fields = result.developer_fields
    assert fields["is_valid"] is False
    assert fields["constraint_id"] == "sql_verifier.schema_violation"
    assert fields["malicious_classification"] is False
    assert admission_decision(result).value == "BLOCKED"
    assert "schema_table_missing" in issues


@pytest.mark.parametrize("query", [
    "SELECT u.name, o.total FROM users u JOIN orders o ON o.user_id = u.id",
    "WITH recent AS (SELECT id FROM orders) SELECT id FROM recent",
    "SELECT name FROM public.users",
])
def test_queries_within_the_schema_are_still_admitted(query):
    result, _ = verify(query, dialect="postgres")
    assert result.developer_fields["is_valid"] is True, result.developer_fields["issues"]
    assert admission_decision(result).value == "ADMIT"


def test_without_a_schema_tables_are_not_checked():
    result, _ = verify("SELECT id FROM secrets", dialect="postgres", schema=None)
    assert result.developer_fields["is_valid"] is True
