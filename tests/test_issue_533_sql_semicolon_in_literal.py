"""#533: a ";" inside a literal or comment no longer makes a statement "stacked".

``SQLVerifier`` flagged ``stacked_queries`` (malicious, not admitted) when a
";" appeared anywhere before the last character of the raw text, so
``WHERE name = 'a;b'``, ``/* ; */`` and ``$$a;b$$`` were refused. Statements
are now counted from sqlglot's parse. Where the database could split the text
differently from sqlglot (a backslash, "--" not followed by whitespace, a
nested "/*"), every ";" still counts, as before.
"""

import pytest

from qwed_new.core.sql_verifier import SQLVerifier, has_stacked_statements

DDL = "CREATE TABLE users (id INT, name TEXT);"

ONE_STATEMENT = [
    "SELECT name FROM users WHERE name = 'a;b'",
    "SELECT name FROM users /* ; */ WHERE id = 1",
    "SELECT name FROM users WHERE id = 1; -- trailing note",
    "SELECT name FROM users WHERE id = 1;",
    "SELECT name FROM users WHERE name = 'it''s; fine'",
]
STACKED = [
    "SELECT name FROM users; SELECT id FROM users",
    "SELECT name FROM users; SELECT id FROM users;",
    "SELECT 1; DROP TABLE users",
    "SELECT 1 /*!50000 ; DROP TABLE users */",
]
# sqlglot reads each of these as one statement in some dialect, but a
# database can read two (review of #533's fix): they stay blocked.
AMBIGUOUS = [
    # MySQL with NO_BACKSLASH_ESCAPES, or PostgreSQL, ends the string at \'.
    "SELECT name FROM users WHERE name = 'a\\'; DROP TABLE users; --'",
    # MySQL starts a comment at "--" only when ASCII whitespace follows; a
    # Unicode space such as U+00A0 is not one (review on #555).
    "SELECT 1 --; DROP TABLE users",
    "SELECT 1 -- ; DROP TABLE users",
    "SELECT 1 --　; DROP TABLE users",
    # Only some engines nest block comments.
    "SELECT 1 /* a /* b */ ; DROP TABLE users; */",
]


def _issue_types(query, dialect):
    result = SQLVerifier().verify_sql(query, DDL, dialect)
    return result, [i.get("type") for i in result.developer_fields.get("issues", [])]


@pytest.mark.parametrize("dialect", ["postgres", "sqlite", "mysql"])
@pytest.mark.parametrize("query", ONE_STATEMENT)
def test_a_semicolon_in_a_literal_or_comment_is_admitted(query, dialect):
    result, issues = _issue_types(query, dialect)

    assert "stacked_queries" not in issues
    assert (result.status.value, result.developer_fields["is_valid"]) == ("VERIFIED", True)
    assert result.developer_fields["malicious_classification"] is False


def test_a_dollar_quoted_string_with_a_semicolon_is_admitted_on_postgres():
    result, issues = _issue_types("SELECT name FROM users WHERE name = $$a;b$$", "postgres")

    assert "stacked_queries" not in issues
    assert result.developer_fields["is_valid"] is True


@pytest.mark.parametrize("dialect", ["postgres", "sqlite", "mysql"])
@pytest.mark.parametrize("query", STACKED)
def test_two_statements_are_still_blocked_as_stacked(query, dialect):
    result, issues = _issue_types(query, dialect)

    assert "stacked_queries" in issues
    assert result.developer_fields["is_valid"] is False
    assert result.developer_fields["malicious_classification"] is True


@pytest.mark.parametrize("dialect", ["postgres", "sqlite", "mysql", "tsql", "bigquery"])
@pytest.mark.parametrize("query", AMBIGUOUS)
def test_an_ambiguous_split_counts_every_semicolon(query, dialect):
    assert has_stacked_statements(query, dialect) is True


@pytest.mark.parametrize("dialect", ["postgres", "sqlite", "mysql"])
@pytest.mark.parametrize("query", AMBIGUOUS)
def test_an_ambiguous_split_is_not_admitted(query, dialect):
    result = SQLVerifier().verify_sql(query, DDL, dialect)

    assert result.developer_fields["is_valid"] is False


def test_a_query_that_does_not_parse_counts_every_semicolon():
    assert has_stacked_statements("SELECT FROM WHERE 'a;b' ;; )", "postgres") is True


@pytest.mark.parametrize("query", ["SELECT 1", "SELECT 1;", "  SELECT 1 ;  "])
def test_a_single_statement_without_an_inner_semicolon_is_not_stacked(query):
    assert has_stacked_statements(query, "postgres") is False
