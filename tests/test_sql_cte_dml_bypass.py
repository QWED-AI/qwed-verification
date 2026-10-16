"""GHSA-6p94-4f75-g2wq: SQLVerifier certified destructive/administrative SQL as
VERIFIED/ADMIT because _check_command_type classified by the root AST node only.

Two classes slipped through on the default (allow_destructive=False) path:
  1. DML hidden in a CTE — `WITH d AS (DELETE ... RETURNING *) SELECT * FROM d`
     has a Select root, so the DELETE ran while the verdict said "safe".
  2. Whole statement families absent from the deny sets — COPY ... FROM PROGRAM,
     ATTACH/DETACH, PRAGMA, LOAD, etc.

The fix walks the whole parse tree and fails closed on any top-level statement
that is not a recognized read-only query type.
"""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

import pytest

from qwed_new.core.sql_verifier import SQLVerifier


def _valid(result):
    return result.developer_fields.get("is_valid")


@pytest.mark.parametrize("query,dialect", [
    ("WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d", "postgres"),
    ("WITH d AS (UPDATE users SET admin = true RETURNING *) SELECT * FROM d", "postgres"),
    ("WITH d AS (INSERT INTO users (id) VALUES (1) RETURNING *) SELECT * FROM d", "postgres"),
    # Nested one level deeper, in a subquery inside the CTE.
    ("WITH d AS (SELECT * FROM (DELETE FROM users RETURNING *) x) SELECT * FROM d", "postgres"),
])
def test_dml_hidden_in_cte_is_not_certified(query, dialect):
    # Select root, DML descendant: must be rejected, not VERIFIED/ADMIT.
    assert _valid(SQLVerifier().verify_sql(query, dialect=dialect)) is False


@pytest.mark.parametrize("query,dialect", [
    ("COPY t FROM PROGRAM 'id'", "postgres"),
    ("COPY t TO '/tmp/out.csv'", "postgres"),
    ("COPY t FROM '/etc/passwd'", "postgres"),
    ("ATTACH DATABASE 'evil.db' AS evil", "sqlite"),
    ("DETACH DATABASE evil", "sqlite"),
    ("PRAGMA table_info(users)", "sqlite"),
])
def test_non_select_statement_families_are_blocked(query, dialect):
    # Statement families that sit in no deny set must still be blocked by the
    # read-only allowlist (fail closed), not waved through.
    assert _valid(SQLVerifier().verify_sql(query, dialect=dialect)) is False


@pytest.mark.parametrize("query,dialect", [
    ("SELECT id, name FROM users WHERE id = 1", "postgres"),
    ("WITH c AS (SELECT id FROM users) SELECT * FROM c", "postgres"),
    ("SELECT id FROM a UNION SELECT id FROM b", "postgres"),
    ("SELECT id FROM a INTERSECT SELECT id FROM b", "postgres"),
])
def test_read_only_queries_still_verify(query, dialect):
    # The fix must not regress legitimate read-only queries, including CTEs whose
    # inner statement is itself a SELECT.
    assert _valid(SQLVerifier().verify_sql(query, dialect=dialect)) is True


def test_allow_destructive_mode_is_preserved():
    # Admin contexts that opt into destructive ops are unaffected by the
    # read-only allowlist (which only applies when allow_destructive is False).
    permissive = SQLVerifier(allow_destructive=True)
    assert _valid(permissive.verify_sql("DROP TABLE users")) is True
    assert _valid(permissive.verify_sql("DELETE FROM users WHERE id = 1")) is True
