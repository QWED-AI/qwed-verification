"""GHSA-6cpx-8jrq-r7h3: two SQLVerifier checks could be bypassed into VERIFIED/ADMIT.

1. The sensitive-column denylist only inspected explicitly named columns, so
   `SELECT * FROM users` (schema declares `password`) was admitted while
   `SELECT password FROM users` was blocked.
2. Tautology detection matched fixed AST shapes only, so `OR 1`, `OR NOT FALSE`,
   `1 = 1.0` and `2 > 1` slipped past while `OR TRUE`/`OR 1=1` were blocked.

The two compose into one admitted credential-dumping query.
"""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

import pytest

from qwed_new.core.sql_verifier import SQLVerifier

_SCHEMA = "CREATE TABLE users (id INT, password TEXT, name TEXT)"
_SCHEMA2 = "CREATE TABLE users (id INT, password TEXT); CREATE TABLE pub (id INT, title TEXT)"


def _valid(query, schema=_SCHEMA):
    return SQLVerifier().verify_sql(query, schema_ddl=schema, dialect="postgres").developer_fields.get("is_valid")


# --- 1. star over a table with a sensitive column ------------------------------

@pytest.mark.parametrize("query,schema", [
    ("SELECT * FROM users", _SCHEMA),
    ("SELECT u.* FROM users u", _SCHEMA),
    ("SELECT * FROM pub JOIN users ON pub.id = users.id", _SCHEMA2),  # star covers sensitive table
])
def test_star_over_sensitive_table_is_blocked(query, schema):
    assert _valid(query, schema) is False


@pytest.mark.parametrize("query,schema", [
    ("SELECT id, name FROM users", _SCHEMA),          # named, no sensitive
    ("SELECT p.* FROM pub p", _SCHEMA2),              # star over a table with no sensitive column
])
def test_non_sensitive_selections_still_verify(query, schema):
    assert _valid(query, schema) is True


def test_named_sensitive_column_still_blocked():
    assert _valid("SELECT password FROM users") is False


# --- 2. always-true predicates by value, not by shape --------------------------

@pytest.mark.parametrize("query", [
    "SELECT id FROM users WHERE id = 1 OR 1",
    "SELECT id FROM users WHERE id = 1 OR NOT FALSE",
    "SELECT id FROM users WHERE id = 1 OR 2 > 1",
    "SELECT id FROM users WHERE 1 = 1.0",
    "SELECT id FROM users WHERE 1",
    "SELECT id FROM users WHERE id = 1 OR TRUE",   # still caught
    "SELECT id FROM users WHERE 1 = 1",            # still caught
])
def test_always_true_predicates_are_blocked(query):
    assert _valid(query) is False


@pytest.mark.parametrize("query", [
    "SELECT id FROM users WHERE id = 1",
    "SELECT id FROM users WHERE id > 5 AND name = 'bob'",
    "SELECT id FROM users WHERE name = 'gold' OR name = 'silver'",  # real OR over data
])
def test_genuine_filters_are_not_flagged_as_tautologies(query):
    assert _valid(query) is True


# --- the composed credential-dumping query -------------------------------------

def test_composed_star_plus_tautology_is_blocked():
    assert _valid("SELECT * FROM users WHERE id = 1 OR 1") is False
