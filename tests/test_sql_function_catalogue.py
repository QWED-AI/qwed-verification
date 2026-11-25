"""The function catalogue sorts every kind the installed sqlglot parses.

SQLVerifier and SQLGuard admit a function sqlglot parses into a known
expression only when its kind is in ``TYPED_FUNCTIONS``, so a kind a newer
sqlglot adds is refused until someone reads it. sqlglot 30.34.0 parses
FIND_IN_SET, ST_X and ST_Y into their own kinds (``findinset``, ``stx`` and
``sty``); older versions read them as calls by name. sqlglot 30.35.0 does
the same for BigQuery's ST_GEOGPOINT (``stgeogpoint``), which builds a
point from a longitude and a latitude. Each computes only from its
arguments, so each is admitted whichever way sqlglot reads it, and a near
miss of the name is still refused. ST_GEOGPOINT is built in only in
BigQuery; in any other dialect a bare call runs whatever routine the
database holds under that name, so it is refused there.
"""

import inspect
import sys

import pytest
import sqlglot
from hypothesis import given, settings
from hypothesis import strategies as st
from sqlglot import exp, parse_one
from sqlglot.dialects.dialect import Dialect, Dialects

from qwed_new.core.diagnostics import admission_decision
from qwed_new.core.sql_function_catalogue import (
    BUILT_IN_ONLY_IN,
    REACHING_TYPED_FUNCTIONS,
    TYPED_FUNCTIONS,
    built_in_only_elsewhere,
)
from qwed_new.core.sql_verifier import KNOWN_VALUE_FUNCTIONS, SQLVerifier, external_reads
from qwed_new.guards.sql_guard import SQLGuard

DDL = "CREATE TABLE users (id INT, name TEXT, geom TEXT);"

DIALECTS = [
    "mysql", "postgres", "duckdb", "bigquery", "snowflake", "spark", "databricks", "hive", "clickhouse",
    "starrocks", "doris", "singlestore", "trino", "tsql", "oracle", "sqlite", "redshift",
]


def _function_kinds():
    """Every ``exp.Func`` kind of the installed sqlglot, with every dialect
    loaded so that a kind a dialect defines is counted too."""
    for dialect in Dialects:
        if dialect.value:
            Dialect.get_or_raise(dialect.value)
    modules = [
        module for name, module in list(sys.modules.items())
        if module is not None and (name == "sqlglot" or name.startswith("sqlglot."))
    ]
    return {
        cls.key for module in modules for _, cls in inspect.getmembers(module, inspect.isclass)
        if issubclass(cls, exp.Func)
    }


def _verdicts(query, dialect):
    with_schema = admission_decision(SQLVerifier().verify_sql(query, DDL, dialect=dialect)).value
    without = admission_decision(SQLVerifier().verify_sql(query, None, dialect=dialect)).value
    guard = SQLGuard().verify_query(query, dialect=dialect)
    return with_schema, without, guard["verified"]


def test_every_function_kind_of_the_installed_sqlglot_is_sorted():
    # An anonymous call is checked by name against KNOWN_VALUE_FUNCTIONS.
    unsorted = sorted(_function_kinds() - TYPED_FUNCTIONS - REACHING_TYPED_FUNCTIONS - {"anonymous"})
    assert not unsorted, (
        f"sqlglot {sqlglot.__version__} parses function kinds the catalogue does not sort: {unsorted}. "
        "Read what each computes and add it to TYPED_FUNCTIONS or REACHING_TYPED_FUNCTIONS in "
        "src/qwed_new/core/sql_function_catalogue.py."
    )


def test_no_kind_is_both_admitted_and_reaching():
    assert not TYPED_FUNCTIONS & REACHING_TYPED_FUNCTIONS


def test_a_kind_built_in_in_one_dialect_is_sorted():
    assert set(BUILT_IN_ONLY_IN) <= TYPED_FUNCTIONS | KNOWN_VALUE_FUNCTIONS


@pytest.mark.parametrize("dialect, elsewhere", [
    ("bigquery", False),
    (" bigquery ", False),
    ("bigquery, normalization_strategy=lowercase", False),
    ("postgres", True),
    ("mysql", True),
    ("", True),
    (None, True),
    # A dialect name sqlglot does not resolve is not BigQuery.
    ("BigQuery", True),
    ("bigqurey", True),
    ("big_query", True),
    ("bigqu" + chr(0x435) + "ry", True),
    ("bigquery" + chr(0x200B), True),
])
def test_st_geogpoint_is_built_in_only_in_bigquery(dialect, elsewhere):
    for name in ("stgeogpoint", "st_geogpoint"):
        assert built_in_only_elsewhere(name, dialect) is elsewhere
    # A name not tied to one dialect is built in wherever it is listed.
    assert built_in_only_elsewhere("abs", dialect) is False


@pytest.mark.parametrize("name", ["find_in_set", "st_x", "st_y", "st_geogpoint"])
def test_the_name_is_known_however_sqlglot_reads_it(name):
    # The name is listed whichever sqlglot is installed: the server image
    # pins one that reads these calls by name, while CI takes the newest.
    assert name in KNOWN_VALUE_FUNCTIONS
    call = parse_one(name + "(a, b)").find(exp.Func)
    assert isinstance(call, exp.Anonymous) or call.key in TYPED_FUNCTIONS


@pytest.mark.parametrize("query", [
    "SELECT ST_X(geom), ST_Y(geom) FROM users",
    "SELECT find_in_set('a', name) FROM users",
    "SELECT id FROM users WHERE FIND_IN_SET(name, 'a,b') > 0 ORDER BY st_x(geom)",
])
@pytest.mark.parametrize("dialect", DIALECTS)
def test_the_sorted_calls_are_admitted(dialect, query):
    assert _verdicts(query, dialect) == ("ADMIT", "ADMIT", True)


@pytest.mark.parametrize("query", [
    "SELECT ST_GEOGPOINT(1, 2)",
    "SELECT ST_GEOGPOINT(id, 2.5) FROM users",
    "SELECT ST_X(ST_GEOGPOINT(id, 2.5)), ST_Y(ST_GEOGPOINT(1, id)) FROM users",
])
@pytest.mark.parametrize("dialect", DIALECTS + ["bigquery, normalization_strategy=lowercase"])
def test_st_geogpoint_is_admitted_only_in_bigquery(dialect, query):
    expected = ("ADMIT", "ADMIT", True) if dialect.startswith("bigquery") else ("BLOCKED", "BLOCKED", False)
    assert _verdicts(query, dialect) == expected


@pytest.mark.parametrize("dialect", DIALECTS + [None])
def test_st_geogpoint_read_by_name_gets_the_same_verdict(dialect):
    # Older sqlglot, the server image's pin among them, reads ST_GEOGPOINT
    # as a call by name; build that call whichever sqlglot is installed.
    query = parse_one("SELECT ST_GEOGPOINT(id, 2.5) FROM users", read=dialect)
    query.find(exp.Func).replace(
        exp.Anonymous(this="ST_GEOGPOINT", expressions=[exp.column("id"), exp.Literal.number(2.5)])
    )
    assert isinstance(query.find(exp.Func), exp.Anonymous)
    assert (external_reads(query, dialect) == ([], [])) is (dialect == "bigquery")


@pytest.mark.parametrize("dialect, query", [
    # MySQL's ST_X(point, new_x) returns the point with X replaced.
    ("mysql", "SELECT ST_X(geom, 1.5) FROM users"),
    ("mysql", "SELECT st_x(geom), St_Y(geom), Find_In_Set('a', name) FROM users"),
    ("mysql", "SELECT ST_X (geom), ST_Y\t(geom), FIND_IN_SET\n('a', name) FROM users"),
    ("mysql", "SELECT ST_X/**/(geom) FROM users"),
    ("mysql", "SELECT find_in_set('a', (SELECT name FROM users)) FROM users"),
    ("bigquery", "SELECT st_geogpoint(id, 1), St_GeogPoint(1, id), ST_GEOGPOINT(-0.1, 51.5) FROM users"),
    ("bigquery", "SELECT ST_GEOGPOINT (id, 1), ST_GEOGPOINT\t(1, id), ST_GEOGPOINT\n(1, 2) FROM users"),
    ("bigquery", "SELECT ST_GEOGPOINT/**/(id, 1) FROM users"),
    ("bigquery", "SELECT ST_GEOGPOINT((SELECT MAX(id) FROM users), 1) FROM users"),
])
def test_other_forms_of_the_same_call_are_admitted(dialect, query):
    assert _verdicts(query, dialect) == ("ADMIT", "ADMIT", True)


@pytest.mark.parametrize("dialect, query", [
    # A name glued, split or inflected is another function.
    ("mysql", "SELECT stx(geom) FROM users"),
    ("mysql", "SELECT findinset('a', name) FROM users"),
    ("mysql", "SELECT st__x(geom) FROM users"),
    ("mysql", "SELECT find_in_sets('a', name) FROM users"),
    ("mysql", "SELECT find_in_setting('a', name) FROM users"),
    ("mysql", "SELECT st-x(geom) FROM users"),
    ("mysql", "SELECT st.x(geom) FROM users"),
    # A quoted name can name another function.
    ("mysql", 'SELECT "ST_X"(geom) FROM users'),
    ("mysql", "SELECT `find_in_set`('a', name) FROM users"),
    # A call through a schema or package can be any function.
    ("mysql", "SELECT db.find_in_set('a', name) FROM users"),
    ("postgres", "SELECT public.st_x(geom) FROM users"),
    ("tsql", "SELECT dbo.find_in_set('a', name) FROM users"),
    ("oracle", "SELECT pkg.st_y(geom) FROM users"),
    # Used as a table, it is not a row generator.
    ("mysql", "SELECT * FROM find_in_set('a', 'b')"),
    ("mysql", "SELECT * FROM users, st_x(geom)"),
    # A call in the arguments that is refused on its own is still refused.
    ("mysql", "SELECT find_in_set('a', load_file('/etc/passwd')) FROM users"),
    ("mysql", "SELECT ST_X(geom) FROM users WHERE find_in_set('a', sleep(5))"),
    ("duckdb", "SELECT find_in_set('a', getenv('HOME'))"),
    ("postgres", "SELECT ST_Y(query_to_xml('SELECT 1', true, true, ''))"),
    # Look-alike letters from other scripts and zero-width characters.
    ("mysql", "SELECT ST_Х(geom) FROM users"),
    ("mysql", "SELECT find_іn_set('a', name) FROM users"),
    ("mysql", "SELECT ST_Χ(geom) FROM users"),
    ("mysql", "SELECT ST​_X(geom) FROM users"),
    ("mysql", "SELECT ＳＴ_X(geom) FROM users"),
    # The same for ST_GEOGPOINT.
    ("bigquery", "SELECT stgeogpoint(1, 2)"),
    ("bigquery", "SELECT st_geog_point(1, 2)"),
    ("bigquery", "SELECT st__geogpoint(1, 2)"),
    ("bigquery", "SELECT st_geogpoints(1, 2)"),
    ("bigquery", "SELECT st_geogpointing(1, 2)"),
    ("bigquery", "SELECT st-geogpoint(1, 2)"),
    ("bigquery", "SELECT `ST_GEOGPOINT`(1, 2)"),
    ("postgres", 'SELECT "st_geogpoint"(1, 2)'),
    ("bigquery", "SELECT ds.ST_GEOGPOINT(1, 2)"),
    ("bigquery", "SELECT `proj.ds.ST_GEOGPOINT`(1, 2)"),
    ("postgres", "SELECT public.st_geogpoint(1, 2)"),
    ("bigquery", "SELECT * FROM ST_GEOGPOINT(1, 2)"),
    ("bigquery", "SELECT * FROM users, ST_GEOGPOINT(1, 2)"),
    # Applied by name in ClickHouse, where it is not built in.
    ("clickhouse", "SELECT * APPLY(st_geogpoint) FROM users"),
    ("clickhouse", "SELECT * APPLY(ST_GEOGPOINT) FROM users"),
    ("mysql", "SELECT ST_GEOGPOINT(sleep(5), 1) FROM users"),
    ("duckdb", "SELECT ST_GEOGPOINT(getenv('HOME'), 1)"),
    ("bigquery", "SELECT ST_GEOGPOINT(AI.GENERATE('x'), 1)"),
    ("bigquery", "SELECT ST_G\u0415OGPOINT(1, 2)"),
    ("bigquery", "SELECT ST_GE\u039fGPOINT(1, 2)"),
    ("bigquery", "SELECT ST_GEOG\u200bPOINT(1, 2)"),
    ("bigquery", "SELECT ST_GEOGPOINT\ufeff(1, 2)"),
    ("bigquery", "SELECT \uff33T_GEOGPOINT(1, 2)"),
])
def test_a_near_miss_or_misuse_is_refused(dialect, query):
    with_schema, without, guard = _verdicts(query, dialect)
    assert (with_schema, without, guard) == ("BLOCKED", "BLOCKED", False)


@pytest.mark.parametrize("query", [
    "SELECT ST_GEOGPOINT(TABLE secret_table, 1)",
    "SELECT id FROM users WHERE id = ABS(TABLE secret_table)",
])
def test_a_table_argument_outside_the_schema_is_refused(query):
    # sqlglot 30.35.0 reads BigQuery's TABLE t inside any call's arguments
    # as a table; older versions do not parse it. Either way, a table the
    # schema does not hold is refused.
    verdict = SQLVerifier().verify_sql(query, DDL, dialect="bigquery")
    assert admission_decision(verdict).value == "BLOCKED"


_LOOK_ALIKES = {"s": "ѕ", "x": "х", "y": "у", "i": "і", "e": "е", "t": "τ", "o": "о", "p": "р"}


@st.composite
def _near_misses(draw):
    """A name one change away from st_x, st_y, find_in_set or st_geogpoint."""
    name = draw(st.sampled_from(["st_x", "st_y", "find_in_set", "st_geogpoint"]))
    change = draw(st.sampled_from(
        ["glue", "double", "suffix", "prefix", "look-alike", "zero-width", "fullwidth"]
    ))
    if change == "glue":
        name = name.replace("_", "")
    elif change == "double":
        at = draw(st.sampled_from([i for i, char in enumerate(name) if char == "_"]))
        name = name[:at] + "_" + name[at:]
    elif change == "suffix":
        name += draw(st.sampled_from(["s", "es", "ed", "ing", "_", "2", "x"]))
    elif change == "prefix":
        name = draw(st.sampled_from(["_", "x", "my_"])) + name
    elif change == "look-alike":
        at = draw(st.sampled_from([i for i, char in enumerate(name) if char in _LOOK_ALIKES]))
        name = name[:at] + _LOOK_ALIKES[name[at]] + name[at + 1:]
    elif change == "zero-width":
        at = draw(st.integers(1, len(name) - 1))
        zero_width = draw(st.sampled_from(["​", "‌", "‍", "⁠", "﻿"]))
        name = name[:at] + zero_width + name[at:]
    else:
        at = draw(st.sampled_from([i for i, char in enumerate(name) if char.isalpha()]))
        name = name[:at] + chr(ord(name[at]) - ord("a") + 0xFF41) + name[at + 1:]
    return draw(st.sampled_from([str.lower, str.upper, str.title]))(name)


@settings(max_examples=150, deadline=None)
@given(
    name=_near_misses(),
    dialect=st.sampled_from(["mysql", "postgres", "duckdb", "spark", "clickhouse", "snowflake"]),
)
def test_a_name_one_change_from_an_admitted_one_is_refused(name, dialect):
    query = "SELECT " + name + "(geom) FROM users"
    _, without, guard = _verdicts(query, dialect)
    assert (without, guard) == ("BLOCKED", False)
