"""
Enterprise SQL Verifier: Security Firewall with Complexity Limits.

Provides AST-based SQL analysis to prevent:
1. Injection attacks (tautologies, UNION, stacking)
2. Data leakage (sensitive column access)
3. Destructive operations (DROP, DELETE, etc.)
4. Resource exhaustion (complexity limits)
5. Schema violations
"""

import hashlib
import math
import re
from decimal import Decimal, localcontext
from functools import lru_cache

import sqlglot
from sqlglot import exp, parse_one
from sqlglot.tokens import TokenType
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass

from .diagnostics import DiagnosticResult
from .sql_filter_check import (
    _FilterContext,
    _declared_schema,
    _dialect_families,
    _unparen,
    _unrestricted_or_operand,
    setting_dependent_tokens,
)
from .sql_function_catalogue import REACHING_TYPED_FUNCTIONS, TYPED_FUNCTIONS

from .verification_context import VerificationContextDocument


CONSTRAINT_PARSE_ERROR = "sql_verifier.parse_error"
CONSTRAINT_EXECUTION_ERROR = "sql_verifier.execution_error"
CONSTRAINT_CONNECTION_FAILURE = "sql_verifier.connection_failure"
CONSTRAINT_SQL_VALID = "sql_verifier.sql_valid"
CONSTRAINT_MALICIOUS = "sql_verifier.malicious"
CONSTRAINT_COMPLEXITY_LIMIT_EXCEEDED = "sql_verifier.complexity_limit_exceeded"
CONSTRAINT_SCHEMA_PARSE_ERROR = "sql_verifier.schema_parse_error"
CONSTRAINT_SCHEMA_VIOLATION = "sql_verifier.schema_violation"
CONSTRAINT_EMPTY_BATCH = "sql_verifier.empty_batch"
CONSTRAINT_UNEVALUATED_PREDICATE = "sql_verifier.unevaluated_predicate"
# An OR in a filter has an operand that restricts no column to a value, so it
# may be always true (GHSA-xpfc).
CONSTRAINT_UNRESTRICTED_OR = "sql_verifier.unrestricted_or"
# The query can be split into tokens differently by sqlglot and the database
# (_AMBIGUOUS_TOKENIZATION), so what was analysed may not be what runs
# (GHSA-xpfc).
CONSTRAINT_AMBIGUOUS_TOKENIZATION = "sql_verifier.ambiguous_tokenization"
# The query calls a function SQLVerifier does not know to compute only from
# its arguments, so it may read files, the network or the environment
# (GHSA-wgcp-398q-m296).
CONSTRAINT_UNKNOWN_FUNCTION = "sql_verifier.unknown_function"
UNKNOWN_FUNCTION = "unknown_function"
# A filter predicate that reads no data but could not be worked out: it may
# be always true, so the query is not admitted, though nothing proves malice.
UNEVALUATED_PREDICATE = "unevaluated_constant_predicate"
UNRESTRICTED_OR = "unrestricted_or_operand"

# MySQL and MariaDB run the body of /*! ... */, /*!NNNNN ... */ and MariaDB's
# /*M! ... */ comments; other engines, and SQLGlot, treat them as comments, so
# SQL inside one escaped analysis (GHSA-q5g6-6cw2-cjm3). They are expanded
# before analysis whatever the declared dialect: if the query reaches MySQL,
# that body is what runs.
_EXECUTABLE_COMMENT = re.compile(r"/\*M?!(?:\d{5,6})?(.*?)\*/", re.DOTALL)


def expand_executable_comments(query: str) -> str:
    """Replace each MySQL/MariaDB executable comment with the SQL inside it."""
    return _EXECUTABLE_COMMENT.sub(lambda m: f" {m.group(1)} ", query)


# Forms where sqlglot and the database can split a query into statements
# differently (#533): a backslash (escape rules depend on server settings,
# such as MySQL's NO_BACKSLASH_ESCAPES or PostgreSQL E'' strings), "--" not
# followed by ASCII whitespace (MySQL starts a comment only then; a Unicode
# space such as U+00A0 does not count, so the class is spelt out rather than
# \s), a "/*" inside a block comment (only some engines nest them) and a
# carriage return not followed by a line feed (PostgreSQL ends a line comment
# there, MySQL and SQLite do not, and sqlglot versions differ: 30.20 ends it,
# 30.26 does not for mysql and sqlite). In a query with one of these, every
# ";" before the end counts as a separator, as it did before #533. The scan
# does not track quotes, so a literal holding one of these forms also counts
# every ";" (fail closed).
_AMBIGUOUS_TOKENIZATION = re.compile(r"\\|--(?![ \t\n\r\f\v])|/\*(?:(?!\*/).)*?/\*|\r(?!\n)", re.DOTALL)
_EMPTY_STATEMENT_TYPES = tuple(
    t for t in (getattr(exp, "Semicolon", None),) if t is not None
)


def has_ambiguous_tokenization(query: str, dialect: str) -> bool:
    """Whether sqlglot and the database may split *query* into tokens
    differently, so that no analysis of it describes what runs: a form
    ``_AMBIGUOUS_TOKENIZATION`` lists, in the query as given or with MySQL
    executable comments expanded, or a token whose meaning a server setting
    changes (a string in double quotes in MySQL, Spark and Hive; MySQL's
    ||) (GHSA-xpfc-qm4c-xf6q)."""
    expanded = expand_executable_comments(query)
    return bool(
        _AMBIGUOUS_TOKENIZATION.search(query)
        or _AMBIGUOUS_TOKENIZATION.search(expanded)
        or setting_dependent_tokens(query, dialect)
        or setting_dependent_tokens(expanded, dialect)
    )


def has_stacked_statements(query: str, dialect: str) -> bool:
    """True when *query* holds more than one statement.

    ``parse_one`` reads only the first statement, so the check is separate.
    A ";" inside a string literal, a dollar-quoted string or a comment is not
    a separator: the statements are counted from sqlglot's parse of the query
    with MySQL executable comments expanded. Where tokenizing is ambiguous
    (``_AMBIGUOUS_TOKENIZATION``, in the query as given or as expanded) or
    the parse fails, any ";" before the end counts (fail closed). Checking the
    query as given matters: expanding ``/*!50000 /* x */ ; DROP ... */`` ends
    the executable comment at the inner "*/" and leaves the rest inside a
    plain comment, which hides the ";" from the parse.
    """
    expanded = expand_executable_comments(query)
    if ";" not in expanded.strip()[:-1]:
        return False
    if _AMBIGUOUS_TOKENIZATION.search(query) or _AMBIGUOUS_TOKENIZATION.search(expanded):
        return True
    try:
        parsed = sqlglot.parse(expanded, read=dialect)
    except Exception:  # noqa: BLE001 — fail closed: count the raw ";"
        return True
    return len(_non_empty(parsed)) > 1


def _non_empty(parsed: List[Optional[exp.Expression]]) -> List[exp.Expression]:
    """The statements of a parse, without the empty ones a trailing ";" or
    a comment after it leaves (None, or ``exp.Semicolon``)."""
    return [e for e in parsed if e is not None and not isinstance(e, _EMPTY_STATEMENT_TYPES)]


def _single_statement(query: str, dialect: str) -> Optional[exp.Expression]:
    """The query's statement when it has exactly one, else None.

    For ``SELECT ...; -- note`` sqlglot 30 ``parse_one`` returns a ``Block``
    of the SELECT and the empty statement after it, which is not a read-only
    root; sqlglot 28 returns the SELECT (#533). With more than one statement
    the caller keeps ``parse_one``'s result, and the query is stacked anyway.
    """
    statements = _non_empty(sqlglot.parse(query, read=dialect))
    return statements[0] if len(statements) == 1 else None


def _parse_query(query: str, dialect: str) -> exp.Expression:
    """The tree verify_sql analyses: the single statement, else parse_one's."""
    return _single_statement(query, dialect) or parse_one(query, read=dialect)
CONSTRAINT_BATCH_BLOCKED = "sql_verifier.batch_blocked"

# Issue types that prove malice. Resource-limit violations (complexity_*) are CRITICAL
# admission failures but are NOT evidence of malicious intent, so they must never set
# developer_fields.malicious_classification (CodeRabbit).
MALICIOUS_ISSUE_TYPES = frozenset({
    "destructive_command",
    "admin_command",
    "sensitive_column_access",
    "injection_tautology",
    "injection_or_true",
    "stacked_queries",
    "dangerous_function",
})

# Functions that read or write server files, load code, or reach the OS or
# another server, in any dialect (GHSA-45jv-2j44-4c2q). A read-only SELECT
# that calls one is not read-only. Shared with guards.sql_guard.SQLGuard so
# the two cannot drift.
DANGEROUS_SQL_FUNCTIONS = frozenset({
    # SQLite
    "load_extension", "readfile", "writefile", "edit", "fts3_tokenizer",
    # PostgreSQL
    "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file",
    "pg_ls_logdir", "pg_ls_waldir", "pg_ls_tmpdir",
    "lo_import", "lo_export", "lo_from_bytea", "lo_get", "lo_put",
    "dblink", "dblink_exec", "dblink_connect", "dblink_connect_u", "dblink_send_query",
    "pg_execute_server_program", "pg_reload_conf", "pg_terminate_backend",
    "pg_cancel_backend", "set_config",
    # MySQL / MariaDB
    "load_file", "sys_exec", "sys_eval",
    # SQL Server
    "xp_cmdshell", "xp_dirtree", "xp_fileexist", "xp_regread", "xp_regwrite",
    "sp_oacreate", "sp_oamethod", "sp_execute_external_script",
    "openrowset", "opendatasource", "openquery",
    # Oracle
    "utl_file", "utl_http", "utl_inaddr", "dbms_java", "dbms_scheduler",
})


def sql_function_names(parsed: exp.Expression) -> Set[str]:
    """The lower-cased name of every function the parse tree calls, known
    to sqlglot or not."""
    names: Set[str] = set()
    for node in parsed.walk():
        node = node[0] if isinstance(node, tuple) else node
        if isinstance(node, exp.Anonymous):
            names.add(str(node.name).lower())
        elif isinstance(node, exp.Func):
            names.add(node.sql_name().lower())
            names.add(type(node).__name__.lower())
        elif isinstance(node, exp.Dot):
            # utl_file.fopen(...), dbms_java.runjava(...): the package name.
            left = node.this
            if isinstance(left, (exp.Column, exp.Identifier)):
                names.add(str(left.name).lower())
    return names


def _available_expression_types(*names: str) -> Set[type]:
    """Return the sqlglot expression classes that exist in the installed version."""
    return {
        expression
        for name in names
        if (expression := getattr(exp, name, None)) is not None
    }


# What a query may read besides the tables it names (GHSA-wgcp-398q-m296).
# A list of functions that must not be called cannot cover every engine:
# each has table functions that read files, URLs or other servers (DuckDB
# read_csv, ClickHouse file and url, Databricks read_files, BigQuery
# EXTERNAL_QUERY), some read a file named as a table (DuckDB FROM '/path' and
# data.csv, Spark csv.`/path`), some run a program (Hive TRANSFORM ... USING)
# and some functions reach the environment, a model or a secret, or run SQL
# held in a string (DuckDB getenv, Hive reflect, BigQuery AI.GENERATE,
# Databricks secret, PostgreSQL query_to_xml). So a query is admitted only
# when what it reads and calls is known to stay inside the database:
# tables, subqueries, VALUES, UNNEST and the row generators below; functions
# sqlglot parses into a kind listed in sql_function_catalogue; and functions
# sqlglot does not know only when they are listed here as computing from
# their arguments. A call through a schema, package, object or type
# (dbo.format, name.ToString(), MyType::fn(x)), a name applied with
# ClickHouse APPLY, and in Oracle a qualified name that names no table in the
# query (UTL_INADDR.GET_HOST_NAME, a call without brackets) can be any
# function, so none is known. A sequence (seq.NEXTVAL), a server setting
# (@@datadir), DuckDB SUMMARIZE or DESCRIBE of a file, and a Spark or Hive
# ${...}, which the engine replaces with a variable, a setting or the
# environment before it parses the query, reach outside too.

# Table functions that only generate rows from their arguments.
VALUE_TABLE_FUNCTIONS = frozenset({
    "generate_series", "generateseries", "explodinggenerateseries", "range", "numbers", "zeros",
    "generator", "generate_subscripts", "regexp_split_to_table", "string_to_table", "string_split",
    "json_array_elements", "jsonb_array_elements", "json_array_elements_text", "jsonb_array_elements_text",
    "json_each", "jsonb_each", "json_each_text", "jsonb_each_text", "json_to_recordset", "jsonb_to_recordset",
    "json_populate_recordset", "jsonb_populate_recordset", "openjson", "splittotable", "strtoksplittotable",
    "flatten", "explode", "explodeouter", "posexplode", "posexplodeouter", "inline", "stack",
    "generatedatearray", "generatetimestamparray", "jsontable", "xmltable", "unnest",
})
# Functions sqlglot does not know that compute only from their arguments.
# Left out on purpose: anything that reads or changes state outside the row
# (nextval, setval, last_insert_rowid, changes), reports on the server or
# session (version, current_setting, currentDatabase), sleeps or loops
# (sleep, benchmark), runs SQL held in a string (query_to_xml, crosstab), or
# reaches files, the network or the environment.
KNOWN_VALUE_FUNCTIONS = frozenset({
    # PostgreSQL
    "json_build_object", "jsonb_build_object", "json_build_array", "jsonb_build_array", "json_object",
    "jsonb_object", "row_to_json", "to_json", "to_jsonb", "json_agg", "jsonb_agg", "json_object_agg",
    "jsonb_object_agg", "json_array_length", "jsonb_array_length", "jsonb_set", "jsonb_insert", "jsonb_typeof",
    "json_typeof", "jsonb_strip_nulls", "json_strip_nulls", "jsonb_pretty", "jsonb_extract_path",
    "jsonb_extract_path_text", "json_extract_path", "json_extract_path_text", "array_to_json",
    "jsonb_path_query", "jsonb_path_query_first", "jsonb_path_query_array", "jsonb_path_exists",
    "jsonb_path_match", "json_populate_record", "jsonb_populate_record",
    "age", "date_bin", "date_part", "make_date", "make_time", "make_timestamp", "make_timestamptz",
    "make_interval", "justify_days", "justify_hours", "justify_interval", "clock_timestamp",
    "statement_timestamp", "transaction_timestamp", "isfinite", "array_to_string", "string_to_array",
    "array_position", "array_positions", "array_remove", "array_replace", "array_append", "array_prepend",
    "array_cat", "cardinality", "array_dims", "array_upper", "array_lower", "array_ndims",
    "regexp_split_to_array", "regexp_match", "regexp_matches", "btrim", "translate", "quote_ident",
    "quote_literal", "quote_nullable", "format", "starts_with", "chr", "ascii", "overlay", "to_hex",
    "encode", "decode", "sha224", "sha256", "sha384", "sha512", "width_bucket", "div", "gcd", "lcm",
    "factorial", "sign", "trunc", "cbrt", "degrees", "radians", "pi", "num_nonnulls", "num_nulls",
    "octet_length", "to_tsvector", "to_tsquery", "plainto_tsquery", "phraseto_tsquery",
    "websearch_to_tsquery", "ts_rank", "ts_rank_cd", "ts_headline", "every", "pg_typeof",
    # MySQL and MariaDB
    "now", "sysdate", "curtime", "utc_timestamp", "utc_date", "utc_time", "unix_timestamp", "field",
    "find_in_set", "truncate", "elt", "conv", "bin", "oct", "soundex", "space", "timestampadd",
    "period_add", "period_diff", "makedate", "maketime", "sec_to_time", "time_to_sec", "to_days",
    "from_days", "weekday", "dayname", "monthname", "quarter", "yearweek", "json_unquote", "json_contains",
    "json_length", "json_keys", "json_array", "json_valid", "json_search", "json_set", "json_insert",
    "json_replace", "json_remove", "json_merge_preserve", "json_merge_patch", "any_value", "bit_count",
    "inet_aton", "inet_ntoa", "uuid", "st_x", "st_y",
    # SQLite
    "date", "time", "datetime", "julianday", "strftime", "printf", "total", "quote", "unixepoch",
    "timediff", "likely", "unlikely", "likelihood", "zeroblob", "char", "unicode", "json_group_array",
    "json_group_object",
    # DuckDB
    "histogram", "list_aggregate", "list_sort", "list_reverse_sort", "list_distinct", "list_transform",
    "list_filter", "list_reduce", "list_slice", "list_extract", "list_contains", "list_position",
    "string_split", "len", "epoch_ms", "approx_quantile", "bar",
    # Oracle
    "nvl2", "to_date", "to_number", "add_months", "months_between", "lengthb", "substrb", "listagg",
    "regexp_substr", "regexp_instr", "regexp_count", "regexp_replace",
    # SQL Server
    "getdate", "getutcdate", "sysdatetime", "datename", "datepart", "eomonth", "charindex", "patindex",
    "newid", "datefromparts", "choose", "quotename", "isjson",
    # Snowflake
    "hash", "ratio_to_report", "to_timestamp_ntz", "to_timestamp_ltz", "to_timestamp_tz", "try_to_number",
    "try_to_date", "try_to_timestamp", "uniform", "seq1", "seq2", "seq4", "seq8",
    # Hive and Spark
    "date_format", "from_unixtime", "size", "collect_list", "collect_set", "get_json_object", "from_json",
    "named_struct", "sort_array", "element_at", "array_contains", "posexplode", "explode", "pmod",
    # ClickHouse
    "tostring", "tofixedstring", "todate", "todatetime", "todatetime64", "tostartofmonth", "tostartofday",
    "tostartofweek", "tostartofhour", "tostartofyear", "tostartofquarter", "tostartofminute",
    "tostartoffiveminutes", "tostartofinterval", "toyear", "toquarter", "tomonth", "toweek", "toisoweek",
    "toyearweek", "todayofmonth", "todayofweek", "todayofyear", "tohour", "tominute", "tosecond",
    "toyyyymm", "toyyyymmdd", "tounixtimestamp", "formatdatetime", "parsedatetimebesteffort",
    "parsedatetimebesteffortornull", "now64", "today", "yesterday", "adddays", "addhours", "addminutes",
    "addseconds", "addweeks", "addmonths", "addyears", "subtractdays", "subtracthours", "subtractminutes",
    "subtractseconds", "subtractweeks", "subtractmonths", "subtractyears", "uniq", "uniqexact",
    "uniqcombined", "quantileexact", "topk", "grouparray", "groupuniqarray", "anylast", "anyheavy",
    "multiif", "tofloat32", "tofloat64", "toint8", "toint16", "toint32", "toint64", "touint8", "touint16",
    "touint32", "touint64", "todecimal32", "todecimal64", "todecimal128", "totypename", "intdiv",
    "intdivorzero", "modulo", "hasany", "hasall", "has", "empty", "notempty", "replaceall", "replaceone",
    "replaceregexpall", "replaceregexpone", "splitbychar", "splitbystring", "arraystringconcat",
    "arrayjoin", "arrayelement", "arraymap", "arrayuniq", "arraysort", "arrayreversesort", "lengthutf8", "lowerutf8",
    "upperutf8", "positioncaseinsensitive", "siphash64", "xxhash64", "murmurhash3_64",
    "runningdifference", "jsonextractstring", "jsonextractint", "jsonextractfloat", "jsonextractbool",
    "jsonextractraw", "jsonhas", "formatreadablesize", "formatreadablequantity", "generateuuidv4",
    "countif", "sumif", "avgif",
})
# Characters a table's name does not hold and a path, URL or stage does.
_PATH_CHARACTERS = frozenset("/\\:@~.{}?")
# A table qualified by one of these is a file read through a data source or
# storage plugin (Spark text.`/path`, Drill dfs.tmp.file).
FILE_SOURCE_PREFIXES = frozenset({
    "text", "csv", "tsv", "json", "parquet", "orc", "avro", "binaryfile", "delta", "iceberg", "hudi",
    "jdbc", "xml", "image", "libsvm", "dfs", "cp", "s3", "hdfs", "file",
})
# A qualified name ending in one of these is read as a file by DuckDB
# (FROM data.csv) or one of its extensions (spatial, Excel, Arrow) when no
# such table exists.
FILE_EXTENSIONS = frozenset({
    "csv", "tsv", "psv", "tab", "tbl", "txt", "dat", "log", "json", "jsonl", "ndjson", "geojson", "parquet",
    "parq", "pq", "orc", "avro", "arrow", "ipc", "feather", "lance", "xlsx", "xls", "ods", "xml", "html",
    "yaml", "yml", "shp", "dbf", "gpkg", "kml", "gml", "fgb", "osm", "pbf", "tif", "tiff", "gz", "zst",
    "bz2", "xz", "lz4", "zip", "tar", "db", "sqlite", "sqlite3", "duckdb", "mdb", "accdb", "sav", "dta",
    "sas7bdat", "gpx", "dxf", "dgn", "kmz", "mif", "e00", "gdb", "vrt", "topojson", "geojsonl", "geojsons",
    "mvt", "pmtiles", "mbtiles",
})
_TABLE_FROM_ROWS = tuple(_available_expression_types("TableFromRows"))
_QUERY_TRANSFORMS = tuple(_available_expression_types("QueryTransform"))
# DuckDB SUMMARIZE and DESCRIBE read what they are given: a file when it is
# a string.
_SUMMARIES = tuple(_available_expression_types("Summarize", "Describe"))
_APPLIES = tuple(_available_expression_types("Apply"))
_SCOPE_RESOLUTIONS = tuple(_available_expression_types("ScopeResolution"))
_SESSION_PARAMETERS = tuple(_available_expression_types("SessionParameter"))
_SEQUENCE_STEPS = frozenset({"nextval", "currval"})
_PLAIN_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
# Reasons are reported by name and capped, so a refusal stays small.
MAX_REASONS = 20


def _label(node: exp.Expression) -> str:
    """A short name for *node* in a reason."""
    if isinstance(node, exp.Anonymous):
        return str(node.name)[:60]
    if isinstance(node, exp.Func):
        return node.key[:60]
    return node.sql()[:60]


def _value_table_function(source: Optional[exp.Expression]) -> bool:
    """Whether *source*, a function used as a table, only generates rows."""
    if isinstance(source, exp.Anonymous):
        return str(source.name).lower() in VALUE_TABLE_FUNCTIONS
    return isinstance(source, exp.Func) and source.key in VALUE_TABLE_FUNCTIONS


def _table_reads(table: exp.Table) -> Tuple[List[str], List[str]]:
    """(reads outside the database, reads not known to stay inside) of one
    table reference."""
    source = table.this
    qualifiers = [
        part.name.lower() for part in (table.args.get("db"), table.args.get("catalog"))
        if isinstance(part, exp.Identifier)
    ]
    if source is None:
        # ROWS FROM (...): each item is a table of its own, read on its own.
        return [], ([] if table.args.get("rows_from") else ["a table with no name"])
    if not isinstance(source, exp.Identifier):
        if qualifiers or not _value_table_function(source):
            return [], [f"'{_label(source)}' used as a table"]
        return [], []
    name = source.name
    reads: List[str] = []
    unknown: List[str] = []
    alias = table.args.get("alias")
    # DuckDB reads (SHOW 'file') as SHOW of that file; sqlglot reads it as a
    # table SHOW with the file as its alias.
    alias_names = [] if alias is None else [alias.name, *(part.name for part in alias.args.get("columns") or [])]
    if any(_PATH_CHARACTERS & set(part) for part in [name, *qualifiers]):
        reads.append(f"'{name[:60]}' names a file, URL or stage, not a table")
    elif any(_PATH_CHARACTERS & set(part) for part in alias_names):
        reads.append(f"'{name[:60]}' is followed by a file, URL or stage")
    elif set(qualifiers) & FILE_SOURCE_PREFIXES:
        reads.append(f"'{name[:60]}' is read from files through '{qualifiers[0]}'")
    elif qualifiers and name.lower() in FILE_EXTENSIONS:
        reads.append(f"'{qualifiers[0][:60]}.{name[:60]}' names a file")
    if alias is not None and alias.args.get("columns") and not alias.name:
        unknown.append(f"'{name[:60]}(...)' is written as a call but read as a table")
    return reads, unknown


def _function_unknown(node: exp.Func) -> bool:
    """Whether *node* is a call not known to compute only from its
    arguments: a call through a schema, package, object or type, a name
    sqlglot does not know and that is not listed, or a kind not in the
    catalogue."""
    if isinstance(node.parent, exp.Dot) and node.arg_key == "expression":
        return True
    if _SCOPE_RESOLUTIONS and isinstance(node.parent, _SCOPE_RESOLUTIONS) and node.arg_key == "expression":
        return True
    if isinstance(node, exp.Anonymous):
        return str(node.name).lower() not in KNOWN_VALUE_FUNCTIONS | VALUE_TABLE_FUNCTIONS
    return node.key not in TYPED_FUNCTIONS


def _in_family(dialect: Optional[str], family: str) -> bool:
    """Whether *dialect* is or extends Oracle (*family* "oracle") or Hive
    ("hive", which Spark and Databricks extend). A dialect that does not
    resolve counts, so the family's check still runs."""
    try:
        resolved = sqlglot.Dialect.get_or_raise(dialect)
        if family == "oracle":
            from sqlglot.dialects.oracle import Oracle as Family
        else:
            from sqlglot.dialects.hive import Hive as Family
    except Exception:  # noqa: BLE001 - an unknown dialect gets the check
        return True
    return isinstance(resolved, Family)


@lru_cache(maxsize=1024)
def _applied_name_unknown(name: str, dialect: Optional[str]) -> bool:
    """Whether *name*, applied to columns with ClickHouse APPLY, is not known
    to compute only from its arguments: it is read as a call of that name.
    Cached, so many APPLYs of one name parse it once."""
    if not _PLAIN_NAME.fullmatch(name):
        return True
    if name.lower() in KNOWN_VALUE_FUNCTIONS:
        return False
    try:
        call = sqlglot.parse_one(f"SELECT {name}(x)", read=dialect).find(exp.Func)
    except Exception:  # noqa: BLE001 - not a call sqlglot reads
        return True
    return call is None or call.key in REACHING_TYPED_FUNCTIONS or _function_unknown(call)


_DERIVED_ARGS = frozenset({"from", "from_", "joins"})


def _sources_of(select: exp.Select) -> List[exp.Expression]:
    """The sources in the FROM and JOINs of one query block."""
    from_ = select.args.get("from_") or select.args.get("from")
    sources = [] if from_ is None else [from_.this]
    return sources + [join.this for join in select.args.get("joins") or []]


def _visible_sources(node: exp.Expression) -> List[exp.Expression]:
    """The sources a qualifier at *node* can name: those of its own query
    block and of every block it is correlated with. A CTE body, and a
    subquery in FROM or a join that is not LATERAL, see no block around
    them."""
    visible: List[exp.Expression] = []
    inside_block = lateral = False
    child, parent = node, node.parent
    while parent is not None and not isinstance(parent, exp.CTE):
        if isinstance(parent, exp.Lateral):
            lateral = True
        if isinstance(parent, exp.Select):
            if inside_block and child.arg_key in _DERIVED_ARGS and not lateral:
                break
            visible += _sources_of(parent)
            inside_block, lateral = True, False
        child, parent = parent, parent.parent
    return visible


def _qualifier_unknown(column: exp.Column) -> bool:
    """Whether the qualifier of *column* names no source it can see. Oracle
    then reads it as a schema or package and calls a function of the
    column's name with no arguments (``utl_inaddr.get_host_name``). A
    schema in the qualifier must be that of a table written with it and no
    alias."""
    if column.args.get("catalog") is not None:
        return True
    table, schema = column.table.lower(), column.text("db").lower()
    for source in _visible_sources(column):
        if not schema and source.alias_or_name.lower() == table:
            return False
        if (
            schema and isinstance(source, exp.Table) and not source.alias
            and source.name.lower() == table and source.text("db").lower() == schema
        ):
            return False
    return True


def external_reads(parsed: exp.Expression, dialect: Optional[str] = None) -> Tuple[List[str], List[str]]:
    """(what the query reads outside the database, what it reads or calls
    that is not known to stay inside), each a short reason, each at most
    ``MAX_REASONS``. Both empty when the query reads only tables and calls
    only known functions."""
    reads: List[str] = []
    unknown: List[str] = []
    for table in parsed.find_all(exp.Table):
        table_reads, table_unknown = _table_reads(table)
        reads += table_reads
        unknown += table_unknown
    if _TABLE_FROM_ROWS:
        unknown += [
            f"'{_label(node.this)}' used as a table" for node in parsed.find_all(*_TABLE_FROM_ROWS)
            if not _value_table_function(node.this)
        ]
    if _QUERY_TRANSFORMS:
        reads += ["a script TRANSFORM runs a program" for _ in parsed.find_all(*_QUERY_TRANSFORMS)]
    if _SUMMARIES:
        reads += [
            f"{node.key.upper()} of something other than a table or query reads it from outside the database"
            for node in parsed.find_all(*_SUMMARIES)
            if not isinstance(node.this, (exp.Table, exp.Query, exp.Values))
        ]
    if _APPLIES:
        for node in parsed.find_all(*_APPLIES):
            applied = node.expression
            if isinstance(applied, exp.Var):
                if _applied_name_unknown(applied.name, dialect):
                    unknown.append(f"'{applied.name[:60]}' applied with APPLY")
            elif not isinstance(applied, (exp.Func, exp.Lambda)):
                unknown.append("an APPLY of something other than a function")
    if _SCOPE_RESOLUTIONS:
        unknown += [f"'{_label(node)}' (a call through a type)" for node in parsed.find_all(*_SCOPE_RESOLUTIONS)]
    if _SESSION_PARAMETERS:
        unknown += [f"'@@{node.name[:60]}' (a server setting)" for node in parsed.find_all(*_SESSION_PARAMETERS)]
    # @@name in T-SQL and BigQuery: a server or session value.
    unknown += [
        f"'@@{node.name[:60]}' (a server value)" for node in parsed.find_all(exp.Parameter)
        if isinstance(node.this, exp.Parameter)
    ]
    # A schema-qualified PostgreSQL operator, OPERATOR(public.+), runs that
    # schema's function (pg_catalog, written exactly so, is the built-in
    # one); a cast to a type that is not built in may run the function its
    # CREATE CAST names (or, in SQL Server, the type's own code). A cast of
    # NULL (json_populate_record(NULL::users, ...)) runs none.
    unknown += [
        f"'{_label(node)}' (an operator named by schema)" for node in parsed.find_all(exp.Operator)
        if str(node.args.get("operator") or "").rpartition(".")[0] not in ("", "pg_catalog")
    ]
    unknown += [
        f"'{_label(node)}' (a cast to a type that is not built in)" for node in parsed.find_all(exp.DataType)
        if node.this == exp.DataType.Type.USERDEFINED
        and not (isinstance(node.parent, exp.Cast) and isinstance(node.parent.this, exp.Null))
    ]
    oracle = dialect is not None and _in_family(dialect, "oracle")
    for column in parsed.find_all(exp.Column):
        if column.name.lower() in _SEQUENCE_STEPS:
            reads.append(f"'{_label(column)}' advances or reads a sequence")
        elif oracle and column.table and _qualifier_unknown(column):
            # Oracle calls a function with no arguments without brackets.
            unknown.append(f"'{_label(column)}' (a call through a package or schema)")
    for node in parsed.find_all(exp.Func):
        if node.key in REACHING_TYPED_FUNCTIONS:
            reads.append(f"'{node.key}' reaches outside the database")
        elif _function_unknown(node):
            unknown.append(f"'{_label(node)}'")
    return list(dict.fromkeys(reads))[:MAX_REASONS], list(dict.fromkeys(unknown))[:MAX_REASONS]


def quoted_calls(sql: str, dialect: str, parsed: Optional[exp.Expression] = None) -> List[str]:
    """Quoted names written as a call (``"FORMAT"(x)``, ``[fn](x)``): a quoted
    name is case-sensitive, so it can name a function other than the one
    sqlglot reads it as. A quoted name that *parsed* (the tree of *sql*)
    reads as the alias of a table, subquery or CTE with its columns is not
    a call. Coming after AS is not enough: ``DEFINE a AS "upper"(name)`` in
    MATCH_RECOGNIZE is a call."""
    try:
        tokens = sqlglot.Dialect.get_or_raise(dialect).tokenize(sql)
    except Exception:  # noqa: BLE001 - the parse check reports it
        return []
    aliases = set()
    if parsed is not None:
        aliases = {
            alias.this.meta.get("start")
            for alias in parsed.find_all(exp.TableAlias)
            if isinstance(alias.this, exp.Identifier) and alias.args.get("columns")
        }
        aliases.discard(None)
    found: List[str] = []
    for token, after in zip(tokens, [*tokens[1:], None]):
        if (
            token.token_type == TokenType.IDENTIFIER
            and after is not None and after.token_type == TokenType.L_PAREN
            and token.start not in aliases
        ):
            found.append(f"'{token.text[:60]}' (a quoted name written as a call)")
    return list(dict.fromkeys(found))[:MAX_REASONS]


def substituted_variables(sql: str, dialect: str) -> List[str]:
    """A ``${...}`` in Spark, Databricks or Hive: the engine replaces it,
    before it parses the query, with a variable, a setting or the
    environment (``${env:HOME}``), so what runs is not what was read."""
    if "${" in sql and _in_family(dialect, "hive"):
        return ["'${...}' is replaced by the engine with a variable, a setting or the environment"]
    return []

class _NotConstant(Exception):
    """A node could not be folded to a column-free constant value."""


def _const_eval(node: exp.Expression):
    """Fold a column-free boolean/numeric/string expression to a Python value.

    Raises :class:`_NotConstant` for anything that references a column or that is
    not a fold-able literal/operator. Used to detect always-true predicates by
    VALUE rather than by matching a fixed list of AST shapes (GHSA-6cpx): ``OR 1``,
    ``OR NOT FALSE``, ``1 = 1.0`` and ``2 > 1`` all fold to a truthy constant.

    Newer sqlglot releases parse ``x IS NOT NULL`` and ``x NOT LIKE y`` as the
    positive node with ``negate`` set, where older ones wrap it in ``Not``.
    The flag is applied here for every node, so the two parses fold alike.
    """
    value = _fold_node(node)
    if node.args.get("negate"):
        return None if value is None else not value
    return value


_NOT_A_LEAF = object()


def _fold_leaf(node: exp.Expression):
    """The value of a Boolean, NULL or literal node, else _NOT_A_LEAF."""
    if isinstance(node, exp.Boolean):
        return bool(node.this)
    if isinstance(node, exp.Null):
        return None
    if not isinstance(node, exp.Literal):
        return _NOT_A_LEAF
    if node.is_string:
        return node.this
    try:
        return int(node.this)
    except (TypeError, ValueError):
        # SQL numeric literals are exact (NUMERIC, DECIMAL), so 0.1 + 0.2 =
        # 0.3 holds there; a float said it did not.
        return Decimal(node.this)


def _fold_node(node: exp.Expression):
    """``_const_eval`` before a node's own ``negate`` flag is applied."""
    if isinstance(node, exp.Paren):
        return _const_eval(node.this)
    leaf = _fold_leaf(node)
    if leaf is not _NOT_A_LEAF:
        return leaf
    if isinstance(node, exp.Neg):
        return -_const_eval(node.this)
    if isinstance(node, exp.Not):
        return not _const_eval(node.this)
    if isinstance(node, exp.And):
        return _fold_and(node)
    if isinstance(node, exp.Or):
        return _fold_or(node)
    self_comparison = _self_comparison(node)
    if self_comparison is not None:
        return self_comparison
    for cls, op in _BINARY_FOLDS.items():
        if isinstance(node, cls):
            return op(_const_eval(node.left), _const_eval(node.right))
    for cls, fold in _NODE_FOLDS.items():
        if isinstance(node, cls):
            return fold(node)
    raise _NotConstant()


_UNKNOWN = object()


def _fold_or_unknown(node: exp.Expression):
    """``_const_eval(node)``, or _UNKNOWN when it reads data."""
    try:
        return _const_eval(node)
    except _NotConstant:
        return _UNKNOWN


def _fold_and(node: exp.And) -> bool:
    """A constant-false operand makes AND false whatever the other side reads,
    so NOT (col = 5 AND 1 = 0) is seen as always true (GHSA-jvhg)."""
    operands = (_fold_or_unknown(node.left), _fold_or_unknown(node.right))
    if any(value is not _UNKNOWN and not value for value in operands):
        return False
    if _UNKNOWN in operands:
        raise _NotConstant()
    return True


def _fold_or(node: exp.Or) -> bool:
    """A constant-true operand makes OR true whatever the other side reads."""
    operands = (_fold_or_unknown(node.left), _fold_or_unknown(node.right))
    if any(value is not _UNKNOWN and value for value in operands):
        return True
    if _UNKNOWN in operands:
        raise _NotConstant()
    return False


# A column compared with itself is true (=, >=, <=, IS NOT DISTINCT FROM) or
# false (<>, >, <) on every row where it is not NULL: col = col is the classic
# always-true filter, though it reads data.
_SELF_TRUE = tuple(_available_expression_types("EQ", "GTE", "LTE", "NullSafeEQ"))
_SELF_FALSE = tuple(_available_expression_types("NEQ", "GT", "LT", "NullSafeNEQ"))


def _self_comparison(node: exp.Expression) -> Optional[bool]:
    if not isinstance(node, _SELF_TRUE + _SELF_FALSE):
        return None
    if not (isinstance(node.left, exp.Column) and node.left == node.right):
        return None
    return isinstance(node, _SELF_TRUE)


def _comparable(a, b) -> None:
    """Refuse a comparison whose result depends on the engine, as not worked
    out: a string against a number (MySQL and PostgreSQL convert, so
    1 = '1' and 'a' = 0 can hold), and two different strings (a case-,
    accent- or pad-insensitive collation can make 'a' = 'A' or 'a ' = 'a'
    hold). Identical strings compare equal under every collation."""
    if a is None or b is None:
        return
    a_text, b_text = isinstance(a, str), isinstance(b, str)
    if a_text != b_text or (a_text and a != b):
        raise _NotConstant()


def _compare(op):
    def fold(a, b):
        _comparable(a, b)
        return op(a, b)
    return fold


def _null_safe_eq(a, b) -> bool:
    if a is None or b is None:
        return a is b
    _comparable(a, b)
    return a == b


def _divide(a, b):
    """SQL division. Integer division truncates in some engines and not in
    others, so an inexact one is not worked out; nor is an inexact decimal
    division, whose digits differ by engine."""
    if isinstance(a, int) and isinstance(b, int):
        if b == 0:
            raise ZeroDivisionError()
        if a % b:
            raise _NotConstant()
        return a // b
    if isinstance(a, Decimal) or isinstance(b, Decimal):
        with localcontext() as context:
            context.prec = 100
            quotient = Decimal(a) / Decimal(b)
            if quotient * Decimal(b) != Decimal(a):
                raise _NotConstant()
            return quotient
    return a / b


def _modulo(a, b):
    """SQL MOD: the remainder takes the sign of the dividend."""
    if isinstance(a, int) and isinstance(b, int):
        remainder = abs(a) % abs(b)
        return -remainder if a < 0 else remainder
    if isinstance(a, Decimal) or isinstance(b, Decimal):
        return Decimal(a) % Decimal(b)
    return math.fmod(a, b)


def _concat(a, b):
    return None if a is None or b is None else f"{a}{b}"


_BINARY_FOLDS = {
    cls: op
    for name, op in (
        ("EQ", _compare(lambda a, b: a == b)),
        ("NEQ", _compare(lambda a, b: a != b)),
        ("GT", _compare(lambda a, b: a > b)),
        ("GTE", _compare(lambda a, b: a >= b)),
        ("LT", _compare(lambda a, b: a < b)),
        ("LTE", _compare(lambda a, b: a <= b)),
        ("NullSafeEQ", _null_safe_eq),
        ("NullSafeNEQ", lambda a, b: not _null_safe_eq(a, b)),
        ("Add", lambda a, b: a + b),
        ("Sub", lambda a, b: a - b),
        ("Mul", lambda a, b: a * b),
        ("Div", _divide),
        ("Mod", _modulo),
        ("DPipe", _concat),
    )
    for cls in _available_expression_types(name)
}


def _fold_in(node: exp.Expression):
    """``x IN (literals)``; a subquery or UNNEST reads data."""
    if any(node.args.get(key) for key in ("query", "unnest", "field")):
        raise _NotConstant()
    value = _const_eval(node.this)
    options = [_const_eval(option) for option in node.expressions]
    if value is None:
        return None
    for option in options:
        _comparable(value, option)
    if value in options:
        return True
    return None if None in options else False


def _fold_is(node: exp.Expression):
    value = _const_eval(node.this)
    target = node.expression
    if isinstance(target, exp.Null):
        return value is None
    if isinstance(target, exp.Boolean):
        return value is not None and bool(value) == bool(target.this)
    raise _NotConstant()


# LIKE patterns are matched by the greedy wildcard walk below, which does at
# most len(text) * len(pattern) steps; longer pairs are not worked out.
_LIKE_MAX_STEPS = 1_000_000


def _like_match(text: str, pattern: str) -> bool:
    """SQL LIKE without an escape character: % is any run, _ any one character."""
    t = p = 0
    star, mark = -1, 0
    while t < len(text):
        if p < len(pattern) and pattern[p] == "%":
            star, mark = p, t
            p += 1
        elif p < len(pattern) and pattern[p] in ("_", text[t]):
            t += 1
            p += 1
        elif star != -1:
            p, mark = star + 1, mark + 1
            t = mark
        else:
            return False
    return all(ch == "%" for ch in pattern[p:])


def _fold_like(node: exp.Expression):
    text, pattern = _const_eval(node.this), _const_eval(node.expression)
    if text is None or pattern is None:
        return None
    text, pattern = str(text), str(pattern)
    # A backslash is an escape character by default in some engines.
    if "\\" in pattern or len(text) * max(len(pattern), 1) > _LIKE_MAX_STEPS:
        raise _NotConstant()
    if isinstance(node, exp.ILike):
        return _like_match(text.lower(), pattern.lower())
    # LIKE ignores case in MySQL and (for ASCII) SQLite, and some collations
    # ignore accents: worked out only where none of that can change it.
    if not (text.isascii() and pattern.isascii()):
        raise _NotConstant()
    matched = _like_match(text, pattern)
    if matched != _like_match(text.lower(), pattern.lower()):
        raise _NotConstant()
    return matched


def _fold_between(node: exp.Expression):
    value = _const_eval(node.this)
    low, high = _const_eval(node.args["low"]), _const_eval(node.args["high"])
    if None in (value, low, high):
        return None
    for bound in (low, high):
        _comparable(value, bound)
    if node.args.get("symmetric"):
        low, high = min(low, high), max(low, high)
    return low <= value <= high


def _fold_coalesce(node: exp.Expression):
    for operand in [node.this, *node.expressions]:
        value = _const_eval(operand)
        if value is not None:
            return value
    return None


def _fold_cast(node: exp.Expression):
    value = _const_eval(node.this)
    target = node.to
    if value is None:
        return None
    # Only conversions every engine makes the same way: a whole number to an
    # integer (1.5 rounds in some engines and truncates in others), an
    # integer or a string to text (a Boolean prints as true or 1), and a
    # Boolean or integer to a Boolean (the string 'false' is true to Python).
    # Floating-point targets differ in width (REAL is 4 bytes in PostgreSQL).
    if target.is_type(*exp.DataType.INTEGER_TYPES) and not isinstance(value, (bool, str)) and value == int(value):
        return int(value)
    if target.is_type(*exp.DataType.TEXT_TYPES) and isinstance(value, (int, str)) and not isinstance(value, bool):
        return str(value)
    if target.is_type(exp.DataType.Type.BOOLEAN) and isinstance(value, int):
        return bool(value)
    raise _NotConstant()


def _fold_abs(node: exp.Expression):
    value = _const_eval(node.this)
    return None if value is None else abs(value)


def _fold_exists(node: exp.Expression):
    """EXISTS over a SELECT with no FROM: true unless its WHERE is false. Any
    other clause (FROM, LIMIT, GROUP BY, ...) is not worked out."""
    select = node.this
    if not isinstance(select, exp.Select):
        raise _NotConstant()
    if any(value for key, value in select.args.items() if key not in ("expressions", "where")):
        raise _NotConstant()
    where = select.args.get("where")
    return True if where is None else bool(_const_eval(where.this))


_NODE_FOLDS = {
    cls: fold
    for names, fold in (
        (("In",), _fold_in),
        (("Is",), _fold_is),
        (("Like", "ILike"), _fold_like),
        (("Between",), _fold_between),
        (("Coalesce",), _fold_coalesce),
        (("Cast", "TryCast"), _fold_cast),
        (("Abs",), _fold_abs),
        (("Exists",), _fold_exists),
    )
    for cls in _available_expression_types(*names)
}


def _is_always_true(node: Optional[exp.Expression]) -> bool:
    """True iff *node* is a column-free predicate that evaluates to a truthy
    constant (a tautology), False for anything referencing data or not fold-able."""
    if node is None:
        return False
    try:
        return bool(_const_eval(node))
    except (_NotConstant, TypeError, ValueError, ArithmeticError):
        return False


# What makes a predicate read data: a column, a table (a subquery's FROM), an
# aggregate or window over the rows, or a bound parameter.
_DATA_NODES = tuple(_available_expression_types("Column", "Table", "AggFunc", "Window", "Placeholder", "Parameter"))
_PREDICATE_NODES = tuple(_available_expression_types(
    "EQ", "NEQ", "GT", "GTE", "LT", "LTE", "NullSafeEQ", "NullSafeNEQ",
    "In", "Is", "Like", "ILike", "Between", "Exists",
))


def _filter_predicates(parsed: exp.Expression):
    """Each WHERE, HAVING and JOIN ... ON condition, every operand of its
    AND, OR and NOT, and every comparison or test inside it."""
    roots = [clause.this for clause in parsed.find_all(exp.Where, exp.Having)]
    roots += [join.args["on"] for join in parsed.find_all(exp.Join) if join.args.get("on") is not None]
    for root in roots:
        yield root
        for node in root.find_all(exp.And, exp.Or, exp.Not, *_PREDICATE_NODES):
            if isinstance(node, (exp.And, exp.Or)):
                yield node.left
                yield node.right
            elif isinstance(node, exp.Not):
                yield node.this
            else:
                yield node


def _unevaluated_data_free_predicates(parsed: exp.Expression):
    """Filter predicates that read no data and cannot be folded: 1 + 'a', an
    unknown function of constants, a LIKE with an escape. A fold that raises
    (division by zero, a type error) is not worked out either."""
    for predicate in _filter_predicates(parsed):
        if isinstance(predicate, _DATA_NODES) or predicate.find(*_DATA_NODES):
            continue
        try:
            _const_eval(predicate)
        except (_NotConstant, TypeError, ValueError, ArithmeticError):
            yield predicate


def _enclosing_select(node: exp.Expression) -> Optional[exp.Expression]:
    """The nearest ancestor Select of *node*, or None."""
    parent = node.parent
    while parent is not None and not isinstance(parent, exp.Select):
        parent = parent.parent
    return parent


def _passes_columns_through(query: Optional[exp.Expression]) -> bool:
    """Whether the subquery or bracketed join *query* gives its alias every
    column of the tables in it: anything but a SELECT, or a set operation
    of SELECTs, whose select list names its columns."""
    query = _unparen(query)
    if isinstance(query, exp.Subquery):
        return _passes_columns_through(query.this)
    if isinstance(query, exp.Select):
        return any(
            isinstance(item, exp.Star) or (isinstance(item, exp.Column) and isinstance(item.this, exp.Star))
            for item in query.expressions
        )
    if isinstance(query, (exp.Union, exp.Except, exp.Intersect)):
        return _passes_columns_through(query.this) or _passes_columns_through(query.expression)
    return True


def _aliases_to_tables(parsed: exp.Expression) -> Dict[str, Set[str]]:
    """Each table name and alias in *parsed* with the tables of the database
    it stands for (GHSA-xpfc). An alias used for several tables (one in a
    subquery) stands for each, and the alias of a bracketed join, or of a
    subquery that selects a star, for every table in it."""
    mapping: Dict[str, Set[str]] = {}
    for tbl in parsed.find_all(exp.Table):
        real = tbl.name.lower()
        mapping.setdefault(real, set()).add(real)
        if tbl.alias:
            mapping.setdefault(tbl.alias.lower(), set()).add(real)
    for subquery in parsed.find_all(exp.Subquery):
        if subquery.alias and _passes_columns_through(subquery.this):
            mapping.setdefault(subquery.alias.lower(), set()).update(
                tbl.name.lower() for tbl in subquery.find_all(exp.Table)
            )
    return mapping


@dataclass
class SQLIssue:
    """A detected SQL security issue."""
    severity: str  # "CRITICAL", "WARNING", "INFO"
    issue_type: str
    description: str
    recommendation: Optional[str] = None


@dataclass 
class ComplexityMetrics:
    """Query complexity metrics."""
    table_count: int = 0
    join_count: int = 0
    subquery_depth: int = 0
    column_count: int = 0
    condition_count: int = 0
    aggregate_count: int = 0
    estimated_cost: float = 0.0


class SecurityViolation(Exception):
    """Raised when a security policy is violated."""
    pass




class SQLVerifier:
    """
    Enterprise SQL Verifier (Security Firewall).
    
    Features:
    1. Command type blocking (DROP, DELETE, etc.)
    2. Sensitive column access control
    3. Injection pattern detection
    4. Query complexity limits
    5. Schema validation
    6. Cost estimation

    Attributes:
        blocked_columns (Set[str]): Set of column names that are forbidden to access.
        limits (Dict[str, int]): Configuration for complexity limits.
        allow_destructive (bool): Whether to allow destructive commands.
    """
    
    # Destructive commands (Blocked by default). ``Into`` is SELECT ... INTO,
    # which creates a table and writes the selected rows into it: sqlglot
    # parses it as a Select, so it is found only by its Into node
    # (GHSA-6m2h-98rq-4f53).
    DESTRUCTIVE_COMMANDS = _available_expression_types(
        "Drop",
        "Delete",
        "Update",
        "Insert",
        "Alter",
        "Truncate",
        "TruncateTable",
        "Create",
        "Merge",
        "Into",
    )

    # Administrative / permission / side-effecting statement families. Blocked
    # anywhere in the parse tree (not just at the root). Beyond GRANT/SET/etc.
    # this covers COPY ... FROM PROGRAM / COPY ... FROM|TO <file>, ATTACH/DETACH,
    # PRAGMA, LOAD DATA and friends, plus the generic ``Command`` node sqlglot
    # emits for statements it does not model (GHSA-6p94).
    ADMIN_COMMANDS = _available_expression_types(
        "Grant",
        "Revoke",
        "Set",
        "Transaction",
        "Command",
        "Use",
        "Copy",
        "Attach",
        "Detach",
        "Pragma",
        "Load",
        "LoadData",
        "Analyze",
        "Cache",
        "Uncache",
        "Vacuum",
        "Export",
        "Import",
        "Call",
        "Execute",
    )

    # Read-only statement types permitted as the top-level query. Anything else
    # is blocked (fail closed) when destructive ops are not allowed: a statement
    # type not recognized as a read-only query is treated as unsafe rather than
    # waved through. sqlglot parses ``WITH ... SELECT`` with a ``Select`` root,
    # so the With/CTE wrapper is a descendant and need not be a root type here.
    READ_ONLY_ROOT_TYPES = _available_expression_types(
        "Select",
        "Union",
        "Intersect",
        "Except",
        "Subquery",
        "With",
        "Paren",
    )

    # Sensitive columns (Forbidden in SELECT/WHERE by default)
    DEFAULT_SENSITIVE_COLUMNS = {
        "password", "password_hash", "passwd", "pwd",
        "secret", "secret_key", "api_key", "token",
        "ssn", "social_security", "salary", "credit_card",
        "bank_account", "balance", "private_key"
    }
    
    # Default complexity limits
    DEFAULT_LIMITS = {
        "max_tables": 10,
        "max_joins": 5,
        "max_subquery_depth": 3,
        "max_columns": 50,
        "max_conditions": 20,
        "max_estimated_cost": 1000.0
    }

    def __init__(
        self, 
        blocked_columns: Optional[Set[str]] = None,
        complexity_limits: Optional[Dict[str, int]] = None,
        allow_destructive: bool = False
    ):
        """
        Initialize SQL Verifier.
        
        Args:
            blocked_columns: Additional columns to block.
            complexity_limits: Override default complexity limits.
            allow_destructive: If True, allow UPDATE/INSERT (for admin contexts).

        Example:
            >>> verifier = SQLVerifier(blocked_columns={"ssn", "password"})
        """
        self.blocked_columns = self.DEFAULT_SENSITIVE_COLUMNS.union(blocked_columns or set())
        self.limits = {**self.DEFAULT_LIMITS, **(complexity_limits or {})}
        self.allow_destructive = allow_destructive

    @staticmethod
    def _constraint_id(issue_types: Set[str], malicious: bool, is_valid: bool) -> str:
        """The result's constraint, in order of precedence. A DDL schema parse
        failure means the analysis is incomplete: an authoritative proof must
        never be generated from an incomplete analysis (fail-closed), so it
        takes precedence over malice detection (Sentry HIGH)."""
        if "schema_parse_error" in issue_types:
            return CONSTRAINT_SCHEMA_PARSE_ERROR
        if malicious:
            return CONSTRAINT_MALICIOUS
        if "schema_table_missing" in issue_types:
            return CONSTRAINT_SCHEMA_VIOLATION
        if UNKNOWN_FUNCTION in issue_types:
            return CONSTRAINT_UNKNOWN_FUNCTION
        if UNEVALUATED_PREDICATE in issue_types:
            return CONSTRAINT_UNEVALUATED_PREDICATE
        if UNRESTRICTED_OR in issue_types:
            return CONSTRAINT_UNRESTRICTED_OR
        return CONSTRAINT_SQL_VALID if is_valid else CONSTRAINT_COMPLEXITY_LIMIT_EXCEEDED

    def verify_sql(
        self, 
        query: str, 
        schema_ddl: Optional[str] = None, 
        dialect: str = "postgres",
        check_complexity: bool = True
    ) -> DiagnosticResult:
        """
        Verify a SQL query for safety.

        Returns a structured :class:`DiagnosticResult`:

        - SAFE query      → VERIFIED (``developer_fields.is_valid`` True, proof_ref from AST)
        - Malicious query → VERIFIED as-malicious (``is_valid`` False,
                          ``developer_fields.malicious_classification`` True). Proving a query
                          is malicious IS a successful proof, so it is not BLOCKED (issue #253).
                          Malicious is the only unsafe case that retains a proof_ref — unless
                          the DDL schema also fails to parse, in which case the incomplete
                          analysis is BLOCKED (schema_parse_error takes precedence).
        - Table outside the declared ``schema_ddl`` → BLOCKED (``sql_verifier.schema_violation``)
        - Complexity-limit violation → BLOCKED (``sql_verifier.complexity_limit_exceeded``)
        - DDL schema parse failure → BLOCKED (``sql_verifier.schema_parse_error``)
        - Parse error     → BLOCKED (``sql_verifier.parse_error``)
        - Internal error  → BLOCKED (``sql_verifier.execution_error``)

        ``sql_verifier.connection_failure`` is reserved for consumers whose engines open a
        database connection; this verifier performs static AST analysis only.

        ``agent_message`` is agent-safe: it never leaks detection rules, rule IDs, or raw
        SQLGlot output. Rule-level detail lives in ``developer_fields``.

        Args:
            query: The SQL query to verify.
            schema_ddl: Optional DDL for schema validation.
            dialect: SQL dialect (postgres, mysql, sqlite, etc.).
            check_complexity: Whether to check complexity limits.

        Example:
            >>> result = verifier.verify_sql("SELECT * FROM users WHERE id = 1")
            >>> print(result.developer_fields.get("is_valid"))
            True
        """
        # 1. Parse Query, with MySQL/MariaDB executable comments expanded.
        executable_comments = bool(_EXECUTABLE_COMMENT.search(query))
        analysed = expand_executable_comments(query) if executable_comments else query
        # Where sqlglot and the database may split the query into tokens
        # differently (MySQL reads "--1 OR 1=1" as code, sqlglot as a
        # comment; with ANSI_QUOTES it reads "name" as a column, sqlglot as a
        # string), no analysis of it describes what runs (GHSA-xpfc).
        if has_ambiguous_tokenization(query, dialect):
            return DiagnosticResult.blocked(
                agent_message=(
                    "SQL verification could not be completed because the query can be "
                    "read in more than one way."
                ),
                developer_fields={
                    "constraint_id": CONSTRAINT_AMBIGUOUS_TOKENIZATION,
                    "is_valid": False,
                    "issues": [{"severity": "CRITICAL", "description": "Ambiguous tokenisation"}],
                    "engine": "SQLGlot-AST-Scanner",
                },
            )
        try:
            parsed_query = _parse_query(analysed, dialect)
        except Exception as exc:  # noqa: BLE001 — fail-closed by design
            return DiagnosticResult.blocked(
                agent_message=(
                    "SQL verification could not be completed because the query "
                    "could not be parsed."
                ),
                developer_fields={
                    "constraint_id": CONSTRAINT_PARSE_ERROR,
                    "is_valid": False,
                    "error_type": type(exc).__name__,
                    "issues": [{"severity": "CRITICAL", "description": "SQL Syntax Error"}],
                    "engine": "SQLGlot-AST-Scanner",
                },
            )

        # Some sqlglot versions read the TABLE statement (TABLE users, every
        # column of every row) as a column named TABLE. TABLE is reserved in
        # most dialects, so an unquoted one is taken to mean the parse is not
        # the query; a ClickHouse column named table must then be quoted
        # (GHSA-xpfc).
        if any(
            not identifier.quoted and identifier.name.upper() == "TABLE"
            for identifier in parsed_query.find_all(exp.Identifier)
        ):
            return DiagnosticResult.blocked(
                agent_message=(
                    "SQL verification could not be completed because the query "
                    "could not be parsed."
                ),
                developer_fields={
                    "constraint_id": CONSTRAINT_PARSE_ERROR,
                    "is_valid": False,
                    "error_type": "MisreadStatement",
                    "issues": [{"severity": "CRITICAL", "description": "TABLE statement misread"}],
                    "engine": "SQLGlot-AST-Scanner",
                },
            )

        # 2..7 Analysis — unexpected failures fail closed as execution errors.
        try:
            issues: List[SQLIssue] = []

            issues.extend(self._check_command_type(parsed_query))
            issues.extend(self._check_dangerous_functions(parsed_query, analysed, dialect))
            issues.extend(self._check_column_access(parsed_query))
            # The query as given: the stacked check expands executable
            # comments itself, and must also see what expansion hides.
            issues.extend(self._check_injection_patterns(parsed_query, query, dialect, schema_ddl))

            complexity = self._analyze_complexity(parsed_query)

            if check_complexity:
                issues.extend(self._check_complexity_limits(complexity))

            if schema_ddl:
                issues.extend(self._validate_against_schema(parsed_query, schema_ddl, dialect))
        except Exception as exc:  # noqa: BLE001 — fail-closed by design
            return DiagnosticResult.blocked(
                agent_message=(
                    "SQL verification could not be completed due to an internal error."
                ),
                developer_fields={
                    "constraint_id": CONSTRAINT_EXECUTION_ERROR,
                    "is_valid": False,
                    "error_type": type(exc).__name__,
                },
            )

        # Determine overall safety
        critical_count = sum(1 for i in issues if i.severity == "CRITICAL")
        warning_count = sum(1 for i in issues if i.severity == "WARNING")

        is_valid = critical_count == 0

        # Malice proof requires true-malice issue types; a resource-limit violation
        # is a CRITICAL admission failure but NOT evidence of malicious intent.
        malicious = any(
            i.severity == "CRITICAL" and i.issue_type in MALICIOUS_ISSUE_TYPES
            for i in issues
        )
        constraint_id = self._constraint_id({i.issue_type for i in issues}, malicious, is_valid)

        developer_fields: Dict[str, Any] = {
            "constraint_id": constraint_id,
            "is_valid": is_valid,
            "malicious_classification": malicious,
            "issues": [
                {
                    "severity": i.severity,
                    "type": i.issue_type,
                    "description": i.description,
                    "recommendation": i.recommendation,
                }
                for i in issues
            ],
            "complexity": {
                "table_count": complexity.table_count,
                "join_count": complexity.join_count,
                "subquery_depth": complexity.subquery_depth,
                "column_count": complexity.column_count,
                "condition_count": complexity.condition_count,
                "aggregate_count": complexity.aggregate_count,
                "estimated_cost": round(complexity.estimated_cost, 2),
            },
            "critical_count": critical_count,
            "warning_count": warning_count,
            "executable_comments_expanded": executable_comments,
            "engine": "SQLGlot-AST-Scanner",
        }

        evidence = self._build_evidence(
            parsed_query,
            query,
            dialect,
            schema_ddl,
            is_valid=is_valid,
            critical_count=critical_count,
            issues=issues,
            check_complexity=check_complexity,
        )

        # Only fully-analysed results may be VERIFIED: sql_valid and proven-malicious.
        # Schema-parse failures (incomplete analysis), complexity-limit violations, and
        # other admission failures are BLOCKED (non-authoritative, no proof_ref). A
        # malicious query whose schema also fails to parse is BLOCKED because the
        # analysis is incomplete (constraint_id is schema_parse_error in that case).
        if is_valid or constraint_id == CONSTRAINT_MALICIOUS:
            return DiagnosticResult.verified(
                agent_message=(
                    "The SQL query passed verification and is safe to execute."
                    if is_valid
                    else "The SQL query failed security verification and is not safe to execute."
                ),
                developer_fields=developer_fields,
                evidence=evidence,
            )

        return DiagnosticResult.blocked(
            agent_message="The SQL query failed admission checks and is not safe to execute.",
            developer_fields=developer_fields,
        )

    def _build_evidence(
        self,
        parsed_query: exp.Expression,
        query: str,
        dialect: str,
        schema_ddl: Optional[str],
        *,
        is_valid: bool,
        critical_count: int,
        issues: List[SQLIssue],
        check_complexity: bool,
    ) -> Dict[str, Any]:
        """Build deterministic, JSON-serializable proof evidence bound to the verdict.

        The proof_ref hashes the AST, the verdict, and the effective policy
        (``allow_destructive``, ``blocked_columns``, ``limits``) so two configurations
        that reach opposite verdicts on identical input can never share a proof_ref.
        """
        return {
            "engine": "SQLAst-Scanner",
            "query": query,
            "dialect": dialect,
            "schema_ddl": schema_ddl if schema_ddl else None,
            "ast": parsed_query.dump(),
            "is_valid": is_valid,
            "critical_count": critical_count,
            "issue_types": sorted({issue.issue_type for issue in issues}),
            "check_complexity": check_complexity,
            "allow_destructive": self.allow_destructive,
            "blocked_columns": sorted(self.blocked_columns),
            "limits": {key: self.limits[key] for key in sorted(self.limits)},
        }
    
    # =========================================================================
    # Command Type Checking
    # =========================================================================
    
    def _check_command_type(self, parsed_query: exp.Expression) -> List[SQLIssue]:
        """Check for blocked command types across the WHOLE parse tree.

        Classifying by the root node alone let a data-modifying or administrative
        statement hide in a CTE or subquery — ``WITH d AS (DELETE FROM t
        RETURNING *) SELECT * FROM d`` has a ``Select`` root yet runs the DELETE —
        and let whole statement families (COPY/ATTACH/PRAGMA/…) that sit in
        neither deny set pass as safe (GHSA-6p94). This walks every node and,
        when destructive ops are not allowed, also fails closed on any top-level
        statement that is not a recognized read-only query type.
        """
        issues = []

        node_types = set()
        for item in parsed_query.walk():
            node = item[0] if isinstance(item, tuple) else item
            node_types.add(type(node))

        if not self.allow_destructive:
            for query_type in sorted(node_types & self.DESTRUCTIVE_COMMANDS, key=lambda c: c.__name__):
                issues.append(SQLIssue(
                    severity="CRITICAL",
                    issue_type="destructive_command",
                    description=f"Destructive command '{query_type.__name__}' blocked. Only SELECT is allowed.",
                    recommendation="Use parameterized API endpoints for data modification."
                ))

        for query_type in sorted(node_types & self.ADMIN_COMMANDS, key=lambda c: c.__name__):
            issues.append(SQLIssue(
                severity="CRITICAL",
                issue_type="admin_command",
                description=f"Administrative command '{query_type.__name__}' blocked.",
                recommendation="Administrative operations must be performed through secure channels."
            ))

        # Fail closed: when destructive ops are not allowed, the top-level
        # statement must be a recognized read-only query type. A COPY/ATTACH/
        # PRAGMA or any statement type we do not model is blocked here rather than
        # waved through — unless it was already flagged above (GHSA-6p94).
        root_type = type(parsed_query)
        already_flagged = root_type in self.DESTRUCTIVE_COMMANDS or root_type in self.ADMIN_COMMANDS
        if (not self.allow_destructive
                and root_type not in self.READ_ONLY_ROOT_TYPES
                and not already_flagged):
            issues.append(SQLIssue(
                severity="CRITICAL",
                issue_type="non_read_only_statement",
                description=f"Only read-only SELECT-style queries are permitted; "
                            f"'{root_type.__name__}' is not allowed.",
                recommendation="Submit a read-only SELECT query."
            ))

        return issues
    
    def _check_dangerous_functions(
        self, parsed_query: exp.Expression, query: Optional[str] = None, dialect: str = "postgres"
    ) -> List[SQLIssue]:
        """Block a call to a function that reads or writes files, loads code
        or reaches the OS or another server (GHSA-45jv-2j44-4c2q). Such a
        call makes a SELECT unsafe, so it is blocked whatever the policy.

        A list of such functions cannot cover every engine, so the query is
        also refused when it reads anything but tables (a table function, a
        file, URL or stage named as a table) or calls a function not known
        to compute only from its arguments (GHSA-wgcp-398q-m296)."""
        issues = [
            SQLIssue(
                severity="CRITICAL",
                issue_type="dangerous_function",
                description=f"Function '{name}' blocked: it reaches files, code, the OS or another server.",
                recommendation="Submit a query that does not call this function.",
            )
            for name in sorted(sql_function_names(parsed_query) & DANGEROUS_SQL_FUNCTIONS)
        ]
        reads, unknown = external_reads(parsed_query, dialect)
        if query is not None:
            reads += substituted_variables(query, dialect)
            unknown = list(dict.fromkeys(unknown + quoted_calls(query, dialect, parsed_query)))
        issues += [
            SQLIssue(
                severity="CRITICAL",
                issue_type="dangerous_function",
                description=f"Blocked: {read}.",
                recommendation="Read from the database's tables only.",
            )
            for read in reads
        ]
        issues += [
            SQLIssue(
                severity="CRITICAL",
                issue_type=UNKNOWN_FUNCTION,
                description=(
                    f"Not known to stay inside the database: {reason}. It may read files, "
                    "the network or the environment."
                ),
                recommendation="Use a standard SQL function, or verify the query without it.",
            )
            for reason in unknown
        ]
        # Named calls first, then reads, then unknown calls: a refusal stays
        # small however many there are.
        return issues[:MAX_REASONS]

    # =========================================================================
    # Column Access Control
    # =========================================================================
    
    def _check_column_access(self, parsed_query: exp.Expression) -> List[SQLIssue]:
        """Check for access to sensitive columns."""
        issues = []
        
        for column in parsed_query.find_all(exp.Column):
            col_name = column.name.lower()
            if col_name in self.blocked_columns:
                issues.append(SQLIssue(
                    severity="CRITICAL",
                    issue_type="sensitive_column_access",
                    description=f"Access to sensitive column '{col_name}' is forbidden.",
                    recommendation="Remove sensitive column from query or request elevated permissions."
                ))
        
        return issues
    
    # =========================================================================
    # Injection Pattern Detection
    # =========================================================================
    
    def _check_injection_patterns(
        self,
        parsed_query: exp.Expression,
        raw_query: str,
        dialect: str = "postgres",
        schema_ddl: Optional[str] = None,
    ) -> List[SQLIssue]:
        """Detect SQL injection patterns. ``schema_ddl``, when given, says
        which names are columns of which tables for the OR check."""
        issues = []
        
        # Tautology detection by VALUE, not by matching a fixed set of AST
        # shapes (GHSA-6cpx). A column-free comparison that folds to true
        # (1=1, 1=1.0, 'a'='a', 2>1), or a WHERE/HAVING whose whole predicate
        # folds to true (WHERE 1, WHERE 2>1), is a tautology.
        _COMPARISONS = tuple(
            c for c in (exp.EQ, exp.NEQ, exp.GT, exp.GTE, exp.LT, exp.LTE) if c is not None
        )
        for condition in parsed_query.find_all(*_COMPARISONS):
            if _is_always_true(condition):
                issues.append(SQLIssue(
                    severity="CRITICAL",
                    issue_type="injection_tautology",
                    description=f"Tautology detected: {condition.sql()}. Likely injection attempt.",
                    recommendation="Validate input before constructing SQL."
                ))
        for clause in parsed_query.find_all(exp.Where, exp.Having):
            if _is_always_true(clause.this):
                issues.append(SQLIssue(
                    severity="CRITICAL",
                    issue_type="injection_tautology",
                    description="Always-true filter predicate detected. Likely injection attempt.",
                    recommendation="Validate input before constructing SQL."
                ))

        # OR with a constant always-true operand (OR TRUE, OR 1, OR NOT FALSE,
        # OR 2>1): the OR as a whole isn't constant (the other side reads data),
        # so each operand is tested on its own.
        for condition in parsed_query.find_all(exp.Or):
            if _is_always_true(condition.left) or _is_always_true(condition.right):
                issues.append(SQLIssue(
                    severity="CRITICAL",
                    issue_type="injection_or_true",
                    description="Always-true OR operand detected. Likely injection attempt."
                ))

        # An OR operand that restricts no column to a value may be always
        # true, so it is not admitted (GHSA-xpfc). Once is enough.
        unrestricted = _unrestricted_or_operand(
            parsed_query,
            _FilterContext(
                parsed_query, dialect, _declared_schema(schema_ddl, dialect), expand_executable_comments(raw_query)
            ),
        )
        if unrestricted is not None:
            issues.append(SQLIssue(
                severity="CRITICAL",
                issue_type=UNRESTRICTED_OR,
                description=(
                    f"An OR operand restricts no column to a value: {unrestricted.sql()}. "
                    "It may be always true."
                ),
                recommendation="Restrict each OR operand to values, e.g. col = 'x' or col IN (1, 2)."
            ))

        # A filter predicate that reads no data but could not be worked out
        # may be always true, so it is not admitted (GHSA-jvhg). Once is enough.
        unevaluated = next(_unevaluated_data_free_predicates(parsed_query), None)
        if unevaluated is not None:
            issues.append(SQLIssue(
                severity="CRITICAL",
                issue_type=UNEVALUATED_PREDICATE,
                description=(
                    f"Filter predicate reads no column and could not be evaluated: {unevaluated.sql()}. "
                    "It may be always true."
                ),
                recommendation="Compare against a column or remove the constant condition."
            ))

        # UNION injection
        if parsed_query.find(exp.Union):
            issues.append(SQLIssue(
                severity="WARNING",
                issue_type="union_query",
                description="UNION query detected. Verify this is intentional.",
                recommendation="Ensure UNION source is trusted."
            ))
        
        # Stacked queries (multiple statements); a ";" in a literal or comment
        # is not one (#533).
        if has_stacked_statements(raw_query, dialect):
            issues.append(SQLIssue(
                severity="CRITICAL",
                issue_type="stacked_queries",
                description="Multiple statements detected (stacked queries).",
                recommendation="Only single statements are allowed."
            ))
        
        # Comment injection
        if "--" in raw_query:
            issues.append(SQLIssue(
                severity="WARNING",
                issue_type="comment_detected",
                description="SQL comment '--' detected. May indicate injection attempt."
            ))
        
        return issues
    
    # =========================================================================
    # Complexity Analysis
    # =========================================================================
    
    def _analyze_complexity(self, parsed_query: exp.Expression) -> ComplexityMetrics:
        """Analyze query complexity for resource protection."""
        metrics = ComplexityMetrics()
        
        # Count tables
        metrics.table_count = len(list(parsed_query.find_all(exp.Table)))
        
        # Count joins
        metrics.join_count = len(list(parsed_query.find_all(exp.Join)))
        
        # Calculate subquery depth
        metrics.subquery_depth = self._calculate_subquery_depth(parsed_query)
        
        # Count columns
        metrics.column_count = len(list(parsed_query.find_all(exp.Column)))
        
        # Count conditions (WHERE, HAVING, ON)
        for expr_type in [exp.Where, exp.Having]:
            for _ in parsed_query.find_all(expr_type):
                metrics.condition_count += 1
        
        # Count binary conditions
        metrics.condition_count += len(list(parsed_query.find_all(exp.Binary)))
        
        # Count aggregates
        aggregate_types = [exp.Sum, exp.Count, exp.Avg, exp.Min, exp.Max]
        for agg_type in aggregate_types:
            metrics.aggregate_count += len(list(parsed_query.find_all(agg_type)))
        
        # Estimate cost (simplified formula)
        metrics.estimated_cost = self._estimate_cost(metrics)
        
        return metrics
    
    # Statements whose SELECTs are subqueries: a SELECT nested in one of these
    # is one level deeper. UPDATE, DELETE, INSERT and MERGE count, so a
    # subquery of a permitted DML statement is held to max_subquery_depth.
    _QUERY_LEVEL_TYPES = tuple(
        {exp.Select} | _available_expression_types("Update", "Delete", "Insert", "Merge")
    )

    def _calculate_subquery_depth(self, expression: exp.Expression) -> int:
        """Calculate maximum subquery nesting depth.

        A statement's depth is the number of SELECT, UPDATE, DELETE, INSERT
        or MERGE nodes it is nested in, wherever it sits (WHERE, FROM, a
        scalar position, a CTE); a CTE counts as one level whatever its body
        or statement, and a MERGE's WHEN actions count as part of the MERGE.
        The query's depth is the deepest statement's.
        One iterative pass carries the depth down the tree,
        so each node is visited once and a long UNION chain stays linear. The
        recursive walk this replaces called itself on the same Subquery node,
        because ``find_all`` yields the node it starts from, and raised
        RecursionError on any parenthesised subquery (#529).
        """
        max_depth = 0
        stack = [(expression, 0)]
        while stack:
            node, depth = stack.pop()
            statement = self._is_statement(node)
            # Every statement counts where it sits, not only a SELECT: an
            # UPDATE or DELETE in a writable CTE is nested too. So does every
            # CTE, whatever its body: sqlglot 20.x keeps a VALUES body bare.
            if statement or isinstance(node, exp.CTE):
                max_depth = max(max_depth, depth)
            if statement or self._is_set_operation_cte(node):
                depth += 1
            stack.extend((child, depth) for child in self._child_expressions(node))
        return max_depth

    def _is_statement(self, node: exp.Expression) -> bool:
        """A SELECT, UPDATE, DELETE, INSERT or MERGE. The UPDATE or INSERT of a
        MERGE ... WHEN action is part of the MERGE, not a statement nested in it."""
        return isinstance(node, self._QUERY_LEVEL_TYPES) and not isinstance(node.parent, exp.When)

    def _is_set_operation_cte(self, node: exp.Expression) -> bool:
        """A WITH that no statement holds. A CTE nests in its statement: under a
        SELECT or DML node that node already added the level, but sqlglot
        attaches the CTE of a UNION, INTERSECT or EXCEPT to the set operation,
        which adds none."""
        return isinstance(node, exp.With) and not isinstance(node.parent, self._QUERY_LEVEL_TYPES)

    @staticmethod
    def _child_expressions(node: exp.Expression) -> List[exp.Expression]:
        """The node's child expressions. Older sqlglot (20.x, allowed by
        pyproject) yields tuples holding the child; take the expression out."""
        children = []
        for child in node.iter_expressions():
            if isinstance(child, tuple):
                child = next((c for c in child if isinstance(c, exp.Expression)), None)
            if child is not None:
                children.append(child)
        return children
    
    def _estimate_cost(self, metrics: ComplexityMetrics) -> float:
        """
        Estimate query cost (simplified formula).
        
        Cost = tables^2 * (joins + 1) * (subquery_depth + 1) * log(columns + 1)
        """
        import math
        
        base_cost = 1.0
        
        # Table cost (each table adds O(n) rows)
        table_cost = max(1, metrics.table_count) ** 2
        
        # Join cost (each join multiplies complexity)
        join_cost = max(1, metrics.join_count + 1) * 2
        
        # Subquery depth (exponential cost)
        subquery_cost = 2 ** metrics.subquery_depth
        
        # Column overhead (logarithmic)
        column_cost = math.log(max(1, metrics.column_count) + 1)
        
        # Aggregate cost
        agg_cost = max(1, metrics.aggregate_count)
        
        return base_cost * table_cost * join_cost * subquery_cost * column_cost * agg_cost
    
    # =========================================================================
    # Complexity Limit Enforcement
    # =========================================================================
    
    def _check_complexity_limits(self, metrics: ComplexityMetrics) -> List[SQLIssue]:
        """Check if query exceeds complexity limits."""
        issues = []
        
        if metrics.table_count > self.limits["max_tables"]:
            issues.append(SQLIssue(
                severity="CRITICAL",
                issue_type="complexity_tables",
                description=f"Query accesses {metrics.table_count} tables (limit: {self.limits['max_tables']}).",
                recommendation="Reduce query scope or use materialized views."
            ))
        
        if metrics.join_count > self.limits["max_joins"]:
            issues.append(SQLIssue(
                severity="CRITICAL",
                issue_type="complexity_joins",
                description=f"Query has {metrics.join_count} joins (limit: {self.limits['max_joins']}).",
                recommendation="Consider breaking into multiple queries or using denormalized tables."
            ))
        
        if metrics.subquery_depth > self.limits["max_subquery_depth"]:
            issues.append(SQLIssue(
                severity="CRITICAL",
                issue_type="complexity_subqueries",
                description=f"Query has {metrics.subquery_depth} levels of subqueries (limit: {self.limits['max_subquery_depth']}).",
                recommendation="Flatten subqueries using CTEs or temporary tables."
            ))
        
        if metrics.column_count > self.limits["max_columns"]:
            issues.append(SQLIssue(
                severity="WARNING",
                issue_type="complexity_columns",
                description=f"Query selects {metrics.column_count} columns (limit: {self.limits['max_columns']}).",
                recommendation="Select only necessary columns."
            ))
        
        if metrics.condition_count > self.limits["max_conditions"]:
            issues.append(SQLIssue(
                severity="WARNING",
                issue_type="complexity_conditions",
                description=f"Query has {metrics.condition_count} conditions (limit: {self.limits['max_conditions']})."
            ))
        
        if metrics.estimated_cost > self.limits["max_estimated_cost"]:
            issues.append(SQLIssue(
                severity="CRITICAL",
                issue_type="complexity_cost",
                description=f"Estimated query cost {metrics.estimated_cost:.0f} exceeds limit {self.limits['max_estimated_cost']}.",
                recommendation="Simplify query or add pagination."
            ))
        
        return issues
    
    # =========================================================================
    # Schema Validation
    # =========================================================================
    
    def _validate_against_schema(
        self, 
        parsed_query: exp.Expression, 
        schema_ddl: str, 
        dialect: str
    ) -> List[SQLIssue]:
        """Validate query against provided schema."""
        issues = []
        tables_in_schema: Dict[str, Set[str]] = {}
        
        try:
            parsed_schema = sqlglot.parse(schema_ddl, read=dialect)
            for expression in parsed_schema:
                if isinstance(expression, exp.Create) and isinstance(expression.this, exp.Schema):
                    table_name = expression.this.this.name.lower()
                    columns = {
                        col.this.name.lower() 
                        for col in expression.this.expressions 
                        if isinstance(col, exp.ColumnDef)
                    }
                    tables_in_schema[table_name] = columns
        except Exception:
            issues.append(SQLIssue(
                severity="CRITICAL",
                issue_type="schema_parse_error",
                description="Could not parse DDL schema; schema verification is incomplete."
            ))
            return issues
        
        # Check table existence. A declared schema is the set of tables the query
        # may touch, so a table outside it is an admission failure, not a warning
        # (GHSA-q5g6-6cw2-cjm3). Names defined by the query itself (CTEs) are not
        # tables of the database.
        cte_names = {cte.alias_or_name.lower() for cte in parsed_query.find_all(exp.CTE)}
        for table in parsed_query.find_all(exp.Table):
            t_name = table.name.lower()
            if t_name not in tables_in_schema and t_name not in cte_names:
                issues.append(SQLIssue(
                    severity="CRITICAL",
                    issue_type="schema_table_missing",
                    description=f"Table '{t_name}' not found in schema.",
                    recommendation="Query only the tables in the declared schema, or add the table to it."
                ))

        issues.extend(self._check_star_sensitive_columns(parsed_query, tables_in_schema))
        issues.extend(self._check_whole_row_references(parsed_query, tables_in_schema, dialect))

        return issues

    def _check_whole_row_references(
        self, parsed_query: exp.Expression, tables_in_schema: Dict[str, Set[str]], dialect: str = "postgres"
    ) -> List[SQLIssue]:
        """Reads of a table's sensitive columns that do not name them
        (GHSA-xpfc):

        - a table or its alias used as a column (``row_to_json(u)``, ``SELECT
          u FROM users u``) is the whole row. Names are compared without
          case, and a name that is also a column still counts: PostgreSQL
          reads a quoted alias that differs from a column only in case as
          the row;
        - a name after a table or its alias that is not one of its columns:
          in PostgreSQL ``u.row_to_json`` is ``row_to_json(u)``;
        - a column list after a table's alias (``users AS t(a, b, c)``)
          renames its columns;
        - DuckDB's ``COLUMNS('pattern')``, and a column by position (DuckDB's
          ``#3``, Snowflake's ``$3``).

        - in Hive, Spark and Databricks, a quoted column name holding regular
          expression characters, which a setting makes a pattern of column
          names.

        An alias used for several tables (one in a subquery) stands for each
        of them, and the alias of a bracketed join, or of a subquery that
        selects a star, for every table in it.
        """
        issues: List[SQLIssue] = []
        alias_to_tables = _aliases_to_tables(parsed_query)

        def exposes(t_names: Set[str], how: str) -> None:
            for t_name in sorted(t_names):
                for col in sorted(tables_in_schema.get(t_name, set()) & self.blocked_columns):
                    issues.append(SQLIssue(
                        severity="CRITICAL",
                        issue_type="sensitive_column_access",
                        description=f"{how} exposes sensitive column '{col}' of '{t_name}'.",
                        recommendation="Select only the non-sensitive columns you need, by name."
                    ))

        for tbl in parsed_query.find_all(exp.Table):
            alias = tbl.args.get("alias")
            if alias is not None and alias.args.get("columns"):
                exposes({tbl.name.lower()}, "A column list after the table's alias")

        for column in parsed_query.find_all(exp.Column):
            if isinstance(column.this, exp.Star):
                continue
            name = column.name.lower()
            if column.table:
                for t_name in sorted(alias_to_tables.get(column.table.lower(), set())):
                    schema_cols = tables_in_schema.get(t_name)
                    if schema_cols is not None and name not in schema_cols:
                        exposes({t_name}, f"'{column.table}.{column.name}', which is not a column,")
            elif name in alias_to_tables:
                exposes(alias_to_tables[name], "A whole-row reference")

        every_table = set().union(*alias_to_tables.values()) if alias_to_tables else set()
        positional = tuple(_available_expression_types("Columns", "PositionalColumn"))
        if positional and any(True for _ in parsed_query.find_all(*positional)):
            exposes(every_table, "Selecting columns by pattern or position")
        elif "Snowflake" in (_dialect_families(dialect) or set()) and any(
            isinstance(_unparen(parameter.this), exp.Literal)
            for parameter in parsed_query.find_all(exp.Parameter)
        ):
            exposes(every_table, "A column by position ($n)")
        families = _dialect_families(dialect)
        if families is None or "Hive" in families:
            pattern_characters = set("*+?|()[]{}^$." + chr(92))
            if any(
                isinstance(column.this, exp.Identifier)
                and column.this.quoted
                and pattern_characters & set(column.name)
                for column in parsed_query.find_all(exp.Column)
            ):
                exposes(every_table, "A quoted column name read as a pattern")

        return issues

    def _check_star_sensitive_columns(
        self, parsed_query: exp.Expression, tables_in_schema: Dict[str, Set[str]]
    ) -> List[SQLIssue]:
        """Expand ``SELECT *`` / ``t.*`` against the declared schema and apply the
        sensitive-column denylist to the expansion (GHSA-6cpx).

        The named-column check never sees a star, so ``SELECT * FROM users`` was
        admitted even when the schema declares a sensitive column like
        ``password``. Resolve each star to the columns of the table(s) it covers
        and block it when any of those columns is sensitive.
        """
        issues: List[SQLIssue] = []

        # alias (and bare name) -> real table names, for resolving stars
        # (GHSA-xpfc): see _aliases_to_tables.
        alias_to_tables = _aliases_to_tables(parsed_query)

        for star in parsed_query.find_all(exp.Star):
            parent = star.parent
            if isinstance(parent, exp.Column) and parent.table:
                covered = sorted(alias_to_tables.get(parent.table.lower(), set()))
            else:
                select = _enclosing_select(star)
                scope = select if select is not None else parsed_query
                # Each table of the SELECT, and every table its alias or name
                # stands for anywhere in the query, as main read it.
                covered = sorted({
                    name
                    for t in scope.find_all(exp.Table)
                    if select is None or _enclosing_select(t) is select
                    for name in {t.name.lower()} | alias_to_tables.get((t.alias or t.name).lower(), set())
                })

            for t_name in covered:
                if not t_name:
                    continue
                schema_cols = tables_in_schema.get(t_name)
                if schema_cols is None:
                    continue  # unknown table is handled by the existence check
                for col in sorted(schema_cols & self.blocked_columns):
                    issues.append(SQLIssue(
                        severity="CRITICAL",
                        issue_type="sensitive_column_access",
                        description=f"Star selection over '{t_name}' exposes sensitive column '{col}'.",
                        recommendation="Select only the non-sensitive columns you need; do not use '*' on tables with restricted columns."
                    ))

        return issues
    
    # =========================================================================
    # Batch Verification
    # =========================================================================
    
    def verify_batch(
        self, 
        queries: List[str], 
        schema_ddl: Optional[str] = None,
        dialect: str = "postgres"
    ) -> DiagnosticResult:
        """
        Verify multiple SQL queries.

        Returns a single :class:`DiagnosticResult`. Per-query verdicts live in
        ``developer_fields.results`` (each a serialized per-query DiagnosticResult) and
        ``developer_fields.summary``.

        The batch is authoritative (VERIFIED with ``proof_ref``) only when every query is
        safe. A batch containing any malicious or blocked query returns BLOCKED (non-
        authoritative, ``proof_ref`` None) so generic consumers that admit on
        ``is_authoritative`` can never accept unsafe SQL (issue #253).

        Args:
            queries: List of SQL queries to verify.
            schema_ddl: Optional DDL schema.
            dialect: SQL dialect.

        Example:
            >>> result = verifier.verify_batch(["SELECT * FROM table1", "SELEC FROM t"])
            >>> print(
            ...     result.developer_fields["summary"]["safe"],
            ...     result.developer_fields["summary"]["unsafe"],
            ...     result.developer_fields["summary"]["blocked"],
            ... )
            1 0 1
        """
        items: List[Dict[str, Any]] = []
        for query in queries:
            dr = self.verify_sql(query, schema_ddl, dialect)
            serialized = dr.to_dict()
            serialized["query"] = query[:100] + "..." if len(query) > 100 else query
            items.append(serialized)

        if not queries:
            return DiagnosticResult.blocked(
                agent_message="Batch SQL verification requires at least one query.",
                developer_fields={
                    "constraint_id": CONSTRAINT_EMPTY_BATCH,
                    "is_valid": False,
                    "malicious_classification": False,
                    "results": [],
                    "summary": {
                        "total": 0,
                        "safe": 0,
                        "unsafe": 0,
                        "malicious": 0,
                        "blocked": 0,
                        "total_critical": 0,
                        "total_warnings": 0,
                    },
                },
            )

        total = len(queries)
        safe = sum(
            1
            for item in items
            if item["status"] == "VERIFIED" and item["developer_fields"].get("is_valid") is True
        )
        malicious = sum(
            1
            for item in items
            if item["status"] == "VERIFIED"
            and item["developer_fields"].get("malicious_classification") is True
        )
        blocked = total - safe - malicious

        is_valid_all = safe == total
        has_proven_malicious = malicious > 0

        summary = {
            "total": total,
            "safe": safe,
            "unsafe": malicious,
            "malicious": malicious,
            "blocked": blocked,
            "total_critical": sum(
                item["developer_fields"].get("critical_count", 0) for item in items
            ),
            "total_warnings": sum(
                item["developer_fields"].get("warning_count", 0) for item in items
            ),
        }

        evidence = {
            "engine": "SQLAst-Scanner",
            "dialect": dialect,
            "count": total,
            "queries": [item["query"] for item in items],
            # Full-query digests bind the complete query text (the truncated
            # ``queries`` field is display-only and not proof-bearing).
            "query_digests": [
                hashlib.sha256(query.encode("utf-8")).hexdigest() for query in queries
            ],
            "schema_ddl": schema_ddl if schema_ddl else None,
            "verdicts": [
                {"status": item["status"], "is_valid": item["developer_fields"].get("is_valid")}
                for item in items
            ],
            "allow_destructive": self.allow_destructive,
            "blocked_columns": sorted(self.blocked_columns),
            "limits": {key: self.limits[key] for key in sorted(self.limits)},
        }

        if is_valid_all:
            batch_constraint_id = CONSTRAINT_SQL_VALID
            batch_malicious = False
        else:
            # A parse/execution failure is NOT a proven-malicious verdict (Greptile P1):
            # only classify the batch as malicious when at least one item was proven so.
            batch_constraint_id = (
                CONSTRAINT_MALICIOUS if has_proven_malicious else CONSTRAINT_BATCH_BLOCKED
            )
            batch_malicious = has_proven_malicious

        batch_fields: Dict[str, Any] = {
            "constraint_id": batch_constraint_id,
            "is_valid": is_valid_all,
            "malicious_classification": batch_malicious,
            "results": items,
            "summary": summary,
            "engine": "SQLGlot-AST-Scanner",
        }

        if is_valid_all:
            return DiagnosticResult.verified(
                agent_message=(
                    "Batch SQL verification succeeded: all queries passed security checks."
                ),
                developer_fields=batch_fields,
                evidence=evidence,
            )

        # Fail-closed: an unsafe or blocked query makes the whole batch non-authoritative
        # (security policy violation per the BLOCKED status contract).
        return DiagnosticResult.blocked(
            agent_message=(
                "Batch SQL verification flagged unsafe or blocked queries; "
                "the batch is not admissible."
            ),
            developer_fields=batch_fields,
        )

    def to_verification_context(self, result: "DiagnosticResult", query: str, attestation_token: Optional[str] = None) -> "VerificationContextDocument":
        """Map a DiagnosticResult to a Verification Context v1.0 document."""
        from .verification_context_bridge import verification_context_from_diagnostic_result
        return verification_context_from_diagnostic_result(
            result,
            formal_statement=query,
            attestation_token=attestation_token,
            verifier="SQLVerifier",
        )



