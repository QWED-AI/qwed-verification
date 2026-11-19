"""SQLVerifier and SQLGuard admit only queries that read tables and known functions (GHSA-wgcp-398q-m296).

The list of functions that reach files, the OS or another server
(GHSA-45jv-2j44-4c2q) named PostgreSQL, SQLite, MySQL, SQL Server and Oracle
functions. Other engines read files and URLs through table functions (DuckDB
read_csv, ClickHouse file and url, Databricks read_files, BigQuery
EXTERNAL_QUERY) or a file named as a table (DuckDB FROM '/path', Spark
csv.`/path`), and some functions reach the environment or run SQL held in a
string (DuckDB getenv, Hive reflect, PostgreSQL query_to_xml). A query is now
refused when it reads anything but tables, subqueries, VALUES, UNNEST and row
generators, or calls a function sqlglot does not know and that is not listed
as computing only from its arguments.
"""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from sqlglot import exp, parse_one

from qwed_new.core.diagnostics import admission_decision
from qwed_new.core.sql_verifier import SQLVerifier
from qwed_new.guards.sql_guard import SQLGuard

DDL = "CREATE TABLE users (id INT, name TEXT, password TEXT, tags TEXT); CREATE TABLE orders (id INT, user_id INT, total INT);"


def _verdicts(query, dialect):
    with_schema = admission_decision(SQLVerifier().verify_sql(query, DDL, dialect=dialect)).value
    without = SQLVerifier().verify_sql(query, None, dialect=dialect)
    guard = SQLGuard().verify_query(query, dialect=dialect)
    return with_schema, admission_decision(without).value, without.developer_fields.get("constraint_id"), guard


READS = [
    ("duckdb", "SELECT * FROM '/etc/passwd'"),
    ("duckdb", "SELECT * FROM 'data.csv'"),
    ("duckdb", "SELECT * FROM 'https://example.invalid/x.csv'"),
    ("duckdb", "SELECT * FROM read_csv('/etc/passwd')"),
    ("duckdb", "SELECT * FROM READ_CSV_AUTO('/etc/passwd')"),
    ("duckdb", "SELECT * FROM read_text('/etc/passwd')"),
    ("duckdb", "SELECT * FROM read_blob('/root/.ssh/id_rsa')"),
    ("duckdb", "SELECT * FROM read_json('/etc/passwd')"),
    ("duckdb", "SELECT * FROM read_parquet('s3://bucket/x.parquet')"),
    ("duckdb", "SELECT * FROM parquet_scan('/x.parquet')"),
    ("duckdb", "SELECT * FROM glob('/home/*')"),
    ("duckdb", "SELECT * FROM users, read_csv('/etc/passwd')"),
    ("duckdb", "SELECT * FROM users u JOIN read_csv('/etc/passwd') f ON TRUE"),
    ("duckdb", "SELECT * FROM users WHERE id IN (SELECT 1 FROM read_csv('/etc/passwd'))"),
    ("duckdb", "WITH f AS (SELECT * FROM read_csv('/etc/passwd')) SELECT * FROM f"),
    ("clickhouse", "SELECT * FROM file('/etc/passwd', 'LineAsString')"),
    ("clickhouse", "SELECT * FROM url('http://169.254.169.254/latest/meta-data/', 'LineAsString')"),
    ("clickhouse", "SELECT * FROM s3('https://bucket.s3.amazonaws.com/x.csv')"),
    ("clickhouse", "SELECT * FROM executable('id', 'TSV', 'x String')"),
    ("clickhouse", "SELECT * FROM remote('other:9000', db, t)"),
    ("clickhouse", "SELECT * FROM mysql('h:3306', 'db', 't', 'u', 'p')"),
    ("spark", "SELECT * FROM csv.`/etc/passwd`"),
    ("spark", "SELECT * FROM parquet.`data.parquet`"),
    ("databricks", "SELECT * FROM read_files('/etc/passwd')"),
    ("snowflake", "SELECT $1 FROM @mystage/data.csv"),
    ("bigquery", "SELECT * FROM EXTERNAL_QUERY('conn', 'SELECT 1')"),
    ("oracle", "SELECT * FROM TABLE(f(1))"),
]


@pytest.mark.parametrize("dialect, query", READS)
def test_reading_anything_but_tables_is_refused(dialect, query):
    with_schema, without, constraint, guard = _verdicts(query, dialect)
    assert (with_schema, without) == ("BLOCKED", "BLOCKED")
    assert constraint in ("sql_verifier.malicious", "sql_verifier.unknown_function")
    assert guard["verified"] is False


CALLS = [
    ("duckdb", "SELECT getenv('HOME')"),
    ("duckdb", "SELECT GetEnv('HOME')"),
    ("duckdb", "SELECT getenv /* note */ ('HOME')"),
    ("hive", "SELECT reflect('java.lang.Runtime', 'getRuntime')"),
    ("hive", "SELECT java_method('java.lang.System', 'getenv', 'HOME')"),
    ("spark", "SELECT reflect('java.lang.System', 'getenv', 'HOME')"),
    ("postgres", "SELECT query_to_xml('SELECT pg_read_file(''/etc/passwd'')', true, true, '')"),
    ("postgres", "SELECT name FROM users WHERE query_to_xml('SELECT 1', true, true, '') IS NOT NULL"),
    ("postgres", "SELECT current_setting('data_directory')"),
    ("postgres", "SELECT nextval('orders_id_seq')"),
    ("postgres", "SELECT name FROM users ORDER BY my_udf(id)"),
    ("postgres", "SELECT pkg.fn(id) FROM users"),
    ("mysql", "SELECT sleep(10)"),
    ("mysql", "SELECT benchmark(1000000000, md5('x'))"),
    ("oracle", "SELECT BFILENAME('DIR', 'x.txt') FROM dual"),
    ("oracle", "SELECT HTTPURITYPE('http://example.invalid').getclob() FROM dual"),
    ("clickhouse", "SELECT file('/etc/passwd')"),
]


@pytest.mark.parametrize("dialect, query", CALLS)
def test_a_function_not_known_to_stay_in_the_database_is_refused(dialect, query):
    with_schema, without, constraint, guard = _verdicts(query, dialect)
    assert (with_schema, without) == ("BLOCKED", "BLOCKED")
    assert constraint in ("sql_verifier.malicious", "sql_verifier.unknown_function")
    assert guard["verified"] is False
    assert guard["risk"] in ("UNKNOWN_FUNCTION_BLOCKED", "DANGEROUS_FUNCTION_BLOCKED", "EXTERNAL_READ_BLOCKED")


def test_an_unknown_function_has_its_own_constraint():
    result = SQLVerifier().verify_sql("SELECT getenv('HOME')", None, dialect="duckdb")
    assert result.developer_fields["constraint_id"] == "sql_verifier.unknown_function"
    assert any("getenv" in issue["description"] for issue in result.developer_fields["issues"])


ADMITTED = [
    ("postgres", "SELECT id, name FROM users WHERE id = 5"),
    ("postgres", "SELECT count(*), max(total), coalesce(sum(total), 0) FROM orders GROUP BY user_id"),
    ("postgres", "SELECT date_trunc('day', now()), to_char(now(), 'YYYY'), lower(name) FROM users"),
    ("postgres", "SELECT json_build_object('id', id), row_to_json(o) FROM orders o"),
    ("postgres", "SELECT age(now()), string_agg(name, ','), array_agg(id) FROM users"),
    ("postgres", "SELECT row_number() OVER (ORDER BY id), lag(id) OVER (ORDER BY id) FROM users"),
    ("postgres", "SELECT g FROM generate_series(1, 3) g"),
    ("postgres", "SELECT e FROM users, jsonb_array_elements(tags::jsonb) e"),
    ("postgres", "SELECT u FROM unnest(ARRAY[1, 2]) u"),
    ("postgres", "SELECT a FROM (VALUES (1), (2)) v(a)"),
    ("postgres", "WITH t AS (SELECT id FROM users) SELECT id FROM t"),
    ("mysql", "SELECT now(), unix_timestamp(), find_in_set('a', name), ifnull(name, '') FROM users"),
    ("mysql", "SELECT group_concat(name), date_format(now(), '%Y') FROM users"),
    ("sqlite", "SELECT datetime('now'), julianday('now'), printf('%d', id), total(id) FROM users"),
    ("duckdb", "SELECT * FROM range(3)"),
    ("duckdb", "SELECT histogram(id), list(name) FROM users"),
    ("clickhouse", "SELECT sumIf(total, total > 1), quantiles(0.5)(total) FROM orders"),
    ("clickhouse", "SELECT number FROM numbers(10)"),
    ("bigquery", "SELECT * FROM `my-project.ds.events_*`"),
    ("tsql", "SELECT getdate(), datepart(year, getdate()) FROM users"),
]


@pytest.mark.parametrize("dialect, query", ADMITTED)
def test_tables_and_known_functions_are_still_admitted(dialect, query):
    _, without, _, guard = _verdicts(query, dialect)
    assert without == "ADMIT"
    assert guard["verified"] is True


def test_with_a_schema_a_query_on_its_tables_is_still_admitted():
    assert _verdicts("SELECT id, lower(name), now() FROM users", "postgres")[0] == "ADMIT"


_NAMES = st.from_regex(r"\Aqx_[a-z]{3,12}\Z", fullmatch=True)


@settings(max_examples=100, deadline=None)
@given(name=_NAMES, dialect=st.sampled_from(["postgres", "mysql", "sqlite", "duckdb", "clickhouse", "snowflake"]))
def test_any_function_sqlglot_does_not_know_is_refused(name, dialect):
    query = f"SELECT {name}(id) FROM users"
    assert any(isinstance(node, exp.Anonymous) for node in parse_one(query, read=dialect).walk())
    _, without, constraint, guard = _verdicts(query, dialect)
    assert (without, constraint) == ("BLOCKED", "sql_verifier.unknown_function")
    assert guard["verified"] is False


REVIEW_READS = [
    # A script transform runs a program.
    ("spark", "SELECT TRANSFORM(name) USING 'cat /etc/passwd' AS (x) FROM users"),
    ("hive", "FROM users SELECT TRANSFORM(name) USING 'sh' AS x"),
    ("spark", "SELECT * FROM users WHERE id IN (SELECT TRANSFORM(id) USING 'sh' AS (x) FROM users)"),
    # Secrets and model calls.
    ("databricks", "SELECT secret('scope', 'key')"),
    ("databricks", "SELECT name FROM users WHERE name = secret('s', 'k')"),
    ("bigquery", "SELECT AI.GENERATE(name, connection_id => 'c') FROM users"),
    ("bigquery", "SELECT AI.EMBED(name) FROM users"),
    ("snowflake", "SELECT AI_CLASSIFY(name, ['a', 'b']) FROM users"),
    ("snowflake", "SELECT AI_AGG(name, 'x') FROM users"),
    # A call through a schema, package or object can be any function.
    ("tsql", "SELECT dbo.format(name) FROM users"),
    ("tsql", "SELECT name.ToString() FROM users"),
    ("bigquery", "SELECT mydataset.len(name) FROM users"),
    ("bigquery", "SELECT `proj`.ds.len(name) FROM users"),
    ("snowflake", "SELECT SNOWFLAKE.CORTEX.TRANSLATE(name, 'en', 'de') FROM users"),
    ("postgres", "SELECT public.format('%s', name) FROM users"),
    ("postgres", "SELECT \"public\".\"format\"('%s', name) FROM users"),
    ("postgres", "SELECT * FROM public.generate_series(1, 3)"),
    ("duckdb", "SELECT * FROM main.generate_series(1, 10)"),
    # A quoted name is case-sensitive: "FORMAT" is not format.
    ("postgres", "SELECT \"FORMAT\"('%s', name) FROM users"),
    ("tsql", "SELECT [len](name) FROM users"),
    # Files read through a data source, a storage plugin or a file name.
    ("spark", "SELECT * FROM text.passwd"),
    ("spark", "SELECT * FROM parquet.`*`"),
    ("spark", "SELECT * FROM json.`{a,b}`"),
    ("spark", "SELECT * FROM binaryFile.`x`"),
    ("drill", "SELECT * FROM dfs.tmp.passwd"),
    ("duckdb", "SELECT * FROM data.csv"),
    ("duckdb", "SELECT * FROM users JOIN data.parquet ON TRUE"),
    # Table functions read as tables, and TABLE(...) wrappers.
    ("clickhouse", "SELECT * FROM dictionary('ext_http_dict')"),
    ("snowflake", "SELECT * FROM TABLE(DIRECTORY(@s))"),
    ("postgres", "SELECT crosstab('SELECT 1')"),
]


@pytest.mark.parametrize("dialect, query", REVIEW_READS)
def test_a_read_found_in_review_is_refused(dialect, query):
    _, without, _, guard = _verdicts(query, dialect)
    assert without == "BLOCKED"
    assert guard["verified"] is False


@pytest.mark.parametrize("query", ["SELECT id FROM text.users", "SELECT id FROM json.users"])
def test_a_data_source_prefix_is_refused_with_a_schema_too(query):
    # A data source prefix reads files, so it is refused with a schema too.
    assert _verdicts(query, "spark")[0] == "BLOCKED"


def test_a_table_wrapper_outside_the_schema_is_refused():
    assert _verdicts("SELECT * FROM TABLE('payroll')", "snowflake")[0] == "BLOCKED"


REVIEW_ADMITTED = [
    ("postgres", "SELECT * FROM ROWS FROM (generate_series(1, 2), generate_series(1, 3)) AS t(a, b)"),
    ("postgres", "SELECT octet_length(name), clock_timestamp(), isfinite(now()) FROM users"),
    ("postgres", "SELECT * FROM json_populate_recordset(NULL::users, '[]')"),
    ("postgres", 'WITH "c"(a) AS (SELECT 1) SELECT a FROM "c"'),
    ("postgres", 'SELECT a FROM users AS "u"(a, b, c)'),
    ("mysql", "SELECT SYSDATE() FROM users"),
    ("sqlite", "SELECT date('now', '-7 days') FROM users"),
    ("tsql", "SELECT CHOOSE(2, 'a', 'b') FROM users"),
    ("tsql", "SELECT value FROM STRING_SPLIT('a,b', ',')"),
    ("tsql", "SELECT * FROM OPENJSON('[1,2]')"),
    ("snowflake", "SELECT HASH(name), RATIO_TO_REPORT(id) OVER (), TO_TIMESTAMP_NTZ('2024-01-01') FROM users"),
    ("snowflake", "SELECT SEQ4() FROM TABLE(GENERATOR(ROWCOUNT => 10))"),
    ("spark", "SELECT pmod(id, 3), hash(name) FROM users"),
    ("oracle", "SELECT LISTAGG(name, ',') WITHIN GROUP (ORDER BY name), REGEXP_SUBSTR(name, 'a') FROM users"),
    ("clickhouse", "SELECT toYYYYMM(now()), toUnixTimestamp(now()), addDays(today(), 1), intDiv(id, 2) FROM users"),
    ("clickhouse", "SELECT arraySort([2, 1]), runningDifference(id), now64(), toDateTime64(now(), 3) FROM users"),
]


@pytest.mark.parametrize("dialect, query", REVIEW_ADMITTED)
def test_common_functions_found_in_review_are_still_admitted(dialect, query):
    _, without, _, guard = _verdicts(query, dialect)
    assert without == "ADMIT"
    assert guard["verified"] is True


SECOND_REVIEW_READS = [
    # DuckDB SUMMARIZE reads what it is given; min and max show a file's lines.
    ("duckdb", "SELECT * FROM (SUMMARIZE TABLE '/etc/passwd')"),
    ("duckdb", "SELECT * FROM (SUMMARIZE '/etc/passwd')"),
    ("duckdb", "SELECT * FROM (SUMMARIZE TABLE 'http://169.254.169.254/latest/meta-data/iam/x.csv')"),
    ("duckdb", "SELECT u.id, s.min FROM users u, (SUMMARIZE TABLE '/etc/passwd') s"),
    ("duckdb", "WITH s AS (SUMMARIZE TABLE '/etc/passwd') SELECT * FROM s"),
    # ClickHouse APPLY calls the name it is given.
    ("clickhouse", "SELECT * APPLY(file) FROM (SELECT name FROM users)"),
    ("clickhouse", "SELECT COLUMNS('name') APPLY(file) FROM users"),
    # Spark and Hive replace ${...} before they parse the query.
    ("spark", "SELECT name, '${env:AWS_SECRET_ACCESS_KEY}' AS k FROM users"),
    ("spark", "SELECT name, '${system:user.home}' AS k FROM users"),
    ("hive", "SELECT name, '${hiveconf:x}' AS k FROM users"),
    ("databricks", "SELECT name FROM users WHERE name = '${env:HOME}'"),
    ("spark2", "SELECT ${env:HOME}"),
    # Oracle calls a function without brackets; sequences advance.
    ("oracle", "SELECT name, UTL_INADDR.GET_HOST_NAME AS h FROM users"),
    ("oracle", "SELECT name FROM users WHERE name = UTL_INADDR.GET_HOST_ADDRESS"),
    ("oracle", "SELECT hr.my_fn FROM users"),
    ("snowflake", "SELECT my_seq.NEXTVAL"),
    ("postgres", "SELECT s.currval FROM users s"),
    # A static member of a type, and a call hidden in a MySQL executable comment.
    ("tsql", "SELECT name, MyClrType::hash(name) FROM users"),
    ("tsql", "SELECT name, MyClrType::StaticProp FROM users"),
    ("mysql", "SELECT name /*! , `format`(1, 2) */ FROM users"),
    # Server settings.
    ("mysql", "SELECT @@datadir"),
    ("mysql", "SELECT @@global.hostname, name FROM users"),
    ("mysql", "SELECT name FROM users WHERE name = @@version"),
    # A quoted call named like a CTE with columns is still a call.
    ("postgres", 'WITH "FORMAT"(a) AS (SELECT 1) SELECT "FORMAT"(name) FROM users'),
]


@pytest.mark.parametrize("dialect, query", SECOND_REVIEW_READS)
def test_a_read_found_in_the_second_review_is_refused(dialect, query):
    with_schema, without, constraint, guard = _verdicts(query, dialect)
    assert (with_schema, without) == ("BLOCKED", "BLOCKED")
    assert constraint in ("sql_verifier.malicious", "sql_verifier.unknown_function")
    assert guard["verified"] is False


@pytest.mark.parametrize("dialect, query", [
    ("clickhouse", "SELECT * APPLY(my_udf) FROM users"),
    ("databricks", "SELECT * FROM users u, LATERAL VECTOR_SEARCH(index => 'c.s.idx', query_text => u.name, num_results => 1) v"),
    ("oracle", "SELECT seq.NEXTVAL FROM dual"),
    ("duckdb", "SELECT * FROM x.tbl"),
    ("duckdb", "SELECT * FROM x.ipc"),
    ("duckdb", "SELECT * FROM x.feather"),
    ("duckdb", "SELECT * FROM x.geojson"),
    ("duckdb", "SELECT * FROM x.shp"),
    ("duckdb", "SELECT * FROM x.gpkg"),
])
def test_a_read_outside_the_schema_found_in_the_second_review_is_refused(dialect, query):
    # Refused with a schema on main too (the source is not in it); without
    # one, and by SQLGuard, they were admitted.
    _, without, _, guard = _verdicts(query, dialect)
    assert without == "BLOCKED"
    assert guard["verified"] is False


SECOND_REVIEW_ADMITTED = [
    ("postgres", 'SELECT * FROM (VALUES (1)) "v"("a")'),
    ("postgres", 'SELECT * FROM users "u"("i","n","p","t")'),
    ("postgres", 'WITH RECURSIVE "r"(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM "r" WHERE n < 3) SELECT n FROM "r"'),
    ("postgres", "SELECT to_tsvector('english', name), ts_rank(to_tsvector(name), to_tsquery('a')) FROM users"),
    ("postgres", "SELECT name FROM users WHERE to_tsvector(name) @@ plainto_tsquery('x')"),
    ("postgres", "SELECT pg_typeof(id), every(id > 0) FROM users"),
    ("tsql", "SELECT QUOTENAME(name), ISJSON(tags) FROM users"),
    ("sqlite", "SELECT json_group_array(name) FROM users"),
    ("clickhouse", "SELECT * APPLY(toString) FROM users"),
    ("clickhouse", "SELECT * APPLY(sum) FROM (SELECT id FROM users)"),
    ("oracle", "SELECT u.name, users.id FROM users, users u"),
    ("duckdb", "SELECT * FROM (SUMMARIZE SELECT id FROM users)"),
    ("spark", "SELECT name, '$HOME' FROM users"),
]


@pytest.mark.parametrize("dialect, query", SECOND_REVIEW_ADMITTED)
def test_queries_found_in_the_second_review_are_still_admitted(dialect, query):
    _, without, _, guard = _verdicts(query, dialect)
    assert without == "ADMIT"
    assert guard["verified"] is True


_CALL_FORMS = [
    ("clickhouse", "SELECT * APPLY({name}) FROM users"),
    ("postgres", "SELECT * FROM users u, LATERAL {name}(u.id) v"),
    ("postgres", "SELECT pkg.{name}(id) FROM users"),
    ("tsql", "SELECT MyType::{name}(id) FROM users"),
    ("oracle", "SELECT pkg.{name} FROM users"),
    ("mysql", "SELECT id /*! , {name}(id) */ FROM users"),
    # The qualifier is a name elsewhere in the query, but not one the
    # column's own query block can see.
    ("oracle", "SELECT {name}.f FROM users WHERE EXISTS (SELECT 1 FROM users {name})"),
    ("oracle", "SELECT sys.{name}.f FROM users {name}"),
    ("oracle", "WITH {name} AS (SELECT id FROM users) SELECT {name}.f FROM users WHERE id IN (SELECT id FROM {name})"),
    ("oracle", "SELECT * FROM users {name}, (SELECT {name}.f FROM dual) x"),
    ("snowflake", 'SELECT * FROM users MATCH_RECOGNIZE (ORDER BY id PATTERN (a) DEFINE a AS "{name}"(name) = 1)'),
    ("postgres", "SELECT CAST(name AS {name}) FROM users"),
    ("postgres", "SELECT name OPERATOR({name}.+) 1 FROM users"),
    ("duckdb", 'SELECT * FROM (SHOW "/srv/{name}.csv")'),
]


@settings(max_examples=100, deadline=None)
@given(name=_NAMES, form=st.sampled_from(_CALL_FORMS))
def test_any_call_form_of_a_name_sqlglot_does_not_know_is_refused(name, form):
    dialect, template = form
    _, without, _, guard = _verdicts(template.format(name=name), dialect)
    assert without == "BLOCKED"
    assert guard["verified"] is False


def test_a_refusal_reports_at_most_twenty_reasons():
    calls = ", ".join([f"qx_fn{i}(id)" for i in range(30)] + [f'"QX{i}"(id)' for i in range(30)])
    query = f"SELECT {calls} FROM users"
    issues = SQLVerifier().verify_sql(query, None, dialect="postgres").developer_fields["issues"]
    reasons = [issue for issue in issues if issue.get("type") in ("dangerous_function", "unknown_function")]
    assert 0 < len(reasons) <= 20
    message = SQLGuard().verify_query(query, dialect="postgres")["message"]
    assert message.count("; ") <= 19


@pytest.mark.timeout(60)
def test_a_refusal_names_what_it_refuses_briefly():
    # Each reason names the call, not the SQL under it, so a deep query with
    # a large literal makes a small refusal.
    query = "'" + "a" * 200_000 + "'"
    for _ in range(25):
        query = f"(SELECT * FROM f({query}))"
    query = f"SELECT * FROM f({query})"
    result = SQLVerifier().verify_sql(query, None, dialect="postgres")
    assert admission_decision(result).value == "BLOCKED"
    assert len(str(result.developer_fields)) < 20_000
    assert len(SQLGuard().verify_query(query, dialect="postgres").get("message", "")) < 5_000


def test_a_long_unknown_name_is_named_briefly():
    query = "SELECT " + "a" * 300_000 + "(1) FROM users"
    result = SQLVerifier().verify_sql(query, None, dialect="postgres")
    assert admission_decision(result).value == "BLOCKED"
    assert len(str(result.developer_fields)) < 20_000
    assert len(SQLGuard().verify_query(query, dialect="postgres").get("message", "")) < 5_000


THIRD_REVIEW_READS = [
    # DuckDB reads (SHOW x) as SHOW of x; sqlglot reads a table SHOW with
    # x as its alias. sqlglot 28 reads (TABLE x) the same way.
    ("duckdb", 'SELECT * FROM (SHOW "/srv/app/secrets.csv")'),
    ("duckdb", "SELECT * FROM (SHOW 'https://internal.example/x.csv')"),
    ("duckdb", "SELECT * FROM (SHOW\n '/etc/passwd')"),
    # Oracle: a qualifier is resolved in the column's own query block and
    # the blocks it is correlated with; a schema needs a table written
    # with it.
    ("oracle", "SELECT utl_inaddr.get_host_name FROM users WHERE EXISTS (SELECT 1 FROM users utl_inaddr)"),
    ("oracle", "SELECT sys.utl_inaddr.get_host_name FROM users utl_inaddr"),
    ("oracle", "WITH hr AS (SELECT id FROM users) SELECT hr.my_fn FROM users WHERE id IN (SELECT id FROM hr)"),
    ("oracle", "SELECT name FROM users utl_inaddr ORDER BY sys.utl_inaddr.get_host_name"),
    ("oracle", "SELECT * FROM users t, (SELECT t.my_fn FROM users) x"),
    # A quoted call after AS.
    ("snowflake", "SELECT * FROM users MATCH_RECOGNIZE (ORDER BY id PATTERN (a) DEFINE a AS \"upper\"(name) = 'X')"),
    ("oracle", "SELECT * FROM users MATCH_RECOGNIZE (ORDER BY id PATTERN (a) DEFINE a AS \"upper\"(name) = 'X')"),
    ("trino", "SELECT * FROM users MATCH_RECOGNIZE (ORDER BY id PATTERN (a) DEFINE a AS \"upper\"(name) = 'X')"),
    ("postgres", 'SELECT CAST(name AS "VARCHAR"(10)) FROM users'),
    # Server values in T-SQL and BigQuery.
    ("tsql", "SELECT @@SERVERNAME"),
    ("tsql", "SELECT name, @@VERSION FROM users"),
    ("tsql", "SELECT @@ROWCOUNT"),
    ("bigquery", "SELECT @@project_id"),
    # A schema-qualified operator, and casts to types that are not built in.
    ("postgres", "SELECT name OPERATOR(public.+) 1 FROM users"),
    ("postgres", "SELECT CAST(name AS my_type) FROM users"),
    ("postgres", "SELECT name::mood FROM users"),
]


@pytest.mark.parametrize("dialect, query", THIRD_REVIEW_READS)
def test_a_read_found_in_the_third_review_is_refused(dialect, query):
    with_schema, without, constraint, guard = _verdicts(query, dialect)
    assert (with_schema, without) == ("BLOCKED", "BLOCKED")
    assert constraint in ("sql_verifier.malicious", "sql_verifier.unknown_function")
    assert guard["verified"] is False


def test_a_table_statement_of_a_path_is_refused():
    # sqlglot 28 reads (TABLE "/path") as a table TABLE with the path as its
    # alias. The verifier refuses an unquoted TABLE name as a parse error,
    # SQLGuard by the alias; sqlglot 30 reads the statement itself.
    with_schema, without, _, guard = _verdicts('SELECT * FROM (TABLE "/srv/app/secrets.csv")', "duckdb")
    assert (with_schema, without) == ("BLOCKED", "BLOCKED")
    assert guard["verified"] is False


@pytest.mark.parametrize("extension", ["gpx", "dxf", "kmz", "mif", "e00", "gdb", "pmtiles"])
def test_more_file_extensions_are_refused(extension):
    _, without, _, guard = _verdicts(f"SELECT * FROM x.{extension}", "duckdb")
    assert without == "BLOCKED"
    assert guard["verified"] is False


THIRD_REVIEW_ADMITTED = [
    ("oracle", "SELECT u.name FROM users u JOIN orders o ON o.user_id = u.id"),
    ("oracle", "SELECT u.name, (SELECT MAX(o.total) FROM orders o WHERE o.user_id = u.id) m FROM users u"),
    ("oracle", "SELECT u.name FROM users u WHERE EXISTS (SELECT 1 FROM orders o WHERE o.user_id = u.id)"),
    ("oracle", "SELECT t.x FROM (SELECT u.id x FROM users u) t"),
    ("oracle", "SELECT hr.users.name FROM hr.users"),
    ("oracle", "WITH c AS (SELECT id FROM users) SELECT c.id FROM c"),
    ("postgres", "SELECT CAST(name AS VARCHAR(10)), id::int FROM users"),
    ("postgres", "SELECT name FROM users WHERE name OPERATOR(pg_catalog.~~) 'x'"),
    ("tsql", "SELECT name FROM users WHERE id = @id"),
    ("duckdb", "SELECT u.name FROM users AS u"),
]


@pytest.mark.parametrize("dialect, query", THIRD_REVIEW_ADMITTED)
def test_queries_found_in_the_third_review_are_still_admitted(dialect, query):
    _, without, _, guard = _verdicts(query, dialect)
    assert without == "ADMIT"
    assert guard["verified"] is True


@pytest.mark.parametrize("query", [None, 123, b"SELECT 1"])
def test_sql_guard_refuses_a_query_that_is_not_text(query):
    result = SQLGuard().verify_query(query)
    assert result["verified"] is False
