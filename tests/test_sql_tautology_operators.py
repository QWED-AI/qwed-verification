"""GHSA-jvhg-jw63-gr5g: SQLVerifier returned VERIFIED · ADMIT for filters
widened by an always-true predicate written with an operator the constant
folder did not handle (IN, IS, LIKE, BETWEEN, /, %, ||, COALESCE, CAST, ABS,
EXISTS), by NOT over an AND with a constant-false operand, and by a column
compared with itself. A column-free predicate that still cannot be worked out
is now not admitted either.
"""
import pytest

from qwed_new.core.diagnostics import admission_decision
from qwed_new.core.sql_verifier import (
    CONSTRAINT_UNEVALUATED_PREDICATE,
    SQLVerifier,
    _like_match,
    _divide,
    _modulo,
    _NotConstant,
)

DDL = "CREATE TABLE users (id INT, name TEXT, role TEXT, created_at TIMESTAMP); CREATE TABLE orders (id INT, user_id INT, total INT)"
WHERE = "SELECT name FROM users WHERE "

TAUTOLOGIES = [
    "id = 5 OR 1 IN (1)",
    "id = 5 OR NULL IS NULL",
    "id = 5 OR 1 IS NOT NULL",
    "id = 5 OR 'a' LIKE 'a'",
    "id = 5 OR 'a' ILIKE 'A'",
    "id = 5 OR 'abc' LIKE 'a_c'",
    "id = 5 OR 1 BETWEEN 0 AND 2",
    "id = 5 OR 2/1 = 2",
    "id = 5 OR 2 % 2 = 0",
    "id = 5 OR 'a' || 'b' = 'ab'",
    "id = 5 OR COALESCE(1, 0) = 1",
    "id = 5 OR CAST(1 AS INT) = 1",
    "id = 5 OR ABS(-1) = 1",
    "id = 5 OR EXISTS (SELECT 1)",
    "NOT (id = 5 AND 1 = 0)",
    "id = 5 OR id = id",
    "id = 5 OR id >= id",
    "id = 5 OR NOT (id <> id)",
    "id = 5 OR 1 <=> 1",
    "id = 5 OR id IS NOT DISTINCT FROM id",
    "id = 5 OR 'a' NOT LIKE 'b'",
    "id = 5 OR 'a' NOT ILIKE 'B'",
    "id = 5 OR NOT 1 IS NULL",
]

UNEVALUATED = [
    "id = 5 OR UPPER('a') = 'A'",
    "id = 5 OR 'a%' LIKE 'a\\%'",
    "id = 5 OR 5/2 = 2",
    "id = 5 OR 1/0 IS NULL",
    "id = 5 OR 1 + 'a' = 1",
]


def _verify(query, dialect="postgres"):
    return SQLVerifier().verify_sql(query, DDL, dialect)


@pytest.mark.parametrize("dialect", ["postgres", "sqlite"])
@pytest.mark.parametrize("predicate", TAUTOLOGIES)
def test_always_true_filters_are_refused(predicate, dialect):
    result = _verify(WHERE + predicate, dialect)
    fields = result.developer_fields
    assert fields["is_valid"] is False, fields
    assert fields["malicious_classification"] is True
    assert admission_decision(result).value == "BLOCKED"


@pytest.mark.parametrize("predicate", UNEVALUATED)
def test_a_constant_filter_that_cannot_be_worked_out_is_not_admitted(predicate):
    result = _verify(WHERE + predicate)
    fields = result.developer_fields
    assert fields["is_valid"] is False, fields
    assert fields["constraint_id"] == CONSTRAINT_UNEVALUATED_PREDICATE
    assert fields["malicious_classification"] is False
    assert any(issue["type"] == "unevaluated_constant_predicate" for issue in fields["issues"])
    assert admission_decision(result).value == "BLOCKED"


ADMITTED = [
    "SELECT id, name FROM users WHERE id = 1",
    "SELECT user_id, COUNT(*) FROM orders GROUP BY user_id HAVING COUNT(*) > 1",
    "SELECT u.name FROM users u JOIN orders o ON o.user_id = u.id WHERE o.total > 100",
    "SELECT a.name FROM users a JOIN users b ON a.id = b.id",
    WHERE + "name LIKE 'a%' AND role IN ('admin', 'owner')",
    WHERE + "created_at BETWEEN '2024-01-01' AND '2024-12-31'",
    "SELECT name FROM users u WHERE EXISTS (SELECT 1 FROM orders o WHERE o.user_id = u.id)",
    WHERE + "id = 5 AND TRUE",
    WHERE + "COALESCE(role, 'user') = 'admin'",
    WHERE + "id = ?",
    WHERE + "id = $1",
    WHERE + "id % 2 = 0",
    WHERE + "NOT (role = 'guest')",
    WHERE + "id = 5 OR 1 IN (2, 3)",
    WHERE + "id = 5 OR 'a' LIKE 'b%'",
    WHERE + "id = 5 OR 'a' NOT LIKE 'a%'",
    WHERE + "id = 5 OR 1 IS NULL",
    WHERE + "name IS NOT NULL",
]


@pytest.mark.parametrize("query", ADMITTED)
def test_filters_that_read_data_are_still_admitted(query):
    result = _verify(query)
    assert result.developer_fields["is_valid"] is True, result.developer_fields
    assert admission_decision(result).value == "ADMIT"


@pytest.mark.parametrize(
    ("text", "pattern", "expected"),
    [
        ("abc", "abc", True),
        ("abc", "a%", True),
        ("abc", "%c", True),
        ("abc", "a_c", True),
        ("abc", "%", True),
        ("", "%", True),
        ("", "", True),
        ("abc", "a_", False),
        ("abc", "%b", False),
        ("aXbYc", "a%b%c", True),
        ("aaab", "a%ab", True),
        ("a%", "a%", True),
        ("abc", "", False),
    ],
)
def test_like_matching(text, pattern, expected):
    assert _like_match(text, pattern) is expected


def test_integer_division_and_modulo_follow_sql():
    assert _divide(6, 3) == 2
    assert _divide(1.0, 4) == pytest.approx(0.25)
    with pytest.raises(_NotConstant):
        _divide(5, 2)
    with pytest.raises(ZeroDivisionError):
        _divide(1, 0)
    assert _modulo(-7, 3) == -1
    assert _modulo(7, -3) == 1
    assert _modulo(7.5, 2) == pytest.approx(1.5)


def test_a_long_like_is_not_worked_out_and_so_not_admitted():
    long_text = "a" * 2000
    query = WHERE + f"id = 5 OR '{long_text}' LIKE '{'%a' * 600}'"
    result = _verify(query)
    assert result.developer_fields["constraint_id"] == CONSTRAINT_UNEVALUATED_PREDICATE
    assert admission_decision(result).value == "BLOCKED"


@pytest.mark.parametrize("predicate", TAUTOLOGIES + UNEVALUATED)
def test_code_verifier_sql_refuses_the_same_filters(predicate):
    # The advisory's rows came back VERIFIED · ADMIT through
    # CodeVerifier.verify_code(..., language="sql") as well, which had only a
    # regex for 1=1 and 'a'='a'.
    from qwed_new.core.code_verifier import CodeVerifier

    result = CodeVerifier().verify_code(WHERE + predicate, language="sql")
    assert result.developer_fields["is_safe"] is False, result.developer_fields
    assert admission_decision(result).value == "BLOCKED"


@pytest.mark.parametrize("query", ADMITTED)
def test_code_verifier_sql_still_admits_data_reading_filters(query):
    from qwed_new.core.code_verifier import CodeVerifier

    result = CodeVerifier().verify_code(query, language="sql")
    assert admission_decision(result).value == "ADMIT", result.developer_fields


# Constant predicates whose value depends on the engine: exact SQL numerics
# (0.1 + 0.2 = 0.3 holds), string-number conversion (1 = '1' holds in MySQL
# and PostgreSQL), collations that ignore case, accents or trailing spaces
# ('a' = 'A', 'a' LIKE 'A' hold in MySQL; LIKE ignores ASCII case in SQLite),
# and casts that differ (CAST(1.5 AS INT) is 2 in PostgreSQL and MySQL).
ENGINE_DEPENDENT = [
    "id = 5 OR 0.1 + 0.2 = 0.3",
    "id = 5 OR 3 * 0.1 = 0.3",
    "id = 5 OR 1 = '1'",
    "id = 5 OR 'a' = 0",
    "id = 5 OR 'a' = 'A'",
    "id = 5 OR 'a ' = 'a'",
    "id = 5 OR 'e' = 'é'",
    "id = 5 OR 'a' LIKE 'A'",
    "id = 5 OR 'a' IN ('A')",
    "id = 5 OR 1 IN ('1')",
    "id = 5 OR 'b' BETWEEN 'A' AND 'C'",
    "id = 5 OR CAST(1.5 AS INT) = 2",
    "id = 5 OR CAST(TRUE AS TEXT) = 'true'",
    "id = 5 OR CAST('0' AS BOOLEAN) = FALSE",
    "id = 5 OR 1.0 / 3 * 3 = 1",
]


@pytest.mark.parametrize("dialect", ["postgres", "mysql", "sqlite"])
@pytest.mark.parametrize("predicate", ENGINE_DEPENDENT)
def test_constant_filters_whose_value_depends_on_the_engine_are_not_admitted(predicate, dialect):
    result = _verify(WHERE + predicate, dialect)
    assert result.developer_fields["is_valid"] is False, result.developer_fields
    assert admission_decision(result).value == "BLOCKED"


@pytest.mark.parametrize("predicate", ENGINE_DEPENDENT)
def test_code_verifier_sql_does_not_admit_them_either(predicate):
    from qwed_new.core.code_verifier import CodeVerifier

    result = CodeVerifier().verify_code(WHERE + predicate, language="sql")
    assert admission_decision(result).value == "BLOCKED", result.developer_fields


def test_exact_decimal_arithmetic_and_safe_casts_still_fold():
    from qwed_new.core.sql_verifier import _divide, _modulo
    from decimal import Decimal

    assert _divide(Decimal("1.5"), 3) == Decimal("0.5")
    one = Decimal("1")
    with pytest.raises(_NotConstant):
        _divide(one, 3)
    assert _modulo(Decimal("7.5"), 2) == Decimal("1.5")
    assert _verify(WHERE + "id = 5 OR CAST(2.0 AS INT) = 3").developer_fields["is_valid"] is True


def _fold(predicate, dialect="postgres"):
    from sqlglot import parse_one

    from qwed_new.core.sql_verifier import _const_eval

    return _const_eval(parse_one("SELECT 1 WHERE " + predicate, read=dialect).args["where"].this)


@pytest.mark.parametrize(
    ("predicate", "dialect", "expected"),
    [
        ("TRUE AND TRUE", "postgres", True),
        ("FALSE OR FALSE", "postgres", False),
        ("NULL = 1", "postgres", False),
        ("NULL <=> NULL", "mysql", True),
        ("NULL IN (1)", "postgres", None),
        ("TRUE IS TRUE", "postgres", True),
        ("NULL LIKE 'a'", "postgres", None),
        ("NULL BETWEEN 1 AND 2", "postgres", None),
        ("2 BETWEEN SYMMETRIC 3 AND 1", "postgres", True),
        ("COALESCE(NULL, NULL)", "postgres", None),
        ("CAST(NULL AS INT)", "postgres", None),
        ("CAST(5 AS TEXT)", "postgres", "5"),
        ("CAST(1 AS BOOLEAN)", "postgres", True),
    ],
)
def test_the_folder_on_null_boolean_and_cast_operands(predicate, dialect, expected):
    assert _fold(predicate, dialect) == expected


def test_a_backslash_in_a_like_pattern_is_not_worked_out():
    # A backslash escapes in some engines and not in others.
    with pytest.raises(_NotConstant):
        _fold("'a' LIKE 'a\\%'")


def test_exists_over_something_other_than_a_select_is_not_worked_out():
    from sqlglot import exp

    from qwed_new.core.sql_verifier import _const_eval

    node = exp.Exists(this=exp.Literal.number(1))
    with pytest.raises(_NotConstant):
        _const_eval(node)


def test_code_verifier_leaves_sql_it_cannot_parse_to_its_other_checks():
    from qwed_new.core.code_verifier import CodeVerifier

    assert CodeVerifier._check_sql_tautologies("SELECT ((( FROM") == []


def test_like_on_text_that_is_not_ascii_is_not_worked_out():
    # Accent- and case-insensitive collations differ beyond ASCII.
    with pytest.raises(_NotConstant):
        _fold("'é' LIKE 'é'")
