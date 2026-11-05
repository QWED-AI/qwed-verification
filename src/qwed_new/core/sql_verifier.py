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

import sqlglot
from sqlglot import exp, parse_one
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass

from .diagnostics import DiagnosticResult

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
# A filter predicate that reads no data but could not be worked out: it may
# be always true, so the query is not admitted, though nothing proves malice.
UNEVALUATED_PREDICATE = "unevaluated_constant_predicate"

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
    except (_NotConstant, TypeError, ValueError, ZeroDivisionError, ArithmeticError):
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
        except (_NotConstant, TypeError, ValueError, ZeroDivisionError, ArithmeticError):
            yield predicate


def _enclosing_select(node: exp.Expression) -> Optional[exp.Expression]:
    """The nearest ancestor Select of *node*, or None."""
    parent = node.parent
    while parent is not None and not isinstance(parent, exp.Select):
        parent = parent.parent
    return parent


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
    
    # Destructive commands (Blocked by default)
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
        if UNEVALUATED_PREDICATE in issue_types:
            return CONSTRAINT_UNEVALUATED_PREDICATE
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

        # 2..7 Analysis — unexpected failures fail closed as execution errors.
        try:
            issues: List[SQLIssue] = []

            issues.extend(self._check_command_type(parsed_query))
            issues.extend(self._check_dangerous_functions(parsed_query))
            issues.extend(self._check_column_access(parsed_query))
            # The query as given: the stacked check expands executable
            # comments itself, and must also see what expansion hides.
            issues.extend(self._check_injection_patterns(parsed_query, query, dialect))

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
    
    def _check_dangerous_functions(self, parsed_query: exp.Expression) -> List[SQLIssue]:
        """Block a call to a function that reads or writes files, loads code
        or reaches the OS or another server (GHSA-45jv-2j44-4c2q). Such a
        call makes a SELECT unsafe, so it is blocked whatever the policy."""
        return [
            SQLIssue(
                severity="CRITICAL",
                issue_type="dangerous_function",
                description=f"Function '{name}' blocked: it reaches files, code, the OS or another server.",
                recommendation="Submit a query that does not call this function.",
            )
            for name in sorted(sql_function_names(parsed_query) & DANGEROUS_SQL_FUNCTIONS)
        ]

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
        self, parsed_query: exp.Expression, raw_query: str, dialect: str = "postgres"
    ) -> List[SQLIssue]:
        """Detect SQL injection patterns."""
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

        # alias (and bare name) -> real table name, for resolving qualified stars.
        alias_to_table: Dict[str, str] = {}
        for tbl in parsed_query.find_all(exp.Table):
            real = tbl.name.lower()
            alias_to_table[real] = real
            if tbl.alias:
                alias_to_table[tbl.alias.lower()] = real

        for star in parsed_query.find_all(exp.Star):
            parent = star.parent
            if isinstance(parent, exp.Column) and parent.table:
                covered = [alias_to_table.get(parent.table.lower())]
            else:
                select = _enclosing_select(star)
                scope = select if select is not None else parsed_query
                covered = [
                    alias_to_table.get((t.alias or t.name).lower(), t.name.lower())
                    for t in scope.find_all(exp.Table)
                    if select is None or _enclosing_select(t) is select
                ]

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



