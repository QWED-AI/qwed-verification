"""The OR check of SQLVerifier (GHSA-xpfc-qm4c-xf6q).

An OR widens what a filter returns, and whether an operand that reads a
column is always true (name LIKE '%', id = id + 0, abs(id) >= 0,
x < 5 OR x >= 5) cannot be decided in general. So the operands of an OR
(or XOR, or an IN list, which is an OR of equalities) in a filter must
restrict one and the same column to values from outside the table:

- Each operand is that column (or LOWER or UPPER of it) equal to or IN
  literals or bound parameters, LIKE a string with no wildcard, or IS
  NULL. An operand that is an AND needs one such part; FALSE, NULL or a
  comparison of integers that is false adds nothing.
- Every operand restricts one same column, named the same way (through
  the same alias, or unqualified) and not a name the query gives to
  anything else (a select-list alias, a CTE); or, with a schema, columns
  it declares for one same table of the database in the SELECT's FROM.
  A name from another table, a subquery, VALUES, an outer query or an
  alias restricts nothing; nor does a name the engine reads as a value
  when it is not quoted (USER, CURRENT_ROLE, SYSDATE), or, in T-SQL and
  SQLite, a name in double quotes, which a setting or a missing column
  turns into a string. (Tokens a setting changes in MySQL, Spark and
  Hive refuse the whole query: see setting_dependent_tokens.)
- A negation of an AND or XOR restricts nothing: NOT (a AND b) is NOT a
  OR NOT b, and so are (a AND b) IS FALSE, = FALSE and IS NOT TRUE. NOT
  LIKE, IS NOT and other negations restrict nothing either.
- A list of values written another way (ANY(ARRAY[...]), IN UNNEST([...]),
  IN (VALUES ...), IN a SELECT with no FROM) is a list too: it must hold
  only values. ANY with a comparison other than = is an OR of those
  comparisons and is refused. A SELECT that reads a table is a semi-join,
  not a list.
- A bound parameter is a value only where the dialect binds it ($1 in
  PostgreSQL and DuckDB, ?, :name, %s); Snowflake's $2 is a column,
  MySQL's or T-SQL's @x a variable a query can assign from each row, and
  ClickHouse's {p:Identifier} a name.
- Values that cover the column cover every row: TRUE and FALSE; for a
  column the schema declares, two values of a boolean or of a type the
  schema defines elsewhere (an enumerated type), or every member of an
  ENUM (by label, compared without case, accents or trailing spaces, or by
  number); in MySQL, which compares a string with a number as numbers, a
  number for a column that is not numeric, and zero or FALSE for a column
  whose type is not known. An unqualified name in a SELECT with several
  sources is covered if it would be in any of them.

An OR in an AND beside a restriction of a column the schema declares for
the only table of the SELECT reads no more than that restriction, so it is
not checked, when every column it reads is a column of that table: an OR
on an outer query's columns, in a correlated subquery, is checked. A filter
that is always true without an OR, or that hides one in a function (CASE,
COALESCE, GREATEST, arithmetic), reads no more than the same query without
that filter, which is admitted.
"""

import re
import unicodedata
from decimal import Decimal, InvalidOperation
from typing import Dict, List, Optional, Set, Tuple

import sqlglot
from sqlglot import exp
from sqlglot.tokens import TokenType


def _optional(read) -> tuple:
    """(the sqlglot class *read* returns,), or () when the installed sqlglot
    does not have it."""
    try:
        return (read(),)
    except AttributeError:  # not in every sqlglot release
        return ()


_POINT_FUNCTIONS = (exp.Lower, exp.Upper)
_OUTSIDE_VALUES = (exp.Literal, exp.Boolean, exp.Null, exp.Placeholder) + _optional(lambda: exp.National)
_LIKE = (exp.Like, exp.ILike)
_DISJUNCTIONS = (exp.Or,) + _optional(lambda: exp.Xor)
_FILTER_CLAUSES = (
    (exp.Where, exp.Having)
    + _optional(lambda: exp.Qualify)
    + _optional(lambda: exp.PreWhere)
    + _optional(lambda: exp.Connect)
)
_SET_OPERATIONS = (exp.Union, exp.Except, exp.Intersect) + _optional(lambda: exp.SetOperation)
# A boolean expression under one of these is negated or compared, so an AND
# or XOR in it may stand for an OR.
_NEGATING_PARENTS = (
    (exp.Not, exp.Is, exp.EQ, exp.NEQ, exp.GT, exp.GTE, exp.LT, exp.LTE)
    + _optional(lambda: exp.NullSafeEQ)
    + _optional(lambda: exp.NullSafeNEQ)
)
_CONJUNCTIONS = (exp.And,) + _optional(lambda: exp.Xor)
# % and _ everywhere; [ ] and ^ make a character class in T-SQL.
_LIKE_WILDCARDS = frozenset("%_[]^")
_SMALL_INTEGER = re.compile(r"\d{1,15}")
_INTEGER_COMPARISONS = {
    exp.EQ: lambda a, b: a == b,
    exp.NEQ: lambda a, b: a != b,
    exp.GT: lambda a, b: a > b,
    exp.GTE: lambda a, b: a >= b,
    exp.LT: lambda a, b: a < b,
    exp.LTE: lambda a, b: a <= b,
}
# Names an engine reads as a value or a pseudo-column when they are not
# quoted, though sqlglot may read them as a column: PostgreSQL's USER is
# CURRENT_USER, Oracle's UID and SYSDATE, and so on.
_ENGINE_NAMES = frozenset({
    "user", "current_user", "session_user", "current_role", "system_user", "current_schema",
    "current_catalog", "uid", "sysdate", "systimestamp", "sessiontimezone", "dbtimezone",
    "rownum", "rowid", "level", "ora_rowscn", "current_date", "current_time",
    "current_timestamp", "localtime", "localtimestamp",
})
_ENUM_TYPES = frozenset({"ENUM", "ENUM8", "ENUM16"})

# (alias of the source, or "" when the SELECT has several; column name)
_ColumnKey = Tuple[str, str]
# table -> column -> declared type (None when the column has none)
_DeclaredSchema = Dict[str, Dict[str, Optional[exp.DataType]]]


def _unparen(node: Optional[exp.Expression]) -> Optional[exp.Expression]:
    """*node* without the brackets around it."""
    while isinstance(node, exp.Paren):
        node = node.this
    return node


def _bare(node: Optional[exp.Expression]) -> Optional[exp.Expression]:
    """*node* without the brackets and minus signs around it."""
    node = _unparen(node)
    while isinstance(node, exp.Neg):
        node = _unparen(node.this)
    return node


def _number(node: Optional[exp.Expression]) -> Optional[Decimal]:
    """The value of *node* when it is a number literal, signs and brackets
    included, else None."""
    node = _unparen(node)
    negative = False
    while isinstance(node, exp.Neg):
        node, negative = _unparen(node.this), not negative
    if not isinstance(node, exp.Literal) or node.is_string:
        return None
    try:
        value = Decimal(node.this)
    except (InvalidOperation, ValueError):
        return None
    return -value if negative else value


def _select_of(node: exp.Expression) -> Optional[exp.Expression]:
    """The nearest ancestor Select of *node*, or None."""
    parent = node.parent
    while parent is not None and not isinstance(parent, exp.Select):
        parent = parent.parent
    return parent


def _operands(node: exp.Expression, kind: type) -> List[exp.Expression]:
    """The operands of a chain of *kind* (AND, OR or XOR), brackets removed."""
    node = _unparen(node)
    if isinstance(node, kind):
        return _operands(node.left, kind) + _operands(node.right, kind)
    return [node]


def _declared_schema(schema_ddl: Optional[str], dialect: str) -> Optional[_DeclaredSchema]:
    """The tables, columns and column types *schema_ddl* declares, or None
    without one or when it does not parse."""
    if not schema_ddl:
        return None
    try:
        statements = sqlglot.parse(schema_ddl, read=dialect)
    except Exception:  # noqa: BLE001 - the schema check reports it
        return None
    schema: _DeclaredSchema = {}
    for statement in statements:
        if isinstance(statement, exp.Create) and isinstance(statement.this, exp.Schema):
            schema[statement.this.this.name.lower()] = {
                column.name.lower(): column.args.get("kind")
                for column in statement.this.expressions
                if isinstance(column, exp.ColumnDef)
            }
    return schema


def _dialect_families(dialect: str) -> Optional[Set[str]]:
    """Which of MySQL, Postgres, DuckDB, Snowflake, Hive, T-SQL and SQLite
    *dialect* is or extends (Doris and StarRocks extend MySQL, Redshift
    Postgres, Spark and Databricks Hive, Fabric T-SQL); None when it does
    not resolve."""
    try:
        resolved = sqlglot.Dialect.get_or_raise(dialect)
        from sqlglot.dialects.duckdb import DuckDB
        from sqlglot.dialects.hive import Hive
        from sqlglot.dialects.mysql import MySQL
        from sqlglot.dialects.postgres import Postgres
        from sqlglot.dialects.snowflake import Snowflake
        from sqlglot.dialects.sqlite import SQLite
        from sqlglot.dialects.tsql import TSQL
    except Exception:  # noqa: BLE001 - an unknown dialect gets no allowance
        return None
    families = {
        "MySQL": MySQL, "Postgres": Postgres, "DuckDB": DuckDB, "Snowflake": Snowflake,
        "Hive": Hive, "TSQL": TSQL, "SQLite": SQLite,
    }
    return {name for name, family in families.items() if isinstance(resolved, family)}


def setting_dependent_tokens(text: str, dialect: str) -> bool:
    """Whether *text* holds a token whose meaning a server setting changes,
    so that the database may read it differently from the analysis: a
    string in double quotes in MySQL (ANSI_QUOTES makes it a name) and in
    Spark, Databricks and Hive (double-quoted identifiers), and MySQL's ||
    (PIPES_AS_CONCAT makes it a concatenation, so id = 5 || name = 'x'
    compares id with '5' || name). A dialect that does not resolve is read
    as MySQL; text that does not split into tokens counts."""
    families = _dialect_families(dialect)
    mysql = families is None or "MySQL" in families
    if not mysql and "Hive" not in families:
        return False
    try:
        tokens = sqlglot.Dialect.get_or_raise(dialect if families is not None else "mysql").tokenize(text)
    except Exception:  # noqa: BLE001 - fail closed
        return True
    for token in tokens:
        if mysql and token.token_type == TokenType.DPIPE:
            return True
        if token.token_type == TokenType.IDENTIFIER:
            continue
        written = text[token.start:token.start + 2]
        if written[:1] == '"' or (written[:1].isalpha() and written[1:2] == '"'):
            return True
    return False


def _boolean_type(declared: Optional[exp.DataType]) -> bool:
    """Whether a column of type *declared* holds two values."""
    if declared is None:
        return False
    name = declared.this.name
    size = [part.sql() for part in declared.expressions]
    return name in ("BOOLEAN", "BIT") or (name == "TINYINT" and size == ["1"])


def _numeric_type(declared: Optional[exp.DataType]) -> bool:
    """Whether a column of type *declared* holds numbers."""
    return declared is not None and (
        declared.is_type(*exp.DataType.NUMERIC_TYPES) or _boolean_type(declared)
    )


def _defined_elsewhere(declared: Optional[exp.DataType]) -> bool:
    """Whether *declared* is a type the schema defines elsewhere (CREATE TYPE),
    such as a PostgreSQL enumerated type, whose values are not known here."""
    return declared is not None and declared.this.name == "USERDEFINED"


def _folded(text: str) -> str:
    """*text* as an accent- and case-insensitive collation with PAD SPACE
    compares it: without accents, case or trailing spaces."""
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(c for c in decomposed if not unicodedata.combining(c)).casefold().rstrip(" ")


def _enum_listed(declared: Optional[exp.DataType], values: List[exp.Expression]) -> bool:
    """Whether *values* name every member of the ENUM type *declared*: by its
    label, or by its number (its position from 1 in MySQL, or the number
    ClickHouse's Enum8 and Enum16 give it)."""
    if declared is None or declared.this.name not in _ENUM_TYPES:
        return False
    labels = {_folded(value.name) for value in (_bare(v) for v in values) if isinstance(value, exp.Literal) and value.is_string}
    numbers = {number for number in (_number(v) for v in values) if number is not None}
    members = 0
    for position, part in enumerate(declared.expressions, 1):
        number: Optional[Decimal] = Decimal(position)
        if isinstance(part, exp.EQ):
            part, number = part.this, _number(part.expression)
        if not isinstance(part, exp.Literal) or not part.is_string:
            return False
        members += 1
        if _folded(part.name) not in labels and number not in numbers:
            return False
    return members > 0


def _written_in_double_quotes(identifier: exp.Identifier, text: str) -> bool:
    """Whether *identifier* is written in double quotes in *text*, the query
    sqlglot parsed. Without its position it counts."""
    if not identifier.quoted:
        return False
    start = identifier.meta.get("start")
    if not isinstance(start, int) or not 0 <= start < len(text):
        return True
    return text[start] == '"'


class _FilterContext:
    """What the OR check reads about a query: its dialect and text, the
    declared schema, the names it gives to anything but a column, and the
    row sources of each SELECT, each worked out once."""

    def __init__(
        self, parsed: exp.Expression, dialect: str, schema: Optional[_DeclaredSchema], text: str = ""
    ):
        families = _dialect_families(dialect)
        self.schema = schema
        self.text = text
        # A dialect that does not resolve is read as MySQL, the strictest here.
        self.mysql = families is None or "MySQL" in families
        self.binds_dollar_numbers = bool((families or set()) & {"Postgres", "DuckDB"})
        # T-SQL with QUOTED_IDENTIFIER OFF, and SQLite when no column has the
        # name, read "x" as a string.
        self.double_quotes_may_be_strings = families is None or bool(families & {"TSQL", "SQLite"})
        ctes = {cte.alias_or_name.lower() for cte in parsed.find_all(exp.CTE)}
        aliases = {
            node.alias.lower()
            for node in parsed.find_all(exp.Alias)
            if not (isinstance(node.this, exp.Column) and node.this.name.lower() == node.alias.lower())
        }
        self._ctes = ctes
        self.other_names = ctes | aliases
        self._sources: Dict[int, Dict[str, Optional[str]]] = {}
        # id(filter root) -> id(part of its AND chain) -> restricts on its own
        self.restricting_parts: Dict[int, Dict[int, bool]] = {}

    def sources(self, select: Optional[exp.Expression]) -> Dict[str, Optional[str]]:
        """The row sources of *select*: each alias (or name) with the table of
        the database it reads, or None for a subquery, CTE, VALUES, lateral or
        table function, or for a name used twice."""
        if select is None:
            return {}
        key = id(select)
        if key not in self._sources:
            sources: Dict[str, Optional[str]] = {}
            from_ = next((value for value in select.args.values() if isinstance(value, exp.From)), None)
            items = [from_.this, *(from_.args.get("expressions") or [])] if from_ is not None else []
            items += [join.this for join in select.args.get("joins") or []]
            items += list(select.args.get("laterals") or [])
            for item in items:
                name = (item.alias_or_name or "").lower()
                table = None
                if (
                    isinstance(item, exp.Table)
                    and isinstance(item.this, exp.Identifier)
                    and item.name.lower() not in self._ctes
                ):
                    table = item.name.lower()
                sources[name] = None if name in sources else table
            self._sources[key] = sources
        return self._sources[key]

    def declared(self, key: _ColumnKey, select: Optional[exp.Expression]) -> Optional[Tuple[exp.DataType, ...]]:
        """(declared type,) when the schema declares the column *key* names
        for a table of the database that *select* reads, else None."""
        if self.schema is None or not key[0]:
            return None
        table = self.sources(select).get(key[0])
        if table is None or key[1] not in self.schema.get(table, {}):
            return None
        return (self.schema[table][key[1]],)

    def kinds(self, key: _ColumnKey, select: Optional[exp.Expression]) -> List[Optional[exp.DataType]]:
        """The types the column *key* names may have: the declared one for a
        column the schema declares for its table, or None where the type is
        not known (no schema, a source that is not a table of the database,
        a name the schema does not declare, an outer query's alias). An
        unqualified name in a SELECT with several sources may be in any."""
        if self.schema is None:
            return [None]
        sources = self.sources(select)
        if key[0] and key[0] not in sources:
            return [None]
        tables = [sources[key[0]]] if key[0] else list(sources.values())
        kinds: List[Optional[exp.DataType]] = []
        for table in tables:
            if table is None:
                kinds.append(None)
            elif key[1] in self.schema.get(table, {}):
                kinds.append(self.schema[table][key[1]])
        return kinds or [None]


def _column_key(side: exp.Expression, select: Optional[exp.Expression], ctx: _FilterContext) -> Optional[_ColumnKey]:
    """How *side* names a column, when it is a column or LOWER or UPPER of
    one: its qualifier (or the only source of *select*) and its name. None
    for anything else, a name the query gives to something else, a name the
    engine reads as a value, or one a setting may make a string."""
    side = _unparen(side)
    if isinstance(side, _POINT_FUNCTIONS):
        side = _unparen(side.this)
    if not isinstance(side, exp.Column) or not isinstance(side.this, exp.Identifier):
        return None
    name = side.name.lower()
    if name in ctx.other_names:
        return None
    if not side.this.quoted and name in _ENGINE_NAMES:
        return None
    if ctx.double_quotes_may_be_strings and _written_in_double_quotes(side.this, ctx.text):
        return None
    if side.table:
        return side.table.lower(), name
    sources = ctx.sources(select)
    return (next(iter(sources)) if len(sources) == 1 else ""), name


def _outside_value(value: exp.Expression, ctx: _FilterContext) -> bool:
    """Whether *value* is a literal, a boolean, NULL or a bound parameter."""
    value = _bare(value)
    if isinstance(value, exp.Parameter):
        number = _unparen(value.this)
        return ctx.binds_dollar_numbers and isinstance(number, exp.Literal) and not number.is_string
    if isinstance(value, exp.Placeholder):
        # ClickHouse's {p:Identifier} binds a name, not a value.
        kind = value.args.get("kind")
        return kind is None or isinstance(kind, exp.DataType)
    return isinstance(value, _OUTSIDE_VALUES)


def _point_restriction(
    atom: exp.Expression, select: Optional[exp.Expression], ctx: _FilterContext
) -> Optional[Tuple[_ColumnKey, List[exp.Expression]]]:
    """(column, values) when *atom* restricts a column to values from
    outside the table, else None."""
    atom = _unparen(atom)
    if atom.args.get("negate"):
        return None
    if isinstance(atom, exp.EQ):
        for key_side, value_side in ((atom.this, atom.expression), (atom.expression, atom.this)):
            key = _column_key(key_side, select, ctx)
            if key is not None and _outside_value(value_side, ctx):
                return key, [value_side]
        return None
    if not isinstance(atom, (exp.In, exp.Is) + _LIKE):
        return None
    key = _column_key(atom.this, select, ctx)
    if key is None:
        return None
    if isinstance(atom, exp.In):
        values = atom.expressions
        if not values or any(atom.args.get(arg) is not None for arg in ("query", "unnest", "field")):
            return None
        return (key, values) if all(_outside_value(v, ctx) for v in values) else None
    if isinstance(atom, exp.Is):
        return (key, []) if isinstance(_unparen(atom.expression), exp.Null) else None
    pattern = _unparen(atom.expression)
    if isinstance(pattern, exp.Literal) and pattern.is_string and pattern.this and not _LIKE_WILDCARDS & set(pattern.this):
        return key, [pattern]
    return None


def _small_integer(node: Optional[exp.Expression]) -> Optional[int]:
    """The value of *node* when it is an integer literal of at most 15 digits
    (exact in every engine, doubles included), else None."""
    node = _unparen(node)
    sign = 1
    if isinstance(node, exp.Neg):
        node, sign = _unparen(node.this), -1
    if isinstance(node, exp.Literal) and not node.is_string and _SMALL_INTEGER.fullmatch(node.this):
        return sign * int(node.this)
    return None


def _always_false(node: exp.Expression) -> bool:
    """Whether *node* is false the same way in every engine: FALSE, NULL, or
    small integers that compare false, are not IN a list of them, or IS NULL.
    Anything else (decimals, strings, casts, arithmetic) is read differently
    by some engine than by the constant folder, so it is not skipped."""
    node = _unparen(node)
    if isinstance(node, exp.Boolean):
        return not node.this
    if isinstance(node, exp.Null):
        return True
    if node.args.get("negate"):
        return False
    compare = _INTEGER_COMPARISONS.get(type(node))
    if compare is not None:
        left, right = _small_integer(node.this), _small_integer(node.expression)
        return left is not None and right is not None and not compare(left, right)
    if isinstance(node, exp.In) and node.args.get("query") is None and node.args.get("unnest") is None:
        value, listed = _small_integer(node.this), [_small_integer(v) for v in node.expressions]
        return value is not None and bool(listed) and None not in listed and value not in listed
    if isinstance(node, exp.Is):
        return _small_integer(node.this) is not None and isinstance(_unparen(node.expression), exp.Null)
    return False


def _zero(value: exp.Expression) -> bool:
    """Whether *value*, signs and brackets removed, is FALSE or a number
    equal to zero (one that does not read as a number counts), which MySQL
    finds equal to every string that does not start with a digit."""
    value = _bare(value)
    if isinstance(value, exp.Boolean):
        return not value.this
    if isinstance(value, exp.Literal) and not value.is_string:
        number = _number(value)
        return number is None or number == 0
    return False


def _covers_the_column(
    key: _ColumnKey, values: List[exp.Expression], select: Optional[exp.Expression], ctx: _FilterContext
) -> bool:
    """Whether *values* may cover every value the column *key* can hold:
    TRUE and FALSE; or, for a type the column may have, two values of a
    boolean or of a type the schema defines elsewhere, every member of an
    ENUM, in MySQL a number for a column that is not numeric, or zero or
    FALSE where the type is not known."""
    values = [value for value in values if not isinstance(_bare(value), exp.Null)]
    bare = [_bare(value) for value in values]
    if {bool(value.this) for value in bare if isinstance(value, exp.Boolean)} == {True, False}:
        return True
    numbers = [
        value for value in bare
        if isinstance(value, exp.Boolean) or (isinstance(value, exp.Literal) and not value.is_string)
    ]
    for kind in ctx.kinds(key, select):
        if kind is None:
            if ctx.mysql and any(_zero(value) for value in numbers):
                return True
            continue
        if (_boolean_type(kind) or _defined_elsewhere(kind)) and len(values) >= 2:
            return True
        if _enum_listed(kind, values):
            return True
        if ctx.mysql and numbers and not _numeric_type(kind):
            return True
    return False


def _filter_root(node: exp.Expression) -> Optional[exp.Expression]:
    """The condition of the WHERE, HAVING, QUALIFY, PREWHERE, START WITH,
    CONNECT BY or JOIN ... ON that *node* is in, within its own SELECT; None
    when it is in no filter (a select list, for example)."""
    child, parent = node, node.parent
    while parent is not None:
        if isinstance(parent, _FILTER_CLAUSES):
            return child
        if isinstance(parent, exp.Join) and parent.args.get("on") is child:
            return child
        if isinstance(parent, (exp.Select, exp.Subquery)):
            return None
        child, parent = parent, parent.parent
    return None


def _confined(node: exp.Expression, select: Optional[exp.Expression], ctx: _FilterContext) -> bool:
    """Whether every column *node* reads is one the schema declares for the
    only table of *select*, through its alias or unqualified, and *node*
    holds no query: then it filters that table's rows and nothing else. An
    outer query's column, in a correlated subquery, is not confined."""
    sources = ctx.sources(select)
    if ctx.schema is None or len(sources) != 1:
        return False
    ((alias, table),) = sources.items()
    if table is None:
        return False
    declared = ctx.schema.get(table, {})
    if any(True for _ in node.find_all(exp.Select, exp.Subquery)):
        return False
    for column in node.find_all(exp.Column):
        key = _column_key(column, select, ctx)
        if key is None or key[0] != alias or key[1] not in declared:
            return False
    return True


def _restricted_beside(
    root: exp.Expression, node: exp.Expression, select: Optional[exp.Expression], ctx: _FilterContext
) -> bool:
    """Whether *root* is an AND with a part, other than the one holding
    *node*, that restricts a column the schema declares for the only table
    of *select* to values that do not cover it, and *node* reads only that
    table's columns. The parts are read once for each root."""
    if len(ctx.sources(select)) != 1 or not _confined(node, select, ctx):
        return False
    key = id(root)
    if key not in ctx.restricting_parts:
        restricting = {}
        for part in _operands(root, exp.And):
            point = _point_restriction(part, select, ctx)
            restricting[id(part)] = (
                point is not None
                and ctx.declared(point[0], select) is not None
                and not _covers_the_column(point[0], point[1], select, ctx)
            )
        ctx.restricting_parts[key] = restricting
    restricting = ctx.restricting_parts[key]
    holder = node
    while holder is not None and id(holder) not in restricting:
        holder = holder.parent
    others = sum(restricting.values()) - (1 if holder is not None and restricting[id(holder)] else 0)
    return others > 0


def _unrestricted_disjunct(
    node: exp.Expression, select: Optional[exp.Expression], ctx: _FilterContext
) -> Optional[exp.Expression]:
    """The first operand of the OR or XOR chain *node* that restricts no
    column, or *node* when its operands neither restrict one same column nor
    columns the schema declares for one same table, or when they cover a
    column; None when it restricts."""
    values_by_column: Dict[_ColumnKey, List[exp.Expression]] = {}
    shared_columns: Optional[Set[_ColumnKey]] = None
    shared_tables: Optional[Set[str]] = None
    for operand in _operands(node, type(node)):
        if _always_false(operand):
            continue
        points = [
            point
            for point in (_point_restriction(part, select, ctx) for part in _operands(operand, exp.And))
            if point is not None
        ]
        if not points:
            return operand
        columns = {key for key, _ in points}
        tables = {key[0] for key in columns if ctx.declared(key, select) is not None}
        shared_columns = columns if shared_columns is None else shared_columns & columns
        shared_tables = tables if shared_tables is None else shared_tables & tables
        for key, values in points:
            values_by_column.setdefault(key, []).extend(values)
    if shared_columns is None:
        return None
    if not shared_columns and not shared_tables:
        return node
    if any(_covers_the_column(key, values, select, ctx) for key, values in values_by_column.items()):
        return node
    return None


def _query_values(query: Optional[exp.Expression]) -> Optional[List[exp.Expression]]:
    """The values a subquery lists without reading a table: the rows of
    VALUES and the select lists of SELECTs with no FROM, through UNION,
    INTERSECT and EXCEPT. None when it lists none (a semi-join)."""
    query = _unparen(query)
    if isinstance(query, exp.Subquery):
        return _query_values(query.this)
    if isinstance(query, exp.Values):
        return [value for row in query.expressions for value in (row.expressions if isinstance(row, exp.Tuple) else [row])]
    if isinstance(query, exp.Select):
        if any(isinstance(value, exp.From) for value in query.args.values()):
            return None
        return [_unparen(item.this) if isinstance(item, exp.Alias) else item for item in query.expressions]
    if isinstance(query, _SET_OPERATIONS):
        parts = [_query_values(query.this), _query_values(query.expression)]
        if all(part is None for part in parts):
            return None
        return [value for part in parts if part is not None for value in part]
    return None


def _listed_values(node: exp.Expression) -> Optional[List[exp.Expression]]:
    """The values an IN, or the ANY or ALL *node*, lists in a form other than
    a plain list: UNNEST of an array, VALUES, a SELECT with no FROM, an
    ARRAY. None when it lists none that way."""
    if isinstance(node, exp.In):
        unnest = node.args.get("unnest")
        if unnest is not None:
            listed = [_unparen(item) for item in unnest.expressions]
            if len(listed) == 1 and isinstance(listed[0], exp.Array):
                return listed[0].expressions
            return None
        if node.args.get("query") is not None:
            return _query_values(node.args.get("query"))
        if any(isinstance(_unparen(item), exp.Values) for item in node.expressions):
            return [value for item in node.expressions for value in (_query_values(item) or [item])]
        return None
    inner = _unparen(node.this)
    if isinstance(inner, exp.Array):
        return inner.expressions
    return _query_values(inner)


def _unrestricted_list(
    node: exp.Expression, values: List[exp.Expression], key_side: Optional[exp.Expression],
    select: Optional[exp.Expression], ctx: _FilterContext,
) -> Optional[exp.Expression]:
    """*node*, a list of values compared with *key_side*, when the list holds
    more than values (id IN (5, id), 5 IN (id, 5)) or the values cover the
    column; None otherwise."""
    if not all(_outside_value(value, ctx) for value in values):
        return node
    key = _column_key(key_side, select, ctx) if key_side is not None else None
    if key is not None and _covers_the_column(key, values, select, ctx):
        return node
    return None


def _negated_conjunction(node: exp.Expression) -> bool:
    """Whether *node*, an AND or XOR, is negated or compared, so that it may
    stand for an OR: NOT (a AND b), (a AND b) IS FALSE, = FALSE, IS NOT
    TRUE."""
    parent = node.parent
    while isinstance(parent, exp.Paren):
        parent = parent.parent
    return isinstance(parent, _NEGATING_PARENTS)


def _comparison_of(node: exp.Expression) -> Optional[exp.Expression]:
    """The expression *node* is an operand of, brackets skipped."""
    parent = node.parent
    while isinstance(parent, exp.Paren):
        parent = parent.parent
    return parent


def _unrestricted_or_operand(parsed: exp.Expression, ctx: _FilterContext) -> Optional[exp.Expression]:
    """The first OR (or XOR) operand in a filter that restricts no column to
    values, an OR whose operands do not restrict one same column or cover
    it, a list that holds more than values or covers its column, an ANY
    with a comparison other than = over several values, or a negated AND or
    XOR; None when every one restricts. Each chain is read once, from its
    top."""
    for node in parsed.find_all(*_DISJUNCTIONS, *_CONJUNCTIONS, exp.In, exp.Any):
        listed: Optional[List[exp.Expression]] = None
        # What the exemption beside a restriction must find confined.
        scope = node
        negated = isinstance(node, _CONJUNCTIONS) and _negated_conjunction(node)
        if negated:
            pass
        elif isinstance(node, exp.And):
            continue
        elif isinstance(node, exp.In):
            if node.args.get("negate"):
                continue
            listed = _listed_values(node)
            if listed is None:
                if len(node.expressions) < 2 or node.args.get("query") is not None:
                    continue
                listed = node.expressions
        elif isinstance(node, exp.Any):
            listed = _listed_values(node)
            if listed is None:
                continue
            scope = _comparison_of(node) or node
        elif type(_comparison_of(node)) is type(node):
            continue
        root = _filter_root(scope)
        if root is None:
            continue
        select = _select_of(scope)
        if _restricted_beside(root, scope, select, ctx):
            continue
        if negated:
            return node
        if isinstance(node, exp.In):
            found = _unrestricted_list(node, listed, node.this, select, ctx)
        elif isinstance(node, exp.Any):
            if not isinstance(scope, exp.EQ):
                found = node if len(listed) > 1 else _unrestricted_list(node, listed, None, select, ctx)
            else:
                other = scope.expression if scope.this is node else scope.this
                found = _unrestricted_list(node, listed, other, select, ctx)
        else:
            found = _unrestricted_disjunct(node, select, ctx)
        if found is not None:
            return found
    return None
