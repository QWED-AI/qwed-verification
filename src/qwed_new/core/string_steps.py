"""
String steps that can leave a critical builtin name (#534).

CodeVerifier matches the critical builtins (``exec``, ``eval``,
``getattr`` ...) in strings as whole identifiers, so prose such as
"executing job" is admitted. A literal that holds a name inside a longer
word can still leave it at runtime when it is sliced, %-formatted, changed in
case or has characters removed (``"xexec"[1:]``). This module works those
steps out where it can (StringSteps) and, where it cannot, matches anywhere
every literal that can reach the step (ReachingLiterals), so the code is not
admitted on a guess.
"""

import ast
import re
import string
from collections.abc import Callable
from dataclasses import dataclass
from typing import ClassVar

# The node types a string step can be.
RESHAPE_NODE_TYPES = frozenset({ast.Subscript, ast.BinOp, ast.Call, ast.Attribute, ast.JoinedStr})
# str.format and format_map, and the builtin format(), insert into a template.
BRACE_FORMATS = frozenset({"format", "format_map"})
# Regex functions that can remove characters (split is read as str.split);
# subf, subfn and splititer are the regex package's own.
REGEX_STEPS = frozenset({
    "sub", "subn", "subf", "subfn", "findall", "finditer", "splititer", "search", "match", "fullmatch",
})

LITERAL_RESHAPERS = {
    "strip": str.strip, "lstrip": str.lstrip, "rstrip": str.rstrip,
    "replace": str.replace, "removeprefix": str.removeprefix, "removesuffix": str.removesuffix,
    "split": str.split, "rsplit": str.rsplit, "partition": str.partition,
    "rpartition": str.rpartition, "translate": str.translate,
    "upper": str.upper, "lower": str.lower, "casefold": str.casefold,
    "swapcase": str.swapcase, "title": str.title, "capitalize": str.capitalize,
}
CASE_METHODS = frozenset({"upper", "lower", "casefold", "swapcase", "title", "capitalize"})
# Methods that remove characters only where they cut: at the ends, or at a
# separator.
EDGE_CUTTERS = frozenset(
    {"strip", "lstrip", "rstrip", "split", "rsplit", "partition", "rpartition", "removeprefix", "removesuffix"}
)
_WORD_CHARACTER = re.compile(r"\w")
_PARENTHESES = re.compile(r"[()]")
MAX_CARRIED = 4096


@dataclass(frozen=True)
class CriticalNames:
    """How CodeVerifier names what it refuses: ``whole`` matches a critical
    name as a whole identifier, ``in_word`` anywhere, and ``bound_by(node)``
    gives the names a node binds."""
    whole: re.Pattern
    in_word: re.Pattern
    bound_by: Callable[[ast.AST], tuple]

    def in_text(self, value, pattern: re.Pattern | None = None) -> str | None:
        text = value.decode("latin-1") if isinstance(value, bytes) else value
        match = (pattern or self.whole).search(text)
        return match.group(1) if match else None

    def in_value(self, value, pattern: re.Pattern | None = None) -> str | None:
        """A critical name a worked-out value (str, or list or tuple of str)
        holds, as ``pattern`` (by default ``whole``) matches it."""
        parts = value if isinstance(value, (list, tuple)) else [value]
        return next(filter(None, (self.in_text(part, pattern) for part in parts if isinstance(part, str))), None)


def reshaped_references(nodes: list[ast.AST], reshapes: list[ast.AST], code: str,
                        names: CriticalNames) -> list[tuple[str, int]]:
    """(name, line) for each step on a string that can leave a critical
    name: a slice or index, a %-format, a str method that removes characters
    or changes case, str() or a concatenation (string_step).

    Steps are worked out deepest first from the literals they start from, so
    a chain is worked out as a whole (``"xexecx"[1:][:-1]``,
    ``"xexec".upper().lower()[1:]``), and each result is matched as whole
    identifiers: ``"executing %s" % job`` and ``"executed,ok".split(",")``
    are not matches. A step that removes characters but cannot be worked out
    (arguments that are not literals, a method read without being called, a
    value too long to carry or one of unknown origin) matches anywhere the
    literals that can reach it (ReachingLiterals), or the value an earlier
    step worked out.
    """
    called = {id(node.func) for node in reshapes if isinstance(node, ast.Call)}
    steps = StringSteps(ReachingLiterals(nodes, code, names), names)
    found: list[tuple[str, int]] = []
    # ast.walk is breadth first, so in reverse an operand comes before the step on it.
    for node in reversed(reshapes):
        name = None if id(node) in called else steps.check(node)
        if name:
            found.append((name, node.lineno))
    found.reverse()
    return found


# =============================================================================
# What a step is
# =============================================================================

def string_step(node: ast.AST) -> tuple[str | None, list[ast.AST]]:
    """How ``node`` reshapes a string, and the operands it works on:
    "remove" (a slice, a str method that can remove characters inside a
    word, or one read without being called), "format" (``%``), "braces"
    (``str.format``, ``format()``, an f-string: the values it inserts),
    "keep" (a literal index, a case change, ``str()``, ``+``, or a method
    that cuts only between words: keeps_words), or None."""
    if isinstance(node, ast.Subscript):
        # A literal index leaves one character, or one item whole; anything
        # else may be a slice object ("xexec"[slice(1, None)]).
        return ("keep" if _is_literal_index(node.slice) else "remove"), [node.value]
    if isinstance(node, ast.BinOp):
        return _operator_step(node)
    if isinstance(node, ast.JoinedStr):
        return "braces", [value.value for value in node.values if isinstance(value, ast.FormattedValue)]
    if isinstance(node, ast.Call):
        return _call_step(node)
    if isinstance(node, ast.Attribute) and node.attr in LITERAL_RESHAPERS:
        return "remove", [node.value]
    return None, []


def _call_step(node: ast.Call) -> tuple[str | None, list[ast.AST]]:
    if _is_str_call(node):
        return "keep", [node.args[0]]
    if _brace_call(node):
        return "braces", [*node.args, *(keyword.value for keyword in node.keywords)]
    if not (isinstance(node.func, ast.Attribute) and node.func.attr in LITERAL_RESHAPERS):
        return None, []
    receiver, _ = _method_call_parts(node)
    return ("keep" if keeps_words(node) else "remove"), [receiver]


def _operator_step(node: ast.BinOp) -> tuple[str | None, list[ast.AST]]:
    if isinstance(node.op, ast.Mod):
        return "format", [node.left, node.right]
    if isinstance(node.op, ast.Add):
        return "keep", [node.left, node.right]
    return None, []


def _is_str_call(node: ast.Call) -> bool:
    return isinstance(node.func, ast.Name) and node.func.id == "str" and len(node.args) == 1 and not node.keywords


def _is_number(node: ast.AST) -> bool:
    """A number written as a literal, or a tuple of them."""
    if isinstance(node, ast.Tuple):
        return bool(node.elts) and all(map(_is_number, node.elts))
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        node = node.operand
    return isinstance(node, ast.Constant) and type(node.value) in (int, float, complex)


def _is_literal_index(node: ast.AST) -> bool:
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        node = node.operand
    return isinstance(node, ast.Constant)


def _brace_call(node: ast.Call) -> bool:
    """``template.format(...)``, ``template.format_map(...)``, or the
    builtin ``format(value, spec)``."""
    if isinstance(node.func, ast.Name):
        return node.func.id == "format"
    return isinstance(node.func, ast.Attribute) and node.func.attr in BRACE_FORMATS


def brace_template(node: ast.AST) -> tuple[list[ast.AST], ast.AST | None]:
    """For an f-string: its parts (Constant or FormattedValue). For a brace
    call: no parts, and the template it formats (None for the builtin)."""
    if isinstance(node, ast.JoinedStr):
        return node.values, None
    if isinstance(node.func, ast.Name):
        return [], None
    receiver, _ = _method_call_parts(node)
    return [], receiver


def read_brace_template(text: str) -> tuple[list[str], bool] | None:
    """``text`` read as a str.format template: the text between its fields,
    and whether a field has a precision (or a nested spec), which cuts what
    it inserts. None when the template does not parse."""
    pieces: list[str] = []
    piece: list[str] = []
    cuts = False
    try:
        for literal, field, spec, _ in string.Formatter().parse(text):
            piece.append(literal)
            if field is not None:
                pieces.append("".join(piece))
                piece = []
                cuts = cuts or _spec_cuts(spec)
    except ValueError:
        return None
    pieces.append("".join(piece))
    return pieces, cuts


def _spec_cuts(spec: str | None) -> bool:
    # A "." may be a fill character (":.<9"); read as a precision anyway.
    return bool(spec) and ("." in spec or "{" in spec)


def _method_call_parts(call: ast.Call) -> tuple[ast.AST, list[ast.AST]]:
    """The string a str method call works on and the arguments it passes:
    ``s.strip(c)``, or ``str.strip(s, c)`` through the class."""
    receiver = call.func.value
    if isinstance(receiver, ast.Name) and receiver.id == "str" and call.args:
        return call.args[0], call.args[1:]
    return receiver, call.args


def keeps_words(call: ast.Call) -> bool:
    """Whether a str method call leaves each word whole: a case change, or
    strip, split, partition and their variants cutting on whitespace or on a
    literal with no word characters. What those remove borders a word, so a
    name in what they leave was already a whole one."""
    method = call.func.attr
    if method in CASE_METHODS:
        return True
    _, args = _method_call_parts(call)
    if method not in EDGE_CUTTERS or any(isinstance(arg, ast.Starred) for arg in args):
        return False
    if any(keyword.arg is None for keyword in call.keywords):
        return False
    cut = args[0] if args else next((keyword.value for keyword in call.keywords if keyword.arg == "sep"), None)
    if cut is None or (isinstance(cut, ast.Constant) and cut.value is None):
        return True
    if not (isinstance(cut, ast.Constant) and isinstance(cut.value, (str, bytes))):
        return False
    return _WORD_CHARACTER.search(_literal_text(cut)) is None


def step_result(node: ast.AST, values: list):
    """What the step ``node`` leaves of its operands' ``values`` (str, or a
    list or tuple of str from split or partition), or None when that is not
    known. Raises when the arguments are not literals."""
    if isinstance(node, ast.Subscript):
        return values[0][_literal_index(node.slice)]
    if isinstance(node, ast.BinOp):
        return values[0] + values[1]
    if isinstance(node, ast.Attribute) or isinstance(node.func, ast.Name):
        # A method read without being called; or str() of a string.
        return None if isinstance(node, ast.Attribute) else values[0]
    method = node.func.attr
    _, arguments = _method_call_parts(node)
    args = [_literal_text(arg) for arg in arguments]
    kwargs = {keyword.arg: _literal_text(keyword.value) for keyword in node.keywords}
    # translate can map one character to many, and replace grows the text
    # when the new part is longer: not worked out, to bound the work.
    if method == "translate" or (method == "replace" and len(args) >= 2 and len(args[1]) > len(args[0])):
        return None
    return LITERAL_RESHAPERS[method](values[0], *args, **kwargs)


def _literal_index(node: ast.AST):
    """A slice or index written as int literals (``[1:]``, ``[-4:]``)."""
    if isinstance(node, ast.Slice):
        bounds = [None if bound is None else ast.literal_eval(bound) for bound in (node.lower, node.upper, node.step)]
        if any(bound is not None and type(bound) is not int for bound in bounds):
            raise TypeError("not an int slice")
        return slice(*bounds)
    index = ast.literal_eval(node)
    if type(index) is not int:
        raise TypeError("not an int index")
    return index


def _literal_text(node: ast.AST):
    value = ast.literal_eval(node)
    return value.decode("latin-1") if isinstance(value, bytes) else value


# =============================================================================
# %-formats
# =============================================================================

def read_format(text: str) -> tuple[list[str], bool, float] | None:
    """``text`` read as a %-format: the text between its conversions (``%%``
    is text), whether a conversion gives a precision, which cuts what it
    inserts, and what the widths and precisions can pad to (``*``
    unbounded): ``%.9d`` zero-pads. None when the format does not parse.
    Conversions are read as CPython reads them, mapping keys with nested
    parentheses included, in one pass."""
    pieces: list[str] = []
    piece: list[str] = []
    cuts = False
    padding = 0.0
    start = 0
    while (percent := text.find("%", start)) >= 0:
        piece.append(text[start:percent])
        conversion = _conversion(text, percent + 1)
        if conversion is None:
            return None
        start, width, precision = conversion
        if text[start - 1] == "%":
            piece.append("%")
            continue
        pieces.append("".join(piece))
        piece = []
        cuts = cuts or precision is not None
        padding += width + (precision or 0)
    piece.append(text[start:])
    pieces.append("".join(piece))
    return pieces, cuts, padding


def _conversion(text: str, i: int) -> tuple[int, float, float | None] | None:
    """(end, width, precision) of the conversion that starts at ``text[i]``,
    just past its ``%``: ``(key)``, flags, width, precision, length and the
    type. The precision is None when there is none."""
    if text.startswith("(", i):
        i = _mapping_key_end(text, i + 1)
        if i is None:
            return None
    while i < len(text) and text[i] in "-+ #0":
        i += 1
    i, width = _number(text, i)
    precision = None
    if text.startswith(".", i):
        i, precision = _number(text, i + 1)
    if i < len(text) and text[i] in "hlL":
        i += 1
    return (i + 1, width, precision) if i < len(text) else None


def _mapping_key_end(text: str, i: int) -> int | None:
    depth = 1
    for match in _PARENTHESES.finditer(text, i):
        depth += 1 if match.group() == "(" else -1
        if depth == 0:
            return match.end()
    return None


def _number(text: str, i: int) -> tuple[int, float]:
    """(end, value) of the width or precision at ``text[i]``: 0 when there
    is none, unbounded for ``*`` or more than nine digits."""
    if text.startswith("*", i):
        return i + 1, float("inf")
    end = i
    while end < len(text) and text[end] in "0123456789":
        end += 1
    if end - i > 9:
        return end, float("inf")
    return end, int(text[i:end]) if end > i else 0


# =============================================================================
# Where literals go
# =============================================================================

class ReachingLiterals:
    """Which critical names the string literals that can reach each value
    hold anywhere, and the literal a name holds when one binding is all it
    has.

    A literal is followed to every value it can become or be stored in
    (LiteralGraph), over-approximately: names and attributes share one key
    per identifier and scopes are not told apart. Where the source holds a
    name inside a word anywhere, identifiers and comments included, what can
    read the source or its names back (introspection, exception messages)
    is taken to hold it too. The graph has one vertex per expression and key
    and is walked once, so the work stays linear in the code, and it is
    built only when the source holds a critical name inside a word.
    """

    def __init__(self, nodes: list[ast.AST], code: str, names: CriticalNames):
        self._nodes = nodes
        self._code = code
        self._names = names
        self._only: dict[str, str] | None = None
        self._hits: dict[object, str] | None = None
        self._regex_reach: set = set()

    def hit(self, node: ast.AST) -> str | None:
        """A critical name a literal that can reach ``node`` holds anywhere."""
        if self._hits is None:
            self._hits = self._reach()
        return self._hits.get(id(node))

    def only(self, name: str) -> str | None:
        """The literal ``name`` holds when its one binding is that literal
        as written."""
        if self._only is None:
            self._only = self._bound_once()
        return self._only.get(name)

    def literal(self, name: str) -> str | None:
        """``only(name)``, when it is short enough to work out per use."""
        text = self.only(name)
        return text if text is not None and len(text) <= MAX_CARRIED else None

    def _reach(self) -> dict[object, str]:
        # Every literal is in the source, but an escape can spell a name
        # ("\x65xec"): the values are read as well.
        source = self._names.in_text(self._code, self._names.in_word)
        seeds = {}
        for node in self._nodes:
            if type(node) is ast.Constant and isinstance(node.value, (str, bytes)):
                hit = self._names.in_text(node.value, self._names.in_word)
                if hit:
                    seeds[id(node)] = hit
        if not (seeds or source):
            return {}
        graph = LiteralGraph(self._names.in_word, source, self._imported_modules())
        for node in self._nodes:
            graph.add_node(node)
        hits = graph.spread(seeds)
        self._regex_reach = graph.regex_reach
        return hits

    def _imported_modules(self) -> dict[str, frozenset]:
        """The names the introspection and regex modules are imported as."""
        found: dict[str, set] = {"introspection": set(), "regex": set()}
        for node in self._nodes:
            if type(node) is not ast.Import:
                continue
            for alias in node.names:
                module = alias.name.split(".")[0]
                bound = alias.asname or module
                if module in LiteralGraph.INTROSPECTION_MODULES:
                    found["introspection"].add(bound)
                if module in LiteralGraph.REGEX_MODULES:
                    found["regex"].add(bound)
        return {kind: frozenset(names) for kind, names in found.items()}

    def regex_call(self, node: ast.AST) -> bool:
        """``re.sub(...)``, ``pattern.findall(...)``, ``sub(...)`` from re:
        a regex function, reached from the re module however it is named."""
        if not isinstance(node, ast.Call):
            return False
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr not in REGEX_STEPS:
                return False
            func = func.value
        self.hit(func)
        return id(func) in self._regex_reach

    # The node types that can bind a name (CriticalNames.bound_by), and
    # those that can reach a namespace.
    _BINDERS: ClassVar[frozenset] = frozenset({
        ast.Name, ast.Attribute, ast.arg, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
        ast.ExceptHandler, ast.MatchAs, ast.MatchStar, ast.MatchMapping, ast.Import, ast.ImportFrom,
    })
    _NAMESPACE_USES: ClassVar[frozenset] = frozenset({ast.Name, ast.Attribute, ast.Call, ast.ImportFrom})

    def _bound_once(self) -> dict[str, str]:
        """Names bound once, to a literal as written. No name is, where the
        code can bind one without a binding the AST shows: through a
        namespace used other than by reading an item (``vars(m)[k]``), or a
        star import."""
        literals: dict[str, str] = {}
        for node in self._nodes:
            if type(node) in (ast.Assign, ast.AnnAssign, ast.NamedExpr):
                literals.update(self._literal_bindings(node))
        bindings = self._binding_counts() if literals else None
        if bindings is None:
            return {}
        return {name: text for name, text in literals.items() if bindings.get(name) == 1}

    def _binding_counts(self) -> dict[str, int] | None:
        """How many times each name is bound, or None when that is not all
        the AST shows."""
        read_items, called = self._read_items_and_calls()
        bindings: dict[str, int] = {}
        for node in self._nodes:
            node_type = type(node)
            if node_type in self._NAMESPACE_USES and self._binds_unseen(node, read_items, called):
                return None
            if node_type in self._BINDERS:
                for name in self._names.bound_by(node):
                    bindings[name] = bindings.get(name, 0) + 1
        return bindings

    def _read_items_and_calls(self) -> tuple[set, set]:
        read_items, called = set(), set()
        for node in self._nodes:
            node_type = type(node)
            if node_type is ast.Subscript and type(node.ctx) is ast.Load:
                read_items.add(id(node.value))
            elif node_type is ast.Call:
                called.add(id(node.func))
        return read_items, called

    @staticmethod
    def _binds_unseen(node: ast.AST, read_items: set, called: set) -> bool:
        if isinstance(node, ast.ImportFrom):
            return any(alias.name == "*" for alias in node.names)
        if isinstance(node, ast.Name):
            return node.id in LiteralGraph.NAMESPACE_CALLS and id(node) not in called
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            return node.func.id in LiteralGraph.NAMESPACE_CALLS and id(node) not in read_items
        if isinstance(node, ast.Attribute):
            return node.attr in LiteralGraph.NAMESPACE_ATTRIBUTES and id(node) not in read_items
        return False

    @staticmethod
    def _literal_bindings(node: ast.AST) -> list[tuple[str, str]]:
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
            targets = [node.target]
        else:
            return []
        if not (isinstance(node.value, ast.Constant) and isinstance(node.value.value, (str, bytes))):
            return []
        text = _literal_text(node.value)
        return [(target.id, text) for target in targets if isinstance(target, ast.Name)]


class LiteralGraph:
    """Where a string literal's value can go. Edges lead from each
    expression to the one holding it where its value can be part of the
    result (not a comparison, a test or an index), and from a value to each
    key it is bound or may be stored to:

    - assignment of any shape, augmented assignment, ``for``, ``with``, a
      comprehension, a match capture and ``:=`` bind to their targets' keys;
      a store into an item or attribute binds to the key holding the object;
    - a call passes its arguments to the parameters of the functions of that
      name (``("()", f)``) and to those it is given (``map(f, ...)``), and
      may store them in the object a method is called on, in another
      argument, or back in an argument through a parameter (``("out", f)``);
      calling a class reaches its constructors, and what is made from a
      value holds what the value holds (``C("xexec").s``);
    - ``return`` and ``yield`` reach the function's key, a docstring
      ``__doc__``, ``raise`` each ``except ... as`` name; a class's dunder
      methods (``__repr__``, ``__getitem__``, ``__enter__``) are called
      without being named, so what they return reaches the class and its
      subclasses, and from there each value made from them;
    - a name bound to another (``b = a``) is the same object: a store into
      one reaches the other;
    - a store into a namespace (``globals()["s"] = ...``) reaches every key
      (WILDCARD).

    Where the source holds a critical name inside a word (``source``),
    identifiers and comments included, it also seeds what can read the
    source or its names back: an exception caught with ``except ... as``
    (its message can quote any name or value: ``int("xexec")``,
    ``o.xexec``), the INTROSPECTION names (``__name__``, ``__code__``,
    ``inspect``, ``dir``, ``globals``), a call given a keyword of that name
    (``dict(xexec=1)``), and a class with a base that has a member of that
    name (an Enum member's ``.name``).
    """

    WILDCARD = "*"
    RAISED = ("raise",)
    NAMESPACE_CALLS: ClassVar[frozenset] = frozenset({"globals", "vars", "locals"})
    NAMESPACE_ATTRIBUTES: ClassVar[frozenset] = frozenset({"__dict__", "f_globals", "f_locals"})
    CONSTRUCTORS = ("__init__", "__new__", "__post_init__")
    # Names that read source text, or the names in it, back as strings,
    # whatever they are read on.
    INTROSPECTION: ClassVar[frozenset] = frozenset({
        "inspect", "traceback", "linecache", "dis", "pydoc", "tokenize",
        "getsource", "getsourcelines", "getsourcefile", "getfile", "getcomments", "findsource",
        "getframeinfo", "currentframe", "getmembers",
        "format_exc", "format_exception", "format_tb", "format_stack", "print_exc",
        "extract_tb", "extract_stack", "exc_info", "__traceback__", "tb_frame",
        "__file__", "__code__", "f_code", "gi_code", "cr_code", "ag_code", "_getframe",
        "_current_frames", "f_back", "f_locals", "f_globals", "__loader__", "__spec__",
        "get_source", "get_data", "get_code", "__name__", "__qualname__", "__module__",
        "__annotations__", "__dict__", "__slots__", "__members__", "_member_names_", "_fields",
        "_asdict", "__match_args__", "__signature__", "__defaults__", "__kwdefaults__",
        "__wrapped__", "dir", "globals", "locals", "vars",
    })
    # Modules whose functions read names back. Their other names are common
    # words (fields, signature, exception), so they count only as imported
    # from these modules or read as attributes of them.
    INTROSPECTION_MODULES: ClassVar[frozenset] = frozenset(
        {"inspect", "traceback", "linecache", "dis", "pydoc", "tokenize", "dataclasses", "sys"}
    )
    MODULE_INTROSPECTION: ClassVar[frozenset] = frozenset(
        {"fields", "asdict", "astuple", "signature", "exception", "stack", "trace"}
    )
    REGEX_MODULES: ClassVar[frozenset] = frozenset({"re", "regex"})
    # What gives a module by name: sys.modules[...], importlib.import_module().
    MODULE_LOOKUPS: ClassVar[frozenset] = frozenset({"modules", "import_module"})

    def __init__(self, in_word: re.Pattern, source: str | None, imported: dict[str, frozenset] | None = None):
        self._edges: dict[object, list[object]] = {}
        self._read: set = set()
        self._in_word = in_word
        self._source = source
        # The keys a module can be reached from: the names it is imported
        # as, what a from-import of it binds, and the module lookups. A
        # module is then followed through the graph (d = dataclasses).
        imported = imported or {}
        self._module_keys = set(imported.get("introspection", ())) | self.MODULE_LOOKUPS
        self._regex_keys = set(imported.get("regex", ())) | self.MODULE_LOOKUPS
        self._module_attributes: list[ast.Attribute] = []
        self.regex_reach: set = set()
        self._seeds: dict[object, str] = {}
        if source:
            self._seeds[self.RAISED] = source

    def add(self, source, target) -> None:
        if target is not None:
            self._edges.setdefault(source, []).append(target)

    def spread(self, seeds: dict[object, str]) -> dict[object, str]:
        """Each vertex a seed reaches, with the seed's name."""
        for name in self._read:
            self.add(self.WILDCARD, name)
        # dataclasses.fields, inspect.signature, sys.exception, on whatever
        # an introspection module can reach.
        module_reach = self._walk(self._module_keys)
        for node in self._module_attributes:
            if self._source and id(node.value) in module_reach:
                self._seeds[id(node)] = self._source
        self.regex_reach = self._walk(self._regex_keys)
        hits = {**self._seeds, **seeds}
        pending = list(hits)
        while pending:
            vertex = pending.pop()
            for target in self._edges.get(vertex, ()):
                if target not in hits:
                    hits[target] = hits[vertex]
                    pending.append(target)
        return hits

    def _walk(self, start) -> set:
        reached = set(start)
        pending = list(reached)
        while pending:
            for target in self._edges.get(pending.pop(), ()):
                if target not in reached:
                    reached.add(target)
                    pending.append(target)
        return reached

    def add_node(self, node: ast.AST) -> None:
        node_type = type(node)
        children = self._VALUE_CHILDREN.get(node_type)
        if children is None and isinstance(node, ast.expr):
            # An expression type not listed (a newer Python's): all its children.
            children = ast.iter_child_nodes
        if children is not None:
            target = id(node)
            for child in children(node):
                if child is not None:
                    self._edges.setdefault(id(child), []).append(target)
        builder = self._BUILDERS.get(node_type)
        if builder is not None:
            builder(self, node)

    # For each expression type, the children whose value can be part of its
    # own: not a comparison's operands, a test, an index or a slice.
    _VALUE_CHILDREN: ClassVar[dict] = {
        ast.Name: lambda node: (), ast.Constant: lambda node: (),
        ast.Compare: lambda node: (), ast.UnaryOp: lambda node: (),
        ast.Attribute: lambda node: (node.value,), ast.Subscript: lambda node: (node.value,),
        ast.Starred: lambda node: (node.value,), ast.NamedExpr: lambda node: (node.value,),
        ast.Await: lambda node: (node.value,), ast.Yield: lambda node: (node.value,),
        ast.YieldFrom: lambda node: (node.value,), ast.Lambda: lambda node: (node.body,),
        ast.BinOp: lambda node: (node.left, node.right), ast.BoolOp: lambda node: node.values,
        ast.IfExp: lambda node: (node.body, node.orelse),
        ast.Tuple: lambda node: node.elts, ast.List: lambda node: node.elts, ast.Set: lambda node: node.elts,
        ast.Dict: lambda node: (*node.keys, *node.values),
        ast.ListComp: lambda node: (node.elt,), ast.SetComp: lambda node: (node.elt,),
        ast.GeneratorExp: lambda node: (node.elt,), ast.DictComp: lambda node: (node.key, node.value),
        ast.JoinedStr: lambda node: node.values,
        ast.FormattedValue: lambda node: (node.value, node.format_spec),
        ast.Call: lambda node: (node.func, *node.args, *(keyword.value for keyword in node.keywords)),
        ast.Slice: lambda node: (),
    }

    def _seed(self, vertex, identifier: str | None) -> None:
        """Seed ``vertex`` where ``identifier`` holds a name inside a word."""
        if self._source and identifier:
            match = self._in_word.search(identifier)
            if match:
                self._seeds.setdefault(vertex, match.group(1))

    @classmethod
    def _head(cls, node: ast.AST):
        """The key holding the object an expression refers to: a name, the
        last attribute read, or WILDCARD for a namespace."""
        # An item, an unpacking or a call result is part of what it is taken from.
        while isinstance(node, (ast.Subscript, ast.Starred, ast.Call)):
            node = node.func if isinstance(node, ast.Call) else node.value
        if isinstance(node, ast.Name):
            return cls.WILDCARD if node.id in cls.NAMESPACE_CALLS else node.id
        if isinstance(node, ast.Attribute):
            return cls.WILDCARD if node.attr in cls.NAMESPACE_ATTRIBUTES else node.attr
        return None

    @classmethod
    def _stored_in(cls, value: ast.AST):
        """The key a store into the object ``value`` refers to changes."""
        head = cls._head(value)
        if isinstance(value, (ast.Name, ast.Attribute, ast.Subscript)) or head == cls.WILDCARD:
            return head
        return None

    @staticmethod
    def _callee(node: ast.AST):
        """The function ``node`` names, if it names one: a name, an
        attribute, or a lambda."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return id(node) if isinstance(node, ast.Lambda) else None

    def _target_keys(self, target: ast.AST) -> list[object]:
        if isinstance(target, (ast.Tuple, ast.List)):
            return [key for element in target.elts for key in self._target_keys(element)]
        if isinstance(target, ast.Starred):
            return self._target_keys(target.value)
        head = self._head(target.value if isinstance(target, ast.Subscript) else target)
        return [] if head is None else [head]

    def _bind(self, value: ast.AST, target: ast.AST, alias: bool = True) -> None:
        """``value`` bound to ``target``; with ``alias``, a store into the
        target changes what the value refers to too."""
        callee = self._callee(value)
        stored_in = self._stored_in(value) if alias else None
        for key in self._target_keys(target):
            self.add(id(value), key)
            if callee is not None:
                self.add(("()", key), ("()", callee))
                self.add(("out", callee), ("out", key))
            if stored_in is not None:
                self.add(key, stored_in)

    def _name(self, node: ast.Name) -> None:
        if type(node.ctx) is ast.Load:
            self._edges.setdefault(node.id, []).append(id(node))
            self._read.add(node.id)
            if node.id in self.INTROSPECTION and self._source:
                self._seeds[id(node)] = self._source

    def _attribute(self, node: ast.Attribute) -> None:
        if type(node.ctx) is ast.Load:
            self._edges.setdefault(node.attr, []).append(id(node))
            self._read.add(node.attr)
            if self._source and node.attr in self.INTROSPECTION:
                self._seeds[id(node)] = self._source
            elif node.attr in self.MODULE_INTROSPECTION:
                self._module_attributes.append(node)

    def _import_from(self, node: ast.ImportFrom) -> None:
        # from inspect import stack: what an introspection module gives. From
        # sys, only what reads names back (sys.argv does not); from sys
        # import * binds exception on Python 3.11+.
        if not node.module:
            return
        module = node.module.split(".")[0]
        for alias in node.names:
            bound = alias.asname or alias.name
            if module in self.REGEX_MODULES:
                # Only the functions that remove characters: re.escape does not.
                self._regex_keys.update(self._regex_names(alias.name, bound))
            if module in self.INTROSPECTION_MODULES:
                self._module_keys.add(bound)
            if alias.name in self.MODULE_LOOKUPS:
                # from importlib import import_module as im
                self._module_keys.add(bound)
                self._regex_keys.add(bound)
            if self._source:
                self._seed_import(module, alias.name, bound)

    @staticmethod
    def _regex_names(name: str, bound: str):
        if name == "*":
            return REGEX_STEPS
        return (bound,) if name in REGEX_STEPS else ()

    def _seed_import(self, module: str, name: str, bound: str) -> None:
        if module == "sys" and name == "*":
            self._seeds["exception"] = self._source
        elif (module in self.INTROSPECTION_MODULES and module != "sys") or name in (
            self.INTROSPECTION | self.MODULE_INTROSPECTION
        ):
            self._seeds[bound] = self._source

    def _assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._bind(node.value, target)

    def _ann_assign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._bind(node.value, node.target)

    def _aug_assign(self, node: ast.AugAssign) -> None:
        self._bind(node.value, node.target, alias=False)

    def _named_expr(self, node: ast.NamedExpr) -> None:
        self._bind(node.value, node.target)

    def _loop(self, node: ast.AST) -> None:
        self._bind(node.iter, node.target)

    def _with(self, node: ast.AST) -> None:
        for item in node.items:
            if item.optional_vars is not None:
                self._bind(item.context_expr, item.optional_vars)

    def _match(self, node: ast.Match) -> None:
        for case in node.cases:
            for pattern in ast.walk(case.pattern):
                for name in (getattr(pattern, "name", None), getattr(pattern, "rest", None)):
                    if isinstance(name, str):
                        self.add(id(node.subject), name)

    def _call(self, node: ast.Call) -> None:
        hub = ("args", id(node))
        callee = self._callee(node.func)
        if callee is not None:
            self.add(hub, ("()", callee))
        if isinstance(node.func, ast.Attribute):
            # A method may store its arguments in the object it is called on.
            self.add(hub, self._head(node.func.value))
        arguments = [arg.value if isinstance(arg, ast.Starred) else arg for arg in node.args]
        for argument in arguments + [keyword.value for keyword in node.keywords]:
            self.add(id(argument), hub)
            stored_in = self._stored_in(argument)
            self.add(hub, stored_in)
            if callee is not None:
                self.add(("out", callee), stored_in)
            passed = self._callee(argument)
            if passed is not None:
                self.add(hub, ("()", passed))
        # dict(xexec=1) gives the keyword's name as a key.
        for keyword in node.keywords:
            self._seed(id(node), keyword.arg)

    def _parameters(self, function, arguments: ast.arguments) -> None:
        entry, out = ("()", function), ("out", function)
        for default in (*arguments.defaults, *arguments.kw_defaults):
            if default is not None:
                self.add(id(default), entry)
        for parameter in (*arguments.posonlyargs, *arguments.args, arguments.vararg,
                          *arguments.kwonlyargs, arguments.kwarg):
            if parameter is not None:
                self.add(entry, parameter.arg)
                self.add(parameter.arg, out)

    def _function(self, node: ast.AST) -> None:
        self._parameters(node.name, node.args)
        for value in self._returned(node.body):
            self.add(id(value), node.name)
        # A dunder's docstring is not what calling the class gives (_class).
        self._docstring(node.body, None if self._is_dunder(node.name) else node.name)

    def _lambda(self, node: ast.Lambda) -> None:
        self._parameters(id(node), node.args)

    def _class(self, node: ast.ClassDef) -> None:
        entry = ("()", node.name)
        for constructor in self.CONSTRUCTORS:
            self.add(entry, ("()", constructor))
        for base in node.bases:
            self.add(self._head(base), node.name)
        for statement in node.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)) and self._is_dunder(statement.name):
                self.add(statement.name, node.name)
            elif node.bases:
                self._member(node.name, statement)
        self._docstring(node.body, node.name)

    def _member(self, cls: str, statement: ast.stmt) -> None:
        """An Enum member, or a named tuple field, gives its own name."""
        if isinstance(statement, ast.Assign):
            targets = statement.targets
        elif isinstance(statement, ast.AnnAssign):
            targets = [statement.target]
        else:
            return
        for target in targets:
            self._seed(cls, getattr(target, "id", None))

    @staticmethod
    def _is_dunder(name: str) -> bool:
        return name.startswith("__") and name.endswith("__")

    def _module(self, node: ast.Module) -> None:
        self._docstring(node.body, None)

    def _raise(self, node: ast.Raise) -> None:
        for value in (node.exc, node.cause):
            if value is not None:
                self.add(id(value), self.RAISED)

    def _except(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.add(self.RAISED, node.name)

    @staticmethod
    def _returned(body: list[ast.stmt]):
        """The values a function's own return and yield statements give."""
        pending: list[ast.AST] = list(body)
        while pending:
            node = pending.pop()
            if isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)) and node.value is not None:
                yield node.value
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                pending.extend(ast.iter_child_nodes(node))

    def _docstring(self, body: list[ast.stmt], name: str | None) -> None:
        """A docstring is what ``__doc__`` reads, and what inspect.getdoc(f)
        reads through f."""
        first = body[0] if body else None
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
            self.add(id(first.value), "__doc__")
            if name is not None:
                self.add(id(first.value), name)

    _BUILDERS: ClassVar[dict] = {
        ast.Name: _name, ast.Attribute: _attribute, ast.Call: _call, ast.ImportFrom: _import_from,
        ast.Assign: _assign, ast.AnnAssign: _ann_assign, ast.AugAssign: _aug_assign,
        ast.NamedExpr: _named_expr, ast.For: _loop, ast.AsyncFor: _loop, ast.comprehension: _loop,
        ast.With: _with, ast.AsyncWith: _with, ast.Match: _match,
        ast.FunctionDef: _function, ast.AsyncFunctionDef: _function, ast.Lambda: _lambda,
        ast.ClassDef: _class, ast.Module: _module, ast.Raise: _raise, ast.ExceptHandler: _except,
    }


# =============================================================================
# Working steps out
# =============================================================================

class StringSteps:
    """Works out string steps deepest first, carrying each value to the step
    on it. A value longer than MAX_CARRIED is carried only from a literal as
    written, so a chain of steps works on at most that much text per step
    and the work stays linear in the code."""

    def __init__(self, reach: ReachingLiterals, names: CriticalNames):
        self._reach = reach
        self._names = names
        self._values: dict[int, object] = {}
        self._hits: dict[int, str | None] = {}
        self._formats: dict[int, tuple[str | None, bool, str | None] | None] = {}
        self._readings: dict[int, object] = {}

    def check(self, node: ast.AST) -> str | None:
        """Work out ``node`` and return the critical name it can leave."""
        kind, operands = string_step(node)
        if kind is None:
            if not self._reach.regex_call(node):
                return None
            # A regex can remove anything it matches; it is not worked out.
            return self._unknown_hit(node, [*node.args, *(keyword.value for keyword in node.keywords)])
        if kind == "format":
            return self._check_format(node, *operands)
        if kind == "braces":
            return self._check_braces(node, operands)
        if isinstance(node, ast.Attribute):
            return self._check_saved_method(node)
        value = self._worked_out(node, [self._value(operand) for operand in operands])
        if value is not None:
            self._values[id(node)] = value
            return self._names.in_value(value)
        hit = self._unknown_hit(node, operands)
        return hit if kind == "remove" else None

    def _unknown_hit(self, node: ast.AST, operands) -> str | None:
        """The hit of a step not worked out: its operands' (an earlier
        step's value included), or a literal that reaches it another way,
        such as an argument (``"abc".replace("b", "xexec")``)."""
        hit = self._operand_hit(operands) or self._reach.hit(node)
        self._hits[id(node)] = hit
        return hit

    def _check_saved_method(self, node: ast.Attribute) -> str | None:
        """A str method read without being called (``f = "xexec".lstrip``)
        may be called later with any arguments: its string is matched
        anywhere, after the change a case method makes."""
        value = self._value(node.value)
        if isinstance(value, str) and node.attr in CASE_METHODS:
            hit = self._names.in_text(LITERAL_RESHAPERS[node.attr](value), self._names.in_word)
        else:
            hit = self._hit(node.value)
        self._hits[id(node)] = hit
        return hit

    def _check_format(self, node: ast.BinOp, left: ast.AST, right: ast.AST) -> str | None:
        """A %-format, worked out when the format and its arguments are
        literals. Otherwise each conversion is read both as a separator and
        as nothing, and a format that cuts what it inserts (a precision), or
        is not known or readable, is a removal."""
        value = self._formatted(left, right)
        if value is not None:
            self._values[id(node)] = value
            return self._names.in_value(value)
        hit = self._unknown_hit(node, (left, right))
        reading = self._format_reading(left)
        if reading is None:
            # 10 % n is arithmetic. A number on the right is not: %c and %x
            # insert letters ("%cexec" % 32).
            return None if _is_number(left) else hit
        # A precision cuts what is inserted, not the format's own text.
        name, cuts, joined = reading
        self._join_hit(node, joined)
        return name or (self._hit(right) if cuts else None)

    def _join_hit(self, node: ast.AST, joined: str | None) -> None:
        """A format's own text, its fields read as separators and as
        nothing, can leave a name for a later step: ("xex%sec" % "")[1:]."""
        if self._hits.get(id(node)) is None:
            self._hits[id(node)] = joined

    def _joined_names(self, pieces: list[str]) -> tuple[str | None, str | None]:
        """The critical name a format's text leaves with its fields read as
        separators or as nothing: as a whole identifier, and anywhere."""
        joined = (" ".join(pieces), "".join(pieces))
        return self._names.in_value(joined), self._names.in_value(joined, self._names.in_word)

    def _check_braces(self, node: ast.AST, inserted: list[ast.AST]) -> str | None:
        """``str.format``, ``format()`` or an f-string, read as a %-format
        whose arguments are not known: the text between its fields both as
        separated and as joined, and a precision as cutting what it inserts.
        A template that is not known or readable is a removal."""
        hit = self._unknown_hit(node, inserted)
        reading = self._brace_reading(node)
        if reading is None:
            return hit
        pieces, cuts = reading
        name, joined = self._joined_names(pieces)
        self._join_hit(node, joined)
        return name or (self._operand_hit(inserted) if cuts else None)

    def _brace_reading(self, node: ast.AST) -> tuple[list[str], bool] | None:
        parts, template = brace_template(node)
        if isinstance(node, ast.JoinedStr):
            return self._f_string_reading(parts)
        if template is None:
            # format(value, spec): a spec that is not a literal may cut.
            spec = node.args[1] if len(node.args) > 1 else None
            text = "" if spec is None else self._value(spec)
            return (["", ""], _spec_cuts(text)) if isinstance(text, str) else (["", ""], True)
        text = self._value(template)
        return read_brace_template(text) if isinstance(text, str) else None

    @staticmethod
    def _f_string_reading(parts: list[ast.AST]) -> tuple[list[str], bool]:
        pieces: list[str] = []
        piece: list[str] = []
        cuts = False
        for part in parts:
            if isinstance(part, ast.Constant):
                piece.append(str(part.value))
                continue
            pieces.append("".join(piece))
            piece = []
            spec = part.format_spec
            if spec is not None:
                texts = [value.value for value in spec.values if isinstance(value, ast.Constant)]
                cuts = cuts or len(texts) < len(spec.values) or _spec_cuts("".join(map(str, texts)))
        pieces.append("".join(piece))
        return pieces, cuts

    def _formatted(self, left: ast.AST, right: ast.AST) -> str | None:
        text = self._value(left)
        args = self._format_arguments(right)
        if not isinstance(text, str) or args is None:
            return None
        reading = self._read(text) if isinstance(left, ast.Name) else read_format(text)
        if reading is None:
            return None
        if isinstance(args, dict):
            inserted = args.values()
        else:
            inserted = args if isinstance(args, tuple) else (args,)
        # Bounded before it is built: widths and precisions pad
        # ("%999999999s" % "" is a gigabyte), and a mapping key can be used
        # by every conversion. ascii() is as long as anything %s, %r or %a
        # inserts.
        pieces, _, padding = reading
        longest = max((len(ascii(arg)) for arg in inserted), default=0)
        if len(text) + padding + (len(pieces) - 1) * longest > 4 * MAX_CARRIED:
            return None
        try:
            return text % args
        except (ValueError, TypeError, KeyError, OverflowError):
            return None

    def _format_arguments(self, node: ast.AST):
        """The arguments of a %-format when they are literals (str, or an
        int ``%c`` or ``%d`` can take): alone, in a tuple, or the values of
        a dict with str keys."""
        if isinstance(node, ast.Tuple):
            args = tuple(self._format_argument(element) for element in node.elts)
            return None if any(arg is None for arg in args) else args
        if isinstance(node, ast.Dict):
            if not all(isinstance(key, ast.Constant) and isinstance(key.value, str) for key in node.keys):
                return None
            values = [self._format_argument(value) for value in node.values]
            return None if any(value is None for value in values) else dict(zip((key.value for key in node.keys), values))
        return self._format_argument(node)

    def _format_argument(self, node: ast.AST):
        if isinstance(node, ast.Constant) and type(node.value) is int and abs(node.value) <= 0x10FFFF:
            return node.value
        value = self._value(node)
        return value if isinstance(value, str) else None

    def _format_reading(self, left: ast.AST) -> tuple[str | None, bool, str | None] | None:
        """For a format whose arguments are not known: the critical name it
        leaves as a whole identifier when each conversion becomes a
        separator or nothing, whether a conversion cuts what it inserts, and
        the name it leaves anywhere (for a later step); None when the format
        is not known or readable. A
        literal reached through names is read once, however often it is
        formatted."""
        if not isinstance(left, ast.Name):
            value = self._value(left)
            return self._read_unknown_format(value) if isinstance(value, str) else None
        text = self._reach.only(left.id)
        if text is None:
            return None
        if id(text) not in self._formats:
            self._formats[id(text)] = self._read_unknown_format(text)
        return self._formats[id(text)]

    def _read(self, text: str):
        """read_format of a literal a name holds, once per literal. The
        literal stays alive in ReachingLiterals, so its id is not reused."""
        if id(text) not in self._readings:
            self._readings[id(text)] = read_format(text)
        return self._readings[id(text)]

    def _read_unknown_format(self, text: str) -> tuple[str | None, bool, str | None] | None:
        reading = read_format(text)
        if reading is None:
            return None
        pieces, cuts, _ = reading
        name, joined = self._joined_names(pieces)
        return name, cuts, joined

    @staticmethod
    def _worked_out(node: ast.AST, values: list):
        if any(value is None for value in values):
            return None
        try:
            return step_result(node, values)
        except (ValueError, TypeError, IndexError, KeyError, OverflowError, RecursionError):
            return None

    def _value(self, operand: ast.AST):
        if isinstance(operand, ast.Constant):
            value = operand.value
            if isinstance(value, bytes):
                return value.decode("latin-1")
            return value if isinstance(value, str) else None
        if isinstance(operand, ast.Name):
            return self._reach.literal(operand.id)
        value = self._values.get(id(operand))
        if value is None:
            return None
        size = len(value) if isinstance(value, str) else sum(len(part) for part in value if isinstance(part, str))
        return value if size <= MAX_CARRIED else None

    def _hit(self, operand: ast.AST) -> str | None:
        """A critical name, anywhere, in what can reach ``operand``: the
        value a step worked out, or the literals that can reach it."""
        key = id(operand)
        if key in self._hits:
            return self._hits[key]
        if key in self._values:
            hit = self._names.in_value(self._values[key], self._names.in_word)
            self._hits[key] = hit
            return hit
        if isinstance(operand, ast.Constant) and isinstance(operand.value, (str, bytes)):
            return self._names.in_text(operand.value, self._names.in_word)
        return self._reach.hit(operand)

    def _operand_hit(self, operands) -> str | None:
        return next(filter(None, map(self._hit, operands)), None)
