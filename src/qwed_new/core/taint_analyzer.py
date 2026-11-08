"""
Taint Analysis Engine: AST-based Data Flow Tracking.

Tracks untrusted data from SOURCES to SINKS for vulnerability detection.
100% Deterministic - No probability/ML involved.

Example:
    x = input()  # SOURCE: x is tainted
    y = x        # PROPAGATION: y is now tainted  
    eval(y)      # SINK: tainted data reaches eval -> VULNERABILITY

Engine Design:
    1. Parse code into AST
    2. Identify all SOURCES (user input points)
    3. Track variable assignments (taint propagation)
    4. Check if tainted variables reach SINKS
    5. Check for SANITIZERS in the path: only a sanitiser the code imports
       itself relieves, and only where its result reaches the sink directly
"""

import ast
import re
import string
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


class TaintStatus(Enum):
    """Taint status of a variable."""
    TAINTED = "tainted"
    CLEAN = "clean"
    UNKNOWN = "unknown"


@dataclass
class TaintSource:
    """A source of tainted data."""
    name: str           # e.g., "input", "request.args.get"
    variable: str       # Variable that holds tainted data
    line: int           # Line number
    col: int = 0        # Column offset


@dataclass
class TaintSink:
    """A dangerous sink that should not receive tainted data."""
    name: str           # e.g., "eval", "exec", "os.system"
    line: int           # Line number
    col: int = 0        # Column offset
    args: List[str] = field(default_factory=list)  # Arguments passed
    arg_nodes: List[Any] = field(default_factory=list)  # Raw argument ASTs
    kw_names: List[Optional[str]] = field(default_factory=list)  # None per positional


@dataclass
class TaintVulnerability:
    """A detected taint vulnerability."""
    source: TaintSource
    sink: TaintSink
    path: List[str]     # Variable flow path from source to sink
    severity: str       # "CRITICAL", "HIGH", "MEDIUM"
    description: str
    recommendation: str


@dataclass
class TaintResult:
    """Result of taint analysis."""
    is_safe: bool
    vulnerabilities: List[TaintVulnerability] = field(default_factory=list)
    tainted_variables: Set[str] = field(default_factory=set)
    sources_found: List[TaintSource] = field(default_factory=list)
    sinks_found: List[TaintSink] = field(default_factory=list)
    error: Optional[str] = None


# How a value is read where it is used, which decides how much sanitiser
# relief it keeps. RAW: something transformed it, so no relief counts.
# OPEN: it reaches the use directly (the whole expression, a ``+`` operand,
# an f-string field with no conversion or format spec, a bare ``%s`` or a
# plain ``{}`` in ``str.format``), but the HTML before it is not known to
# end in text content. TEXT: the same, and the HTML before it does.
_RAW, _OPEN, _TEXT = 0, 1, 2
_NONE: FrozenSet[str] = frozenset()
_NO_RELIEF: Tuple[FrozenSet[str], FrozenSet[str], FrozenSet[str]] = (_NONE, _NONE, _NONE)
_NO_TAINT = _NO_RELIEF
_READ_RAW = (_RAW, _RAW, _RAW)

# One read inside an expression: a variable (with the set it is read from,
# by mode) or a source, plus the sink classes a sanitiser around the read
# relieves, by mode.
_Term = Tuple[
    Optional[str],
    Optional[TaintSource],
    Tuple[int, int, int],
    Tuple[FrozenSet[str], FrozenSet[str], FrozenSet[str]],
]

_PERCENT_FIELD = re.compile(r"%(\([^)]*\))?([#0\- +]*)(\*|\d+)?(?:\.(\*|\d*))?[hlL]?(.?)", re.S)
_PERCENT_CONVERSIONS = frozenset("diouxXeEfFgGcrsa")
_FORMATTER = string.Formatter()
_HTML_SPACE = " \t\n\f\r"
# Elements after which the HTML tokenizer reads text differently: raw text
# and RCDATA (script, style, textarea, title, ...), plaintext, and foreign
# content (svg, math). Constant text with one of these gets no relief.
_UNFOLLOWED_TAGS = frozenset({
    "script", "style", "textarea", "title", "xmp", "iframe", "noembed",
    "noframes", "noscript", "plaintext", "svg", "math",
})


def _percent_plan(template: str) -> Optional[List[Any]]:
    """The text and fields of a ``%`` template, in order, or None.

    A field is True for a bare ``%s`` and False for any other conversion.
    A mapping key, a ``*`` width or an unknown conversion gives None.
    """
    plan: List[Any] = []
    position = 0
    for match in _PERCENT_FIELD.finditer(template):
        plan.append(template[position:match.start()])
        position = match.end()
        key, flags, width, precision, conversion = match.groups()
        modified = bool(key or flags or width) or precision is not None
        if conversion == "%" and not modified:
            plan.append("%")
        elif key or "*" in (width or "") + (precision or ""):
            return None
        elif conversion not in _PERCENT_CONVERSIONS:
            return None
        else:
            plan.append(conversion == "s" and not modified)
    plan.append(template[position:])
    return plan


def _format_plan(template: str) -> Optional[List[Any]]:
    """The text and fields of a ``str.format`` template, in order, or None.

    Only automatically numbered fields are followed: a field is True for a
    plain ``{}`` and False with a conversion or format spec. Named or
    numbered fields, nested fields and malformed templates give None.
    """
    plan: List[Any] = []
    try:
        parsed = list(_FORMATTER.parse(template))
    except ValueError:
        return None
    for literal, name, spec, conversion in parsed:
        if literal:
            plan.append(literal)
        if name is None:
            continue
        if name or "{" in (spec or ""):
            return None
        plan.append(not spec and conversion is None)
    return plan


def _next_tag_state(state: str, char: str) -> str:
    """The HTML tokenizer's next state inside a tag, after ``char``.

    ``before``: before an attribute name (also after a quoted value or
    a ``/``); ``attr``: in an attribute name; ``after``: after one;
    ``value``: before an attribute value; ``unquoted``: in an unquoted
    value. A quote opens a value only in ``value``; anywhere else it is
    an ordinary character, as in a browser.
    """
    space = char in _HTML_SPACE
    if state == "value":
        if char in "\"'":
            return char
        return "value" if space else "unquoted"
    if state == "unquoted":
        return "before" if space else "unquoted"
    if char == "/":
        return "before"
    if char == "=" and state in ("attr", "after"):
        return "value"
    if space:
        return "after" if state == "attr" else state
    return "attr"


def _tag_end(low: str, start: int) -> int:
    """Index of the ``>`` that ends a tag whose name ends at ``start``.

    -1 if the text ends first, inside the tag or a quoted value.
    """
    state = "before"
    index = start
    while index < len(low):
        if state in ("\"", "'"):
            close = low.find(state, index)
            if close < 0:
                return -1
            index, state = close + 1, "before"
            continue
        char = low[index]
        if char == ">":
            return index
        state = _next_tag_state(state, char)
        index += 1
    return -1


def _after_tag(low: str, start: int) -> int:
    """Where text content resumes after the tag whose name is at ``start``.

    -1 for a tag that changes how what follows is read (raw text such as
    ``<script>`` or ``<textarea>``, foreign content such as ``<svg>``).
    """
    end = start
    while end < len(low) and low[end] not in _HTML_SPACE and low[end] not in "/>":
        end += 1
    if low[start:end] in _UNFOLLOWED_TAGS:
        return -1
    close = _tag_end(low, end)
    return close + 1 if close >= 0 else -1


def _after_bogus_comment(low: str, start: int) -> int:
    """``<?...``, ``<!...`` and ``</ ...`` end at the first ``>``."""
    close = low.find(">", start)
    return close + 1 if close >= 0 else -1


def _after_comment(low: str, start: int) -> int:
    """Where text content resumes after a comment whose ``<!--`` ends at
    ``start``: at ``-->`` or ``--!>``, or at once for ``<!-->`` and
    ``<!--->``."""
    if low.startswith(">", start):
        return start + 1
    if low.startswith("->", start):
        return start + 2
    ends = [e for e in (low.find("-->", start), low.find("--!>", start)) if e >= 0]
    if not ends:
        return -1
    close = min(ends)
    return close + (3 if low.startswith("-->", close) else 4)


def _after_end_tag_open(low: str, start: int) -> int:
    """Where text content resumes after ``</`` (which ends at ``start``).

    ``</>`` is dropped, ``</name`` is an end tag, and anything else is a
    bogus comment; ``</`` at the very end is not known to be text.
    """
    name = low[start:start + 1]
    if name == ">":
        return start + 1
    if name.isascii() and name.isalpha():
        return _after_tag(low, start)
    return _after_bogus_comment(low, start) if name else -1


def _after_markup(low: str, start: int) -> int:
    """Where text content resumes after the ``<`` at ``start``, or -1.

    Follows the HTML tokenizer: a ``<`` not followed by a letter, ``/``,
    ``!`` or ``?`` is text; a ``<`` at the very end is not known to be.
    """
    following = low[start + 1:start + 2]
    if following == "!":
        if low.startswith("--", start + 2):
            return _after_comment(low, start + 4)
        return _after_bogus_comment(low, start + 2)
    if following == "?":
        return _after_bogus_comment(low, start + 2)
    if following == "/":
        return _after_end_tag_open(low, start + 2)
    if following.isascii() and following.isalpha():
        return _after_tag(low, start + 1)
    return start + 1 if following else -1


def _html_ends_in_text(html_text: str) -> bool:
    """Whether HTML that starts in text content also ends in text content.

    Anything it cannot follow counts as not text: text that ends inside
    markup, and any element that changes how the rest is read.
    """
    low = html_text.lower()
    index = 0
    while index >= 0:
        start = low.find("<", index)
        if start < 0:
            return True
        index = _after_markup(low, start)
    return False


def _is_str_constant(node: ast.AST) -> bool:
    """Whether ``node`` is a string literal."""
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _is_format_call(node: ast.AST) -> bool:
    """Whether ``node`` is ``"<literal>".format(...)``."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and _is_str_constant(node.func.value)
    )


class TaintAnalyzer:
    """
    AST-based Taint Analysis for Python Code.
    
    Tracks untrusted data (taint) from sources to sinks using
    data flow analysis. 100% deterministic.
    
    Sources (untrusted data entry points):
        - input(), sys.stdin
        - every request.<attr> read (args, form, data, path, ...)
        - os.environ, os.getenv, sys.argv
    
    Sinks (dangerous operations):
        - eval(), exec(), compile()
        - os.system(), subprocess.call/run/Popen
        - pickle.loads(), yaml.load()
        - SQL queries, file paths, URLs, mark_safe, render_template_string

    Sanitizers (each relieves only the sink classes it protects):
        - int(), float(), bool(): every class
        - html.escape, markupsafe.escape, django.utils.html.escape: HTML
        - werkzeug.utils.secure_filename: file paths
        A sanitiser relieves only when the code imports it itself (or, for
        the builtins, never binds the name), never rebinds or patches it,
        uses no reflection, and its result reaches the sink directly.
        There is no shell sanitiser: shlex.quote protects one word, but the
        command around it decides what the word does.
    """
    
    # =========================================================================
    # Source Patterns (Functions that introduce tainted data)
    # =========================================================================
    
    SOURCES: Dict[str, str] = {
        # User input
        "input": "User input from stdin",
        "raw_input": "User input (Python 2)",
        
        # Web frameworks
        "request.args.get": "Flask URL parameter",
        "request.form.get": "Flask form data",
        "request.data": "Flask raw request body",
        "request.json": "Flask JSON body",
        "request.files": "Flask uploaded files",
        "request.GET.get": "Django GET parameter",
        "request.POST.get": "Django POST parameter",
        
        # Environment
        "os.environ.get": "Environment variable",
        "os.getenv": "Environment variable",
        "os.environ": "Environment variables",
        
        # Command line
        "sys.argv": "Command line argument",
        "argparse": "Parsed command line argument",
    }
    
    # Source function names (for simple matching)
    SOURCE_FUNCTIONS: Set[str] = {
        "input", "raw_input", "read", "readline", "readlines",
        "recv", "recvfrom", "get", "getenv"
    }
    
    # =========================================================================
    # Sink Patterns (Dangerous functions that should not receive tainted data)
    # =========================================================================
    
    SINKS: Dict[str, Tuple[str, str]] = {
        # Code execution (CRITICAL)
        "eval": ("CRITICAL", "Remote code execution"),
        "exec": ("CRITICAL", "Remote code execution"),
        "compile": ("CRITICAL", "Dynamic code compilation"),
        "__import__": ("CRITICAL", "Dynamic module import"),
        
        # System commands (CRITICAL)
        "os.system": ("CRITICAL", "Command injection"),
        "os.popen": ("CRITICAL", "Command injection"),
        "subprocess.call": ("CRITICAL", "Command injection"),
        "subprocess.run": ("CRITICAL", "Command injection"),
        "subprocess.Popen": ("CRITICAL", "Command injection"),
        "subprocess.check_output": ("CRITICAL", "Command injection"),
        
        # Deserialization (CRITICAL)
        "pickle.loads": ("CRITICAL", "Insecure deserialization"),
        "pickle.load": ("CRITICAL", "Insecure deserialization"),
        "yaml.load": ("CRITICAL", "Insecure YAML parsing"),
        "yaml.unsafe_load": ("CRITICAL", "Insecure YAML parsing"),
        "marshal.loads": ("CRITICAL", "Insecure deserialization"),
        
        # Database (HIGH)
        "cursor.execute": ("HIGH", "SQL injection"),
        "execute": ("HIGH", "Potential SQL injection"),
        
        # File operations (HIGH)  
        "open": ("HIGH", "Path traversal"),
        "shutil.copy": ("HIGH", "Path traversal"),
        "shutil.move": ("HIGH", "Path traversal"),
        "os.remove": ("HIGH", "Path traversal"),
        "os.unlink": ("HIGH", "Path traversal"),
        
        # Network (MEDIUM)
        "requests.get": ("MEDIUM", "SSRF"),
        "requests.post": ("MEDIUM", "SSRF"),
        "urllib.request.urlopen": ("MEDIUM", "SSRF"),

        # HTML / template output (HIGH)
        "render_template_string": ("HIGH", "Cross-site scripting (XSS)"),
        "mark_safe": ("HIGH", "Cross-site scripting (XSS)"),
    }
    
    SINK_FUNCTIONS: Set[str] = {
        "eval", "exec", "compile", "system", "popen",
        "call", "run", "Popen", "check_output",
        "loads", "load", "execute", "open",
        "render_template_string", "mark_safe"
    }
    
    # =========================================================================
    # Sanitizer Patterns (Functions that clean tainted data)
    # =========================================================================
    
    #: Maps a sink's short name (last dotted component) to its sink class.
    #: Unknown sinks fall back to "generic", which no sanitiser cleans.
    SINK_CATEGORIES: Dict[str, str] = {
        "eval": "code",
        "exec": "code",
        "compile": "code",
        "__import__": "code",
        "system": "shell",
        "popen": "shell",
        "call": "shell",
        "run": "shell",
        "Popen": "shell",
        "check_output": "shell",
        "loads": "deserialize",
        "load": "deserialize",
        "unsafe_load": "deserialize",
        "execute": "sql",
        "executemany": "sql",
        "open": "path",
        "copy": "path",
        "move": "path",
        "remove": "path",
        "unlink": "path",
        "get": "network",
        "post": "network",
        "urlopen": "network",
        "render_template_string": "template",
        "mark_safe": "html",
    }

    #: Every sink class a fresh source is tainted for.
    #: ``template`` (SSTI via render_template_string) is separate from
    #: ``html`` (XSS via mark_safe): HTML sanitisers do not neutralise
    #: template instructions such as ``{{ ... }}``.
    ALL_TAINT_CATEGORIES: Set[str] = {
        "code", "shell", "deserialize", "sql",
        "path", "network", "html", "template", "generic",
    }

    #: Builtin casts: the result is a number or a boolean, safe for every
    #: sink class. Trusted only while the code never binds the name itself.
    UNIVERSAL_SANITIZERS: Set[str] = {"int", "float", "bool"}

    #: HTML escapers that also escape quotes, by full name. They relieve
    #: only the ``html`` class, and only where the HTML before the value
    #: ends in text content (not inside a tag, a comment, a script or a
    #: style). ``html.escape`` with ``quote`` not True relieves nothing.
    HTML_SANITIZERS: Set[str] = {
        "html.escape", "markupsafe.escape", "markupsafe.Markup.escape",
        "django.utils.html.escape",
    }

    #: Filename cleaners, by full name. They relieve only the ``path`` class.
    PATH_SANITIZERS: Set[str] = {
        "werkzeug.utils.secure_filename", "werkzeug.secure_filename",
    }

    #: Backwards-compatible union of every known sanitiser name.
    #: This union is not consulted by the analysis itself.
    SANITIZERS: Set[str] = (
        UNIVERSAL_SANITIZERS | HTML_SANITIZERS | PATH_SANITIZERS
    )

    #: Keyword arguments that never carry an injected payload, by sink class.
    #: Every other keyword value is inspected (fail closed), and so is every
    #: keyword of a sink class not listed here. ``env=os.environ`` and
    #: ``env=os.environ.copy()`` pass the environment through unchanged and
    #: are not inspected either.
    SAFE_KEYWORDS: Dict[str, FrozenSet[str]] = {
        "shell": frozenset({
            "shell", "check", "timeout", "capture_output", "text",
            "universal_newlines", "encoding", "errors", "bufsize",
            "close_fds", "stdin", "stdout", "stderr", "start_new_session",
        }),
        "network": frozenset({
            "params", "data", "json", "headers", "cookies", "files",
            "auth", "timeout", "allow_redirects", "stream",
        }),
        "sql": frozenset({
            "params", "parameters", "args", "vars", "seq_of_parameters",
            "vars_list", "multi",
        }),
    }

    #: Code that could replace a sanitiser at run time gets no sanitiser
    #: relief at all: code that reads one of these names (reflection,
    #: dynamic code), reads one of these attributes (namespaces, frames,
    #: code objects, a builtin's module, attribute lookups by a string),
    #: imports one of these modules
    #: (reflection, object loaders), stores to any special ``__name__``
    #: attribute or to an attribute named like part of a sanitiser
    #: (``html.escape = str``), or stores to any attribute of a name it
    #: imports.
    REFLECTIVE_NAMES: FrozenSet[str] = frozenset({
        "getattr", "setattr", "delattr", "vars", "globals", "locals",
        "exec", "eval", "compile", "__import__", "__builtins__",
        "breakpoint",
    })
    REFLECTIVE_ATTRIBUTES: FrozenSet[str] = frozenset({
        "modules", "f_globals", "f_locals", "f_builtins", "_getframe",
        # Attribute lookups by a string.
        "getattr", "attrgetter", "methodcaller", "Formatter", "get_field",
        "__dict__", "__setattr__", "__delattr__", "__getattribute__",
        "__globals__", "__builtins__", "__code__", "__closure__",
        "__self__", "__func__", "__class__", "__base__", "__bases__",
        "__mro__", "__subclasses__", "__reduce__", "__reduce_ex__",
        "__loader__", "__spec__", "__import__",
    })
    REFLECTIVE_MODULES: FrozenSet[str] = frozenset({
        "builtins", "importlib", "gc", "ctypes", "pickle", "_pickle",
        "marshal", "shelve", "dill", "cloudpickle", "joblib", "copyreg",
        "yaml", "runpy", "code", "codeop", "inspect",
    })
    #: Every part of every sanitiser name (``html``, ``escape``, ``int``).
    SANITIZER_PARTS: FrozenSet[str] = frozenset(
        part for name in SANITIZERS for part in name.split(".")
    )
    
    def __init__(self):
        """Initialize the Taint Analyzer."""
        self._reset()

    def _reset(self) -> None:
        """Clear the state of the previous analysis."""
        # var -> the source a direct assignment (x = input()) gave it.
        self._taint_sources: Dict[str, TaintSource] = {}
        self._flow_graph: Dict[str, Set[str]] = {}  # var -> depends_on
        # var -> every expression ever assigned to it. Taint is the union
        # over the list, so a reassignment on another branch (or a later
        # plain assignment) never drops taint from an earlier one.
        self._flow_rhs: Dict[str, List[ast.AST]] = {}
        self._terms: Dict[str, List[_Term]] = {}
        # var -> sink classes it is tainted for, read RAW, OPEN and TEXT.
        self._sets: Dict[str, Tuple[FrozenSet[str], ...]] = {}
        # name -> each binding: the imported full name, or None for any
        # other binding (assignment, def, class, parameter, ...).
        self._bindings: Dict[str, List[Optional[str]]] = {}
        self._stored_roots: Set[str] = set()
        self._relief_allowed = True
        self._calls: List[ast.Call] = []
        self._sources: List[TaintSource] = []
    
    def analyze(self, code: str) -> Dict[str, Any]:
        """
        Analyze Python code for taint vulnerabilities.
        
        Args:
            code: Python source code to analyze.
            
        Returns:
            Dict with analysis results.
            
        Example:
            >>> analyzer = TaintAnalyzer()
            >>> result = analyzer.analyze("x = input(); eval(x)")
            >>> print(result["is_safe"])
            False
        """
        self._reset()
        
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return {
                "is_safe": False,
                "error": f"Syntax error: {e}",
                "vulnerabilities": [],
                "tainted_variables": set(),
                "sources_found": [],
                "sinks_found": []
            }
        
        # Phase 1: one walk collects sources, assignments, bindings and calls
        self._scan(tree)
        sources = self._sources

        # Phase 2: build the data flow and propagate taint to a fixed point
        self._compile_assignments()
        self._propagate_taint()
        
        # Phase 3: Find all sinks
        sinks = self._find_sinks()
        
        # Phase 4: Check if tainted data reaches sinks
        vulnerabilities = self._find_vulnerabilities(sources, sinks)
        
        is_safe = len(vulnerabilities) == 0
        
        return {
            "is_safe": is_safe,
            "status": "SAFE" if is_safe else "VULNERABLE",
            "vulnerabilities": [
                {
                    "severity": v.severity,
                    "description": v.description,
                    "source": {
                        "name": v.source.name,
                        "variable": v.source.variable,
                        "line": v.source.line
                    },
                    "sink": {
                        "name": v.sink.name,
                        "line": v.sink.line,
                        "args": v.sink.args
                    },
                    "flow_path": v.path,
                    "recommendation": v.recommendation
                }
                for v in vulnerabilities
            ],
            "tainted_variables": sorted(self._get_all_tainted()),
            "sources_found": [
                {"name": s.name, "variable": s.variable, "line": s.line}
                for s in sources
            ],
            "sinks_found": [
                {"name": s.name, "line": s.line, "args": s.args}
                for s in sinks
            ],
            "summary": {
                "total_sources": len(sources),
                "total_sinks": len(sinks),
                "total_vulnerabilities": len(vulnerabilities),
                "critical": sum(1 for v in vulnerabilities if v.severity == "CRITICAL"),
                "high": sum(1 for v in vulnerabilities if v.severity == "HIGH"),
                "medium": sum(1 for v in vulnerabilities if v.severity == "MEDIUM")
            }
        }
    
    # =========================================================================
    # Phase 1: one walk over the tree
    # =========================================================================

    def _scan(self, tree: ast.AST) -> None:
        """Collect sources, assignments, name bindings and calls."""
        handlers = _SCAN_HANDLERS
        calls = self._calls
        for node in ast.walk(tree):
            kind = type(node)
            if kind is ast.Call:
                calls.append(node)
                continue
            handler = handlers.get(kind)
            if handler is not None:
                handler(self, node)
        for root in self._stored_roots:
            # An attribute stored on an imported name (``html.escape = str``)
            # may replace a sanitiser.
            if any(site is not None for site in self._bindings.get(root, ())):
                self._relief_allowed = False

    def _bind(self, name: str, imported: Optional[str] = None) -> None:
        """Record one binding of ``name``."""
        self._bindings.setdefault(name, []).append(imported)

    def _scan_name(self, node: ast.Name) -> None:
        """A name read may be reflective; a name stored or deleted binds it."""
        if isinstance(node.ctx, ast.Load):
            if node.id in self.REFLECTIVE_NAMES:
                self._relief_allowed = False
        else:
            self._bind(node.id)

    def _scan_attribute(self, node: ast.Attribute) -> None:
        """Reflective attributes and stores that may patch end relief."""
        attr = node.attr
        if attr in self.REFLECTIVE_ATTRIBUTES:
            self._relief_allowed = False
        if isinstance(node.ctx, ast.Load):
            return
        if (attr.startswith("__") and attr.endswith("__")) or (
            attr in self.SANITIZER_PARTS
        ):
            self._relief_allowed = False
        root = node.value
        while isinstance(root, ast.Attribute):
            root = root.value
        if isinstance(root, ast.Name):
            self._stored_roots.add(root.id)

    def _scan_import(self, node: ast.AST) -> None:
        """Record what each imported name is bound to."""
        for alias in node.names:
            if alias.name == "*":
                # A star import may bind any name, sanitisers included.
                self._relief_allowed = False
                continue
            if isinstance(node, ast.Import):
                root, bound, imported = self._import_binding(alias)
            else:
                root, bound, imported = self._import_from_binding(node, alias)
            if root in self.REFLECTIVE_MODULES:
                self._relief_allowed = False
            self._bind(bound, imported)

    @staticmethod
    def _import_binding(alias: ast.alias) -> Tuple[str, str, Optional[str]]:
        """Module root, bound name and full name of ``import a.b [as c]``."""
        root = alias.name.split(".")[0]
        if alias.asname:
            return root, alias.asname, alias.name
        return root, root, root

    def _import_from_binding(
        self, node: ast.ImportFrom, alias: ast.alias
    ) -> Tuple[str, str, Optional[str]]:
        """Module root, bound name and full name of ``from m import n``.

        A relative import has no known full name. Importing a reflective
        name (``from builtins import setattr``) ends relief.
        """
        module = node.module or ""
        if alias.name in self.REFLECTIVE_NAMES or alias.name in self.REFLECTIVE_ATTRIBUTES:
            self._relief_allowed = False
        imported = None if node.level else f"{module}.{alias.name}"
        return module.split(".")[0], alias.asname or alias.name, imported

    def _scan_parameter(self, node: ast.arg) -> None:
        """A function or lambda parameter binds its name."""
        self._bind(node.arg)

    def _scan_named(self, node: ast.AST) -> None:
        """Defs, classes, ``except ... as`` and case captures bind a name."""
        if node.name:
            self._bind(node.name)

    def _scan_mapping_rest(self, node: ast.MatchMapping) -> None:
        """``case {**rest}`` binds ``rest``."""
        if node.rest:
            self._bind(node.rest)

    def _scan_assignment(self, node: ast.AST) -> None:
        """Record what an assignment stores and any direct source in it."""
        if isinstance(node, ast.Assign):
            for target in node.targets:
                self._record_assignment(target, node.value)
                self._mark_assign_source(target, node.value, node.lineno)
        elif isinstance(node, ast.AugAssign):
            self._record_aug_assignment(node.target, node.value, node.op)
        elif node.value is not None:
            # Annotated assignment (x: str = input()) or named expression
            # (if (x := input()):).
            self._record_assignment(node.target, node.value)
            source = self._check_source_expr(node.value)
            if source:
                self._mark_source_target(node.target, source, node.lineno)

    def _mark_assign_source(
        self,
        target: ast.AST,
        value: ast.AST,
        lineno: int,
    ) -> None:
        """Mark direct sources, pairing tuple targets element-wise.

        ``safe, bad = "ls", input()`` taints only ``bad``: each target
        is checked against its own element. Anything else (unequal
        lengths, starred elements, non-literal RHS) falls back to
        checking the whole RHS for every target.
        """
        if self._is_pairwise_unpacking(target, value):
            for elt, val in zip(target.elts, value.elts):
                self._mark_assign_source(elt, val, lineno)
            return
        source = self._check_source_expr(value)
        if source:
            self._mark_source_target(target, source, lineno)

    def _mark_source_target(
        self,
        target: ast.AST,
        source: TaintSource,
        lineno: int,
    ) -> None:
        """Record that an assignment target now holds source taint."""
        if isinstance(target, ast.Starred):
            self._mark_source_target(target.value, source, lineno)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._mark_source_target(elt, source, lineno)
        elif isinstance(target, ast.Name):
            tainted = TaintSource(
                name=source.name, variable=target.id, line=lineno
            )
            self._sources.append(tainted)
            self._taint_sources[target.id] = tainted

    @staticmethod
    def _is_pairwise_unpacking(target: ast.AST, value: ast.AST) -> bool:
        """Whether tuple targets pair element-wise with a literal RHS."""
        return (
            isinstance(target, (ast.Tuple, ast.List))
            and isinstance(value, (ast.Tuple, ast.List))
            and len(target.elts) == len(value.elts)
            and not any(isinstance(e, ast.Starred) for e in target.elts)
            and not any(isinstance(e, ast.Starred) for e in value.elts)
        )

    def _record_assignment(self, target: ast.AST, value: ast.AST) -> None:
        """Record an assignment target and the expression assigned to it.

        Every RHS is appended (never overwritten) so the union over all
        of them keeps branch taint. Tuple unpacking against a literal
        tuple/list RHS pairs element-wise, so only the targets whose
        own element is tainted inherit taint.
        """
        if isinstance(target, (ast.Tuple, ast.List)):
            if self._is_pairwise_unpacking(target, value):
                for elt, val in zip(target.elts, value.elts):
                    self._record_assignment(elt, val)
            else:
                for elt in target.elts:
                    if isinstance(elt, ast.Starred):
                        self._record_assignment(elt.value, value)
                    else:
                        self._record_assignment(elt, value)
        elif isinstance(target, ast.Name):
            self._flow_rhs.setdefault(target.id, []).append(value)

    def _record_aug_assignment(
        self, target: ast.AST, value: ast.AST, op: ast.AST
    ) -> None:
        """Record ``x <op>= value`` as ``x = x <op> value``.

        The self-reference keeps every earlier assignment's taint (the
        union over all of them), and the expression stays the size of
        this one statement however many ``+=`` follow.
        """
        if not isinstance(target, ast.Name):
            return
        combined = ast.BinOp(
            left=ast.Name(id=target.id, ctx=ast.Load()), op=op, right=value
        )
        self._flow_rhs.setdefault(target.id, []).append(combined)

    # =========================================================================
    # Sources
    # =========================================================================

    def _check_source_call(self, node: ast.AST) -> Optional[TaintSource]:
        """Check if a node is a taint source call.

        A call is a source when its full dotted name is listed, when its
        name is a listed source function, when its last dotted segment is
        a listed source function other than the generic ``get``
        (``sys.stdin.readline``, ``conn.recv``; not ``os.getcwd`` or
        ``some_dict.get``), or when it reads from the request object.
        """
        if not isinstance(node, ast.Call):
            return None
        func_name = self._get_func_name(node.func)
        last = func_name.rsplit(".", 1)[-1]
        if (
            func_name in self.SOURCES
            or func_name in self.SOURCE_FUNCTIONS
            or (last != "get" and last in self.SOURCE_FUNCTIONS)
            or self._is_request_reference(func_name)
        ):
            return TaintSource(name=func_name, variable="", line=node.lineno)
        return None

    @staticmethod
    def _is_request_reference(dotted: Optional[str]) -> bool:
        """Whether a dotted name reads from the request object.

        Every ``request.<attr>`` read is a source (``request.path``,
        ``request.META["X"]``, ``request.method``, ``request.args.get``),
        also as ``self.request.<attr>`` or ``flask.request.<attr>``. The
        HTTP method grammar allows ``|``, ``&``, ``$`` and backticks, so no
        attribute is exempt. ``urllib.request.urlopen`` is not one.
        """
        if not dotted:
            return False
        parts = dotted.split(".")
        if parts[0] == "request":
            return len(parts) >= 2
        return (
            len(parts) >= 3
            and parts[1] == "request"
            and parts[0] in ("self", "flask")
        )

    def _check_source_expr(self, node: ast.AST) -> Optional[TaintSource]:
        """Check if an expression directly introduces tainted data.

        Covers source calls (``x = input()``) as well as direct reads of
        source attributes/subscripts (``x = sys.argv[1]``).
        """
        if isinstance(node, ast.Call):
            return self._check_source_call(node)
        dotted = self._get_source_name(node)
        if dotted is not None and (
            dotted in self.SOURCES or self._is_request_reference(dotted)
        ):
            return TaintSource(
                name=dotted,
                variable="",
                line=getattr(node, "lineno", 0)
            )
        return None

    def _source_of(self, node: ast.AST) -> Optional[TaintSource]:
        """The source a call or an attribute/subscript read is, if any."""
        if isinstance(node, ast.Call):
            return self._check_source_call(node)
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            return self._check_source_expr(node)
        return None

    def _get_source_name(self, node: ast.AST) -> Optional[str]:
        """Dotted name of a source reference, unwrapping subscripts."""
        while isinstance(node, ast.Subscript):
            node = node.value
        if isinstance(node, (ast.Name, ast.Attribute)):
            return self._get_func_name(node)
        return None
    
    def _get_func_name(self, node: ast.AST) -> str:
        """Extract function name from a call node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            # e.g., request.args.get -> "request.args.get"
            parts = []
            current = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""
    
    # =========================================================================
    # Sanitisers
    # =========================================================================

    def _resolve(self, node: ast.AST) -> Optional[str]:
        """The full name a callee resolves to through the code's imports.

        ``html.escape`` resolves to ``html.escape`` only after ``import
        html``; a bare ``escape`` resolves only through ``from html import
        escape``. A name bound in any other way (def, assignment,
        parameter, a different import) does not resolve. A builtin name
        resolves to itself only while the code never binds it.
        """
        parts: List[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name):
            return None
        sites = self._bindings.get(node.id)
        if not sites:
            if not parts and node.id in self.UNIVERSAL_SANITIZERS:
                return node.id
            return None
        root = sites[0]
        if root is None or any(site != root for site in sites):
            return None
        parts.append(root)
        return ".".join(reversed(parts))

    def _call_relief(
        self, node: ast.Call, in_text: bool
    ) -> Optional[Tuple[FrozenSet[str], FrozenSet[str], FrozenSet[str]]]:
        """Sink classes a sanitiser call relieves, by mode, or None."""
        if not self._relief_allowed:
            return None
        name = self._resolve(node.func)
        if name in self.UNIVERSAL_SANITIZERS:
            every = frozenset(self.ALL_TAINT_CATEGORIES)
            return (_NONE, every, every)
        if name in self.PATH_SANITIZERS:
            path = frozenset({"path"})
            return (_NONE, path, path)
        if name in self.HTML_SANITIZERS and self._escapes_quotes(node, name):
            return (_NONE, _NONE, frozenset({"html"}) if in_text else _NONE)
        return None

    @staticmethod
    def _escapes_quotes(node: ast.Call, name: str) -> bool:
        """Whether an HTML escaper call also escapes quotes.

        ``html.escape(s, quote=False)`` leaves quotes alone, so a value
        placed in an attribute could close it. Any second argument or
        ``quote`` keyword must be the literal True, and nothing may be
        passed through ``*`` or ``**``.
        """
        if name != "html.escape":
            return True
        if any(isinstance(arg, ast.Starred) for arg in node.args):
            return False
        flags = list(node.args[1:])
        for keyword in node.keywords:
            if keyword.arg == "quote":
                flags.append(keyword.value)
            elif keyword.arg != "s":
                return False
        return all(
            isinstance(flag, ast.Constant) and flag.value is True
            for flag in flags
        )

    # =========================================================================
    # Phase 2: expressions to reads, and propagation
    # =========================================================================

    def _expand(self, node: ast.AST) -> List[Any]:
        """One step of flattening ``node`` into output segments.

        Returns, in output order, text (str), finished segments
        ``(node, direct)`` and nodes still to flatten. Only ``+``, plain
        f-string fields, ``%s`` and plain ``{}`` pass a value through
        unchanged; anything else is a segment of its own.
        """
        if isinstance(node, ast.Constant):
            return [node.value] if isinstance(node.value, str) else [(node, True)]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return [node.left, node.right]
        if isinstance(node, ast.JoinedStr):
            return [self._fstring_item(value) for value in node.values]
        items = self._template_items(node)
        return items if items is not None else [(node, True)]

    @staticmethod
    def _fstring_item(value: ast.AST) -> Any:
        """A plain f-string field passes its value through; others do not."""
        if isinstance(value, ast.FormattedValue):
            if value.conversion == -1 and value.format_spec is None:
                return value.value
            return (value, False)
        return value

    def _template_items(self, node: ast.AST) -> Optional[List[Any]]:
        """Items of ``"..." % values`` or ``"...".format(values)``, or None."""
        if (
            isinstance(node, ast.BinOp)
            and isinstance(node.op, ast.Mod)
            and _is_str_constant(node.left)
        ):
            plan = _percent_plan(node.left.value)
            if isinstance(node.right, ast.Tuple):
                values = list(node.right.elts)
            else:
                values = [node.right]
            exact = True
        elif _is_format_call(node) and not node.keywords:
            plan = _format_plan(node.func.value.value)
            values = list(node.args)
            exact = False
        else:
            return None
        return self._fill_template(plan, values, exact)

    @staticmethod
    def _fill_template(
        plan: Optional[List[Any]], values: List[ast.AST], exact: bool
    ) -> Optional[List[Any]]:
        """Pair template fields with their values, in output order."""
        if plan is None or any(isinstance(v, ast.Starred) for v in values):
            return None
        fields = sum(1 for part in plan if isinstance(part, bool))
        if fields > len(values) or (exact and fields != len(values)):
            return None
        items: List[Any] = []
        remaining = iter(values)
        for part in plan:
            if isinstance(part, bool):
                value = next(remaining)
                items.append(value if part else (value, False))
            else:
                items.append(part)
        return items

    def _segments(self, root: ast.AST) -> List[Any]:
        """Flatten an expression into text and ``(node, direct)`` segments."""
        segments: List[Any] = []
        stack: List[Any] = [root]
        while stack:
            item = stack.pop()
            if isinstance(item, (str, tuple)):
                segments.append(item)
            else:
                stack.extend(reversed(self._expand(item)))
        return segments

    def _compile(self, root: ast.AST) -> List[_Term]:
        """Every variable and source read in an expression, with relief.

        A sanitiser relieves only when its result reaches the expression
        directly, and an HTML escaper only when the constant text before
        it ends in HTML text content. A variable used directly is read
        with the relief its own assignments earned; used anywhere else
        (sliced, stripped, passed to another call) it is read RAW.

        The HTML before a value is known only while everything before it
        is constant text or a sanitiser result, whose output holds no
        ``<`` or quote. Each stretch of text is scanned once.
        """
        if isinstance(root, ast.Name):
            return [(root.id, None, (_RAW, _OPEN, _TEXT), _NO_RELIEF)]
        terms: List[_Term] = []
        # Constant text written since the HTML was last known to be in
        # text content, or None once something unknown was written.
        pending: Optional[List[str]] = []
        for segment in self._segments(root):
            if isinstance(segment, str):
                if pending is not None:
                    pending.append(segment)
                continue
            in_text = pending is not None and _html_ends_in_text("".join(pending))
            pending = [] if self._segment_terms(segment, in_text, terms) else None
        return terms

    def _segment_terms(
        self, segment: Tuple[ast.AST, bool], in_text: bool, terms: List[_Term]
    ) -> bool:
        """Reads of one value segment; True if text content stays text."""
        node, direct = segment
        if not direct:
            self._read_terms(node, _NO_RELIEF, terms)
            return False
        return self._direct_terms(node, in_text, terms) and in_text

    def _direct_terms(
        self, node: ast.AST, in_text: bool, terms: List[_Term]
    ) -> bool:
        """Reads of a value that reaches the expression directly.

        Returns True for a sanitiser call that relieves: its output holds
        no ``<`` or quote, so text content stays text content.
        """
        if isinstance(node, ast.Name):
            reads = (_RAW, _OPEN, _TEXT if in_text else _OPEN)
            terms.append((node.id, None, reads, _NO_RELIEF))
            return False
        relief = None
        if isinstance(node, ast.Call):
            relief = self._call_relief(node, in_text)
        if relief is None:
            self._read_terms(node, _NO_RELIEF, terms)
            return False
        for arg in node.args:
            self._read_terms(arg, relief, terms)
        for keyword in node.keywords:
            self._read_terms(keyword.value, relief, terms)
        return True

    def _read_terms(
        self,
        node: ast.AST,
        relief: Tuple[FrozenSet[str], FrozenSet[str], FrozenSet[str]],
        terms: List[_Term],
    ) -> None:
        """RAW reads of every variable and source inside ``node``.

        A source's own parts are not searched again, so
        ``request.args.get("c")`` is one read, not two.
        """
        stack = [node]
        while stack:
            current = stack.pop()
            if isinstance(current, ast.Name):
                if isinstance(current.ctx, ast.Load):
                    terms.append((current.id, None, _READ_RAW, relief))
                continue
            source = self._source_of(current)
            if source is not None:
                terms.append((None, source, _READ_RAW, relief))
                continue
            stack.extend(ast.iter_child_nodes(current))

    def _compile_assignments(self) -> None:
        """Compile every assigned expression into reads, once."""
        for var, rhs_list in self._flow_rhs.items():
            terms: List[_Term] = []
            for rhs in rhs_list:
                terms.extend(self._compile(rhs))
            self._terms[var] = terms
            self._flow_graph[var] = {t[0] for t in terms if t[0] is not None}

    def _evaluate(self, terms: List[_Term]) -> Tuple[FrozenSet[str], ...]:
        """Sink classes the reads taint, by mode (RAW, OPEN, TEXT)."""
        result: Tuple[Set[str], Set[str], Set[str]] = (set(), set(), set())
        every = self.ALL_TAINT_CATEGORIES
        for var, source, reads, relief in terms:
            if source is not None:
                bases: Tuple[Any, ...] = (every, every, every)
            else:
                sets = self._sets.get(var)
                if sets is None:
                    continue
                bases = (sets[reads[0]], sets[reads[1]], sets[reads[2]])
            for mode in (_RAW, _OPEN, _TEXT):
                result[mode].update(bases[mode] - relief[mode])
        return (frozenset(result[0]), frozenset(result[1]), frozenset(result[2]))

    def _dependents(self) -> Dict[str, Set[str]]:
        """var -> the variables whose assigned expressions read it."""
        dependents: Dict[str, Set[str]] = {}
        for var, terms in self._terms.items():
            for term in terms:
                if term[0] is not None:
                    dependents.setdefault(term[0], set()).add(var)
        return dependents

    def _propagate_taint(self) -> None:
        """Propagate taint to a fixed point with a worklist.

        Taint only ever grows, so the worklist reaches the fixed point
        without a pass limit, and a variable is evaluated again only
        when something it reads has changed.
        """
        dependents = self._dependents()
        queue = deque(self._terms)
        queued = set(self._terms)
        while queue:
            var = queue.popleft()
            queued.discard(var)
            new = self._evaluate(self._terms[var])
            if new == self._sets.get(var, _NO_TAINT):
                continue
            self._sets[var] = new
            for dependent in dependents.get(var, ()):
                if dependent not in queued:
                    queued.add(dependent)
                    queue.append(dependent)

    # =========================================================================
    # Phase 3: sinks
    # =========================================================================

    def _find_sinks(self) -> List[TaintSink]:
        """Find all sink calls among the calls the walk collected."""
        sinks = []
        for node in self._calls:
            func_name = self._get_func_name(node.func)
            if func_name not in self.SINKS and not any(
                sink_func in func_name for sink_func in self.SINK_FUNCTIONS
            ):
                continue
            arg_nodes, kw_names = self._sink_arguments(
                node, self._sink_category(func_name)
            )
            sinks.append(TaintSink(
                name=func_name,
                line=node.lineno,
                args=[self._node_to_str(arg) for arg in arg_nodes],
                arg_nodes=arg_nodes,
                kw_names=kw_names
            ))
        return sinks

    def _sink_arguments(
        self, node: ast.Call, category: str
    ) -> Tuple[List[Any], List[Optional[str]]]:
        """Positional arguments and every keyword that can carry a payload.

        ``**`` expansions are always kept, marked ``"**"`` so they are never
        mistaken for positional arguments.
        """
        safe = self.SAFE_KEYWORDS.get(category, _NONE)
        arg_nodes: List[Any] = list(node.args)
        kw_names: List[Optional[str]] = [None] * len(node.args)
        for keyword in node.keywords:
            if keyword.arg in safe or (
                category == "shell"
                and keyword.arg == "env"
                and self._is_environ_passthrough(keyword.value)
            ):
                continue
            arg_nodes.append(keyword.value)
            kw_names.append(keyword.arg if keyword.arg is not None else "**")
        return arg_nodes, kw_names

    def _is_environ_passthrough(self, node: ast.AST) -> bool:
        """``os.environ`` or ``os.environ.copy()``, with ``os`` imported."""
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "copy"
            and not node.args
            and not node.keywords
        ):
            node = node.func.value
        return self._relief_allowed and self._resolve(node) == "os.environ"
    
    def _node_to_str(self, node: ast.AST) -> str:
        """Convert AST node to string representation."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Constant):
            return repr(node.value)
        elif isinstance(node, ast.BinOp):
            return f"({self._node_to_str(node.left)} op {self._node_to_str(node.right)})"
        elif isinstance(node, ast.Call):
            return f"{self._get_func_name(node.func)}(...)"
        return "<expr>"
    
    def _sink_category(self, func_name: str) -> str:
        """Sink class of a sink call (falls back to "generic")."""
        return self.SINK_CATEGORIES.get(func_name.split(".")[-1], "generic")

    # =========================================================================
    # Phase 4: findings
    # =========================================================================

    def _relevant_args(self, sink: TaintSink, category: str) -> List[Any]:
        """The sink arguments that can inject.

        Parameter binding is the SQL sanitiser: only the query can inject.
        The query is the first positional argument if there is one,
        otherwise every keyword kept for the sink and every ``**``
        expansion (fail closed: an expansion may carry the query).
        """
        if category != "sql":
            return sink.arg_nodes
        positionals = [
            arg for arg, name in zip(sink.arg_nodes, sink.kw_names)
            if name is None
        ]
        if positionals:
            return positionals[:1]
        return list(sink.arg_nodes)

    def _term_categories(self, term: _Term) -> FrozenSet[str]:
        """Sink classes one read taints at a sink (read as TEXT)."""
        var, source, reads, relief = term
        if source is not None:
            base: Any = self.ALL_TAINT_CATEGORIES
        else:
            base = self._sets.get(var, _NO_TAINT)[reads[_TEXT]]
        return frozenset(base - relief[_TEXT])

    def _source_for(self, var: str) -> Optional[TaintSource]:
        """A source that explains the taint of ``var``, searched breadth first."""
        queue = deque([var])
        seen = {var}
        while queue:
            current = queue.popleft()
            if current in self._taint_sources:
                return self._taint_sources[current]
            for term in self._terms.get(current, ()):
                dep, source = term[0], term[1]
                if source is not None:
                    return TaintSource(
                        name=source.name,
                        variable=f"<direct:{source.name}>",
                        line=source.line,
                    )
                if dep not in seen and self._sets.get(dep, _NO_TAINT)[_RAW]:
                    seen.add(dep)
                    queue.append(dep)
        return None

    def _finding_source(
        self, term: _Term, sink: TaintSink, arg: ast.AST
    ) -> Tuple[TaintSource, str, str]:
        """The source, flow target and display text for a tainted read."""
        var, source = term[0], term[1]
        if source is not None:
            shown = self._node_to_str(arg)
            direct = TaintSource(
                name=source.name,
                variable=f"<direct:{source.name}>",
                line=sink.line,
            )
            return direct, shown, shown
        found = self._source_for(var)
        if found is None:
            # Fail closed: a tainted variable is always reported, even if
            # no source can be named for it.
            found = TaintSource(name="<unknown>", variable=var, line=sink.line)
        shown = var if isinstance(arg, ast.Name) else self._node_to_str(arg)
        return found, var, shown

    def _find_vulnerabilities(
        self, 
        sources: List[TaintSource], 
        sinks: List[TaintSink]
    ) -> List[TaintVulnerability]:
        """Find vulnerabilities where tainted data reaches sinks."""
        vulnerabilities = []
        seen = set()

        for sink in sinks:
            category = self._sink_category(sink.name)
            for arg in self._relevant_args(sink, category):
                for term in self._compile(arg):
                    if category not in self._term_categories(term):
                        continue
                    source, target, shown = self._finding_source(term, sink, arg)
                    key = (sink.name, sink.line, source.variable)
                    if key in seen:
                        continue
                    seen.add(key)
                    vulnerabilities.append(
                        self._make_vulnerability(source, sink, target, shown)
                    )

        return vulnerabilities

    def _make_vulnerability(
        self,
        source: TaintSource,
        sink: TaintSink,
        flow_target: str,
        display: str,
    ) -> TaintVulnerability:
        """Build a vulnerability record for taint reaching a sink."""
        severity, desc = self.SINKS.get(
            sink.name,
            ("HIGH", f"Tainted data in {sink.name}")
        )
        path = self._build_flow_path(source.variable, flow_target)
        return TaintVulnerability(
            source=source,
            sink=sink,
            path=path,
            severity=severity,
            description=(
                f"{desc}: tainted data from {source.name}() "
                f"reaches {sink.name}()"
            ),
            recommendation=(
                f"Sanitize '{display}' before passing to {sink.name}()"
            )
        )
    
    def _build_flow_path(self, source_var: str, sink_var: str) -> List[str]:
        """Build the flow path from source variable to sink variable."""
        if source_var == sink_var:
            return [source_var]
        
        visited = {source_var}
        
        # BFS to find path
        queue = [(source_var, [source_var])]
        
        while queue:
            current, current_path = queue.pop(0)
            
            # Find variables that depend on current
            for var, deps in self._flow_graph.items():
                if current in deps and var not in visited:
                    new_path = current_path + [var]
                    if var == sink_var:
                        return new_path
                    visited.add(var)
                    queue.append((var, new_path))
        
        # Direct path if BFS fails
        return [source_var, sink_var]
    
    def _get_all_tainted(self) -> Set[str]:
        """Get all tainted variables (tainted for at least one sink class)."""
        return {var for var, sets in self._sets.items() if sets[_TEXT]}
    
    def analyze_with_context(
        self, 
        code: str, 
        trusted_sources: Optional[Set[str]] = None,
        additional_sinks: Optional[Dict[str, Tuple[str, str]]] = None
    ) -> Dict[str, Any]:
        """
        Analyze with custom trusted sources and additional sinks.
        
        Args:
            code: Python source code.
            trusted_sources: Set of variable names to consider clean.
            additional_sinks: Extra sinks to check {name: (severity, desc)}.
            
        Returns:
            Dict with analysis results.
        """
        result = self.analyze(code)
        
        if trusted_sources:
            # Remove vulnerabilities where source is trusted
            result["vulnerabilities"] = [
                v for v in result["vulnerabilities"]
                if v["source"]["variable"] not in trusted_sources
            ]
            result["is_safe"] = len(result["vulnerabilities"]) == 0
        
        return result


# What the one walk in TaintAnalyzer._scan does with each kind of node
# (calls are collected separately; every other kind is skipped).
_SCAN_HANDLERS = {
    ast.Name: TaintAnalyzer._scan_name,
    ast.Attribute: TaintAnalyzer._scan_attribute,
    ast.Assign: TaintAnalyzer._scan_assignment,
    ast.AnnAssign: TaintAnalyzer._scan_assignment,
    ast.AugAssign: TaintAnalyzer._scan_assignment,
    ast.NamedExpr: TaintAnalyzer._scan_assignment,
    ast.Import: TaintAnalyzer._scan_import,
    ast.ImportFrom: TaintAnalyzer._scan_import,
    ast.arg: TaintAnalyzer._scan_parameter,
    ast.FunctionDef: TaintAnalyzer._scan_named,
    ast.AsyncFunctionDef: TaintAnalyzer._scan_named,
    ast.ClassDef: TaintAnalyzer._scan_named,
    ast.ExceptHandler: TaintAnalyzer._scan_named,
    ast.MatchAs: TaintAnalyzer._scan_named,
    ast.MatchStar: TaintAnalyzer._scan_named,
    ast.MatchMapping: TaintAnalyzer._scan_mapping_rest,
}
