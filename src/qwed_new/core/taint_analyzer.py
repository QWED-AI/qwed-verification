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
    5. Check for SANITIZERS in the path
"""

import ast
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum


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


class TaintAnalyzer:
    """
    AST-based Taint Analysis for Python Code.
    
    Tracks untrusted data (taint) from sources to sinks using
    data flow analysis. 100% deterministic.
    
    Sources (untrusted data entry points):
        - input(), sys.stdin
        - request.args, request.form, request.data
        - os.environ.get, subprocess output
        - File reads from user-controlled paths
    
    Sinks (dangerous operations):
        - eval(), exec(), compile()
        - os.system(), subprocess.call/run/Popen
        - pickle.loads(), yaml.load()
        - SQL queries, shell commands
        
    Sanitizers (functions that clean tainted data):
        - escape(), sanitize(), validate()
        - int(), float() (type casting)
        - re.match/search with validation
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

    #: Type casts and boolean checks produce a value safe for every sink.
    UNIVERSAL_SANITIZERS: Set[str] = {
        "int", "float", "bool",
        "isdigit", "isalnum", "isalpha",
    }

    #: Only neutralises shell metacharacters.
    SHELL_SANITIZERS: Set[str] = {
        "shlex.quote", "quote", "shlex.split",
    }

    #: Only neutralises HTML markup (XSS), not shell/SQL metacharacters.
    HTML_SANITIZERS: Set[str] = {
        "escape", "html.escape", "html_escape", "markupsafe.escape",
        "bleach", "bleach.clean", "strip_tags", "sanitize", "clean",
    }

    #: Only makes a filename safe for path operations.
    PATH_SANITIZERS: Set[str] = {
        "secure_filename", "werkzeug.secure_filename",
    }

    #: Backwards-compatible union of every known sanitiser name.
    #: Prefer the sink-specific sets above; this union is no longer
    #: consulted by the analysis itself.
    SANITIZERS: Set[str] = (
        UNIVERSAL_SANITIZERS | SHELL_SANITIZERS
        | HTML_SANITIZERS | PATH_SANITIZERS
    )

    #: Keyword arguments that can carry injected payloads, by sink class.
    #: A keyword value is inspected only when its sink class is absent
    #: from this map (fail closed) or its name is in the class's set.
    INJECTABLE_KEYWORDS: Dict[str, Set[str]] = {
        "shell": {"args", "cmd", "command", "executable"},
        "network": {"url"},
        "sql": {"query", "operation", "sql"},
    }

    #: Request attributes whose direct subscript/attribute read is a
    #: source (``request.form['cmd']``). ``request.method`` is not one.
    REQUEST_DATA_ATTRS: Set[str] = {
        "args", "form", "values", "cookies", "headers", "json",
        "data", "files", "GET", "POST", "query_params",
    }
    def __init__(self):
        """Initialize the Taint Analyzer."""
        # var -> set of sink classes the variable is tainted for.
        # A variable absent from the map (or mapped to the empty set)
        # is clean.
        self._taint_map: Dict[str, Set[str]] = {}
        self._taint_sources: Dict[str, TaintSource] = {}
        self._flow_graph: Dict[str, Set[str]] = {}  # var -> depends_on
        # var -> every expression ever assigned to it. Taint is the union
        # over the list, so a reassignment on another branch (or a later
        # plain assignment) never drops taint from an earlier one.
        self._flow_rhs: Dict[str, List[ast.AST]] = {}
    
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
        # Reset state
        self._taint_map = {}
        self._taint_sources = {}
        self._flow_graph = {}
        self._flow_rhs = {}
        
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
        
        # Phase 1: Find all sources and initial tainted variables
        sources = self._find_sources(tree)
        
        # Phase 2: Build data flow graph and propagate taint
        self._build_flow_graph(tree)
        self._propagate_taint()
        
        # Phase 3: Find all sinks
        sinks = self._find_sinks(tree)
        
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
    
    def _find_sources(self, tree: ast.AST) -> List[TaintSource]:
        """Find all taint sources in the AST."""
        sources = []

        for node in ast.walk(tree):
            # Assignment: x = input()
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    self._mark_assign_source(target, node.value, node.lineno, sources)
            # Annotated assignment: x: str = input()
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                source = self._check_source_expr(node.value)
                if source:
                    self._mark_source_target(node.target, source, node.lineno, sources)
            # Named expr: if (x := input()):
            elif isinstance(node, ast.NamedExpr):
                source = self._check_source_expr(node.value)
                if source:
                    self._mark_source_target(node.target, source, node.lineno, sources)

        return sources

    def _mark_assign_source(
        self,
        target: ast.AST,
        value: ast.AST,
        lineno: int,
        sources: List[TaintSource],
    ) -> None:
        """Mark direct sources, pairing tuple targets element-wise.

        ``safe, bad = "ls", input()`` taints only ``bad``: each target
        is checked against its own element. Anything else (unequal
        lengths, starred elements, non-literal RHS) falls back to
        checking the whole RHS for every target.
        """
        if (
            isinstance(target, (ast.Tuple, ast.List))
            and isinstance(value, (ast.Tuple, ast.List))
            and len(target.elts) == len(value.elts)
            and not any(isinstance(e, ast.Starred) for e in target.elts)
            and not any(isinstance(e, ast.Starred) for e in value.elts)
        ):
            for elt, val in zip(target.elts, value.elts):
                self._mark_assign_source(elt, val, lineno, sources)
            return
        source = self._check_source_expr(value)
        if source:
            self._mark_source_target(target, source, lineno, sources)

    def _mark_source_target(
        self,
        target: ast.AST,
        source: TaintSource,
        lineno: int,
        sources: List[TaintSource],
    ) -> None:
        """Record that an assignment target now holds source taint."""
        if isinstance(target, ast.Starred):
            self._mark_source_target(target.value, source, lineno, sources)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._mark_source_target(elt, source, lineno, sources)
        elif isinstance(target, ast.Name):
            tainted = TaintSource(
                name=source.name, variable=target.id, line=lineno
            )
            sources.append(tainted)
            self._taint_map[target.id] = set(self.ALL_TAINT_CATEGORIES)
            self._taint_sources[target.id] = tainted
    
    def _check_source_call(self, node: ast.AST) -> Optional[TaintSource]:
        """Check if a node is a taint source call."""
        if isinstance(node, ast.Call):
            func_name = self._get_func_name(node.func)
            
            # Check direct function match
            if func_name in self.SOURCES:
                return TaintSource(
                    name=func_name,
                    variable="",  # Will be filled by caller
                    line=node.lineno
                )
            
            # Exact match only: substring matching misclassified
            # ``os.getcwd()`` (contains "get") and ``some_dict.get()``.
            if func_name in self.SOURCE_FUNCTIONS:
                return TaintSource(
                    name=func_name,
                    variable="",
                    line=node.lineno
                )

            # Method-call sources match by last dotted segment, except the
            # generic ``get`` (``sys.stdin.readline``, ``conn.recv``,
            # ``f.read``, ``sock.recvfrom`` are sources; ``os.getcwd()``
            # and ``some_dict.get()`` are still not).
            last = func_name.rsplit(".", 1)[-1] if func_name else ""
            if last in (self.SOURCE_FUNCTIONS - {"get"}):
                return TaintSource(
                    name=func_name,
                    variable="",
                    line=node.lineno
                )

            # Request-object sources: ``request`` as the first segment,
            # or as the second segment after ``self`` or ``flask``
            # (``flask.request.args.get``), with a ``get*`` last segment
            # (``get``, ``get_json``, ``get_data``, ``getlist``).
            # Other ``.get`` calls (``some_dict.get``) stay non-sources,
            # and ``urllib.request.urlopen`` (root ``urllib``) stays a sink.
            parts = func_name.split(".") if func_name else []
            if (
                parts
                and (
                    parts[0] == "request"
                    or (
                        len(parts) >= 2
                        and parts[1] == "request"
                        and parts[0] in ("self", "flask")
                    )
                )
                and last.startswith("get")
            ):
                return TaintSource(
                    name=func_name,
                    variable="",
                    line=node.lineno
                )

        return None

    @classmethod
    def _is_request_data_reference(cls, dotted: Optional[str]) -> bool:
        """Whether a dotted name is a request-data read (a source).

        Matches ``request.<attr>``, ``self.request.<attr>`` and
        ``flask.request.<attr>`` with ``<attr>`` in
        :attr:`REQUEST_DATA_ATTRS` (``request.form['cmd']`` unwraps to
        ``request.form``). ``request.method`` and ``some_obj.form['x']``
        are not sources.
        """
        if not dotted:
            return False
        parts = dotted.split(".")
        if len(parts) == 2 and parts[0] == "request":
            return parts[1] in cls.REQUEST_DATA_ATTRS
        if (
            len(parts) == 3
            and parts[1] == "request"
            and parts[0] in ("self", "flask")
        ):
            return parts[2] in cls.REQUEST_DATA_ATTRS
        return False

    def _check_source_expr(self, node: ast.AST) -> Optional[TaintSource]:
        """Check if an expression directly introduces tainted data.

        Covers source calls (``x = input()``) as well as direct reads of
        source attributes/subscripts (``x = sys.argv[1]``).
        """
        if isinstance(node, ast.Call):
            return self._check_source_call(node)
        dotted = self._get_source_name(node)
        if (
            dotted is not None
            and (
                dotted in self.SOURCES
                or self._is_request_data_reference(dotted)
            )
        ):
            return TaintSource(
                name=dotted,
                variable="",
                line=getattr(node, "lineno", 0)
            )
        return None

    def _get_source_name(self, node: ast.AST) -> Optional[str]:
        """Dotted name of a source reference, unwrapping subscripts."""
        if isinstance(node, (ast.Name, ast.Attribute)):
            return self._get_func_name(node)
        if isinstance(node, ast.Subscript):
            return self._get_source_name(node.value)
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
    
    def _build_flow_graph(self, tree: ast.AST) -> None:
        """Build data flow graph from assignments."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    self._record_assignment(target, node.value)
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                self._record_assignment(node.target, node.value)
            elif isinstance(node, ast.AugAssign):
                self._record_aug_assignment(node.target, node.value, node.op)
            elif isinstance(node, ast.NamedExpr):
                self._record_assignment(node.target, node.value)

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
            self._flow_graph[target.id] = (
                self._flow_graph.get(target.id, set())
                | self._extract_dependencies(value)
            )
            self._flow_rhs.setdefault(target.id, []).append(value)

    def _record_aug_assignment(
        self, target: ast.AST, value: ast.AST, op: ast.AST
    ) -> None:
        """Record ``x <op>= value`` as ``x = <previous RHS> <op> value``.

        The previous RHS expression is kept (not a self-reference), so
        augmented assignment adds the RHS taint to the existing taint of
        the target instead of dropping it.
        """
        if not isinstance(target, ast.Name):
            return
        previous = self._flow_rhs.get(target.id, [])
        if previous:
            left: ast.AST = previous[-1]
        else:
            left = ast.Name(id=target.id, ctx=ast.Load())
        combined = ast.BinOp(left=left, op=op, right=value)
        self._flow_graph[target.id] = (
            self._flow_graph.get(target.id, set())
            | self._extract_dependencies(combined)
            | {target.id}
        )
        self._flow_rhs.setdefault(target.id, []).append(combined)
    
    def _extract_dependencies(self, node: ast.AST) -> Set[str]:
        """Extract all variable names that this expression depends on."""
        deps = set()
        
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                deps.add(child.id)
        
        return deps
    
    def _sanitizer_relief(self, func_name: str) -> Set[str]:
        """Sink classes a call to ``func_name`` cleans (exact match only).

        Substring matching is deliberately NOT used: it misclassified
        ``print_and_return`` as sanitised (contains ``int``) and treated
        ``html.escape`` as a shell sanitiser.
        """
        if func_name in self.UNIVERSAL_SANITIZERS:
            return set(self.ALL_TAINT_CATEGORIES)
        if func_name in self.SHELL_SANITIZERS:
            return {"shell"}
        if func_name in self.HTML_SANITIZERS:
            return {"html"}
        if func_name in self.PATH_SANITIZERS:
            return {"path"}
        return set()

    @staticmethod
    def _transformed_call_ids(node: ast.AST) -> Set[int]:
        """Ids of calls whose result is transformed after the call.

        ``shlex.quote(x).strip(...)`` and ``shlex.quote(x)[1:-1]``
        transform the sanitiser result, so the sanitiser must not relieve
        anything. Only the direct receiver (the ``Call`` that is the
        ``.value`` of the outer call's ``func`` or of a ``Subscript``)
        counts; plain arguments (``"ls " + shlex.quote(x)``) are untouched.
        """
        transformed: Set[int] = set()
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and isinstance(child.func.value, ast.Call)
            ):
                transformed.add(id(child.func.value))
            elif (
                isinstance(child, ast.Subscript)
                and isinstance(child.value, ast.Call)
            ):
                transformed.add(id(child.value))
        return transformed

    def _expr_taint_categories(self, node: ast.AST) -> Set[str]:
        """Sink classes an expression is tainted for.

        Any tainted variable, source call, or source reference anywhere
        inside the expression taints the whole expression (covers BinOp,
        JoinedStr/f-strings, %-formatting, str.format, join, ...). A
        sanitiser call relieves its own sink classes for its own subtree
        only, whether it is the top-level node or nested inside a larger
        expression (``"ls " + shlex.quote(x)`` is clean for shell sinks,
        exactly like the inline sink-argument form).
        """
        sanitisers: List[Tuple[Set[int], Set[str]]] = []
        transformed = self._transformed_call_ids(node)
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if id(child) in transformed:
                    continue
                relief = self._sanitizer_relief(
                    self._get_func_name(child.func)
                )
                if relief:
                    sanitisers.append(
                        ({id(sub) for sub in ast.walk(child)}, relief)
                    )
        categories: Set[str] = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                contributed = set(self._taint_map.get(child.id, set()))
            elif isinstance(child, ast.Call):
                if self._check_source_call(child) is None:
                    continue
                contributed = set(self.ALL_TAINT_CATEGORIES)
            elif isinstance(child, (ast.Attribute, ast.Subscript)):
                dotted = self._get_source_name(child)
                if dotted is None or (
                    dotted not in self.SOURCES
                    and not self._is_request_data_reference(dotted)
                ):
                    continue
                contributed = set(self.ALL_TAINT_CATEGORIES)
            else:
                continue
            if not contributed:
                continue
            for subtree_ids, relief in sanitisers:
                if id(child) in subtree_ids:
                    contributed -= relief
            categories |= contributed
        return categories

    def _direct_source_reference(self, node: ast.AST) -> Optional[TaintSource]:
        """A source for a direct ``Attribute``/``Subscript`` reference.

        ``sys.argv[1]`` and ``os.environ["CMD"]`` are sources even when
        they appear inside a larger expression rather than as a call.
        """
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            dotted = self._get_source_name(node)
            if dotted is not None and (
                dotted in self.SOURCES
                or self._is_request_data_reference(dotted)
            ):
                return TaintSource(name=dotted, variable="", line=0)
        return None

    def _find_contributing_source(self, node: ast.AST) -> Optional[TaintSource]:
        """Find a source explaining taint flowing through an expression."""
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                if child.id in self._taint_sources:
                    return self._taint_sources[child.id]
        for child in ast.walk(node):
            source: Optional[TaintSource] = None
            if isinstance(child, ast.Call):
                source = self._check_source_call(child)
            else:
                source = self._direct_source_reference(child)
            if source is not None:
                return TaintSource(
                    name=source.name,
                    variable=f"<direct:{source.name}>",
                    line=getattr(node, "lineno", 0),
                )
        return None
    
    def _propagate_taint(self) -> None:
        """Propagate taint through the flow graph (fixed-point iteration)."""
        changed = True
        iterations = 0
        max_iterations = 100  # Prevent infinite loops

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for var, rhs_list in self._flow_rhs.items():
                computed: Set[str] = set()
                for rhs in rhs_list:
                    computed |= self._expr_taint_categories(rhs)
                authoritative = (
                    len(rhs_list) == 1
                    and isinstance(rhs_list[0], ast.Call)
                    and self._sanitizer_relief(
                        self._get_func_name(rhs_list[0].func)
                    )
                )
                if authoritative:
                    # A lone sanitiser call defines the result: tainted
                    # for every sink class except the ones it cleans.
                    new_categories = computed
                else:
                    # Otherwise taint only ever accumulates (fail closed on
                    # branches: no reassignment ever removes taint).
                    new_categories = (
                        self._taint_map.get(var, set()) | computed
                    )
                if new_categories != self._taint_map.get(var, set()):
                    self._taint_map[var] = new_categories
                    changed = True
                if new_categories and var not in self._taint_sources:
                    for rhs in rhs_list:
                        source = self._find_contributing_source(rhs)
                        if source is not None:
                            self._taint_sources[var] = source
                            break
    
    def _find_sinks(self, tree: ast.AST) -> List[TaintSink]:
        """Find all sink calls in the AST."""
        sinks = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node.func)
                is_sink = False
                
                # Check direct sink match
                if func_name in self.SINKS:
                    is_sink = True
                else:
                    # Check if any sink function is in the call
                    for sink_func in self.SINK_FUNCTIONS:
                        if sink_func in func_name or func_name == sink_func:
                            is_sink = True
                            break
                
                if is_sink:
                    # Keep the raw argument nodes (positional and keyword)
                    # so the vulnerability check can look *inside*
                    # expressions instead of only matching bare names.
                    # Keyword values are kept only when the sink class is
                    # absent from INJECTABLE_KEYWORDS (fail closed) or the
                    # keyword name is injectable for that class.
                    category = self._sink_category(func_name)
                    allowed = self.INJECTABLE_KEYWORDS.get(category)
                    arg_nodes: List[Any] = list(node.args)
                    kw_names: List[Optional[str]] = [None] * len(node.args)
                    for kw in node.keywords:
                        if allowed is None or kw.arg is None or (
                            kw.arg in allowed
                        ):
                            arg_nodes.append(kw.value)
                            # ``**`` expansions (kw.arg is None) are
                            # marked distinctly so they are never
                            # mistaken for positional arguments.
                            kw_names.append(kw.arg if kw.arg is not None else "**")
                    args = [self._node_to_str(arg) for arg in arg_nodes]

                    sinks.append(TaintSink(
                        name=func_name,
                        line=node.lineno,
                        args=args,
                        arg_nodes=arg_nodes,
                        kw_names=kw_names
                    ))
        
        return sinks
    
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

    def _relieved_subtree_ids(
        self, arg: ast.AST, category: str
    ) -> Set[int]:
        """Ids of nodes cleaned for ``category`` by an inline sanitiser.

        Mirrors :meth:`_expr_taint_categories`: a sanitiser whose result is
        transformed (``shlex.quote(x).strip(...)``) relieves nothing.
        """
        relieved: Set[int] = set()
        transformed = self._transformed_call_ids(arg)
        for child in ast.walk(arg):
            if (
                isinstance(child, ast.Call)
                and id(child) not in transformed
                and category
                in self._sanitizer_relief(self._get_func_name(child.func))
            ):
                for sub in ast.walk(child):
                    relieved.add(id(sub))
        return relieved

    def _tainted_names_in_arg(
        self, arg: ast.AST, category: str, relieved: Set[int]
    ) -> List[str]:
        """Tainted variable names in an argument, honouring sanitisers."""
        names = []
        for child in ast.walk(arg):
            if id(child) in relieved:
                continue
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                if category in self._taint_map.get(child.id, ()):
                    names.append(child.id)
        return names

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
            # Parameter binding is the SQL sanitiser: only the query
            # argument can inject; bound parameters cannot. The query is
            # the first true positional argument if there is one,
            # otherwise every ``query``/``operation``/``sql`` keyword AND
            # every ``**`` expansion (fail closed: an expansion may
            # carry the query).
            if sink.name.split(".")[-1] in ("execute", "executemany"):
                kw_names = list(getattr(sink, "kw_names", []) or [])
                if len(kw_names) != len(sink.arg_nodes):
                    relevant_args = sink.arg_nodes[:1]
                else:
                    positionals = [
                        arg for arg, name in
                        zip(sink.arg_nodes, kw_names) if name is None
                    ]
                    if positionals:
                        relevant_args = positionals[:1]
                    else:
                        relevant_args = [
                            arg for arg, name in
                            zip(sink.arg_nodes, kw_names)
                            if name in ("query", "operation", "sql")
                            or name == "**"
                        ]
            else:
                relevant_args = sink.arg_nodes
            for arg in relevant_args:
                relieved = self._relieved_subtree_ids(arg, category)
                # Tainted variables anywhere inside the argument
                # expression (BinOp, f-string, %, .format(), join, ...).
                for name in self._tainted_names_in_arg(arg, category, relieved):
                    source = self._taint_sources.get(name)
                    if source is None:
                        continue
                    key = (sink.name, sink.line, source.variable)
                    if key in seen:
                        continue
                    seen.add(key)
                    display = (
                        name
                        if isinstance(arg, ast.Name)
                        else self._node_to_str(arg)
                    )
                    vulnerabilities.append(
                        self._make_vulnerability(
                            source, sink, name, display
                        )
                    )
                # Source calls and direct source references nested
                # anywhere inside the argument, e.g.
                # os.system("ls " + input()) or
                # os.system("ls " + sys.argv[1]).
                for child in ast.walk(arg):
                    if id(child) in relieved:
                        continue
                    nested: Optional[TaintSource] = None
                    if isinstance(child, ast.Call):
                        nested = self._check_source_call(child)
                    elif isinstance(child, (ast.Attribute, ast.Subscript)):
                        nested = self._direct_source_reference(child)
                    if nested is not None:
                        direct = TaintSource(
                            name=nested.name,
                            variable=f"<direct:{nested.name}>",
                            line=sink.line,
                        )
                        key = (sink.name, sink.line, direct.variable)
                        if key in seen:
                            continue
                        seen.add(key)
                        vulnerabilities.append(
                            self._make_vulnerability(
                                direct,
                                sink,
                                self._node_to_str(arg),
                                self._node_to_str(arg),
                            )
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
        return {
            var for var, categories in self._taint_map.items() if categories
        }
    
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
