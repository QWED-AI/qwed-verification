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
    }
    
    SINK_FUNCTIONS: Set[str] = {
        "eval", "exec", "compile", "system", "popen",
        "call", "run", "Popen", "check_output",
        "loads", "load", "execute", "open"
    }
    
    # =========================================================================
    # Sanitizer Patterns (Functions that clean tainted data)
    # =========================================================================
    
    SANITIZERS: Set[str] = {
        # Explicit sanitizers
        "escape", "html_escape", "quote", "sanitize", "clean",
        "validate", "filter", "strip_tags", "bleach",
        
        # Type casting (converts to safe types)
        "int", "float", "bool",
        
        # Validation patterns
        "isdigit", "isalnum", "isalpha",
        
        # Security functions
        "shlex.quote", "shlex.split",
        "werkzeug.secure_filename",
        "markupsafe.escape",
    }
    
    def __init__(self):
        """Initialize the Taint Analyzer."""
        self._taint_map: Dict[str, TaintStatus] = {}
        self._taint_sources: Dict[str, TaintSource] = {}
        self._flow_graph: Dict[str, Set[str]] = {}  # var -> depends_on
    
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
            "tainted_variables": list(self._get_all_tainted()),
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
                source = self._check_source_call(node.value)
                if source:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            source.variable = target.id
                            source.line = node.lineno
                            sources.append(source)
                            self._taint_map[target.id] = TaintStatus.TAINTED
                            self._taint_sources[target.id] = source
            
            # Named expr: if (x := input()):
            elif isinstance(node, ast.NamedExpr):
                source = self._check_source_call(node.value)
                if source:
                    source.variable = node.target.id
                    source.line = node.lineno
                    sources.append(source)
                    self._taint_map[node.target.id] = TaintStatus.TAINTED
                    self._taint_sources[node.target.id] = source
        
        return sources
    
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
            
            # Check if any source function is in the call
            for source_func in self.SOURCE_FUNCTIONS:
                if source_func in func_name:
                    return TaintSource(
                        name=func_name,
                        variable="",
                        line=node.lineno
                    )
        
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
                    if isinstance(target, ast.Name):
                        deps = self._extract_dependencies(node.value)
                        self._flow_graph[target.id] = deps
                        
                        # Check if assigned from sanitizer
                        if self._is_sanitized(node.value):
                            self._taint_map[target.id] = TaintStatus.CLEAN
    
    def _extract_dependencies(self, node: ast.AST) -> Set[str]:
        """Extract all variable names that this expression depends on."""
        deps = set()
        
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                deps.add(child.id)
        
        return deps
    
    def _is_sanitized(self, node: ast.AST) -> bool:
        """Check if a value is sanitized (passed through a sanitizer)."""
        if isinstance(node, ast.Call):
            func_name = self._get_func_name(node.func)
            
            # Direct sanitizer call
            if func_name in self.SANITIZERS:
                return True
            
            # Any sanitizer in the call chain
            for sanitizer in self.SANITIZERS:
                if sanitizer in func_name:
                    return True
        
        return False
    
    def _propagate_taint(self) -> None:
        """Propagate taint through the flow graph (fixed-point iteration)."""
        changed = True
        iterations = 0
        max_iterations = 100  # Prevent infinite loops
        
        while changed and iterations < max_iterations:
            changed = False
            iterations += 1
            
            for var, deps in self._flow_graph.items():
                if self._taint_map.get(var) == TaintStatus.CLEAN:
                    continue  # Already sanitized
                
                # If any dependency is tainted, this var is tainted
                for dep in deps:
                    if self._taint_map.get(dep) == TaintStatus.TAINTED:
                        if self._taint_map.get(var) != TaintStatus.TAINTED:
                            self._taint_map[var] = TaintStatus.TAINTED
                            # Inherit the source
                            if dep in self._taint_sources:
                                self._taint_sources[var] = self._taint_sources[dep]
                            changed = True
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
                    args = [self._node_to_str(arg) for arg in node.args]
                    
                    # Check for DIRECT source calls in arguments
                    # e.g., eval(input()) - source directly inside sink
                    has_direct_source = False
                    for arg in node.args:
                        if isinstance(arg, ast.Call):
                            arg_func = self._get_func_name(arg.func)
                            if arg_func in self.SOURCES or arg_func in self.SOURCE_FUNCTIONS:
                                has_direct_source = True
                                # Create a synthetic source for this
                                direct_source = TaintSource(
                                    name=arg_func,
                                    variable=f"<direct:{arg_func}>",
                                    line=node.lineno
                                )
                                self._taint_sources[f"<direct:{arg_func}>"] = direct_source
                                self._taint_map[f"<direct:{arg_func}>"] = TaintStatus.TAINTED
                                # Update args to include the synthetic tainted variable
                                args = [f"<direct:{arg_func}>" if self._node_to_str(a) == f"{arg_func}(...)" else self._node_to_str(a) for a in node.args]
                    
                    sinks.append(TaintSink(
                        name=func_name,
                        line=node.lineno,
                        args=args
                    ))
        
        return sinks
    
    def _node_to_str(self, node: ast.AST) -> str:
        """Convert AST node to string representation."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Constant):
            return repr(node.value)
        elif isinstance(node, ast.Str):  # Python 3.7
            return repr(node.s)
        elif isinstance(node, ast.BinOp):
            return f"({self._node_to_str(node.left)} op {self._node_to_str(node.right)})"
        elif isinstance(node, ast.Call):
            return f"{self._get_func_name(node.func)}(...)"
        return "<expr>"
    
    def _find_vulnerabilities(
        self, 
        sources: List[TaintSource], 
        sinks: List[TaintSink]
    ) -> List[TaintVulnerability]:
        """Find vulnerabilities where tainted data reaches sinks."""
        vulnerabilities = []
        
        for sink in sinks:
            for arg in sink.args:
                # Check if this argument is tainted
                if arg in self._taint_map and self._taint_map[arg] == TaintStatus.TAINTED:
                    # Find the original source
                    source = self._taint_sources.get(arg)
                    if source:
                        severity, desc = self.SINKS.get(
                            sink.name, 
                            ("HIGH", f"Tainted data in {sink.name}")
                        )
                        
                        # Build flow path
                        path = self._build_flow_path(source.variable, arg)
                        
                        vulnerabilities.append(TaintVulnerability(
                            source=source,
                            sink=sink,
                            path=path,
                            severity=severity,
                            description=f"{desc}: tainted data from {source.name}() reaches {sink.name}()",
                            recommendation=f"Sanitize '{arg}' before passing to {sink.name}()"
                        ))
        
        return vulnerabilities
    
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
        """Get all tainted variables."""
        return {var for var, status in self._taint_map.items() 
                if status == TaintStatus.TAINTED}
    
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
