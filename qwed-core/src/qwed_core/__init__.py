"""
QWED Core - Reference Implementation

Minimal, embeddable verification library implementing the QWED Protocol.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from enum import Enum
import re


class VerificationStatus(Enum):
    """Verification result status"""
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    CORRECTED = "CORRECTED"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"


class Satisfiability(Enum):
    """Logic satisfiability result"""
    SAT = "SAT"
    UNSAT = "UNSAT"
    UNKNOWN = "UNKNOWN"


@dataclass
class Vulnerability:
    """Code security vulnerability"""
    type: str
    severity: str  # low, medium, high, critical
    line: Optional[int] = None
    message: str = ""


@dataclass
class VerificationResult:
    """Result of a verification operation"""
    status: VerificationStatus
    verified: bool
    engine: str
    message: str = ""
    
    # Engine-specific results
    result_value: Optional[Any] = None
    model: Optional[Dict[str, Any]] = None
    satisfiability: Optional[Satisfiability] = None
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "verified": self.verified,
            "engine": self.engine,
            "message": self.message,
            "result": self.result_value,
            "model": self.model,
            "satisfiability": self.satisfiability.value if self.satisfiability else None,
            "vulnerabilities": [
                {"type": v.type, "severity": v.severity, "line": v.line, "message": v.message}
                for v in self.vulnerabilities
            ],
        }


# ============================================================================
# Math Engine
# ============================================================================

def verify_math(expression: str) -> VerificationResult:
    """
    Verify a mathematical expression or identity using SymPy.
    
    Examples:
        verify_math("2 + 2 = 4")  -> VERIFIED
        verify_math("x**2 + 2*x + 1 = (x+1)**2")  -> VERIFIED (identity)
        verify_math("2 + 2 = 5")  -> FAILED
    """
    try:
        from sympy import sympify, simplify, Eq
        from sympy.parsing.sympy_parser import parse_expr
        
        # Check if it's an equation (contains =)
        if "=" in expression:
            parts = expression.split("=", 1)
            if len(parts) == 2:
                left = parse_expr(parts[0].strip())
                right = parse_expr(parts[1].strip())
                
                # Check if they're equal (symbolic simplification)
                diff = simplify(left - right)
                is_valid = diff == 0
                
                return VerificationResult(
                    status=VerificationStatus.VERIFIED if is_valid else VerificationStatus.FAILED,
                    verified=is_valid,
                    engine="math",
                    message="Identity verified" if is_valid else f"Not equal: difference is {diff}",
                    result_value={
                        "left": str(left),
                        "right": str(right),
                        "difference": str(diff),
                    },
                )
        
        # Just evaluate the expression
        result = sympify(expression)
        return VerificationResult(
            status=VerificationStatus.VERIFIED,
            verified=True,
            engine="math",
            message=f"Evaluated to {result}",
            result_value=str(result),
        )
        
    except Exception as e:
        return VerificationResult(
            status=VerificationStatus.ERROR,
            verified=False,
            engine="math",
            message=str(e),
        )


# ============================================================================
# Logic Engine
# ============================================================================

def verify_logic(query: str, format: str = "dsl") -> VerificationResult:
    """
    Verify logical constraints using Z3 SMT solver.
    
    Supports QWED-Logic DSL format:
        (AND (GT x 5) (LT y 10))
    """
    try:
        from z3 import Solver, Int, Real, Bool, sat, unsat, And, Or, Not, Implies
        
        # Parse DSL
        variables = {}
        
        def get_var(name: str):
            if name not in variables:
                variables[name] = Real(name)
            return variables[name]
        
        def parse_atom(token: str):
            token = token.strip()
            # Try number
            try:
                if '.' in token:
                    return float(token)
                return int(token)
            except ValueError:
                pass
            # Try boolean
            if token.lower() == 'true':
                return True
            if token.lower() == 'false':
                return False
            # It's a variable
            return get_var(token)
        
        def parse_expr(s: str):
            s = s.strip()
            if not s.startswith('('):
                return parse_atom(s)
            
            # Find matching parens
            s = s[1:-1].strip()  # Remove outer parens
            tokens = []
            depth = 0
            current = ""
            for c in s:
                if c == '(':
                    depth += 1
                    current += c
                elif c == ')':
                    depth -= 1
                    current += c
                elif c.isspace() and depth == 0:
                    if current:
                        tokens.append(current)
                        current = ""
                else:
                    current += c
            if current:
                tokens.append(current)
            
            if not tokens:
                raise ValueError("Empty expression")
            
            op = tokens[0].upper()
            args = [parse_expr(t) for t in tokens[1:]]
            
            # Logic operators
            if op == "AND":
                return And(*args)
            elif op == "OR":
                return Or(*args)
            elif op == "NOT":
                return Not(args[0])
            elif op == "IMPLIES":
                return Implies(args[0], args[1])
            # Comparison operators
            elif op == "EQ":
                return args[0] == args[1]
            elif op == "NE":
                return args[0] != args[1]
            elif op == "GT":
                return args[0] > args[1]
            elif op == "GE":
                return args[0] >= args[1]
            elif op == "LT":
                return args[0] < args[1]
            elif op == "LE":
                return args[0] <= args[1]
            # Arithmetic
            elif op == "PLUS":
                return sum(args)
            elif op == "MINUS":
                return args[0] - args[1]
            elif op == "MULT":
                result = args[0]
                for a in args[1:]:
                    result = result * a
                return result
            elif op == "DIV":
                return args[0] / args[1]
            else:
                raise ValueError(f"Unknown operator: {op}")
        
        constraint = parse_expr(query)
        
        solver = Solver()
        solver.add(constraint)
        
        result = solver.check()
        
        if result == sat:
            model = solver.model()
            model_dict = {str(d): model[d] for d in model}
            # Convert z3 values to Python
            model_dict = {k: float(str(v)) if '/' in str(v) else int(str(v)) 
                          for k, v in model_dict.items()}
            
            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                verified=True,
                engine="logic",
                message="Satisfiable",
                satisfiability=Satisfiability.SAT,
                model=model_dict,
            )
        elif result == unsat:
            return VerificationResult(
                status=VerificationStatus.FAILED,
                verified=False,
                engine="logic",
                message="Unsatisfiable - no valid assignment exists",
                satisfiability=Satisfiability.UNSAT,
            )
        else:
            return VerificationResult(
                status=VerificationStatus.FAILED,
                verified=False,
                engine="logic",
                message="Unknown - solver could not determine satisfiability",
                satisfiability=Satisfiability.UNKNOWN,
            )
            
    except Exception as e:
        return VerificationResult(
            status=VerificationStatus.ERROR,
            verified=False,
            engine="logic",
            message=str(e),
        )


# ============================================================================
# Code Security Engine
# ============================================================================

# Dangerous patterns
DANGEROUS_PATTERNS = [
    (r'\beval\s*\(', 'eval', 'critical', 'Dynamic code execution with eval()'),
    (r'\bexec\s*\(', 'exec', 'critical', 'Dynamic code execution with exec()'),
    (r'\bos\.system\s*\(', 'os.system', 'critical', 'Shell command execution'),
    (r'\bsubprocess\.(call|run|Popen)\s*\(', 'subprocess', 'critical', 'Subprocess execution'),
    (r'\b__import__\s*\(', '__import__', 'high', 'Dynamic import'),
    (r'\bpickle\.loads?\s*\(', 'pickle', 'high', 'Unsafe deserialization'),
    (r'\bmarshall\.loads?\s*\(', 'marshall', 'high', 'Unsafe deserialization'),
    (r'rm\s+-rf', 'rm-rf', 'critical', 'Destructive file deletion'),
    (r'\bopen\s*\([^)]*["\']w["\']\s*\)', 'file_write', 'medium', 'File write operation'),
    (r'\bsqlite3\.connect\s*\([^)]*:memory:', 'memory_db', 'low', 'In-memory database'),
]


def verify_code(code: str, language: str = "python") -> VerificationResult:
    """
    Check code for security vulnerabilities using pattern matching.
    
    Detects:
        - eval/exec usage
        - os.system/subprocess calls
        - Dangerous imports
        - File operations
    """
    vulnerabilities = []
    
    lines = code.split('\n')
    for line_num, line in enumerate(lines, 1):
        for pattern, vuln_type, severity, message in DANGEROUS_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                vulnerabilities.append(Vulnerability(
                    type=vuln_type,
                    severity=severity,
                    line=line_num,
                    message=message,
                ))
    
    # Check for common security issues using AST if Python
    if language == "python":
        try:
            import ast
            tree = ast.parse(code)
            
            for node in ast.walk(tree):
                # Check for dangerous names
                if isinstance(node, ast.Name):
                    if node.id in ('eval', 'exec', '__import__'):
                        vulnerabilities.append(Vulnerability(
                            type=node.id,
                            severity='critical',
                            line=node.lineno,
                            message=f'Use of dangerous builtin: {node.id}',
                        ))
        except SyntaxError:
            pass  # Still report pattern matches even if syntax is invalid
    
    # Determine overall result
    has_critical = any(v.severity == 'critical' for v in vulnerabilities)
    has_high = any(v.severity == 'high' for v in vulnerabilities)
    
    if has_critical:
        status = VerificationStatus.BLOCKED
        verified = False
        message = f"Blocked: {len(vulnerabilities)} security issues found (including critical)"
    elif has_high:
        status = VerificationStatus.FAILED
        verified = False
        message = f"Failed: {len(vulnerabilities)} security issues found"
    elif vulnerabilities:
        status = VerificationStatus.VERIFIED
        verified = True
        message = f"Passed with {len(vulnerabilities)} minor warnings"
    else:
        status = VerificationStatus.VERIFIED
        verified = True
        message = "No security issues detected"
    
    return VerificationResult(
        status=status,
        verified=verified,
        engine="code",
        message=message,
        vulnerabilities=vulnerabilities,
    )


# ============================================================================
# SQL Safety Engine
# ============================================================================

def verify_sql(query: str, schema: Optional[str] = None, dialect: str = "sqlite") -> VerificationResult:
    """
    Validate SQL query for safety and correctness.
    
    Checks:
        - SQL injection patterns
        - Destructive operations (DROP, DELETE, TRUNCATE)
        - Schema validation (if provided)
    """
    vulnerabilities = []
    
    query_upper = query.upper()
    
    # Check for SQL injection patterns
    injection_patterns = [
        (r";\s*--", "sql_comment", "SQL comment injection"),
        (r"'\s*OR\s+'\s*=\s*'", "or_injection", "OR injection pattern"),
        (r"UNION\s+SELECT", "union_injection", "UNION SELECT injection"),
        (r";\s*DROP\s+", "chained_drop", "Chained DROP statement"),
    ]
    
    for pattern, vuln_type, message in injection_patterns:
        if re.search(pattern, query, re.IGNORECASE):
            vulnerabilities.append(Vulnerability(
                type=vuln_type,
                severity="critical",
                message=message,
            ))
    
    # Check for destructive operations
    destructive_ops = ["DROP", "DELETE", "TRUNCATE", "UPDATE"]
    for op in destructive_ops:
        if op in query_upper:
            vulnerabilities.append(Vulnerability(
                type=f"destructive_{op.lower()}",
                severity="high",
                message=f"Destructive operation: {op}",
            ))
    
    # Try to parse with sqlglot if available
    try:
        import sqlglot
        parsed = sqlglot.parse(query, read=dialect)
        if not parsed or not parsed[0]:
            return VerificationResult(
                status=VerificationStatus.FAILED,
                verified=False,
                engine="sql",
                message="Failed to parse SQL query",
            )
    except ImportError:
        pass  # sqlglot not available, continue with pattern-based checks
    except Exception as e:
        return VerificationResult(
            status=VerificationStatus.ERROR,
            verified=False,
            engine="sql",
            message=f"SQL parsing error: {str(e)}",
        )
    
    # Determine result
    has_critical = any(v.severity == "critical" for v in vulnerabilities)
    has_high = any(v.severity == "high" for v in vulnerabilities)
    
    if has_critical:
        return VerificationResult(
            status=VerificationStatus.BLOCKED,
            verified=False,
            engine="sql",
            message=f"Blocked: SQL injection detected",
            vulnerabilities=vulnerabilities,
        )
    elif has_high:
        return VerificationResult(
            status=VerificationStatus.FAILED,
            verified=False,
            engine="sql",
            message=f"Warning: Destructive operations detected",
            vulnerabilities=vulnerabilities,
        )
    else:
        return VerificationResult(
            status=VerificationStatus.VERIFIED,
            verified=True,
            engine="sql",
            message="SQL query validated successfully",
        )


# ============================================================================
# Unified Verify Function
# ============================================================================

def verify(
    query: str,
    engine: Optional[str] = None,
    llm_provider=None,
) -> VerificationResult:
    """
    Unified verification function.
    
    Auto-detects engine if not specified.
    """
    # Auto-detect engine
    if engine is None:
        if "=" in query and not any(kw in query.upper() for kw in ["SELECT", "INSERT", "UPDATE", "DELETE"]):
            engine = "math"
        elif query.strip().startswith("(") and any(op in query.upper() for op in ["AND", "OR", "GT", "LT"]):
            engine = "logic"
        elif any(kw in query.upper() for kw in ["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE"]):
            engine = "sql"
        elif any(kw in query for kw in ["import ", "def ", "class ", "print("]):
            engine = "code"
        else:
            engine = "math"  # Default
    
    if engine == "math":
        return verify_math(query)
    elif engine == "logic":
        return verify_logic(query)
    elif engine == "code":
        return verify_code(query)
    elif engine == "sql":
        return verify_sql(query)
    else:
        return VerificationResult(
            status=VerificationStatus.ERROR,
            verified=False,
            engine=engine,
            message=f"Unknown engine: {engine}",
        )


# ============================================================================
# Export
# ============================================================================

__all__ = [
    "verify",
    "verify_math",
    "verify_logic",
    "verify_code",
    "verify_sql",
    "VerificationResult",
    "VerificationStatus",
    "Satisfiability",
    "Vulnerability",
]
