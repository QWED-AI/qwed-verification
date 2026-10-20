"""
QWED Custom Exceptions.

Provides actionable, developer-friendly error messages with:
- Clear error descriptions
- Suggestions for fixing
- Context (line numbers, variable names)
- Links to documentation
"""

from typing import Optional, List, Dict, Any


class QWEDError(Exception):
    """Base exception for all QWED errors."""
    
    def __init__(
        self,
        message: str,
        suggestion: Optional[str] = None,
        docs_url: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        self.message = message
        self.suggestion = suggestion
        self.docs_url = docs_url or "https://docs.qwedai.tech/faq"
        self.details = details or {}
        super().__init__(self._format_message())
    
    def _format_message(self) -> str:
        """Format error message with suggestion and docs link."""
        parts = [f"❌ {self.message}"]
        
        if self.suggestion:
            parts.append(f"\n💡 Suggestion: {self.suggestion}")
        
        if self.docs_url:
            parts.append(f"\n📚 Docs: {self.docs_url}")
        
        return "".join(parts)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "error": self.__class__.__name__,
            "message": self.message,
            "suggestion": self.suggestion,
            "docs_url": self.docs_url,
            "details": self.details
        }


# =============================================================================
# DSL & Parsing Errors
# =============================================================================

class QWEDSyntaxError(QWEDError):
    """Syntax error in DSL expression."""
    
    def __init__(
        self,
        message: str,
        expression: Optional[str] = None,
        line: Optional[int] = None,
        column: Optional[int] = None,
        suggestion: Optional[str] = None
    ):
        self.expression = expression
        self.line = line
        self.column = column
        
        details = {}
        if expression:
            details["expression"] = expression
        if line is not None:
            details["line"] = line
        if column is not None:
            details["column"] = column
        
        super().__init__(
            message=message,
            suggestion=suggestion or "Check your expression syntax",
            docs_url="https://docs.qwedai.tech/api/dsl-reference",
            details=details
        )
    
    def _format_message(self) -> str:
        parts = [f"❌ Syntax Error: {self.message}"]
        
        if self.expression:
            parts.append(f"\n   Expression: {self.expression}")
            if self.column is not None:
                # Show caret pointing to error location
                pointer = " " * (15 + self.column) + "^"
                parts.append(f"\n{pointer}")
        
        if self.line is not None:
            parts.append(f"\n   At line {self.line}")
        
        if self.suggestion:
            parts.append(f"\n💡 {self.suggestion}")

        if self.docs_url:
            parts.append(f"\n📚 Docs: {self.docs_url}")
        
        return "".join(parts)


class QWEDSymbolNotFoundError(QWEDError):
    """Variable or function not found."""
    
    def __init__(
        self,
        symbol: str,
        available_symbols: Optional[List[str]] = None,
        expression: Optional[str] = None
    ):
        self.symbol = symbol
        self.available_symbols = available_symbols or []
        
        # Find similar symbols for "did you mean?"
        suggestions = self._find_similar(symbol, self.available_symbols)
        
        suggestion = None
        if suggestions:
            suggestion = f"Did you mean: {', '.join(suggestions[:3])}?"
        elif self.available_symbols:
            suggestion = f"Available symbols: {', '.join(self.available_symbols[:5])}"
        
        super().__init__(
            message=f"Symbol '{symbol}' not found",
            suggestion=suggestion,
            docs_url="https://docs.qwedai.tech/api/dsl-reference#variables",
            details={"symbol": symbol, "expression": expression}
        )
    
    @staticmethod
    def _find_similar(target: str, candidates: List[str], threshold: float = 0.6) -> List[str]:
        """Find similar symbols using simple edit distance."""
        def similarity(a: str, b: str) -> float:
            if not a or not b:
                return 0.0
            # Simple character overlap ratio
            common = sum(1 for c in a.lower() if c in b.lower())
            return common / max(len(a), len(b))
        
        similar = [(c, similarity(target, c)) for c in candidates]
        similar = [(c, s) for c, s in similar if s >= threshold]
        similar.sort(key=lambda x: x[1], reverse=True)
        return [c for c, _ in similar]


# =============================================================================
# Verification Errors
# =============================================================================

class QWEDVerificationError(QWEDError):
    """Base class for verification failures."""
    
    def __init__(
        self,
        message: str,
        expected: Any = None,
        actual: Any = None,
        suggestion: Optional[str] = None,
        engine: Optional[str] = None
    ):
        self.expected = expected
        self.actual = actual
        self.engine = engine
        
        details = {}
        if expected is not None:
            details["expected"] = expected
        if actual is not None:
            details["actual"] = actual
        if engine:
            details["engine"] = engine
        
        super().__init__(
            message=message,
            suggestion=suggestion,
            docs_url="https://docs.qwedai.tech/engines/overview",
            details=details
        )


class QWEDMathError(QWEDVerificationError):
    """Mathematical verification failed."""
    
    def __init__(
        self,
        message: str,
        expression: Optional[str] = None,
        expected: Any = None,
        calculated: Any = None,
        tolerance: Optional[float] = None
    ):
        suggestion = None
        if expected is not None and calculated is not None:
            diff = abs(float(expected) - float(calculated)) if isinstance(expected, (int, float)) else None
            if diff is not None:
                suggestion = f"Difference: {diff:.6f}. Check if tolerance ({tolerance or 1e-6}) is appropriate."
        
        super().__init__(
            message=message,
            expected=expected,
            actual=calculated,
            suggestion=suggestion,
            engine="Math"
        )
        self.expression = expression
        self.tolerance = tolerance


class QWEDLogicError(QWEDVerificationError):
    """Logical verification failed."""
    
    def __init__(
        self,
        message: str,
        formula: Optional[str] = None,
        model: Optional[Dict] = None
    ):
        suggestion = "Check your logical formula and variable bindings."
        if model:
            suggestion = f"Counterexample found: {model}"
        
        super().__init__(
            message=message,
            suggestion=suggestion,
            engine="Logic"
        )
        self.formula = formula
        self.model = model


class QWEDCodeError(QWEDVerificationError):
    """Code verification failed."""
    
    def __init__(
        self,
        message: str,
        code: Optional[str] = None,
        output: Any = None,
        expected_output: Any = None,
        execution_error: Optional[str] = None
    ):
        suggestion = None
        if execution_error:
            suggestion = f"Code execution failed: {execution_error[:100]}"
        elif output != expected_output:
            suggestion = "Output doesn't match expected. Check your test case."
        
        super().__init__(
            message=message,
            expected=expected_output,
            actual=output,
            suggestion=suggestion,
            engine="Code"
        )
        self.code = code
        self.execution_error = execution_error


class QWEDSQLError(QWEDVerificationError):
    """SQL verification failed."""
    
    def __init__(
        self,
        message: str,
        query: Optional[str] = None,
        schema: Optional[Dict] = None,
        issue: Optional[str] = None
    ):
        suggestion = None
        if issue:
            suggestion = f"SQL Issue: {issue}"
        else:
            suggestion = "Check SQL syntax and schema compatibility."
        
        super().__init__(
            message=message,
            suggestion=suggestion,
            engine="SQL"
        )
        self.query = query
        self.schema = schema


# =============================================================================
# Configuration Errors
# =============================================================================

class QWEDConfigError(QWEDError):
    """Configuration error."""
    
    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        expected_type: Optional[str] = None,
        actual_value: Any = None
    ):
        suggestion = None
        if config_key:
            suggestion = f"Check your configuration for '{config_key}'"
        
        super().__init__(
            message=message,
            suggestion=suggestion,
            docs_url="https://docs.qwedai.tech/getting-started/installation",
            details={
                "config_key": config_key,
                "expected_type": expected_type,
                "actual_value": str(actual_value)[:100] if actual_value else None
            }
        )


class QWEDAPIError(QWEDError):
    """API communication error."""
    
    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        endpoint: Optional[str] = None
    ):
        suggestion = None
        if status_code == 401:
            suggestion = "Check your API key. Is QWED_API_KEY set?"
        elif status_code == 429:
            suggestion = "Rate limit exceeded. Wait and retry."
        elif status_code == 500:
            suggestion = "Server error. Check the QWED server logs and retry."
        elif status_code:
            suggestion = f"HTTP {status_code}. Check your request."
        
        super().__init__(
            message=message,
            suggestion=suggestion,
            docs_url="https://docs.qwedai.tech/api/authentication",
            details={"status_code": status_code, "endpoint": endpoint}
        )


class QWEDDependencyError(QWEDError):
    """Missing dependency."""
    
    INSTALL_COMMANDS = {
        "sympy": "pip install sympy",
        "z3": "pip install z3-solver",
        "numpy": "pip install numpy",
        "cryptography": "pip install cryptography",
        "aiohttp": "pip install aiohttp",
    }
    
    def __init__(self, package: str, feature: Optional[str] = None):
        install_cmd = self.INSTALL_COMMANDS.get(package, f"pip install {package}")
        
        message = f"Missing required package: {package}"
        if feature:
            message = f"Package '{package}' is required for {feature}"
        
        super().__init__(
            message=message,
            suggestion=f"Install with: {install_cmd}",
            docs_url="https://docs.qwedai.tech/getting-started/installation",
            details={"package": package, "install_command": install_cmd}
        )


# =============================================================================
# Utility Functions
# =============================================================================

def wrap_error(exception: Exception, context: Optional[str] = None) -> QWEDError:
    """
    Wrap a generic exception in a QWED error for better messaging.
    
    Usage:
        try:
            result = sympy.parse_expr(expr)
        except Exception as e:
            raise wrap_error(e, "parsing expression")
    """
    message = str(exception)
    
    # Try to identify common error types
    if "not defined" in message.lower() or "undefined" in message.lower():
        return QWEDSymbolNotFoundError(
            symbol=message.split("'")[1] if "'" in message else "unknown"
        )
    
    if "syntax" in message.lower():
        return QWEDSyntaxError(message)
    
    # Generic wrapper
    return QWEDError(
        message=f"{context}: {message}" if context else message,
        suggestion="Check the error details and try again"
    )
