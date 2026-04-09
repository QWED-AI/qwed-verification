"""
Enterprise Statistical Verification Engine.

Verifies claims about tabular data using a secure Docker sandbox.
In-process execution fallbacks are intentionally disabled.

Enhanced Features:
- Pre-execution security validation
- Memory and CPU limits
- Timeout enforcement
- Result validation
"""

import pandas as pd
import logging
import time
from typing import Optional, Dict, Any, Tuple, List
from dataclasses import dataclass, field
import ast

logger = logging.getLogger(__name__)
INTERNAL_VERIFICATION_ERROR = "Internal verification error"

SECURE_STATS_SANDBOX_REQUIRED = (
    "Statistical verification requires the secure Docker sandbox. "
    "In-process fallback execution is disabled."
)
SECURE_STATS_BLOCKED_CODE = "SERVICE_UNAVAILABLE"
SECURE_STATS_RUNTIME_UNAVAILABLE = "SECURE_RUNTIME_UNAVAILABLE"


@dataclass
class ExecutionResult:
    """Result of code execution."""
    success: bool
    result: Any = None
    error: Optional[str] = None
    execution_time_ms: float = 0.0
    sandbox_type: str = "unknown"
    memory_used_mb: float = 0.0


@dataclass
class SecurityReport:
    """Security validation report."""
    is_safe: bool
    checks_passed: List[str] = field(default_factory=list)
    checks_failed: List[str] = field(default_factory=list)
    risk_level: str = "unknown"  # "low", "medium", "high", "critical"


class WasmSandbox:
    """
    Deprecated Wasm fallback.

    This class is retained only to preserve explicit fail-closed behavior for
    older call sites. It never executes model-generated code in-process.

    Attributes:
        memory_limit_mb (int): Memory limit in MB.
        timeout_seconds (float): Execution timeout in seconds.
    """
    
    def __init__(
        self,
        memory_limit_mb: int = 128,
        timeout_seconds: float = 30.0
    ):
        """
        Initialize Wasm sandbox.

        Args:
            memory_limit_mb: Memory limit in megabytes.
            timeout_seconds: Execution timeout in seconds.
        """
        self.memory_limit_mb = memory_limit_mb
        self.timeout_seconds = timeout_seconds
        self._pyodide = None
        self._available = None
    
    def is_available(self) -> bool:
        """
        Check if Wasm sandbox is available.

        Returns:
            bool: True if available, False otherwise.
        """
        if self._available is not None:
            return self._available
        
        try:
            # Check for pyodide-py (Python wrapper for Pyodide)
            import pyodide
            self._available = True
        except ImportError:
            # Check for wasmtime as alternative
            try:
                import wasmtime
                self._available = True
            except ImportError:
                self._available = False
        
        return self._available
    
    def execute(
        self,
        code: str,
        context: Dict[str, Any]
    ) -> ExecutionResult:
        """
        Execute code in Wasm sandbox.
        
        The Wasm fallback is intentionally disabled. QWED requires Docker
        isolation for model-generated statistical code.

        Args:
            code: Python code to execute.
            context: Dictionary of variables to inject into the execution scope.

        Returns:
            ExecutionResult object containing success status and output.

        Example:
            >>> result = sandbox.execute("result = 1 + 1", {})
            >>> print(result.success)
            False
        """
        del code, context
        start_time = time.time()
        return ExecutionResult(
            success=False,
            error=SECURE_STATS_SANDBOX_REQUIRED,
            execution_time_ms=(time.time() - start_time) * 1000,
            sandbox_type="wasm_disabled"
        )


class RestrictedExecutor:
    """
    Restricted AST validator for generated statistical code.

    Execution is intentionally disabled; the class only retains AST validation
    helpers so QWED can block unsafe code before Docker execution.

    Attributes:
        timeout_seconds (float): Execution timeout in seconds.
    """
    
    # Allowed AST node types
    ALLOWED_NODES = {
        ast.Module, ast.Expr, ast.Call, ast.Name, ast.Load, ast.Store,
        ast.Constant, ast.Num, ast.Str, ast.List, ast.Dict, ast.Tuple,
        ast.BinOp, ast.UnaryOp, ast.Compare, ast.BoolOp,
        ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Pow, ast.FloorDiv,
        ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
        ast.And, ast.Or, ast.Not, ast.UAdd, ast.USub,
        ast.Subscript, ast.Index, ast.Slice, ast.Attribute,
        ast.Assign, ast.AugAssign, ast.If, ast.For, ast.While,
        ast.ListComp, ast.DictComp, ast.SetComp, ast.GeneratorExp,
        ast.comprehension, ast.Return, ast.Pass, ast.Break, ast.Continue,
        ast.FunctionDef, ast.arguments, ast.arg, ast.Lambda,
    }
    
    # Blocked function names
    BLOCKED_FUNCTIONS = {
        'eval', 'exec', 'compile', 'open', 'input', '__import__',
        'getattr', 'setattr', 'delattr', 'globals', 'locals',
        'vars', 'dir', 'type', 'object', 'super',
    }
    
    def __init__(self, timeout_seconds: float = 30.0):
        """
        Initialize RestrictedExecutor.

        Args:
            timeout_seconds: Execution timeout in seconds.
        """
        self.timeout_seconds = timeout_seconds
    
    def is_code_safe(self, code: str) -> Tuple[bool, List[str]]:
        """
        Check if code is safe to execute.

        Args:
            code: Python code to check.

        Returns:
            Tuple containing boolean status and list of issues.

        Example:
            >>> is_safe, issues = executor.is_code_safe("import os")
            >>> print(is_safe)
            False
        """
        issues = []
        
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return False, [f"Syntax error: {e}"]
        
        # Walk AST and check nodes
        for node in ast.walk(tree):
            # Check for blocked function calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in self.BLOCKED_FUNCTIONS:
                        issues.append(f"Blocked function: {node.func.id}")
            
            # Check for import statements
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                issues.append("Import statements not allowed")
        
        return len(issues) == 0, issues
    
    def execute(self, code: str, context: Dict[str, Any]) -> ExecutionResult:
        """
        Execution is intentionally disabled.

        Args:
            code: Python code to execute.
            context: Dictionary of variables to inject.

        Returns:
            ExecutionResult with execution details.

        Example:
            >>> result = executor.execute("result = 5 * 5", {})
            >>> print(result.success)
            False
        """
        del code, context
        start_time = time.time()
        return ExecutionResult(
            success=False,
            error=SECURE_STATS_SANDBOX_REQUIRED,
            execution_time_ms=(time.time() - start_time) * 1000,
            sandbox_type="restricted_disabled"
        )


class StatsVerifier:
    """
    Enterprise Statistical Verification Engine.
    
    Verifies claims about tabular data using the secure Docker sandbox only.

    Attributes:
        preferred_sandbox (str): Preferred sandbox type.
        timeout_seconds (float): Execution timeout.
        memory_limit_mb (int): Memory limit.
    """
    
    def __init__(
        self,
        preferred_sandbox: str = "auto",
        timeout_seconds: float = 30.0,
        memory_limit_mb: int = 128
    ):
        """
        Initialize Stats Verifier.
        
        Args:
            preferred_sandbox: "docker", "wasm", "restricted", or "auto".
                Non-Docker choices are blocked for model-generated code.
            timeout_seconds: Execution timeout in seconds.
            memory_limit_mb: Memory limit in megabytes.

        Example:
            >>> verifier = StatsVerifier(preferred_sandbox="docker")
        """
        self.preferred_sandbox = preferred_sandbox
        self.timeout_seconds = timeout_seconds
        self.memory_limit_mb = memory_limit_mb
        
        # Lazy-loaded components
        self._translator = None
        self._code_verifier = None
        self._docker_executor = None
        self._wasm_sandbox = None
        self._restricted_executor = None
        
        # Determine available sandboxes
        self._sandbox_availability = {}
    
    @property
    def translator(self):
        if self._translator is None:
            from qwed_new.core.translator import TranslationLayer
            self._translator = TranslationLayer()
        return self._translator
    
    @property
    def code_verifier(self):
        if self._code_verifier is None:
            from qwed_new.core.code_verifier import CodeVerifier
            self._code_verifier = CodeVerifier()
        return self._code_verifier
    
    @property
    def docker_executor(self):
        if self._docker_executor is None:
            try:
                from qwed_new.core.secure_code_executor import SecureCodeExecutor
                self._docker_executor = SecureCodeExecutor()
            except ImportError:
                self._docker_executor = None
        return self._docker_executor
    
    @property
    def wasm_sandbox(self):
        if self._wasm_sandbox is None:
            self._wasm_sandbox = WasmSandbox(
                memory_limit_mb=self.memory_limit_mb,
                timeout_seconds=self.timeout_seconds
            )
        return self._wasm_sandbox
    
    @property
    def restricted_executor(self):
        if self._restricted_executor is None:
            self._restricted_executor = RestrictedExecutor(
                timeout_seconds=self.timeout_seconds
            )
        return self._restricted_executor
    
    def _select_sandbox(self) -> Tuple[str, Any]:
        """Select the secure sandbox or fail closed."""
        if self.docker_executor and self.docker_executor.is_available():
            return "docker", self.docker_executor

        return "blocked", None
    
    def verify_stats(
        self,
        query: str,
        df: pd.DataFrame,
        provider: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verify a statistical claim about tabular data.
        
        Args:
            query: The user's question or claim.
            df: The pandas DataFrame containing the data.
            provider: Optional LLM provider.
            
        Returns:
            dict with status, result, code, and security info.

        Example:
            >>> df = pd.DataFrame({'a': [1, 2, 3]})
            >>> result = verifier.verify_stats("What is the mean of a?", df)
            >>> print(result["result"])
            2.0
        """
        start_time = time.time()
        columns = list(df.columns)
        
        # 1. Generate code from query
        try:
            code = self.translator.translate_stats(query, columns, provider=provider)
        except Exception as e:
            logger.error(
                "Stats code generation failed (exception_type=%s)",
                type(e).__name__,
                exc_info=False,
            )
            return {
                "status": "ERROR",
                "error": INTERNAL_VERIFICATION_ERROR,
                "columns": columns,
                "execution_time_ms": (time.time() - start_time) * 1000
            }
        
        # 2. Pre-execution security validation
        security_report = self._validate_security(code)
        
        if not security_report.is_safe:
            logger.warning(f"Code failed security validation: {security_report.checks_failed}")
            return {
                "status": "BLOCKED",
                "error": "Code failed security validation",
                "issues": security_report.checks_failed,
                "risk_level": security_report.risk_level,
                "code": code,
                "columns": columns,
                "execution_time_ms": (time.time() - start_time) * 1000
            }
        
        # 3. Select sandbox and execute
        sandbox_type, sandbox = self._select_sandbox()
        if sandbox_type != "docker" or sandbox is None:
            logger.warning("Blocked stats execution because secure Docker sandbox is unavailable")
            return {
                "status": "BLOCKED",
                "error": SECURE_STATS_BLOCKED_CODE,
                "code": code,
                "columns": columns,
                "execution_time_ms": (time.time() - start_time) * 1000
            }
        
        context = {"df": df}
        
        exec_result = self._execute_docker(code, context)
        
        total_time = (time.time() - start_time) * 1000
        
        if exec_result.success:
            return {
                "status": "SUCCESS",
                "result": exec_result.result,
                "code": code,
                "columns": columns,
                "security_checks": {
                    "ast_validation": "PASSED",
                    "sandbox_type": sandbox_type,
                    "checks_passed": security_report.checks_passed,
                    "risk_level": security_report.risk_level
                },
                "execution_time_ms": exec_result.execution_time_ms,
                "total_time_ms": total_time
            }
        if exec_result.error == SECURE_STATS_RUNTIME_UNAVAILABLE:
            logger.warning("Blocked stats execution because secure Docker sandbox became unavailable")
            return {
                "status": "BLOCKED",
                "error": SECURE_STATS_BLOCKED_CODE,
                "code": code,
                "columns": columns,
                "execution_time_ms": exec_result.execution_time_ms,
                "total_time_ms": total_time
            }
        else:
            return {
                "status": "EXECUTION_FAILED",
                "error": exec_result.error,
                "code": code,
                "columns": columns,
                "sandbox_type": sandbox_type,
                "execution_time_ms": exec_result.execution_time_ms,
                "total_time_ms": total_time
            }
    
    def _validate_security(self, code: str) -> SecurityReport:
        """Perform comprehensive security validation."""
        checks_passed = []
        checks_failed = []
        
        # 1. Code verifier check
        cv_result = self.code_verifier.verify_code(code, language="python")
        if cv_result["is_safe"]:
            checks_passed.append("code_verifier")
        else:
            for issue in cv_result.get("issues", []):
                if isinstance(issue, dict):
                    checks_failed.append(f"{issue.get('type', 'unknown')}: {issue.get('description', '')}")
                else:
                    checks_failed.append(str(issue))
        
        # 2. AST check
        is_ast_safe, ast_issues = self.restricted_executor.is_code_safe(code)
        if is_ast_safe:
            checks_passed.append("ast_analysis")
        else:
            checks_failed.extend(ast_issues)
        
        # 3. Pattern check (additional dangerous patterns)
        dangerous_patterns = [
            "__", "import os", "import sys", "subprocess",
            "open(", "exec(", "eval(", "compile("
        ]
        for pattern in dangerous_patterns:
            if pattern in code:
                checks_failed.append(f"Dangerous pattern: {pattern}")
        
        if dangerous_patterns and not any(p in code for p in dangerous_patterns):
            checks_passed.append("pattern_analysis")
        
        # Determine risk level
        if len(checks_failed) == 0:
            risk_level = "low"
        elif any("eval" in f or "exec" in f for f in checks_failed):
            risk_level = "critical"
        elif len(checks_failed) > 3:
            risk_level = "high"
        else:
            risk_level = "medium"
        
        return SecurityReport(
            is_safe=len(checks_failed) == 0,
            checks_passed=checks_passed,
            checks_failed=checks_failed,
            risk_level=risk_level
        )
    
    def _execute_docker(self, code: str, context: Dict[str, Any]) -> ExecutionResult:
        """Execute code in Docker sandbox."""
        start_time = time.time()
        
        try:
            from qwed_new.core.secure_code_executor import SECURE_RUNTIME_UNAVAILABLE
            success, error, result = self.docker_executor.execute(code, context)
            if error == SECURE_RUNTIME_UNAVAILABLE:
                error = SECURE_STATS_RUNTIME_UNAVAILABLE
            
            return ExecutionResult(
                success=success,
                result=result,
                error=error,
                execution_time_ms=(time.time() - start_time) * 1000,
                sandbox_type="docker"
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000,
                sandbox_type="docker"
            )
    
    # =========================================================================
    # Direct Statistical Operations (no code generation)
    # =========================================================================
    
    def compute_statistics(
        self,
        df: pd.DataFrame,
        column: str,
        operation: str
    ) -> Dict[str, Any]:
        """
        Compute statistics directly without code generation.
        
        Safer alternative for common operations.
        
        Args:
            df: DataFrame containing the data.
            column: Name of the column to operate on.
            operation: One of "mean", "median", "std", "var", "sum", "count", "min", "max", "mode".

        Returns:
            Dict containing the result or error.

        Example:
            >>> result = verifier.compute_statistics(df, "age", "mean")
            >>> print(result["result"])
            35.5
        """
        start_time = time.time()
        
        if column not in df.columns:
            return {
                "status": "ERROR",
                "error": f"Column '{column}' not found",
                "available_columns": list(df.columns)
            }
        
        operations = {
            "mean": lambda s: s.mean(),
            "median": lambda s: s.median(),
            "std": lambda s: s.std(),
            "var": lambda s: s.var(),
            "sum": lambda s: s.sum(),
            "count": lambda s: s.count(),
            "min": lambda s: s.min(),
            "max": lambda s: s.max(),
            "mode": lambda s: s.mode().iloc[0] if len(s.mode()) > 0 else None,
        }
        
        if operation not in operations:
            return {
                "status": "ERROR",
                "error": f"Unknown operation '{operation}'",
                "available_operations": list(operations.keys())
            }
        
        try:
            series = df[column]
            result = operations[operation](series)
        except Exception as e:
            return {
                "status": "ERROR",
                "error": str(e),
                "operation": operation,
                "column": column
            }

        if operation == "mode":
            mode_values = series.mode()
            if len(mode_values) > 1:
                return {
                    "status": "ERROR",
                    "error": (
                        f"mode is ambiguous because {len(mode_values)} equally frequent "
                        "values exist"
                    ),
                    "operation": operation,
                    "column": column,
                }
            if len(mode_values) == 0:
                return {
                    "status": "ERROR",
                    "error": "mode produced an undefined result (NaN)",
                    "operation": operation,
                    "column": column,
                }
            result = mode_values.iloc[0]

        if pd.isna(result):
            return {
                "status": "ERROR",
                "error": f"{operation} produced an undefined result (NaN)",
                "operation": operation,
                "column": column,
            }

        return {
            "status": "SUCCESS",
            "result": result,
            "operation": operation,
            "column": column,
            "execution_time_ms": (time.time() - start_time) * 1000
        }
    
    def get_sandbox_info(self) -> Dict[str, Any]:
        """
        Get information about available sandboxes.

        Returns:
            Dict with availability status for each sandbox type.
        """
        docker_available = (
            self.docker_executor is not None and 
            self.docker_executor.is_available()
        )
        
        return {
            "preferred": self.preferred_sandbox,
            "docker_available": docker_available,
            "wasm_available": False,
            "restricted_available": False,
            "current": self._select_sandbox()[0]
        }
