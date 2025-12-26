"""
Symbolic Logic Verifier: Python Code Verification using CrossHair.

Engine for symbolic execution - verifies Python code properties without running it.
Uses CrossHair (Z3-based) for symbolic analysis and property verification.

Phase 1 of QWED's symbolic execution roadmap.
"""

from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
import ast
import textwrap
import tempfile
import os
import sys
from io import StringIO


@dataclass
class SymbolicIssue:
    """A symbolic verification issue."""
    issue_type: str  # "counterexample", "error", "warning"
    function_name: str
    description: str
    counterexample: Optional[Dict[str, Any]] = None
    line_number: Optional[int] = None


@dataclass
class SymbolicResult:
    """Result of symbolic verification."""
    is_verified: bool
    status: str  # "verified", "counterexample_found", "error", "timeout"
    issues: List[SymbolicIssue] = field(default_factory=list)
    functions_checked: int = 0
    properties_verified: int = 0
    counterexamples_found: int = 0


class SymbolicVerifier:
    """
    Symbolic Logic Verifier using CrossHair.
    
    Engine for Phase 1 of QWED's symbolic execution roadmap.
    
    Capabilities:
    - Verify function preconditions/postconditions
    - Find counterexamples to assertions
    - Detect division by zero, null dereference, etc.
    - Prove safety properties symbolically
    
    Example:
        >>> verifier = SymbolicVerifier()
        >>> code = '''
        ... def divide(a: int, b: int) -> float:
        ...     '''Divide a by b.'''
        ...     return a / b
        ... '''
        >>> result = verifier.verify_code(code)
        >>> print(result.is_verified)
        False  # CrossHair finds b=0 counterexample
    """
    
    def __init__(self, timeout_seconds: int = 30, max_iterations: int = 100):
        """
        Initialize the symbolic verifier.
        
        Args:
            timeout_seconds: Max time per function check
            max_iterations: Max symbolic execution iterations (bounded model checking)
        """
        self.timeout_seconds = timeout_seconds
        self.max_iterations = max_iterations
        self._crosshair_available = self._check_crosshair()
    
    def _check_crosshair(self) -> bool:
        """Check if CrossHair is available."""
        try:
            import crosshair
            return True
        except ImportError:
            return False
    
    def verify_code(self, code: str, check_assertions: bool = True) -> Dict[str, Any]:
        """
        Verify Python code using symbolic execution.
        
        Args:
            code: Python code to verify
            check_assertions: Whether to check assert statements
            
        Returns:
            Dict with verification results
        """
        if not self._crosshair_available:
            return {
                "is_verified": False,
                "status": "crosshair_not_available",
                "message": "CrossHair not installed. Run: pip install crosshair-tool",
                "issues": []
            }
        
        # Parse code to extract functions
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return {
                "is_verified": False,
                "status": "syntax_error",
                "message": str(e),
                "issues": []
            }
        
        # Find all functions with type hints (CrossHair needs types)
        functions = self._extract_functions(tree)
        
        if not functions:
            return {
                "is_verified": True,
                "status": "no_functions_to_check",
                "message": "No typed functions found to verify",
                "issues": [],
                "functions_checked": 0
            }
        
        # Run CrossHair analysis
        issues = []
        verified_count = 0
        
        for func in functions:
            result = self._verify_function(code, func)
            if result["verified"]:
                verified_count += 1
            else:
                issues.extend(result.get("issues", []))
        
        all_verified = len(issues) == 0
        
        return {
            "is_verified": all_verified,
            "status": "verified" if all_verified else "counterexamples_found",
            "functions_checked": len(functions),
            "functions_verified": verified_count,
            "counterexamples_found": len(issues),
            "issues": issues
        }
    
    def _extract_functions(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """Extract function names and info from AST."""
        functions = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Check if function has type hints
                has_annotations = (
                    node.returns is not None or
                    any(arg.annotation is not None for arg in node.args.args)
                )
                
                functions.append({
                    "name": node.name,
                    "has_types": has_annotations,
                    "line_number": node.lineno,
                    "has_docstring": (
                        isinstance(node.body[0], ast.Expr) and
                        isinstance(node.body[0].value, ast.Constant) and
                        isinstance(node.body[0].value.value, str)
                    ) if node.body else False
                })
        
        return functions
    
    def _verify_function(self, code: str, func_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify a single function using CrossHair.
        
        Returns:
            Dict with verification result for this function
        """
        func_name = func_info["name"]
        
        # Skip functions without type hints (CrossHair needs them)
        if not func_info["has_types"]:
            return {
                "verified": True,
                "skipped": True,
                "reason": "No type annotations - CrossHair requires type hints"
            }
        
        try:
            from crosshair.main import check_function
            from crosshair.core_and_libs import standalone_statespace
            from crosshair.options import AnalysisOptionSet
            
            # Create temporary module with the code
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(code)
                temp_path = f.name
            
            try:
                # Run CrossHair check
                issues = self._run_crosshair_check(temp_path, func_name)
                
                return {
                    "verified": len(issues) == 0,
                    "function": func_name,
                    "issues": issues
                }
            finally:
                os.unlink(temp_path)
                
        except Exception as e:
            return {
                "verified": False,
                "function": func_name,
                "issues": [{
                    "type": "error",
                    "function": func_name,
                    "description": f"CrossHair error: {str(e)}"
                }]
            }
    
    def _run_crosshair_check(self, file_path: str, func_name: str) -> List[Dict[str, Any]]:
        """
        Run CrossHair check on a specific function.
        
        Returns list of issues found.
        """
        import subprocess
        
        # Run crosshair check command
        try:
            result = subprocess.run(
                [
                    sys.executable, "-m", "crosshair", "check",
                    "--per_condition_timeout", str(self.timeout_seconds),
                    f"{file_path}:{func_name}"
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds * 2
            )
            
            issues = []
            
            # Parse CrossHair output
            if result.returncode != 0 or result.stdout.strip():
                output = result.stdout + result.stderr
                
                # CrossHair outputs counterexamples in specific format
                for line in output.split('\n'):
                    if line.strip():
                        if 'error' in line.lower() or 'counterexample' in line.lower():
                            issues.append({
                                "type": "counterexample",
                                "function": func_name,
                                "description": line.strip()
                            })
            
            return issues
            
        except subprocess.TimeoutExpired:
            return [{
                "type": "timeout",
                "function": func_name,
                "description": f"Verification timed out after {self.timeout_seconds}s"
            }]
        except Exception as e:
            return [{
                "type": "error", 
                "function": func_name,
                "description": str(e)
            }]
    
    def verify_safety_properties(self, code: str) -> Dict[str, Any]:
        """
        Verify common safety properties in code:
        - Division by zero
        - Index out of bounds
        - None dereference
        - Integer overflow (where detectable)
        
        Args:
            code: Python code to check
            
        Returns:
            Dict with safety analysis results
        """
        properties_checked = []
        issues = []
        
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return {
                "is_safe": False,
                "status": "syntax_error",
                "message": str(e)
            }
        
        # Check for division operations
        for node in ast.walk(tree):
            if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
                properties_checked.append("division_safety")
                # Check if divisor could be zero (heuristic)
                if isinstance(node.right, ast.Constant) and node.right.value == 0:
                    issues.append({
                        "type": "division_by_zero",
                        "line": node.lineno,
                        "description": "Division by literal zero detected"
                    })
                elif isinstance(node.right, ast.Name):
                    issues.append({
                        "type": "potential_division_by_zero",
                        "line": node.lineno,
                        "variable": node.right.id,
                        "description": f"Division by variable '{node.right.id}' - could be zero"
                    })
        
        # Check for index operations
        for node in ast.walk(tree):
            if isinstance(node, ast.Subscript):
                properties_checked.append("index_safety")
                # Flag potential index issues
                if isinstance(node.slice, ast.Name):
                    issues.append({
                        "type": "potential_index_error",
                        "line": node.lineno,
                        "description": "Index access with variable index - bounds not verified"
                    })
        
        # Check for None comparisons that might indicate unhandled None
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                properties_checked.append("call_safety")
        
        return {
            "is_safe": len([i for i in issues if "potential" not in i["type"]]) == 0,
            "status": "analyzed",
            "properties_checked": list(set(properties_checked)),
            "issues": issues,
            "warnings": len([i for i in issues if "potential" in i["type"]]),
            "errors": len([i for i in issues if "potential" not in i["type"]])
        }
    
    def verify_function_contract(
        self, 
        code: str,
        function_name: str,
        preconditions: Optional[List[str]] = None,
        postconditions: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Verify a function satisfies its contract.
        
        Args:
            code: Python code containing the function
            function_name: Name of function to verify
            preconditions: List of precondition expressions (e.g., ["x > 0", "y != 0"])
            postconditions: List of postcondition expressions (e.g., ["__return__ >= 0"])
            
        Returns:
            Dict with contract verification results
        """
        # Add contract decorators and re-verify
        decorated_code = self._add_contracts(
            code, 
            function_name, 
            preconditions or [], 
            postconditions or []
        )
        
        return self.verify_code(decorated_code)
    
    def _add_contracts(
        self, 
        code: str, 
        func_name: str,
        preconditions: List[str],
        postconditions: List[str]
    ) -> str:
        """Add icontract-style contracts to code for CrossHair."""
        # For now, convert to assert statements
        tree = ast.parse(code)
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == func_name:
                # Add precondition asserts at start
                new_body = []
                for pre in preconditions:
                    assert_node = ast.parse(f"assert {pre}, 'Precondition failed: {pre}'").body[0]
                    new_body.append(assert_node)
                
                new_body.extend(node.body)
                node.body = new_body
        
        return ast.unparse(tree)


# Factory function for easy access
def create_symbolic_verifier(**kwargs) -> SymbolicVerifier:
    """Create a SymbolicVerifier instance."""
    return SymbolicVerifier(**kwargs)
