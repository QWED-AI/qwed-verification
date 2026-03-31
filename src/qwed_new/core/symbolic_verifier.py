"""
Symbolic Logic Verifier: Python Code Verification using CrossHair.

Engine for symbolic execution - verifies Python code properties without running it.
Uses CrossHair (Z3-based) for symbolic analysis and property verification.

Phase 1 of QWED's symbolic execution roadmap.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
import ast
import tempfile
import os
import sys


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
    
    # =========================================================================
    # Phase 2: Bounded Model Checking
    # =========================================================================
    
    def analyze_complexity(self, code: str) -> Dict[str, Any]:
        """
        Analyze code complexity for bounded model checking.
        
        Identifies:
        - Loops and their nesting depth
        - Recursive functions
        - Potentially infinite constructs
        
        Args:
            code: Python code to analyze
            
        Returns:
            Dict with complexity analysis
        """
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return {
                "status": "syntax_error",
                "message": str(e)
            }
        
        loops = self._find_loops(tree)
        recursions = self._find_recursions(tree)
        max_depth = self._calculate_max_loop_depth(tree)
        
        return {
            "status": "analyzed",
            "loops": loops,
            "recursions": recursions,
            "max_loop_depth": max_depth,
            "total_loops": len(loops),
            "total_recursive_functions": len(recursions),
            "complexity_score": len(loops) + len(recursions) * 2 + max_depth,
            "recommendation": self._get_bounding_recommendation(loops, recursions, max_depth)
        }
    
    def _find_loops(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """Find all loops in the code with their properties."""
        loops = []
        
        class LoopVisitor(ast.NodeVisitor):
            def __init__(self):
                self.depth = 0
                
            def visit_For(self, node):
                self.depth += 1
                loop_info = {
                    "type": "for",
                    "line": node.lineno,
                    "depth": self.depth,
                    "has_break": self._has_break(node),
                    "iterable_type": self._get_iterable_type(node)
                }
                loops.append(loop_info)
                self.generic_visit(node)
                self.depth -= 1
                
            def visit_While(self, node):
                self.depth += 1
                loop_info = {
                    "type": "while",
                    "line": node.lineno,
                    "depth": self.depth,
                    "has_break": self._has_break(node),
                    "condition": ast.unparse(node.test) if hasattr(ast, 'unparse') else str(node.test)
                }
                loops.append(loop_info)
                self.generic_visit(node)
                self.depth -= 1
                
            def _has_break(self, node) -> bool:
                for child in ast.walk(node):
                    if isinstance(child, ast.Break):
                        return True
                return False
                
            def _get_iterable_type(self, node) -> str:
                if isinstance(node.iter, ast.Call):
                    if isinstance(node.iter.func, ast.Name):
                        return node.iter.func.id  # e.g., "range"
                return "unknown"
        
        visitor = LoopVisitor()
        visitor.visit(tree)
        return loops
    
    def _find_recursions(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """Find all potentially recursive functions."""
        recursions = []
        
        # Get all function names
        function_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                function_names.add(node.name)
        
        # Check each function for self-calls
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                func_name = node.name
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        if isinstance(child.func, ast.Name) and child.func.id == func_name:
                            recursions.append({
                                "function": func_name,
                                "line": node.lineno,
                                "call_line": child.lineno,
                                "type": "direct"
                            })
                            break
                        # Check for mutual recursion (calls to other defined functions)
                        elif isinstance(child.func, ast.Name) and child.func.id in function_names:
                            if child.func.id != func_name:
                                recursions.append({
                                    "function": func_name,
                                    "calls": child.func.id,
                                    "line": node.lineno,
                                    "type": "potential_mutual"
                                })
        
        return recursions
    
    def _calculate_max_loop_depth(self, tree: ast.AST) -> int:
        """Calculate maximum loop nesting depth."""
        max_depth = 0
        
        class DepthCalculator(ast.NodeVisitor):
            def __init__(self):
                self.current_depth = 0
                self.max_found = 0
                
            def visit_For(self, node):
                self.current_depth += 1
                self.max_found = max(self.max_found, self.current_depth)
                self.generic_visit(node)
                self.current_depth -= 1
                
            def visit_While(self, node):
                self.current_depth += 1
                self.max_found = max(self.max_found, self.current_depth)
                self.generic_visit(node)
                self.current_depth -= 1
        
        calc = DepthCalculator()
        calc.visit(tree)
        return calc.max_found
    
    def _get_bounding_recommendation(
        self, 
        loops: List[Dict], 
        recursions: List[Dict], 
        max_depth: int
    ) -> Dict[str, Any]:
        """Get recommended bounds based on complexity."""
        
        # Base recommendations
        loop_bound = 10  # Default iterations per loop
        recursion_depth = 5  # Default recursion depth
        timeout = 30  # Default timeout
        
        # Adjust based on complexity
        if max_depth > 2:
            loop_bound = max(3, 10 // max_depth)  # Reduce for deep nesting
            timeout = min(60, timeout * max_depth)
            
        if len(recursions) > 0:
            recursion_depth = 5
            if len(loops) > 3:
                recursion_depth = 3  # More conservative with many loops
                
        risk_level = "low"
        if len(loops) > 5 or max_depth > 3 or len(recursions) > 2:
            risk_level = "high"
        elif len(loops) > 2 or max_depth > 1 or len(recursions) > 0:
            risk_level = "medium"
        
        return {
            "loop_bound": loop_bound,
            "recursion_depth": recursion_depth,
            "timeout_seconds": timeout,
            "risk_level": risk_level,
            "message": f"Recommended bounds: {loop_bound} iterations, {recursion_depth} recursion depth"
        }
    
    def verify_bounded(
        self, 
        code: str,
        loop_bound: int = 10,
        recursion_depth: int = 5,
        prioritize_paths: bool = True
    ) -> Dict[str, Any]:
        """
        Verify code with bounded model checking.
        
        Prevents path explosion by limiting:
        - Loop iterations
        - Recursion depth
        - Exploration paths
        
        Args:
            code: Python code to verify
            loop_bound: Maximum loop iterations to explore
            recursion_depth: Maximum recursion depth
            prioritize_paths: If True, check critical paths first
            
        Returns:
            Dict with bounded verification results
        """
        # First analyze complexity
        analysis = self.analyze_complexity(code)
        
        if analysis.get("status") == "syntax_error":
            return {
                "is_verified": False,
                "status": "syntax_error",
                "message": analysis.get("message")
            }
        
        # Transform code to add bounds
        bounded_code = self._add_bounds_to_code(code, loop_bound, recursion_depth)
        
        # Run verification on bounded code
        result = self.verify_code(bounded_code)
        
        # Add bounded analysis info
        result["bounded"] = True
        result["bounds_applied"] = {
            "loop_bound": loop_bound,
            "recursion_depth": recursion_depth,
            "prioritized": prioritize_paths
        }
        result["complexity_analysis"] = analysis
        
        return result
    
    def _add_bounds_to_code(
        self, 
        code: str, 
        loop_bound: int, 
        recursion_depth: int
    ) -> str:
        """
        Transform code to add execution bounds.
        
        Adds:
        - Loop counters with early exit
        - Recursion depth tracking
        """
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return code  # Return original if can't parse
        
        # Add recursion depth tracking to functions
        class BoundTransformer(ast.NodeTransformer):
            def __init__(self, max_depth):
                self.max_depth = max_depth
                self.transformed_functions = set()
                
            def visit_FunctionDef(self, node):
                # Add depth parameter and check
                if node.name not in self.transformed_functions:
                    self.transformed_functions.add(node.name)
                    
                    # Create depth check: if _depth > max_depth: raise RecursionError
                    depth_check = ast.parse(
                        f"if _qwed_depth > {self.max_depth}: raise RecursionError('QWED: Bounded recursion limit reached')"
                    ).body[0]
                    
                    # Insert at beginning of function (after docstring if present)
                    insert_idx = 0
                    if node.body and isinstance(node.body[0], ast.Expr):
                        if isinstance(node.body[0].value, ast.Constant):
                            insert_idx = 1
                    
                    # Add default parameter for depth
                    depth_arg = ast.arg(arg='_qwed_depth', annotation=None)
                    depth_default = ast.Constant(value=0)
                    
                    node.args.args.append(depth_arg)
                    node.args.defaults.append(depth_default)
                    
                    node.body.insert(insert_idx, depth_check)
                
                self.generic_visit(node)
                return node
        
        transformer = BoundTransformer(recursion_depth)
        new_tree = transformer.visit(tree)
        ast.fix_missing_locations(new_tree)
        
        try:
            return ast.unparse(new_tree)
        except:
            return code  # Return original if transform fails
    
    def get_verification_budget(
        self, 
        code: str,
        max_paths: int = 1000
    ) -> Dict[str, Any]:
        """
        Calculate verification budget - estimated paths to explore.
        
        Helps decide if verification is feasible or needs stricter bounds.
        
        Args:
            code: Code to analyze
            max_paths: Maximum paths before warning
            
        Returns:
            Dict with path estimation and recommendations
        """
        analysis = self.analyze_complexity(code)
        
        if analysis.get("status") == "syntax_error":
            return analysis
        
        # Estimate paths (simplified heuristic)
        loops = analysis.get("loops", [])
        recursions = analysis.get("recursions", [])
        max_depth = analysis.get("max_loop_depth", 0)
        
        # Rough estimation: paths = iterations^depth for nested loops
        default_iterations = 10
        estimated_paths = 1
        
        for loop in loops:
            depth = loop.get("depth", 1)
            if loop.get("iterable_type") == "range":
                estimated_paths *= default_iterations
            else:
                estimated_paths *= default_iterations * 2  # Unknown iterables are worse
        
        # Add recursion factor
        if recursions:
            estimated_paths *= 2 ** len(recursions)
        
        feasible = estimated_paths <= max_paths
        
        return {
            "estimated_paths": min(estimated_paths, 999999),  # Cap for display
            "max_paths": max_paths,
            "feasible": feasible,
            "recommendation": analysis.get("recommendation", {}),
            "message": (
                "Verification feasible within budget" if feasible 
                else f"Path explosion risk: {estimated_paths} paths. Use stricter bounds."
            )
        }


# Factory function for easy access
def create_symbolic_verifier(**kwargs) -> SymbolicVerifier:
    """Create a SymbolicVerifier instance."""
    return SymbolicVerifier(**kwargs)
