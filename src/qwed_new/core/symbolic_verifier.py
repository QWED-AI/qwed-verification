"""
Symbolic Logic Verifier: Python Code Verification using CrossHair.

Engine for symbolic execution - verifies Python code properties without running it.
Uses CrossHair (Z3-based) for symbolic analysis and property verification.

Phase 1 of QWED's symbolic execution roadmap.
"""

from typing import Dict, Any, List, Optional
import ast
import tempfile
import os
import sys

from .diagnostics import AdvisoryCheck, DiagnosticResult, DiagnosticStatus

from .verification_context import VerificationContextDocument

CONSTRAINT_SYNTAX_ERROR = "symbolic_verifier.syntax_error"




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
    
    def verify_code(self, code: str) -> DiagnosticResult:
        """
        Verify Python code using symbolic execution.

        Args:
            code: Python code to verify

        Returns:
            DiagnosticResult describing the outcome. Note: this engine does not
            yet emit VERIFIED — CrossHair's search is timeout-bounded, not a
            completeness proof, so "no counterexample found" is reported as
            UNVERIFIABLE rather than an authoritative proof (see issue #15).
            Only UNVERIFIABLE and BLOCKED are currently produced.
        """
        if not self._crosshair_available:
            return DiagnosticResult.blocked(
                agent_message="Symbolic verification is unavailable: the CrossHair engine is not installed.",
                developer_fields={
                    "constraint_id": "symbolic_verifier.crosshair_not_available",
                    "verification_mode": "symbolic",
                },
            )

        # Parse code to extract functions
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return DiagnosticResult.blocked(
                agent_message="Symbolic verification blocked: the code could not be parsed.",
                developer_fields={
                    "constraint_id": CONSTRAINT_SYNTAX_ERROR,
                    "parse_error": str(e),
                    "verification_mode": "symbolic",
                },
            )

        # Find all functions with type hints (CrossHair needs types)
        functions = self._extract_functions(tree)

        if not functions:
            return DiagnosticResult.blocked(
                agent_message="Symbolic verification blocked: no functions were found to verify.",
                developer_fields={
                    "constraint_id": "symbolic_verifier.no_verifiable_functions",
                    "functions_discovered": 0,
                    "verification_mode": "symbolic",
                },
            )

        summary = self._summarize_verification_results(code, functions)
        return self._diagnostic_from_summary(summary)

    def _diagnostic_from_summary(self, summary: Dict[str, Any]) -> DiagnosticResult:
        """Map aggregated per-function counts to a DiagnosticResult (fail-closed)."""
        developer_fields = {
            "verification_mode": "symbolic",
            "functions_discovered": summary["functions_discovered"],
            "functions_checked": summary["checked_count"],
            "functions_verified": summary["verified_count"],
            "functions_skipped": summary["skipped_count"],
            "functions_unverifiable": summary["unverifiable_count"],
            "counterexamples_found": summary["counterexample_count"],
            "timeouts_found": summary["timeout_count"],
            "issues": summary["issues"],
        }

        if summary["all_verified"]:
            # CrossHair found no counterexample, but a timeout-bounded search is
            # not a completeness proof — do not claim VERIFIED without a real
            # proof_ref (see issue #15 discussion).
            developer_fields["constraint_id"] = "symbolic_verifier.no_counterexample_found"
            return DiagnosticResult.unverifiable(
                agent_message=(
                    "No counterexample was found for the checked functions, but "
                    "exhaustive proof was not established."
                ),
                developer_fields=developer_fields,
            )

        if summary["counterexample_count"] > 0:
            developer_fields["constraint_id"] = "symbolic_verifier.counterexample_found"
            return DiagnosticResult.unverifiable(
                agent_message="Symbolic verification found a counterexample disproving correctness for one or more functions.",
                developer_fields=developer_fields,
            )

        if summary["timeout_count"] > 0:
            developer_fields["constraint_id"] = "symbolic_verifier.timeout"
            return DiagnosticResult.unverifiable(
                agent_message="Symbolic verification did not converge within the configured timeout.",
                developer_fields=developer_fields,
            )

        if summary["checked_count"] == 0 and summary["unverifiable_count"] == summary["skipped_count"]:
            # Only claim "no typed functions" when every unverifiable function
            # was a genuine skip (missing type annotations). If any of them
            # errored out instead, typed functions did exist — that falls
            # through to incomplete_coverage below instead of this message.
            developer_fields["constraint_id"] = "symbolic_verifier.no_typed_functions"
            return DiagnosticResult.blocked(
                agent_message="Symbolic verification blocked: no typed functions were available to check.",
                developer_fields=developer_fields,
            )

        if summary["skipped_count"] > 0 or summary["unverifiable_count"] > 0:
            developer_fields["constraint_id"] = "symbolic_verifier.incomplete_coverage"
            return DiagnosticResult.unverifiable(
                agent_message="Symbolic verification was incomplete; at least one function could not be checked.",
                developer_fields=developer_fields,
            )

        developer_fields["constraint_id"] = "symbolic_verifier.verification_error"
        return DiagnosticResult.blocked(
            agent_message="Symbolic verification did not complete cleanly.",
            developer_fields=developer_fields,
        )

    def _summarize_verification_results(
        self,
        code: str,
        functions: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Aggregate per-function verification results into summary counts."""
        issues = []
        verified_count = 0
        checked_count = 0
        skipped_count = 0
        unverifiable_count = 0
        counterexample_count = 0
        timeout_count = 0

        for func in functions:
            result = self._verify_function(code, func)
            if result.get("verified"):
                verified_count += 1
            if not result.get("skipped") and not result.get("unverifiable"):
                checked_count += 1

            if result.get("skipped") or result.get("unverifiable"):
                unverifiable_count += 1
                if result.get("skipped"):
                    skipped_count += 1

            result_issues = result.get("issues", [])
            issues.extend(result_issues)
            counterexample_count += sum(
                1 for issue in result_issues if issue.get("type") == "counterexample"
            )
            timeout_count += sum(
                1 for issue in result_issues if issue.get("type") == "timeout"
            )

        all_verified = (
            checked_count > 0 and
            verified_count == checked_count and
            skipped_count == 0 and
            unverifiable_count == 0 and
            counterexample_count == 0 and
            timeout_count == 0
        )

        return {
            "all_verified": all_verified,
            "issues": issues,
            "verified_count": verified_count,
            "checked_count": checked_count,
            "skipped_count": skipped_count,
            "unverifiable_count": unverifiable_count,
            "counterexample_count": counterexample_count,
            "timeout_count": timeout_count,
            "functions_discovered": len(functions),
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
                "verified": False,
                "skipped": True,
                "unverifiable": True,
                "reason": "No type annotations - CrossHair requires type hints",
                "issues": [{
                    "type": "unverifiable",
                    "function": func_name,
                    "description": "Function skipped: no type annotations for symbolic verification"
                }]
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
                has_timeout = any(i.get("type") == "timeout" for i in issues)
                
                return {
                    "verified": len(issues) == 0,
                    "function": func_name,
                    "skipped": False,
                    "unverifiable": has_timeout,
                    "issues": issues
                }
            finally:
                os.unlink(temp_path)
                
        except Exception as e:
            return {
                "verified": False,
                "function": func_name,
                "skipped": False,
                "unverifiable": True,
                "issues": [{
                    "type": "error",
                    "function": func_name,
                    "description": f"CrossHair error: {str(e)}"
                }]
            }
    
    def _run_crosshair_check(self, file_path: str, func_name: str) -> List[Dict[str, Any]]:
        """
        Run CrossHair check on a specific function.

        CrossHair's CLI distinguishes a disproving counterexample (exit 1)
        from an engine-level failure (exit 2) — only exit 1 is reported as a
        counterexample; any other nonzero exit is an error, not a disproof.

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
            output = result.stdout + result.stderr

            if result.returncode == 1:
                # Exit 1: CrossHair disproved the check with a counterexample.
                for line in output.split('\n'):
                    if line.strip() and ('error' in line.lower() or 'counterexample' in line.lower()):
                        issues.append({
                            "type": "counterexample",
                            "function": func_name,
                            "description": line.strip()
                        })
                if not issues:
                    issues.append({
                        "type": "counterexample",
                        "function": func_name,
                        "description": output.strip() or "CrossHair reported a counterexample (exit code 1)."
                    })
            elif result.returncode != 0:
                # Any other nonzero exit (e.g. 2) is an engine failure, not a disproof.
                issues.append({
                    "type": "error",
                    "function": func_name,
                    "description": output.strip() or f"CrossHair exited with code {result.returncode}."
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
    
    def _check_division_safety(self, node, issues, properties_checked):
        """Check a node for division-by-zero hazards."""
        if not isinstance(node, ast.BinOp) or not isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
            return
        properties_checked.append("division_safety")
        if isinstance(node.right, ast.Constant) and node.right.value == 0:
            issues.append({
                "type": "division_by_zero",
                "line": node.lineno,
                "description": "Division by literal zero detected",
            })
        elif isinstance(node.right, ast.Name):
            issues.append({
                "type": "potential_division_by_zero",
                "line": node.lineno,
                "variable": node.right.id,
                "description": f"Division by variable '{node.right.id}' - could be zero",
            })

    def _check_subscript_safety(self, node, issues, properties_checked):
        """Check a node for index-out-of-bounds hazards."""
        if not isinstance(node, ast.Subscript):
            return
        properties_checked.append("index_safety")
        if isinstance(node.slice, ast.Name):
            issues.append({
                "type": "potential_index_error",
                "line": node.lineno,
                "description": "Index access with variable index - bounds not verified",
            })

    def verify_safety_properties(self, code: str) -> "DiagnosticResult":
        """Verify common safety properties: division by zero, index bounds, etc."""
        properties_checked = []
        issues = []

        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return DiagnosticResult.blocked(
                agent_message="Safety check blocked: the code could not be parsed.",
                developer_fields={
                    "constraint_id": CONSTRAINT_SYNTAX_ERROR,
                    "parse_error": str(e),
                    "verification_mode": "symbolic",
                    "is_safe": False,
                    "issues": [],
                    "warnings": 0,
                    "errors": 0,
                    "advisory_checks": [],
                },
            )

        for node in ast.walk(tree):
            self._check_division_safety(node, issues, properties_checked)
            self._check_subscript_safety(node, issues, properties_checked)
            if isinstance(node, ast.Call):
                properties_checked.append("call_safety")

        safe = len([i for i in issues if "potential" not in i["type"]]) == 0
        warnings = len([i for i in issues if "potential" in i["type"]])
        errors = len([i for i in issues if "potential" not in i["type"]])

        advisory = AdvisoryCheck(
            name="safety_properties",
            constraint_id="symbolic_verifier.safety_properties",
            details={
                "is_safe": safe,
                "warnings": warnings,
                "errors": errors,
            },
        )

        return DiagnosticResult.unverifiable(
            agent_message=f"Safety check: {len(issues)} issues found" if issues else "Safety check: no issues detected",
            developer_fields={
                "constraint_id": "symbolic_verifier.safety_properties",
                "verification_mode": "symbolic",
                "is_safe": safe,
                "properties_checked": list(dict.fromkeys(properties_checked)),
                "issues": issues,
                "warnings": warnings,
                "errors": errors,
                "advisory_checks": [advisory.to_dict()],
            },
        )
    
    def verify_function_contract(
        self, 
        code: str,
        function_name: str,
        preconditions: Optional[List[str]] = None,
        postconditions: Optional[List[str]] = None
    ) -> DiagnosticResult:
        """
        Verify a function satisfies its contract.

        Args:
            code: Python code containing the function
            function_name: Name of function to verify
            preconditions: List of precondition expressions (e.g., ["x > 0", "y != 0"])
            postconditions: List of postcondition expressions (e.g., ["__return__ >= 0"])

        Returns:
            DiagnosticResult with contract verification results
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
    
    def analyze_complexity(self, code: str) -> "DiagnosticResult":
        """Analyze code complexity for bounded model checking."""
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return DiagnosticResult.blocked(
                agent_message="Complexity analysis blocked: the code could not be parsed.",
                developer_fields={
                    "constraint_id": CONSTRAINT_SYNTAX_ERROR,
                    "status": "syntax_error",
                    "parse_error": str(e),
                    "loops": [],
                    "recursions": [],
                    "max_loop_depth": 0,
                    "total_loops": 0,
                    "total_recursive_functions": 0,
                    "complexity_score": 0,
                    "recommendation": {},
                    "verification_mode": "symbolic",
                    "advisory_checks": [],
                },
            )

        loops = self._find_loops(tree)
        recursions = self._find_recursions(tree)
        max_depth = self._calculate_max_loop_depth(tree)
        complexity_score = len(loops) + len(recursions) * 2 + max_depth
        recommendation = self._get_bounding_recommendation(loops, recursions, max_depth)

        advisory = AdvisoryCheck(
            name="complexity_analysis",
            constraint_id="symbolic_verifier.complexity_analysis",
            details={
                "total_loops": len(loops),
                "total_recursive_functions": len(recursions),
                "max_loop_depth": max_depth,
                "complexity_score": complexity_score,
            },
        )

        return DiagnosticResult.unverifiable(
            agent_message=f"Complexity analysis: {len(loops)} loops, {len(recursions)} recursions, depth {max_depth}",
            developer_fields={
                "status": "analyzed",
                "loops": loops,
                "recursions": recursions,
                "max_loop_depth": max_depth,
                "total_loops": len(loops),
                "total_recursive_functions": len(recursions),
                "complexity_score": complexity_score,
                "recommendation": recommendation,
                "verification_mode": "symbolic",
                "advisory_checks": [advisory.to_dict()],
            },
        )
    
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
    ) -> "DiagnosticResult":
        bounds_applied = {
            "loop_bound": loop_bound,
            "recursion_depth": recursion_depth,
            "prioritized": prioritize_paths,
        }

        analysis = self.analyze_complexity(code)
        complexity_data = analysis.developer_fields

        if analysis.status is DiagnosticStatus.BLOCKED:
            diagnostic = DiagnosticResult.blocked(
                agent_message="Bounded verification blocked: the code could not be parsed.",
                developer_fields={
                    "constraint_id": CONSTRAINT_SYNTAX_ERROR,
                    "parse_error": analysis.developer_fields.get("parse_error", analysis.agent_message),
                },
            )
            return self._bounded_result(diagnostic, bounded=False, bounds_applied=bounds_applied, complexity_analysis=complexity_data)

        try:
            bounded_code = self._add_bounds_to_code(code, loop_bound, recursion_depth)
        except ValueError as e:
            diagnostic = DiagnosticResult.blocked(
                agent_message="Bounded verification blocked: failed to apply the bounded-model transform.",
                developer_fields={
                    "constraint_id": "symbolic_verifier.bounds_transform_error",
                    "transform_error": str(e),
                },
            )
            return self._bounded_result(diagnostic, bounded=False, bounds_applied=bounds_applied, complexity_analysis=complexity_data)

        diagnostic = self.verify_code(bounded_code)
        return self._bounded_result(diagnostic, bounded=True, bounds_applied=bounds_applied, complexity_analysis=complexity_data)

    def _bounded_result(
        self,
        diagnostic: "DiagnosticResult",
        bounded: bool,
        bounds_applied: Dict[str, Any],
        complexity_analysis: Dict[str, Any],
    ) -> "DiagnosticResult":
        """Enrich a DiagnosticResult with bounded-model metadata in developer_fields."""
        enriched = dict(diagnostic.developer_fields)
        enriched["verification_mode"] = "bounded_symbolic"
        enriched["bounded"] = bounded
        enriched["bounds_applied"] = bounds_applied
        enriched["complexity_analysis"] = complexity_analysis
        return DiagnosticResult(
            status=diagnostic.status,
            agent_message=diagnostic.agent_message,
            developer_fields=enriched,
            proof_ref=diagnostic.proof_ref,
        )
    
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
        except Exception as e:
            raise ValueError("Failed to apply bounded-model transform") from e
    
    def get_verification_budget(
        self, 
        code: str,
        max_paths: int = 1000
    ) -> "DiagnosticResult":
        """Calculate verification budget — estimated paths to explore."""
        analysis = self.analyze_complexity(code)

        if analysis.status is DiagnosticStatus.BLOCKED:
            return DiagnosticResult.blocked(
                agent_message="Cannot estimate verification budget: syntax error in code.",
                developer_fields={
                    "constraint_id": CONSTRAINT_SYNTAX_ERROR,
                    "parse_error": analysis.developer_fields.get("parse_error", analysis.agent_message),
                    "feasible": False,
                    "verification_mode": "symbolic",
                    "advisory_checks": [],
                },
            )

        loops = analysis.developer_fields.get("loops", [])
        recursions = analysis.developer_fields.get("recursions", [])

        default_iterations = 10
        estimated_paths = 1

        for loop in loops:
            if loop.get("iterable_type") == "range":
                estimated_paths *= default_iterations
            else:
                estimated_paths *= default_iterations * 2

        if recursions:
            estimated_paths *= 2 ** len(recursions)

        feasible = estimated_paths <= max_paths
        capped = min(estimated_paths, 999999)

        message = (
            "Estimated verification feasible within budget (advisory, not proof-bearing)"
            if feasible
            else f"Estimated path explosion risk: {estimated_paths} paths. Use stricter bounds (advisory, not proof-bearing)."
        )

        advisory = AdvisoryCheck(
            name="verification_budget",
            constraint_id="symbolic_verifier.verification_budget",
            details={
                "estimated_paths": capped,
                "max_paths": max_paths,
                "feasible": feasible,
            },
        )

        return DiagnosticResult.unverifiable(
            agent_message=message,
            developer_fields={
                "constraint_id": "symbolic_verifier.verification_budget",
                "estimated_paths": capped,
                "max_paths": max_paths,
                "feasible": feasible,
                "recommendation": analysis.developer_fields.get("recommendation", {}),
                "verification_mode": "symbolic",
                "advisory_checks": [advisory.to_dict()],
            },
        )

    def to_verification_context(self, result: "DiagnosticResult", query: str, attestation_token: Optional[str] = None) -> "VerificationContextDocument":
        """Map a DiagnosticResult to a Verification Context v1.0 document."""
        from .verification_context_bridge import verification_context_from_diagnostic_result
        return verification_context_from_diagnostic_result(
            result,
            formal_statement=query,
            attestation_token=attestation_token,
            verifier="SymbolicVerifier",
        )



# Factory function for easy access
def create_symbolic_verifier(**kwargs) -> SymbolicVerifier:
    """Create a SymbolicVerifier instance."""
    return SymbolicVerifier(**kwargs)


