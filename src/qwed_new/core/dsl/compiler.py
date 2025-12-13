"""
QWED DSL Compiler.

Compiles validated AST from the parser into Z3 constraints or SymPy expressions.
"""

from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass

# Z3 imports (lazy to avoid import errors if Z3 not installed)
try:
    from z3 import (
        Int, Bool, Real, And, Or, Not, Implies, Xor,
        ForAll, Exists, Solver, sat, unsat
    )
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False

# SymPy imports (lazy)
try:
    import sympy
    from sympy import symbols, Eq, Ne, Gt, Lt, Ge, Le, And as SymAnd, Or as SymOr, Not as SymNot
    SYMPY_AVAILABLE = True
except ImportError:
    SYMPY_AVAILABLE = False


@dataclass
class CompileResult:
    """Result of compiling DSL to Z3/SymPy."""
    success: bool
    compiled: Optional[Any] = None
    variables: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class Z3Compiler:
    """
    Compiles QWED-DSL AST to Z3 constraints.
    
    Example:
        ['AND', ['GT', 'x', 5], ['LT', 'y', 10]]
        → And(x > 5, y < 10)
    """
    
    def __init__(self):
        if not Z3_AVAILABLE:
            raise ImportError("Z3 is not installed. Run: pip install z3-solver")
    
    def compile(
        self, 
        ast: Any, 
        var_declarations: Optional[Dict[str, Dict[str, str]]] = None
    ) -> CompileResult:
        """
        Compile AST to Z3 constraint.
        
        Args:
            ast: The validated AST from parser
            var_declarations: Dict of {var_name: {"type": "Int"|"Bool"|"Real"}}
            
        Returns:
            CompileResult with Z3 constraint or error
        """
        try:
            # Create Z3 variables from declarations
            z3_vars: Dict[str, Any] = {}
            
            # Process VAR declarations from AST if present
            if isinstance(ast, list) and len(ast) > 0:
                # Check if this is a list of expressions (multiple statements)
                if isinstance(ast[0], list):
                    # Process each statement, collect VAR declarations
                    constraints = []
                    for stmt in ast:
                        if isinstance(stmt, list) and len(stmt) > 0:
                            if isinstance(stmt[0], str) and stmt[0].upper() == 'VAR':
                                # Variable declaration
                                var_name = stmt[1]
                                var_type = stmt[2]
                                z3_vars[var_name] = self._create_z3_var(var_name, var_type)
                            else:
                                # Constraint - compile and add
                                constraints.append(self._compile_expr(stmt, z3_vars))
                    
                    if len(constraints) == 0:
                        return CompileResult(success=True, compiled=None, variables=z3_vars)
                    elif len(constraints) == 1:
                        return CompileResult(success=True, compiled=constraints[0], variables=z3_vars)
                    else:
                        return CompileResult(success=True, compiled=And(*constraints), variables=z3_vars)
            
            # Also use provided var_declarations
            if var_declarations:
                for name, spec in var_declarations.items():
                    if name not in z3_vars:
                        z3_vars[name] = self._create_z3_var(name, spec.get('type', 'Int'))
            
            # Compile the expression
            constraint = self._compile_expr(ast, z3_vars)
            
            return CompileResult(success=True, compiled=constraint, variables=z3_vars)
            
        except Exception as e:
            return CompileResult(success=False, error=f"Z3 compilation error: {str(e)}")
    
    def _create_z3_var(self, name: str, var_type: str) -> Any:
        """Create a Z3 variable of the specified type."""
        type_upper = var_type.upper() if isinstance(var_type, str) else 'INT'
        
        if type_upper == 'INT':
            return Int(name)
        elif type_upper == 'BOOL':
            return Bool(name)
        elif type_upper == 'REAL':
            return Real(name)
        else:
            # Default to Int
            return Int(name)
    
    def _compile_expr(self, node: Any, z3_vars: Dict[str, Any]) -> Any:
        """
        Recursively compile AST node to Z3 expression.
        """
        # Atoms
        if isinstance(node, bool):
            return node
        if isinstance(node, (int, float)):
            return node
        if isinstance(node, str):
            # Variable reference - create if not exists
            if node not in z3_vars:
                # Auto-create as Int (fallback)
                z3_vars[node] = Int(node)
            return z3_vars[node]
        
        # List expression: [OPERATOR, arg1, arg2, ...]
        if not isinstance(node, list) or len(node) == 0:
            return node
        
        operator = node[0].upper() if isinstance(node[0], str) else node[0]
        args = node[1:]
        
        # Compile arguments recursively
        compiled_args = [self._compile_expr(arg, z3_vars) for arg in args]
        
        # Map operators to Z3
        if operator == 'AND':
            return And(*compiled_args)
        elif operator == 'OR':
            return Or(*compiled_args)
        elif operator == 'NOT':
            return Not(compiled_args[0])
        elif operator == 'IMPLIES':
            return Implies(compiled_args[0], compiled_args[1])
        elif operator == 'XOR':
            return Xor(compiled_args[0], compiled_args[1])
        elif operator == 'EQ':
            return compiled_args[0] == compiled_args[1]
        elif operator == 'NEQ':
            return compiled_args[0] != compiled_args[1]
        elif operator == 'GT':
            return compiled_args[0] > compiled_args[1]
        elif operator == 'LT':
            return compiled_args[0] < compiled_args[1]
        elif operator == 'GTE':
            return compiled_args[0] >= compiled_args[1]
        elif operator == 'LTE':
            return compiled_args[0] <= compiled_args[1]
        elif operator == 'PLUS':
            result = compiled_args[0]
            for arg in compiled_args[1:]:
                result = result + arg
            return result
        elif operator == 'MINUS':
            return compiled_args[0] - compiled_args[1]
        elif operator == 'MULT':
            result = compiled_args[0]
            for arg in compiled_args[1:]:
                result = result * arg
            return result
        elif operator == 'DIV':
            return compiled_args[0] / compiled_args[1]
        elif operator == 'POW':
            return compiled_args[0] ** compiled_args[1]
        elif operator == 'MOD':
            return compiled_args[0] % compiled_args[1]
        elif operator == 'VAR':
            # Variable declaration - create the variable
            var_name = args[0]
            var_type = args[1]
            z3_vars[var_name] = self._create_z3_var(var_name, var_type)
            return None  # VAR doesn't produce a constraint
        else:
            raise ValueError(f"Unknown operator: {operator}")


class SymPyCompiler:
    """
    Compiles QWED-DSL AST to SymPy expressions.
    
    Used for mathematical verification (Engine 1: Math).
    
    Example:
        ['MULT', 0.15, 200]
        → 0.15 * 200
    """
    
    def __init__(self):
        if not SYMPY_AVAILABLE:
            raise ImportError("SymPy is not installed. Run: pip install sympy")
    
    def compile(self, ast: Any) -> CompileResult:
        """
        Compile AST to SymPy expression.
        
        Args:
            ast: The validated AST from parser
            
        Returns:
            CompileResult with SymPy expression or error
        """
        try:
            sympy_vars: Dict[str, Any] = {}
            expr = self._compile_expr(ast, sympy_vars)
            return CompileResult(success=True, compiled=expr, variables=sympy_vars)
        except Exception as e:
            return CompileResult(success=False, error=f"SymPy compilation error: {str(e)}")
    
    def _compile_expr(self, node: Any, sympy_vars: Dict[str, Any]) -> Any:
        """
        Recursively compile AST node to SymPy expression.
        """
        # Atoms
        if isinstance(node, (int, float)):
            return sympy.Number(node)
        if isinstance(node, bool):
            return sympy.true if node else sympy.false
        if isinstance(node, str):
            # Variable - create SymPy symbol
            if node not in sympy_vars:
                sympy_vars[node] = sympy.Symbol(node)
            return sympy_vars[node]
        
        # List expression
        if not isinstance(node, list) or len(node) == 0:
            return node
        
        operator = node[0].upper() if isinstance(node[0], str) else node[0]
        args = node[1:]
        
        # Compile arguments
        compiled_args = [self._compile_expr(arg, sympy_vars) for arg in args]
        
        # Map operators to SymPy
        if operator == 'PLUS':
            result = compiled_args[0]
            for arg in compiled_args[1:]:
                result = result + arg
            return result
        elif operator == 'MINUS':
            return compiled_args[0] - compiled_args[1]
        elif operator == 'MULT':
            result = compiled_args[0]
            for arg in compiled_args[1:]:
                result = result * arg
            return result
        elif operator == 'DIV':
            return compiled_args[0] / compiled_args[1]
        elif operator == 'POW':
            return compiled_args[0] ** compiled_args[1]
        elif operator == 'MOD':
            return sympy.Mod(compiled_args[0], compiled_args[1])
        elif operator == 'EQ':
            return sympy.Eq(compiled_args[0], compiled_args[1])
        elif operator == 'NEQ':
            return sympy.Ne(compiled_args[0], compiled_args[1])
        elif operator == 'GT':
            return sympy.Gt(compiled_args[0], compiled_args[1])
        elif operator == 'LT':
            return sympy.Lt(compiled_args[0], compiled_args[1])
        elif operator == 'GTE':
            return sympy.Ge(compiled_args[0], compiled_args[1])
        elif operator == 'LTE':
            return sympy.Le(compiled_args[0], compiled_args[1])
        elif operator == 'AND':
            return sympy.And(*compiled_args)
        elif operator == 'OR':
            return sympy.Or(*compiled_args)
        elif operator == 'NOT':
            return sympy.Not(compiled_args[0])
        else:
            raise ValueError(f"Unsupported SymPy operator: {operator}")


# Convenience functions

def compile_to_z3(ast: Any, var_declarations: Optional[Dict] = None) -> CompileResult:
    """Compile DSL AST to Z3 constraint."""
    compiler = Z3Compiler()
    return compiler.compile(ast, var_declarations)


def compile_to_sympy(ast: Any) -> CompileResult:
    """Compile DSL AST to SymPy expression."""
    compiler = SymPyCompiler()
    return compiler.compile(ast)


# --- DEMO / TEST ---
if __name__ == "__main__":
    from parser import QWEDLogicDSL
    
    parser = QWEDLogicDSL()
    
    print("=" * 60)
    print("QWED-Logic DSL Compiler Demo")
    print("=" * 60)
    
    # Test 1: Logic constraint to Z3
    print("\nTest 1: Compile to Z3")
    test1 = "(AND (GT x 5) (LT y 10))"
    result = parser.run(test1)
    if result['status'] == 'SUCCESS':
        z3_result = compile_to_z3(result['ast'])
        print(f"Input: {test1}")
        print(f"Z3 Constraint: {z3_result.compiled}")
        print(f"Variables: {z3_result.variables}")
    
    # Test 2: Math expression to SymPy
    print("\nTest 2: Compile to SymPy")
    test2 = "(MULT 0.15 200)"
    result = parser.run(test2)
    if result['status'] == 'SUCCESS':
        sympy_result = compile_to_sympy(result['ast'])
        print(f"Input: {test2}")
        print(f"SymPy Expression: {sympy_result.compiled}")
        # Evaluate
        if sympy_result.success:
            evaluated = sympy.simplify(sympy_result.compiled)
            print(f"Evaluated: {evaluated}")
    
    # Test 3: Enterprise rule
    print("\nTest 3: Enterprise Rule (IMPLIES)")
    test3 = "(IMPLIES (GT amount 10000) (EQ requires_approval True))"
    result = parser.run(test3)
    if result['status'] == 'SUCCESS':
        z3_result = compile_to_z3(result['ast'])
        print(f"Input: {test3}")
        print(f"Z3 Constraint: {z3_result.compiled}")
    
    print("\n" + "=" * 60)
    print("Compiler tests complete!")
