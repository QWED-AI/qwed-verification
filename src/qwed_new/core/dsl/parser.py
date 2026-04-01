"""
QWED Domain Specific Language (DSL) Parser.

This module provides a secure, whitelist-based parser for QWED's
S-expression logic format. It replaces unsafe eval() with structured parsing.

Format: (AND (GT x 5) (LT y 10))
"""

from typing import List, Dict, Any, Tuple, Optional, Union
from dataclasses import dataclass
from enum import Enum


class OperatorCategory(str, Enum):
    """Categories of allowed operators."""
    LOGIC = "logic"
    QUANTIFIER = "quantifier"
    COMPARISON = "comparison"
    ARITHMETIC = "arithmetic"
    SPECIAL = "special"


@dataclass
class OperatorSpec:
    """Specification for an allowed operator."""
    name: str
    category: OperatorCategory
    min_arity: int
    max_arity: Optional[int]  # None = unlimited
    z3_name: Optional[str] = None
    sympy_op: Optional[str] = None


@dataclass
class ParseResult:
    """Result of parsing a DSL expression."""
    success: bool
    ast: Optional[Any] = None
    error: Optional[str] = None
    position: Optional[int] = None


@dataclass
class Variable:
    """A declared variable with type."""
    name: str
    var_type: str  # "Int", "Bool", "Real"


class QWEDLogicDSL:
    """
    QWED Domain Specific Language Parser v1.0
    
    Security: Uses strict operator whitelist - anything not on the list is BLOCKED.
    Reliability: S-expression format is easy for LLMs to generate correctly.
    """
    
    def __init__(self):
        # THE WHITELIST - Only these operators are allowed
        self.operators: Dict[str, OperatorSpec] = {
            # Boolean Logic
            'AND': OperatorSpec('AND', OperatorCategory.LOGIC, 2, None, 'And', 'And'),
            'OR': OperatorSpec('OR', OperatorCategory.LOGIC, 2, None, 'Or', 'Or'),
            'NOT': OperatorSpec('NOT', OperatorCategory.LOGIC, 1, 1, 'Not', 'Not'),
            'IMPLIES': OperatorSpec('IMPLIES', OperatorCategory.LOGIC, 2, 2, 'Implies', None),
            'IFF': OperatorSpec('IFF', OperatorCategory.LOGIC, 2, 2, 'Iff', None),
            'XOR': OperatorSpec('XOR', OperatorCategory.LOGIC, 2, 2, 'Xor', None),
            
            # Quantifiers
            'FORALL': OperatorSpec('FORALL', OperatorCategory.QUANTIFIER, 2, 2, 'ForAll', None),
            'EXISTS': OperatorSpec('EXISTS', OperatorCategory.QUANTIFIER, 2, 2, 'Exists', None),
            
            # Comparison
            'EQ': OperatorSpec('EQ', OperatorCategory.COMPARISON, 2, 2, '==', 'Eq'),
            'NEQ': OperatorSpec('NEQ', OperatorCategory.COMPARISON, 2, 2, '!=', 'Ne'),
            'GT': OperatorSpec('GT', OperatorCategory.COMPARISON, 2, 2, '>', 'Gt'),
            'LT': OperatorSpec('LT', OperatorCategory.COMPARISON, 2, 2, '<', 'Lt'),
            'GTE': OperatorSpec('GTE', OperatorCategory.COMPARISON, 2, 2, '>=', 'Ge'),
            'LTE': OperatorSpec('LTE', OperatorCategory.COMPARISON, 2, 2, '<=', 'Le'),
            
            # Arithmetic
            'PLUS': OperatorSpec('PLUS', OperatorCategory.ARITHMETIC, 2, None, '+', '+'),
            'MINUS': OperatorSpec('MINUS', OperatorCategory.ARITHMETIC, 2, 2, '-', '-'),
            'MULT': OperatorSpec('MULT', OperatorCategory.ARITHMETIC, 2, None, '*', '*'),
            'DIV': OperatorSpec('DIV', OperatorCategory.ARITHMETIC, 2, 2, '/', '/'),
            'POW': OperatorSpec('POW', OperatorCategory.ARITHMETIC, 2, 2, '**', '**'),
            'MOD': OperatorSpec('MOD', OperatorCategory.ARITHMETIC, 2, 2, '%', 'Mod'),
            
            # Special - Variable declaration
            'VAR': OperatorSpec('VAR', OperatorCategory.SPECIAL, 2, 2, None, None),
        }
        
        # Allowed types for VAR declarations
        self.allowed_types = {'Int', 'Bool', 'Real'}
        
        # Reserved keywords that cannot be variable names
        self.reserved = set(self.operators.keys()) | {'True', 'False', 'None'}
    
    def tokenize(self, text: str) -> Tuple[List[str], Dict[int, int]]:
        """
        Tokenize S-expression into a list of tokens.
        Also returns position map for error reporting.
        
        Args:
            text: The S-expression string
            
        Returns:
            Tuple of (tokens, position_map) where position_map maps token index to char position
        """
        tokens = []
        positions = {}
        
        # Add spaces around parentheses
        text = text.replace('(', ' ( ').replace(')', ' ) ')
        
        pos = 0
        for i, token in enumerate(text.split()):
            if token:
                tokens.append(token)
                positions[len(tokens) - 1] = pos
            pos += len(token) + 1
        
        return tokens, positions
    
    def parse(self, text: str) -> ParseResult:
        """
        Parse an S-expression string into an AST.
        
        Args:
            text: The S-expression string (e.g., "(AND (GT x 5) (LT y 10))")
            
        Returns:
            ParseResult with success status and AST or error
        """
        text = text.strip()
        if not text:
            return ParseResult(success=False, error="Empty expression")
        
        try:
            tokens, positions = self.tokenize(text)
            if not tokens:
                return ParseResult(success=False, error="No tokens found")
            
            ast, remaining = self._parse_expr(tokens)
            
            if remaining:
                return ParseResult(
                    success=False, 
                    error=f"Unexpected tokens after expression: {remaining}",
                    position=positions.get(len(tokens) - len(remaining), 0)
                )
            
            return ParseResult(success=True, ast=ast)
            
        except SyntaxError as e:
            return ParseResult(success=False, error=str(e))
        except Exception as e:
            return ParseResult(success=False, error=f"Parse error: {str(e)}")
    
    def _parse_expr(self, tokens: List[str]) -> Tuple[Any, List[str]]:
        """
        Recursive descent parser for S-expressions.
        
        Returns:
            Tuple of (parsed_ast, remaining_tokens)
        """
        if not tokens:
            raise SyntaxError("Unexpected end of expression")
        
        token = tokens[0]
        
        if token == '(':
            # Start of a list expression
            tokens = tokens[1:]  # consume '('
            
            if not tokens:
                raise SyntaxError("Unexpected end after '('")
            
            if tokens[0] == ')':
                # Empty list ()
                return [], tokens[1:]
            
            elements = []
            while tokens and tokens[0] != ')':
                element, tokens = self._parse_expr(tokens)
                elements.append(element)
            
            if not tokens:
                raise SyntaxError("Missing closing ')'")
            
            return elements, tokens[1:]  # consume ')'
            
        elif token == ')':
            raise SyntaxError("Unexpected ')'")
        
        else:
            # Atom (variable, number, or boolean)
            return self._parse_atom(token), tokens[1:]
    
    def _parse_atom(self, token: str) -> Union[int, float, bool, str]:
        """
        Parse an atomic token (number, boolean, or variable name).
        """
        # Boolean literals
        if token == 'True':
            return True
        if token == 'False':
            return False
        
        # Try integer
        try:
            return int(token)
        except ValueError:
            pass
        
        # Try float
        try:
            return float(token)
        except ValueError:
            pass
        
        # It's a variable name or operator
        return token
    
    def validate(self, ast: Any) -> Tuple[bool, Optional[str], Dict[str, Variable]]:
        """
        Validate the AST against the operator whitelist.
        
        Args:
            ast: The parsed AST
            
        Returns:
            Tuple of (is_valid, error_message, variables_dict)
        """
        variables: Dict[str, Variable] = {}
        
        try:
            self._validate_recursive(ast, variables)
            return True, None, variables
        except ValueError as e:
            return False, str(e), variables
    
    def _validate_recursive(self, node: Any, variables: Dict[str, Variable]) -> None:
        """
        Recursively validate the AST.
        
        Raises:
            ValueError: If validation fails (security block or invalid syntax)
        """
        # Atoms are always valid (variables, numbers, booleans)
        if not isinstance(node, list):
            return
        
        # Empty list is valid
        if not node:
            return
        
        # First element should be an operator
        operator = node[0]
        
        if not isinstance(operator, str):
            raise ValueError(f"Operator must be a string, got: {type(operator)}")
        
        # SECURITY CHECK: Is this operator on the whitelist?
        op_upper = operator.upper()
        if op_upper not in self.operators:
            raise ValueError(
                f"SECURITY BLOCK: Unknown operator '{operator}'. "
                f"Allowed operators: {', '.join(sorted(self.operators.keys()))}"
            )
        
        spec = self.operators[op_upper]
        args = node[1:]
        
        # Arity check
        if len(args) < spec.min_arity:
            raise ValueError(
                f"Operator '{op_upper}' requires at least {spec.min_arity} arguments, "
                f"got {len(args)}"
            )
        
        if spec.max_arity is not None and len(args) > spec.max_arity:
            raise ValueError(
                f"Operator '{op_upper}' requires at most {spec.max_arity} arguments, "
                f"got {len(args)}"
            )
        
        # Special handling for VAR declarations
        if op_upper == 'VAR':
            var_name = args[0]
            var_type = args[1]
            
            if not isinstance(var_name, str):
                raise ValueError(f"Variable name must be a string, got: {var_name}")
            
            if var_name in self.reserved:
                raise ValueError(f"Cannot use reserved word as variable name: {var_name}")
            
            if not isinstance(var_type, str) or var_type not in self.allowed_types:
                raise ValueError(
                    f"Invalid variable type '{var_type}'. "
                    f"Allowed types: {', '.join(self.allowed_types)}"
                )
            
            variables[var_name] = Variable(name=var_name, var_type=var_type)
            return
        
        # Recursively validate arguments
        for arg in args:
            self._validate_recursive(arg, variables)
    
    def run(self, source_code: str) -> Dict[str, Any]:
        """
        Parse and validate a QWED-Logic expression.
        
        Args:
            source_code: The S-expression string
            
        Returns:
            Dict with status, compiled AST, variables, or error
        """
        # Parse
        parse_result = self.parse(source_code)
        if not parse_result.success:
            return {
                "status": "PARSE_ERROR",
                "error": parse_result.error,
                "position": parse_result.position
            }
        
        # Validate
        is_valid, error, variables = self.validate(parse_result.ast)
        if not is_valid:
            return {
                "status": "BLOCKED",
                "error": error
            }
        
        return {
            "status": "SUCCESS",
            "ast": parse_result.ast,
            "variables": {name: {"name": v.name, "type": v.var_type} for name, v in variables.items()}
        }


# Module-level singleton for convenience
_parser = None

def get_parser() -> QWEDLogicDSL:
    """Get the singleton parser instance."""
    global _parser
    if _parser is None:
        _parser = QWEDLogicDSL()
    return _parser


def parse_and_validate(source_code: str) -> Dict[str, Any]:
    """Convenience function to parse and validate DSL code."""
    return get_parser().run(source_code)


# --- DEMO / TEST ---
if __name__ == "__main__":
    parser = QWEDLogicDSL()
    
    print("=" * 60)
    print("QWED-Logic DSL Parser v1.0")
    print("=" * 60)
    
    # Test 1: Valid enterprise rule
    print("\nTest 1: Valid Enterprise Rule")
    test1 = "(IMPLIES (GT amount 10000) (EQ requires_approval True))"
    print(f"Input: {test1}")
    print(f"Result: {parser.run(test1)}")
    
    # Test 2: Security attack - IMPORT
    print("\nTest 2: Security Attack (IMPORT)")
    test2 = "(AND (GT x 5) (IMPORT os))"
    print(f"Input: {test2}")
    print(f"Result: {parser.run(test2)}")
    
    # Test 3: Hallucination - unknown operator
    print("\nTest 3: LLM Hallucination (unknown operator)")
    test3 = "(CHECK_IF_VALID user)"
    print(f"Input: {test3}")
    print(f"Result: {parser.run(test3)}")
    
    # Test 4: Variable declarations
    print("\nTest 4: Variable Declarations")
    test4 = "(VAR x Int)"
    print(f"Input: {test4}")
    print(f"Result: {parser.run(test4)}")
    
    # Test 5: Complex nested expression
    print("\nTest 5: Complex Nested Expression")
    test5 = "(AND (OR (GT x 5) (LT y 10)) (NOT (EQ z 0)))"
    print(f"Input: {test5}")
    print(f"Result: {parser.run(test5)}")
    
    # Test 6: Arity error
    print("\nTest 6: Arity Error (NOT takes 1 arg)")
    test6 = "(NOT a b c)"
    print(f"Input: {test6}")
    print(f"Result: {parser.run(test6)}")
    
    print("\n" + "=" * 60)
    print("All tests complete!")
