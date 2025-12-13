"""
QWED Domain Specific Language (DSL) Module.

Provides secure, whitelist-based parsing and compilation for QWED's
S-expression logic/math format.

Usage:
    from qwed_new.core.dsl import parse_and_validate, compile_to_z3
    
    result = parse_and_validate("(AND (GT x 5) (LT y 10))")
    if result['status'] == 'SUCCESS':
        z3_result = compile_to_z3(result['ast'])
"""

from qwed_new.core.dsl.parser import (
    QWEDLogicDSL,
    ParseResult,
    Variable,
    OperatorSpec,
    OperatorCategory,
    get_parser,
    parse_and_validate,
)

from qwed_new.core.dsl.compiler import (
    Z3Compiler,
    SymPyCompiler,
    CompileResult,
    compile_to_z3,
    compile_to_sympy,
)

__all__ = [
    # Parser
    'QWEDLogicDSL',
    'ParseResult',
    'Variable',
    'OperatorSpec',
    'OperatorCategory',
    'get_parser',
    'parse_and_validate',
    
    # Compiler
    'Z3Compiler',
    'SymPyCompiler',
    'CompileResult',
    'compile_to_z3',
    'compile_to_sympy',
]
