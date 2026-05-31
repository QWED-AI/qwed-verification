"""
CodSpeed performance benchmarks for QWED verification engines.

Benchmarks cover the core deterministic verification engines:
- Math Verification (SymPy)
- DSL Parsing (S-expression parser)
- Code Verification (AST-based security)
- SQL Verification (SQLGlot-based)
- Taint Analysis (data flow analysis)
- Schema Verification (JSON schema validation)
- Output Sanitization (content sanitization)
"""

import os
import sys
import pytest

# Ensure test environment variables are set before importing qwed modules
os.environ.setdefault("QWED_JWT_SECRET_KEY", "bench-jwt-secret")
os.environ.setdefault("QWED_CORS_ORIGINS", "http://localhost:3000")
os.environ.setdefault("API_KEY_SECRET", "bench-api-secret")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from qwed_new.core.verifier import VerificationEngine
from qwed_new.core.dsl.parser import QWEDLogicDSL
from qwed_new.core.code_verifier import CodeVerifier
from qwed_new.core.sql_verifier import SQLVerifier
from qwed_new.core.taint_analyzer import TaintAnalyzer
from qwed_new.core.schema_verifier import SchemaVerifier
from qwed_new.core.output_sanitizer import OutputSanitizer
from qwed_new.core.sanitizer import ConstraintSanitizer


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def math_engine():
    return VerificationEngine()


@pytest.fixture
def dsl_parser():
    return QWEDLogicDSL()


@pytest.fixture
def code_verifier():
    return CodeVerifier()


@pytest.fixture
def sql_verifier():
    return SQLVerifier()


@pytest.fixture
def taint_analyzer():
    return TaintAnalyzer()


@pytest.fixture
def schema_verifier():
    return SchemaVerifier()


@pytest.fixture
def output_sanitizer():
    return OutputSanitizer()


@pytest.fixture
def constraint_sanitizer():
    return ConstraintSanitizer()


# ---------------------------------------------------------------------------
# Math Verification Benchmarks
# ---------------------------------------------------------------------------

def test_bench_math_simple_arithmetic(benchmark, math_engine):
    """Benchmark simple arithmetic verification."""
    benchmark(math_engine.verify_math, "2 * (5 + 10)", 30)


def test_bench_math_algebraic_expression(benchmark, math_engine):
    """Benchmark algebraic expression verification."""
    benchmark(math_engine.verify_math, "(2+1)**2", 9)


def test_bench_math_percentage(benchmark, math_engine):
    """Benchmark percentage calculation verification."""
    benchmark(math_engine.verify_percentage, 200, 15, 30, "of")


def test_bench_math_identity(benchmark, math_engine):
    """Benchmark mathematical identity verification."""
    benchmark(math_engine.verify_identity, "(x+1)**2", "x**2 + 2*x + 1")


# ---------------------------------------------------------------------------
# DSL Parser Benchmarks
# ---------------------------------------------------------------------------

def test_bench_dsl_simple_expression(benchmark, dsl_parser):
    """Benchmark parsing a simple comparison expression."""
    benchmark(dsl_parser.run, "(GT x 5)")


def test_bench_dsl_nested_expression(benchmark, dsl_parser):
    """Benchmark parsing a complex nested expression."""
    benchmark(
        dsl_parser.run,
        "(AND (OR (GT x 5) (LT y 10)) (NOT (EQ z 0)))",
    )


def test_bench_dsl_large_expression(benchmark, dsl_parser):
    """Benchmark parsing a large expression with many clauses."""
    expr = "(AND " + " ".join(f"(GT x{i} {i})" for i in range(20)) + ")"
    benchmark(dsl_parser.run, expr)


# ---------------------------------------------------------------------------
# Code Verification Benchmarks
# ---------------------------------------------------------------------------

_SAFE_CODE = """\
def calculate_sum(a, b):
    return a + b

def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n - 1) + fibonacci(n - 2)
"""

_DANGEROUS_CODE = """\
import os
user_input = input("cmd: ")
os.system(user_input)
"""


def test_bench_code_verify_safe(benchmark, code_verifier):
    """Benchmark verification of safe Python code."""
    benchmark(code_verifier.verify_code, _SAFE_CODE, "python")


def test_bench_code_verify_dangerous(benchmark, code_verifier):
    """Benchmark verification of dangerous Python code."""
    benchmark(code_verifier.verify_code, _DANGEROUS_CODE, "python")


# ---------------------------------------------------------------------------
# SQL Verification Benchmarks
# ---------------------------------------------------------------------------

_SIMPLE_SELECT = "SELECT id, name FROM users WHERE active = true"
_COMPLEX_QUERY = (
    "SELECT u.id, u.name, COUNT(o.id) as order_count "
    "FROM users u "
    "JOIN orders o ON u.id = o.user_id "
    "WHERE u.active = true "
    "GROUP BY u.id, u.name "
    "HAVING COUNT(o.id) > 5 "
    "ORDER BY order_count DESC"
)
_INJECTION_QUERY = "SELECT * FROM users WHERE id = 1 OR 1=1"


def test_bench_sql_simple_select(benchmark, sql_verifier):
    """Benchmark SQL verification of a simple SELECT query."""
    benchmark(sql_verifier.verify_sql, _SIMPLE_SELECT)


def test_bench_sql_complex_join(benchmark, sql_verifier):
    """Benchmark SQL verification of a complex JOIN query."""
    benchmark(sql_verifier.verify_sql, _COMPLEX_QUERY)


def test_bench_sql_injection_detection(benchmark, sql_verifier):
    """Benchmark SQL injection detection."""
    benchmark(sql_verifier.verify_sql, _INJECTION_QUERY)


# ---------------------------------------------------------------------------
# Taint Analysis Benchmarks
# ---------------------------------------------------------------------------

_TAINT_DIRECT = 'eval(input("Enter: "))'

_TAINT_INDIRECT = """\
user_data = input("Enter value: ")
processed = user_data
eval(processed)
"""

_TAINT_SANITIZED = """\
user_data = input("Enter number: ")
safe_value = int(user_data)
result = safe_value + 10
"""


def test_bench_taint_direct_vulnerability(benchmark, taint_analyzer):
    """Benchmark detection of direct taint vulnerability."""
    benchmark(taint_analyzer.analyze, _TAINT_DIRECT)


def test_bench_taint_indirect_flow(benchmark, taint_analyzer):
    """Benchmark detection of indirect taint flow."""
    benchmark(taint_analyzer.analyze, _TAINT_INDIRECT)


def test_bench_taint_sanitized_flow(benchmark, taint_analyzer):
    """Benchmark analysis of properly sanitized data flow."""
    benchmark(taint_analyzer.analyze, _TAINT_SANITIZED)


# ---------------------------------------------------------------------------
# Schema Verification Benchmarks
# ---------------------------------------------------------------------------

_USER_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "age": {"type": "integer", "minimum": 0, "maximum": 150},
        "email": {"type": "string"},
        "active": {"type": "boolean"},
    },
    "required": ["name", "age", "email"],
}

_VALID_USER_DATA = {
    "name": "Alice",
    "age": 30,
    "email": "alice@example.com",
    "active": True,
}

_NESTED_SCHEMA = {
    "type": "object",
    "properties": {
        "user": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "addresses": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "street": {"type": "string"},
                            "city": {"type": "string"},
                            "zip": {"type": "string"},
                        },
                        "required": ["street", "city"],
                    },
                },
            },
            "required": ["name"],
        }
    },
    "required": ["user"],
}

_NESTED_DATA = {
    "user": {
        "name": "Bob",
        "addresses": [
            {"street": "123 Main St", "city": "Springfield", "zip": "62701"},
            {"street": "456 Oak Ave", "city": "Shelbyville"},
        ],
    }
}


def test_bench_schema_flat_object(benchmark, schema_verifier):
    """Benchmark flat object schema verification."""
    benchmark(schema_verifier.verify, _VALID_USER_DATA, _USER_SCHEMA)


def test_bench_schema_nested_object(benchmark, schema_verifier):
    """Benchmark nested object with arrays schema verification."""
    benchmark(schema_verifier.verify, _NESTED_DATA, _NESTED_SCHEMA)


# ---------------------------------------------------------------------------
# Output Sanitization Benchmarks
# ---------------------------------------------------------------------------

_CLEAN_OUTPUT = {
    "result": "The derivative of x^2 is 2x",
    "confidence": 0.99,
    "engine": "math",
}

_DANGEROUS_OUTPUT = {
    "result": "<script>alert('xss')</script>The answer is 42",
    "debug_info": "internal_path: /var/log/app.log",
    "api_key": "sk-1234567890abcdef",
}


def test_bench_sanitize_clean_output(benchmark, output_sanitizer):
    """Benchmark sanitization of clean output."""
    benchmark(output_sanitizer.sanitize_output, _CLEAN_OUTPUT, "math")


def test_bench_sanitize_dangerous_output(benchmark, output_sanitizer):
    """Benchmark sanitization of output containing dangerous content."""
    benchmark(output_sanitizer.sanitize_output, _DANGEROUS_OUTPUT, "math")


# ---------------------------------------------------------------------------
# Constraint Sanitizer Benchmarks
# ---------------------------------------------------------------------------

def test_bench_constraint_sanitize(benchmark, constraint_sanitizer):
    """Benchmark constraint sanitization."""
    constraints = ["x > 0", "y < 100", "z == 42", "w != 0"]
    variables = {"x": "int", "y": "int", "z": "int", "w": "int"}
    benchmark(constraint_sanitizer.sanitize, constraints, variables)
