"""
QWED Core Module.

Exports verification engines, exceptions, and utility functions.
"""

# Core exceptions for better error handling
from .exceptions import (
    QWEDError,
    QWEDSyntaxError,
    QWEDSymbolNotFoundError,
    QWEDVerificationError,
    QWEDMathError,
    QWEDLogicError,
    QWEDCodeError,
    QWEDSQLError,
    QWEDConfigError,
    QWEDAPIError,
    QWEDDependencyError,
    wrap_error,
)

# Structured verification diagnostics (Issue #204)
from .diagnostics import (
    DiagnosticStatus,
    DiagnosticResult,
    AdvisoryCheck,
    compute_proof_ref,
)

__all__ = [
    # Exceptions
    "QWEDError",
    "QWEDSyntaxError",
    "QWEDSymbolNotFoundError",
    "QWEDVerificationError",
    "QWEDMathError",
    "QWEDLogicError",
    "QWEDCodeError",
    "QWEDSQLError",
    "QWEDConfigError",
    "QWEDAPIError",
    "QWEDDependencyError",
    "wrap_error",
    # Diagnostics (#204)
    "DiagnosticStatus",
    "DiagnosticResult",
    "AdvisoryCheck",
    "compute_proof_ref",
]

# Lazy imports for verifiers (avoid circular imports and missing deps)
def __getattr__(name):
    """Lazy import verifiers on demand."""
    if name == "VerificationEngine":
        from .verifier import VerificationEngine
        return VerificationEngine
    elif name == "VerificationResult":
        from .verifier import VerificationResult
        return VerificationResult
    elif name == "SymbolicVerifier":
        from .symbolic_verifier import SymbolicVerifier
        return SymbolicVerifier
    elif name == "CodeVerifier":
        from .code_verifier import CodeVerifier
        return CodeVerifier
    elif name == "SQLVerifier":
        from .sql_verifier import SQLVerifier
        return SQLVerifier
    elif name == "StatisticsVerifier":
        from .stats_verifier import StatisticsVerifier
        return StatisticsVerifier
    elif name == "ReasoningVerifier":
        from .reasoning_verifier import ReasoningVerifier
        return ReasoningVerifier
    elif name == "ImageVerifier":
        from .image_verifier import ImageVerifier
        return ImageVerifier
    raise AttributeError(f"module 'qwed_new.core' has no attribute '{name}'")
