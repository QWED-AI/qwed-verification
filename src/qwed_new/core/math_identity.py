"""The verdict on a math identity ``left = right``, shared by /verify/math
and the math items of /verify/batch so the two cannot drift (#530).

Before #530 the batch decided on ``simplify(left - right) != 0`` and reported
a claim proven false as UNVERIFIABLE, while /verify/math reported it VERIFIED
with ``is_valid`` False (admission DENY, #437), and kept a difference SymPy
could not decide UNVERIFIABLE.
"""

from sympy import simplify

from qwed_new.core.diagnostics import DiagnosticResult
from qwed_new.core.safe_parser import (
    DERIVATIVE_NOTATION_MESSAGE,
    DerivativeNotationError,
    SafeParserError,
    safe_parse_expr,
)
from qwed_new.core.verifier import (
    DISPROVEN_STATUS,
    DOMAIN_RESTRICTED_IDENTITY,
    has_undefined_part,
    identity_domains_match,
    symbolic_difference_status,
)

# A side has an undefined part SymPy evaluated away (log(0)**0 is 1): the
# claim is not about a defined value, so it is neither proven nor disproven.
UNDEFINED_PART_IDENTITY = "math.undefined_part"
# The parser refused the expression (#522): BLOCKED, as SQL and schema
# parse errors are.
MATH_PARSE_ERROR = "math.parse_error"


def math_parse_error_result(error: SafeParserError) -> DiagnosticResult:
    """BLOCKED with ``MATH_PARSE_ERROR`` for input the parser refused, shared
    by /verify/math and batch math items. The parser's own text, which can
    carry SymPy's, is not returned."""
    message = (
        DERIVATIVE_NOTATION_MESSAGE if isinstance(error, DerivativeNotationError)
        else "Expression could not be parsed"
    )
    return DiagnosticResult.blocked(message, {"constraint_id": MATH_PARSE_ERROR, "is_valid": False})


def math_identity_result(expression: str) -> DiagnosticResult:
    """Decide the identity in *expression*, which holds an ``=``.

    - VERIFIED, ``is_valid`` True: the difference simplifies to 0 and both
      sides are defined on the same domain.
    - UNVERIFIABLE with ``DOMAIN_RESTRICTED_IDENTITY``: simplify cancelled a
      removable singularity (``x/x = 1`` is false at ``x = 0``), so the
      identity holds only where both sides are defined (#429).
    - VERIFIED, ``is_valid`` False (``DiagnosticResult.disproven``): SymPy
      decides the difference is non-zero. A proven-false claim is a decided
      verdict, never "inconclusive" (#437).
    - UNVERIFIABLE with ``UNDEFINED_PART_IDENTITY``: the difference is
      non-zero, but a side has an undefined part SymPy evaluated away
      (``log(0)**0 = 2``), so there is no defined value to disprove.
    - UNVERIFIABLE: anything undecided, including a non-zero difference that
      holds a Float, whose rounding residue proves nothing.

    ``==`` reads as ``=`` (#522). The caller signs and enforces the result
    and decides admission. Parse errors propagate to the caller.
    """
    separator = "==" if expression.count("==") == 1 and expression.count("=") == 2 else "="
    left_str, right_str = expression.split(separator, 1)
    left = safe_parse_expr(left_str)
    right = safe_parse_expr(right_str)
    difference = simplify(left - right)
    identity_status = symbolic_difference_status(difference)

    fields = {
        "left_side": str(left),
        "right_side": str(right),
        "simplified_difference": str(difference),
    }
    if identity_status == "VERIFIED" and not identity_domains_match(left_str, right_str):
        return DiagnosticResult.unverifiable(
            "Identity holds only where both sides are defined",
            developer_fields={
                "is_valid": False,
                "result": None,
                "constraint_id": DOMAIN_RESTRICTED_IDENTITY,
                **fields,
            },
        )
    if identity_status == "VERIFIED":
        return DiagnosticResult.verified(
            "Identity is true",
            developer_fields={"is_valid": True, "result": True, **fields},
            evidence=fields,
        )
    if identity_status == DISPROVEN_STATUS and (has_undefined_part(left_str) or has_undefined_part(right_str)):
        return DiagnosticResult.unverifiable(
            "A side of the identity is undefined",
            developer_fields={
                "is_valid": False,
                "result": None,
                "constraint_id": UNDEFINED_PART_IDENTITY,
                **fields,
            },
        )
    if identity_status == DISPROVEN_STATUS:
        return DiagnosticResult.disproven(
            "Identity is false",
            developer_fields={"result": False, **fields},
            evidence={**fields, "verdict": "disproven"},
        )
    return DiagnosticResult.unverifiable(
        "Identity could not be proven or disproven",
        developer_fields={"is_valid": False, "result": None, **fields},
    )
