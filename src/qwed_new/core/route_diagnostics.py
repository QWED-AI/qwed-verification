"""The DiagnosticResult a route builds from control-plane output (#494).

``/verify/logic`` and ``/verify/natural_language`` turn the control plane's
dict into a ``DiagnosticResult`` before they respond and log. ``/verify/batch``
used to return that dict as it was, so the same query got a different result
shape, and sometimes a different verdict, in a batch. Both now call these
helpers, so a batch item gets what its route returns.

Trust enforcement and admission stay with the caller, which applies them the
same way in both places.
"""

from typing import Any

from qwed_new.core.diagnostics import DiagnosticResult


def logic_diagnostic(result: dict) -> DiagnosticResult:
    """``/verify/logic``'s mapping: SAT is VERIFIED with the model as evidence,
    UNSAT is UNVERIFIABLE, anything else (an error) is BLOCKED."""
    status = result.get("status", "ERROR")
    if status == "SAT":
        return DiagnosticResult.verified(
            "Logic constraints are satisfiable",
            developer_fields=result,
            evidence={"model": str(result.get("model")), "dsl_code": result.get("dsl_code", "")},
        )
    if status == "UNSAT":
        return DiagnosticResult.unverifiable(
            "Logic constraints are unsatisfiable",
            developer_fields=result,
        )
    return DiagnosticResult.blocked(
        result.get("error", "Logic verification failed"),
        developer_fields=result,
    )


def natural_language_diagnostic(result: Any) -> DiagnosticResult:
    """The verdict for a control-plane result.

    The control plane attaches the DiagnosticResult it enforced (signed and
    attested for decided verdicts, #437), so it is used as produced. Results
    without one (security or policy blocks, non-math queries, errors) fall back
    to the fail-closed legacy mapping, which can never yield VERIFIED.
    """
    if isinstance(result, dict) and "diagnostic" in result:
        try:
            return DiagnosticResult.from_dict(result["diagnostic"])
        except (TypeError, ValueError, KeyError, AttributeError):
            return DiagnosticResult.blocked(
                "Verification blocked — control plane returned a malformed diagnostic",
                {"constraint_id": "api.natural_language.malformed_diagnostic"},
            )
    verification_result = result.get("verification", {}) if isinstance(result, dict) else {}
    try:
        return DiagnosticResult.from_legacy_dict(verification_result, engine="math")
    except ValueError:
        return DiagnosticResult.unverifiable(
            "Verification result unavailable — legacy engine did not retain proof artifacts",
            {"constraint_id": "api.natural_language.legacy_conversion_failed", "legacy_status": verification_result.get("status")},
        )
