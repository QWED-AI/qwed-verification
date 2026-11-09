"""The DiagnosticResult a route builds from control-plane output (#494).

``/verify/logic`` and ``/verify/natural_language`` turn the control plane's
dict into a ``DiagnosticResult`` before they respond and log. ``/verify/batch``
used to return that dict as it was, so the same query got a different result
shape, and sometimes a different verdict, in a batch. Both now call these
helpers, so a batch item gets what its route returns.

Trust enforcement and admission stay with the caller, which applies them the
same way in both places.

``/verify/rag`` and ``/verify/process`` build theirs with ``guard_diagnostic``.
"""

from typing import Any

from qwed_new.core.diagnostics import AdvisoryCheck, DiagnosticResult


def guard_diagnostic(result: dict, *, route: str, passed: str, failed: str) -> DiagnosticResult:
    """The verdict of a route whose guard checks only what the request says (#320).

    ``/verify/rag`` compares the document labels on the chunks with a target
    label and a threshold, all sent in the same request, and the server holds
    no documents. ``/verify/process`` looks for keywords in the trace, and in
    milestones mode the request names the keywords too. Neither can establish
    that the retrieval or the reasoning is right, so the verdict is always
    UNVERIFIABLE, and the guard's own result is advisory only: it sits in
    ``advisory_checks``, so its ``verified`` key never reaches the response's
    top level. ``passed`` and ``failed`` are the messages for the guard's two
    outcomes.
    """
    guard_passed = result.get("verified") is True
    check = AdvisoryCheck(
        name=f"{route}_guard",
        constraint_id=f"api.{route}.guard",
        details=dict(result),
    )
    return DiagnosticResult.unverifiable(
        passed if guard_passed else failed,
        developer_fields={
            "constraint_id": f"api.{route}.{'advisory_only' if guard_passed else 'guard_failed'}",
            "advisory_checks": [check],
        },
    )


def _logic_scope(result: dict) -> dict:
    """What a logic verdict covers (#320).

    An LLM writes the constraints from the question, and the engine decides
    only those constraints: nothing checks that they mean what was asked. So
    the query semantics are never verified here, whatever the input says, and
    where the constraints are known the verdict names them as its scope, as
    the natural-language maths verdict does. The route admits the verdict
    through ``natural_language_admission``, which reads this.
    """
    scope: dict = {"query_semantics_verified": False}
    dsl_code = result.get("dsl_code")
    if isinstance(dsl_code, str) and dsl_code:
        scope.update({
            "query_interpretation_source": "llm_translation",
            "verification_scope": "translated_expression_only",
            "translated_expression": _typed_statement(dsl_code, result.get("declarations")),
        })
    return scope


def _typed_statement(dsl_code: str, declarations: Any) -> str:
    """The statement Z3 decided: the DSL, after a ``(VAR name Sort)`` for
    each declared variable.

    The DSL alone does not fix the sorts (an undeclared name is an Int):
    ``(AND (GT x 0) (LT x 1))`` is satisfiable for a Real ``x`` and not for
    an Int one, so a statement without the declarations would name a
    different claim from the one decided.
    """
    if not isinstance(declarations, dict):
        return dsl_code
    parts = [
        f"(VAR {name} {sort})"
        for name, sort in sorted(declarations.items())
        if isinstance(name, str) and isinstance(sort, str)
    ]
    return " ".join([*parts, dsl_code])


def logic_diagnostic(result: dict) -> DiagnosticResult:
    """``/verify/logic``'s mapping: SAT is VERIFIED with the model as evidence,
    UNSAT is UNVERIFIABLE, anything else (an error) is BLOCKED. The verdict
    covers the translated constraints only (see ``_logic_scope``)."""
    fields = {**result, **_logic_scope(result)}
    status = result.get("status", "ERROR")
    if status == "SAT":
        evidence = {"model": str(result.get("model")), "dsl_code": result.get("dsl_code", "")}
        if isinstance(result.get("declarations"), dict) and result["declarations"]:
            evidence["declarations"] = result["declarations"]
        return DiagnosticResult.verified(
            "Logic constraints are satisfiable",
            developer_fields=fields,
            evidence=evidence,
        )
    if status == "UNSAT":
        return DiagnosticResult.unverifiable(
            "Logic constraints are unsatisfiable",
            developer_fields=fields,
        )
    return DiagnosticResult.blocked(
        result.get("error", "Logic verification failed"),
        developer_fields=fields,
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
