"""
Verdicts for code CodeVerifier has no sound checker for (GHSA-7xrf).

CodeVerifier shows Python safe by its shape: only listed modules, names and
builtins (code_admission), and no name read before the code binds it
(code_names). For JavaScript, TypeScript, Java and Go it only searches for
listed substrings, and a call reached through destructuring, a variable or an
alias matches none of them. Finding a listed substring still shows the code
unsafe, but finding none shows nothing, so such code is UNVERIFIABLE, never
admitted.

SQL is also decided by SQLVerifier, after CodeVerifier's own SQL checks: a
statement it proves unsafe is unsafe here too, and one it could not verify is
not admitted. /verify/code has no schema, so SQLVerifier runs without one:
its checks of the statement apply, its checks of tables and columns do not
(send SQL with its schema to /verify/sql for those).
"""

from typing import Any, Dict, List, Optional

from .diagnostics import AdmissionDecision, DiagnosticResult, DiagnosticStatus, admission_decision

CONSTRAINT_LANGUAGE_UNVERIFIABLE = "code_verifier.language_unverifiable"
CONSTRAINT_SQL_UNVERIFIED = "code_verifier.sql_unverified"

# Languages whose code CodeVerifier can show safe.
CHECKED_LANGUAGES = frozenset({"python", "sql"})


def sql_verdict(code: str) -> DiagnosticResult:
    """SQLVerifier's verdict on ``code``, without a schema."""
    from .sql_verifier import SQLVerifier

    return SQLVerifier().verify_sql(code)


def sql_findings(verdict: Optional[DiagnosticResult]) -> List[Dict[str, Any]]:
    """A CodeVerifier finding when SQLVerifier proved the statement unsafe."""
    if verdict is None or verdict.status is not DiagnosticStatus.VERIFIED:
        return []
    if verdict.developer_fields.get("is_valid") is True:
        return []
    constraint = str(verdict.developer_fields.get("constraint_id") or "sql_verifier")
    return [{
        "severity": "CRITICAL",
        "issue_type": "sql_not_admitted",
        "pattern": constraint,
        "description": "SQLVerifier does not admit this SQL (the /verify/sql decision)",
        "recommendation": "Send SQL to /verify/sql with its schema and dialect.",
    }]


def unproven(
    language: str, developer_fields: Dict[str, Any], sql: Optional[DiagnosticResult]
) -> Optional[DiagnosticResult]:
    """For code CodeVerifier found nothing wrong with: None when its checker
    shows it safe (Python, or SQL that SQLVerifier admits), else the result
    that refuses it."""
    if language not in CHECKED_LANGUAGES:
        return DiagnosticResult.unverifiable(
            agent_message=(
                "The code could not be verified: QWED has no checker that shows code in this language safe."
            ),
            developer_fields={
                **developer_fields,
                "constraint_id": CONSTRAINT_LANGUAGE_UNVERIFIABLE,
                "is_safe": False,
                "is_valid": False,
            },
        )
    if language == "sql" and (sql is None or admission_decision(sql) is not AdmissionDecision.ADMIT):
        refused = {
            **developer_fields,
            "constraint_id": CONSTRAINT_SQL_UNVERIFIED,
            "is_safe": False,
            "is_valid": False,
            "sql_constraint_id": None if sql is None else sql.developer_fields.get("constraint_id"),
        }
        message = "The SQL could not be verified, so it is not admitted."
        if sql is not None and sql.status is DiagnosticStatus.UNVERIFIABLE:
            return DiagnosticResult.unverifiable(agent_message=message, developer_fields=refused)
        return DiagnosticResult.blocked(agent_message=message, developer_fields=refused)
    return None
