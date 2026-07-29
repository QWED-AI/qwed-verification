"""
Test script for Constraint Sanitizer.
Deliberately sends broken syntax to see if the middleware fixes it.
"""

from qwed_new.core.diagnostics import DiagnosticStatus
from qwed_new.core.logic_verifier import LogicVerifier


def test_sanitizer():
    verifier = LogicVerifier()

    # Case 1: Assignment '=' instead of '=='
    vars1 = {'x': 'Int'}
    constrs1 = ["x = 5", "x > 0"]
    result1 = verifier.verify_logic(vars1, constrs1)
    assert result1.status == DiagnosticStatus.VERIFIED, (
        f"Expected VERIFIED after sanitizer fix, got {result1.status.value}: {result1.agent_message}"
    )
    assert result1.developer_fields.get("deterministic_verdict") == "SAT", (
        f"Expected SAT verdict, got {result1.developer_fields.get('deterministic_verdict')}"
    )

if __name__ == "__main__":
    test_sanitizer()
