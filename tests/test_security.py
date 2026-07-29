"""
Test script for Security & Stability.
Verifies SafeEvaluator blocks malicious code and Timeouts work.
"""

from qwed_new.core.diagnostics import DiagnosticStatus
from qwed_new.core.logic_verifier import LogicVerifier


def test_security():
    verifier = LogicVerifier()

    # Case 1: Malicious Code Execution
    malicious_query = "x > 0 and __import__('os').system('echo HACKED') == 0"
    vars1 = {'x': 'Int'}
    constrs1 = [malicious_query]

    result1 = verifier.verify_logic(vars1, constrs1)
    assert result1.status == DiagnosticStatus.BLOCKED, (
        f"Expected BLOCKED for malicious code, got {result1.status.value}: {result1.agent_message}"
    )
    assert result1.constraint_id is not None, "BLOCKED result should have constraint_id"

    # Case 2: Normal query
    vars2 = {'x': 'Int'}
    constrs2 = ["x > 0", "x < 10"]
    result2 = verifier.verify_logic(vars2, constrs2)
    assert result2.status == DiagnosticStatus.VERIFIED, (
        f"Expected VERIFIED for normal query, got {result2.status.value}: {result2.agent_message}"
    )
    assert result2.developer_fields.get("deterministic_verdict") == "SAT"

if __name__ == "__main__":
    test_security()
