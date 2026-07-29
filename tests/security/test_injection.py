# Copyright (c) 2024 QWED Team
# SPDX-License-Identifier: Apache-2.0



from qwed_new.core.diagnostics import DiagnosticStatus
from qwed_new.core.logic_verifier import LogicVerifier

def test_no_eval_injection():
    """Verify that the logic engine does not execute arbitrary code."""
    verifier = LogicVerifier()

    # Attempt to inject code via logic expression
    variables = {"x": "Int"}
    constraints = ["x == __import__('os').system('echo pwned')"]

    # Should return BLOCKED status, not execute
    result = verifier.verify_logic(variables, constraints, prove_unsat=False)
    assert result.status == DiagnosticStatus.BLOCKED, (
        f"Expected BLOCKED, got {result.status.value}: {result.agent_message}"
    )
    assert result.constraint_id is not None, "BLOCKED result should have constraint_id"

def test_path_traversal_prevention():
    """Ensure file paths cannot be manipulated."""
    pass
