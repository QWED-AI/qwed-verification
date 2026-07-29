# Copyright (c) 2024 QWED Team
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import patch

from qwed_new.core.diagnostics import DiagnosticStatus
from qwed_new.core.logic_verifier import LogicVerifier

def test_no_eval_injection():
    """Verify that the logic engine does not execute arbitrary code."""
    verifier = LogicVerifier()

    variables = {"x": "Int"}
    constraints = ["x == __import__('os').system('echo pwned')"]

    with patch("os.system") as mock_system:
        result = verifier.verify_logic(variables, constraints, prove_unsat=False)
        mock_system.assert_not_called()
    assert result.status == DiagnosticStatus.BLOCKED, (
        f"Expected BLOCKED, got {result.status.value}: {result.agent_message}"
    )
    assert result.constraint_id == "logic_verifier.invalid_constraint"

def test_path_traversal_prevention():
    """Ensure file paths cannot be manipulated."""
    verifier = LogicVerifier()

    variables = {"x": "Int"}
    constraints = ["open('/tmp/../etc/passwd')"]

    with patch("builtins.open") as mock_open:
        result = verifier.verify_logic(variables, constraints, prove_unsat=False)
        mock_open.assert_not_called()
    assert result.status == DiagnosticStatus.BLOCKED
    assert result.constraint_id == "logic_verifier.invalid_constraint"
