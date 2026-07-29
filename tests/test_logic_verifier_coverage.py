"""Targeted coverage tests for LogicVerifier uncovered lines."""

from unittest.mock import patch, MagicMock

from qwed_new.core.logic_verifier import LogicVerifier, QuantifiedFormula
from qwed_new.core.diagnostics import DiagnosticResult, DiagnosticStatus


# =========================================================================
# verify_logic coverage
# =========================================================================

def test_verify_logic_prove_unsat():
    """Cover unsat explanation path (prove_unsat=True)."""
    v = LogicVerifier()
    result = v.verify_logic({"x": "Int"}, ["x > 5", "x < 3"], prove_unsat=True)
    assert result.status == DiagnosticStatus.UNVERIFIABLE
    assert result.developer_fields.get("deterministic_verdict") == "UNSAT"
    assert "explanation" in result.developer_fields


def test_verify_logic_unknown():
    """Cover Z3 unknown result path."""
    v = LogicVerifier()
    with patch("qwed_new.core.logic_verifier.Solver") as mock_solver_cls:
        mock_solver = MagicMock()
        mock_solver_cls.return_value = mock_solver
        from z3 import unknown
        mock_solver.check.return_value = unknown
        from z3 import Int
        mock_z3_vars = {"x": Int("x")}
        with patch.object(v, "_create_z3_variables", return_value=mock_z3_vars):
            result = v.verify_logic({"x": "Int"}, ["x > 0"])
            assert result.status == DiagnosticStatus.UNVERIFIABLE
            assert result.developer_fields.get("deterministic_verdict") == "UNKNOWN"


def test_verify_logic_pipeline_error():
    """Cover the outer exception handler."""
    v = LogicVerifier()
    with patch.object(v, "_ensure_sanitizer", side_effect=RuntimeError("boom")):
        result = v.verify_logic({"x": "Int"}, ["x > 0"])
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "logic_verifier.execution_error"


# =========================================================================
# verify_with_quantifiers coverage
# =========================================================================

def test_quantifiers_no_vars_no_formulas():
    """Cover: not variables and not quantified_formulas guard."""
    v = LogicVerifier()
    result = v.verify_with_quantifiers({}, [])
    assert result.status == DiagnosticStatus.BLOCKED
    assert result.constraint_id == "logic_verifier.explicit_declarations_required"


def test_quantifiers_sat():
    """Cover SAT path with quantifiers."""
    v = LogicVerifier()
    qf = QuantifiedFormula("forall", [("x", "Int")], "x == x")
    result = v.verify_with_quantifiers({}, [qf])
    assert result.status == DiagnosticStatus.VERIFIED
    assert result.developer_fields.get("deterministic_verdict") == "SAT"


def test_quantifiers_unsat():
    """Cover UNSAT path with quantifiers."""
    v = LogicVerifier()
    qf = QuantifiedFormula("forall", [("x", "Int")], "And(x > 10, x < 5)")
    result = v.verify_with_quantifiers({}, [qf])
    assert result.status == DiagnosticStatus.UNVERIFIABLE
    assert result.developer_fields.get("deterministic_verdict") == "UNSAT"


def test_quantifiers_exists():
    """Cover exists quantifier."""
    v = LogicVerifier()
    qf = QuantifiedFormula("exists", [("x", "Int")], "x == 42")
    result = v.verify_with_quantifiers({}, [qf])
    assert result.status == DiagnosticStatus.VERIFIED


def test_quantifiers_unknown_quantifier():
    """Cover unknown quantifier rejection."""
    v = LogicVerifier()
    qf = QuantifiedFormula("bogus", [("x", "Int")], "x == 42")
    result = v.verify_with_quantifiers({}, [qf])
    assert result.status == DiagnosticStatus.BLOCKED
    assert result.constraint_id == "logic_verifier.unknown_quantifier"


def test_quantifiers_with_constraints():
    """Cover constraints + quantifiers path."""
    v = LogicVerifier()
    qf = QuantifiedFormula("forall", [("x", "Int")], "x == x")
    result = v.verify_with_quantifiers({"y": "Int"}, [qf], constraints=["y > 0"])
    assert result.status == DiagnosticStatus.VERIFIED


def test_quantifiers_bound_var_conflict():
    """Cover bound variable collision detection."""
    v = LogicVerifier()
    qf = QuantifiedFormula("forall", [("x", "Bool")], "x == True")
    result = v.verify_with_quantifiers({"x": "Int"}, [qf])
    assert result.status == DiagnosticStatus.BLOCKED
    assert result.constraint_id == "logic_verifier.bound_variable_conflict"


def test_quantifiers_scope_isolation():
    """Cover Greptile P1: each formula has isolated scope."""
    v = LogicVerifier()
    qf_a = QuantifiedFormula("exists", [("x", "Int")], "x == 5")
    qf_b = QuantifiedFormula("exists", [("y", "Int")], "y == 10")
    result = v.verify_with_quantifiers(
        {}, [qf_a, qf_b]
    )
    assert result.status == DiagnosticStatus.VERIFIED


def test_quantifiers_exception():
    """Cover quantifier exception handler."""
    v = LogicVerifier()
    with patch.object(v, "_ensure_sanitizer", side_effect=RuntimeError("boom")):
        result = v.verify_with_quantifiers({"x": "Int"}, [], constraints=["x > 0"])
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "logic_verifier.execution_error"


# =========================================================================
# verify_bitvector coverage
# =========================================================================

def test_bitvector_sat():
    """Cover SAT path."""
    v = LogicVerifier()
    result = v.verify_bitvector({"x": 8}, ["x == 42"])
    assert result.status == DiagnosticStatus.VERIFIED


def test_bitvector_unsat():
    """Cover UNSAT path."""
    v = LogicVerifier()
    result = v.verify_bitvector({"x": 8}, ["x == 42", "x == 100"])
    assert result.status == DiagnosticStatus.UNVERIFIABLE


def test_bitvector_no_vars():
    """Cover empty variables guard."""
    v = LogicVerifier()
    result = v.verify_bitvector({}, [])
    assert result.status == DiagnosticStatus.BLOCKED
    assert result.constraint_id == "logic_verifier.explicit_declarations_required"


def test_bitvector_exception():
    """Cover bitvector exception handler."""
    v = LogicVerifier()
    with patch.object(v, "_ensure_sanitizer", side_effect=RuntimeError("boom")):
        result = v.verify_bitvector({"x": 8}, ["x > 0"])
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "logic_verifier.execution_error"


# =========================================================================
# verify_array coverage
# =========================================================================

def test_array_sat():
    """Cover SAT path."""
    v = LogicVerifier()
    result = v.verify_array(
        {"arr": ("Int", "Int")},
        {},
        ["Select(arr, 0) == 42"],
    )
    assert result.status == DiagnosticStatus.VERIFIED


def test_array_unsat():
    """Cover UNSAT path."""
    v = LogicVerifier()
    result = v.verify_array(
        {"arr": ("Int", "Int")},
        {},
        ["Select(arr, 0) == 42", "Select(arr, 0) == 100"],
    )
    assert result.status == DiagnosticStatus.UNVERIFIABLE


def test_array_no_vars_no_decls():
    """Cover empty variables and array_decls guard."""
    v = LogicVerifier()
    result = v.verify_array({}, {}, [])
    assert result.status == DiagnosticStatus.BLOCKED
    assert result.constraint_id == "logic_verifier.explicit_declarations_required"


def test_array_only_decls():
    """Cover: only array_decls, no variables."""
    v = LogicVerifier()
    result = v.verify_array({"arr": ("Int", "Int")}, {}, ["Select(arr, 0) != Select(arr, 1)"])
    assert result.status == DiagnosticStatus.VERIFIED


def test_array_unsupported_sort():
    """Cover unsupported array sort rejection."""
    v = LogicVerifier()
    result = v.verify_array({"arr": ("Integer", "Bol")}, {}, [])
    assert result.status == DiagnosticStatus.BLOCKED
    assert result.constraint_id == "dsl_compiler.type_validation"


def test_array_duplicate_symbol():
    """Cover duplicate symbol detection."""
    v = LogicVerifier()
    result = v.verify_array({"x": ("Int", "Int")}, {"x": "Int"}, [])
    assert result.status == DiagnosticStatus.BLOCKED
    assert result.constraint_id == "logic_verifier.duplicate_symbol"


def test_array_mixed():
    """Cover arrays + regular variables mix."""
    v = LogicVerifier()
    result = v.verify_array(
        {"arr": ("Int", "Int")},
        {"x": "Int"},
        ["Select(arr, 0) == x", "x == 10"],
    )
    assert result.status == DiagnosticStatus.VERIFIED


def test_array_exception():
    """Cover array exception handler."""
    v = LogicVerifier()
    with patch.object(v, "_ensure_sanitizer", side_effect=RuntimeError("boom")):
        result = v.verify_array({"arr": ("Int", "Int")}, {}, ["Select(arr, 0) > 0"])
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "logic_verifier.execution_error"


# =========================================================================
# _build_proof_data coverage
# =========================================================================

def test_build_proof_data_with_extra():
    """Cover _build_proof_data extra param."""
    v = LogicVerifier()
    from z3 import Solver, Int, Bool
    s = Solver()
    x = Int("x")
    s.add(x > 0)
    result = v._build_proof_data(s, extra=["maximize: x"])
    assert result is not None
    assert "maximize: x" in result


def test_build_proof_data_empty_assertions():
    """Cover empty assertions → None."""
    v = LogicVerifier()
    from z3 import Solver
    s = Solver()
    result = v._build_proof_data(s)
    assert result == "[]"


# =========================================================================
# _create_z3_variables edge cases
# =========================================================================

def test_create_z3_variables_bool():
    """Cover Bool type."""
    v = LogicVerifier()
    result = v._create_z3_variables({"p": "Bool"})
    assert "p" in result
    from z3 import Bool
    # By default Bool requires explicit sort creation
    assert result["p"].sort().name() == "Bool"


# =========================================================================
# check_equivalence coverage
# =========================================================================

def test_equivalence_equal():
    """Cover equivalent formulas path."""
    v = LogicVerifier()
    result = v.check_equivalence({"x": "Int"}, "x > 0", "x > 0")
    assert result.status == DiagnosticStatus.VERIFIED


def test_equivalence_not_equal():
    """Cover not-equivalent formulas path."""
    v = LogicVerifier()
    result = v.check_equivalence({"x": "Int"}, "x > 0", "x < 0")
    assert result.status == DiagnosticStatus.BLOCKED
    assert result.developer_fields.get("deterministic_verdict") == "not_equivalent"


def test_equivalence_no_vars():
    """Cover equivalence empty variables guard."""
    v = LogicVerifier()
    result = v.check_equivalence({}, "x > 0", "x < 0")
    assert result.status == DiagnosticStatus.BLOCKED
    assert result.constraint_id == "logic_verifier.explicit_declarations_required"


def test_equivalence_exception():
    """Cover equivalence exception handler."""
    v = LogicVerifier()
    with patch.object(v, "_ensure_sanitizer", side_effect=RuntimeError("boom")):
        result = v.check_equivalence({"x": "Int"}, "x > 0", "x < 0")
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "logic_verifier.execution_error"


# =========================================================================
# check_implication coverage
# =========================================================================

def test_implication():
    """Cover check_implication (delegates to prove_theorem)."""
    v = LogicVerifier()
    result = v.check_implication({"x": "Int"}, "x > 10", "x > 5")
    assert result.status == DiagnosticStatus.VERIFIED


def test_implication_false():
    """Cover check_implication false."""
    v = LogicVerifier()
    result = v.check_implication({"x": "Int"}, "x > 10", "x > 20")
    assert result.status == DiagnosticStatus.BLOCKED


# =========================================================================
# prove_theorem additional coverage
# =========================================================================

def test_prove_theorem_unknown():
    """Cover prove_theorem unknown result path."""
    v = LogicVerifier()
    with patch("qwed_new.core.logic_verifier.Solver") as mock_solver_cls:
        mock_solver = MagicMock()
        mock_solver_cls.return_value = mock_solver
        from z3 import unknown
        mock_solver.check.return_value = unknown
        from z3 import Int
        mock_z3 = {"x": Int("x")}
        with patch.object(v, "_create_z3_variables", return_value=mock_z3):
            result = v.prove_theorem({"x": "Int"}, ["x > 0"], "x < 10")
            assert result.status == DiagnosticStatus.UNVERIFIABLE
            assert result.developer_fields.get("deterministic_verdict") == "UNKNOWN"


def test_prove_theorem_exception():
    """Cover prove_theorem exception handler."""
    v = LogicVerifier()
    with patch.object(v, "_ensure_sanitizer", side_effect=RuntimeError("boom")):
        result = v.prove_theorem({"x": "Int"}, ["x > 0"], "x < 10")
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "logic_verifier.execution_error"


# =========================================================================
# verify_optimization coverage
# =========================================================================

def test_optimization_sat():
    """Cover optimization SAT path."""
    v = LogicVerifier()
    result = v.verify_optimization(
        {"x": "Int"}, ["x >= 0", "x <= 10"], "x", maximize=True
    )
    assert result.status == DiagnosticStatus.VERIFIED
    assert result.developer_fields.get("deterministic_verdict") == "OPTIMAL"


def test_optimization_unsat():
    """Cover optimization UNSAT path."""
    v = LogicVerifier()
    result = v.verify_optimization(
        {"x": "Int"}, ["x > 10", "x < 5"], "x", maximize=True
    )
    assert result.status == DiagnosticStatus.UNVERIFIABLE
    assert result.developer_fields.get("deterministic_verdict") == "UNSAT"


def test_optimization_no_vars():
    """Cover optimization empty variables guard."""
    v = LogicVerifier()
    result = v.verify_optimization({}, [], "x")
    assert result.status == DiagnosticStatus.BLOCKED
    assert result.constraint_id == "logic_verifier.explicit_declarations_required"


def test_optimization_minimize():
    """Cover minimize direction."""
    v = LogicVerifier()
    result = v.verify_optimization(
        {"x": "Int"}, ["x >= 0", "x <= 10"], "x", maximize=False
    )
    assert result.status == DiagnosticStatus.VERIFIED
    assert result.developer_fields.get("deterministic_verdict") == "OPTIMAL"


def test_optimization_exception():
    """Cover optimization exception handler."""
    v = LogicVerifier()
    with patch.object(v, "_ensure_sanitizer", side_effect=RuntimeError("boom")):
        result = v.verify_optimization({"x": "Int"}, ["x >= 0"], "x")
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "logic_verifier.execution_error"


# =========================================================================
# check_vacuity coverage
# =========================================================================

def test_vacuity_sat():
    """Cover non-vacuous (satisfiable antecedent) path."""
    v = LogicVerifier()
    result = v.check_vacuity({"x": "Int"}, "x > 0")
    assert result.status == DiagnosticStatus.VERIFIED
    assert result.developer_fields.get("deterministic_verdict") == "NON_VACUOUS"


def test_vacuity_unsat():
    """Cover vacuous (unsatisfiable antecedent) path."""
    v = LogicVerifier()
    result = v.check_vacuity({"x": "Int"}, "And(x > 10, x < 5)")
    assert result.status == DiagnosticStatus.UNVERIFIABLE
    assert result.developer_fields.get("deterministic_verdict") == "VACUOUS"


def test_vacuity_with_consequent():
    """Cover vacuity with consequent recorded in fields."""
    v = LogicVerifier()
    result = v.check_vacuity({"x": "Int"}, "x > 0", consequent="x > -1")
    assert result.status == DiagnosticStatus.VERIFIED
    assert "consequent" in result.developer_fields
    assert result.developer_fields["consequent"] == "x > -1"


def test_vacuity_no_vars():
    """Cover vacuity empty variables guard."""
    v = LogicVerifier()
    result = v.check_vacuity({}, "x > 0")
    assert result.status == DiagnosticStatus.BLOCKED
    assert result.constraint_id == "logic_verifier.explicit_declarations_required"


def test_vacuity_exception():
    """Cover vacuity exception handler."""
    v = LogicVerifier()
    with patch.object(v, "_ensure_sanitizer", side_effect=RuntimeError("boom")):
        result = v.check_vacuity({"x": "Int"}, "x > 0")
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "logic_verifier.execution_error"


# =========================================================================
# verify_logic: additional edge cases (empty vars, sanitizer, z3_vars)
# =========================================================================

def test_verify_logic_empty_vars():
    """Cover line 109: empty variables guard."""
    v = LogicVerifier()
    result = v.verify_logic({}, ["x > 0"])
    assert result.status == DiagnosticStatus.BLOCKED
    assert result.constraint_id == "logic_verifier.explicit_declarations_required"


def test_verify_logic_sanitizer_blocked():
    """Cover line 116: _ensure_sanitizer returns blocked."""
    v = LogicVerifier()
    blocked = DiagnosticResult.blocked("test", {"constraint_id": "logic_verifier.sanitizer_unavailable"})
    with patch.object(v, "_ensure_sanitizer", return_value=blocked):
        result = v.verify_logic({"x": "Int"}, ["x > 0"])
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "logic_verifier.sanitizer_unavailable"


def test_verify_logic_z3_vars_error():
    """Cover line 126: _create_z3_variables returns DiagnosticResult."""
    v = LogicVerifier()
    with patch.object(v, "_create_z3_variables", return_value=DiagnosticResult.blocked(
        "mock", {"constraint_id": "logic_verifier.explicit_declarations_required"}
    )):
        result = v.verify_logic({"x": "Int"}, ["x > 0"])
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "logic_verifier.explicit_declarations_required"


# =========================================================================
# verify_with_quantifiers: sanitizer blocked, z3_vars errors, unknown
# =========================================================================

def test_quantifiers_sanitizer_blocked():
    """Cover line 209: sanitizer blocked in quantifiers."""
    v = LogicVerifier()
    blocked = DiagnosticResult.blocked("test", {"constraint_id": "logic_verifier.sanitizer_unavailable"})
    with patch.object(v, "_ensure_sanitizer", return_value=blocked):
        result = v.verify_with_quantifiers({"x": "Int"}, [], constraints=["x > 0"])
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "logic_verifier.sanitizer_unavailable"


def test_quantifiers_free_vars_error():
    """Cover line 214: free_vars _create_z3_variables error."""
    v = LogicVerifier()
    with patch.object(v, "_create_z3_variables", return_value=DiagnosticResult.blocked(
        "mock", {"constraint_id": "dsl_compiler.type_validation"}
    )):
        result = v.verify_with_quantifiers({"x": "Int"}, [], constraints=["x > 0"])
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "dsl_compiler.type_validation"


def test_quantifiers_unknown():
    """Cover line 286: solver.check() unknown for quantifiers."""
    v = LogicVerifier()
    with patch("qwed_new.core.logic_verifier.Solver") as mock_solver_cls:
        mock_solver = MagicMock()
        mock_solver_cls.return_value = mock_solver
        from z3 import unknown
        mock_solver.check.return_value = unknown
        from z3 import Int
        mock_z3 = {"x": Int("x")}
        with patch.object(v, "_create_z3_variables", return_value=mock_z3):
            result = v.verify_with_quantifiers({"x": "Int"}, [], constraints=["x > 0"])
            assert result.status == DiagnosticStatus.UNVERIFIABLE
            assert result.developer_fields.get("deterministic_verdict") == "UNKNOWN"


# =========================================================================
# verify_bitvector: sanitizer blocked, unknown
# =========================================================================

def test_bitvector_sanitizer_blocked():
    """Cover line 316: sanitizer blocked in bitvector."""
    v = LogicVerifier()
    blocked = DiagnosticResult.blocked("test", {"constraint_id": "logic_verifier.sanitizer_unavailable"})
    with patch.object(v, "_ensure_sanitizer", return_value=blocked):
        result = v.verify_bitvector({"x": 8}, ["x > 0"])
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "logic_verifier.sanitizer_unavailable"


def test_bitvector_unknown():
    """Cover line 359: solver.check() unknown for bitvector."""
    v = LogicVerifier()
    with patch("qwed_new.core.logic_verifier.Solver") as mock_solver_cls:
        mock_solver = MagicMock()
        mock_solver_cls.return_value = mock_solver
        from z3 import unknown
        mock_solver.check.return_value = unknown
        result = v.verify_bitvector({"x": 8}, ["x > 0"])
        assert result.status == DiagnosticStatus.UNVERIFIABLE
        assert result.developer_fields.get("deterministic_verdict") == "UNKNOWN"


# =========================================================================
# verify_array: sanitizer blocked, z3_vars error, unknown
# =========================================================================

def test_array_sanitizer_blocked():
    """Cover line 390: sanitizer blocked in array."""
    v = LogicVerifier()
    blocked = DiagnosticResult.blocked("test", {"constraint_id": "logic_verifier.sanitizer_unavailable"})
    with patch.object(v, "_ensure_sanitizer", return_value=blocked):
        result = v.verify_array({"arr": ("Int", "Int")}, {}, ["Select(arr, 0) > 0"])
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "logic_verifier.sanitizer_unavailable"


def test_array_z3_vars_error():
    """Cover line 416: _create_z3_variables returns DiagnosticResult for regular vars."""
    v = LogicVerifier()
    with patch.object(v, "_create_z3_variables", return_value=DiagnosticResult.blocked(
        "mock", {"constraint_id": "dsl_compiler.type_validation"}
    )):
        result = v.verify_array({}, {"x": "Bool"}, ["x == True"])
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "dsl_compiler.type_validation"


def test_array_unknown():
    """Cover line 456: solver.check() unknown for array."""
    v = LogicVerifier()
    with patch("qwed_new.core.logic_verifier.Solver") as mock_solver_cls:
        mock_solver = MagicMock()
        mock_solver_cls.return_value = mock_solver
        from z3 import unknown
        mock_solver.check.return_value = unknown
        result = v.verify_array({}, {"x": "Int"}, ["x > 0"])
        assert result.status == DiagnosticStatus.UNVERIFIABLE
        assert result.developer_fields.get("deterministic_verdict") == "UNKNOWN"


# =========================================================================
# prove_theorem: empty vars, sanitizer blocked, z3_vars error
# =========================================================================

def test_prove_theorem_empty_vars():
    """Cover line 480: empty variables guard."""
    v = LogicVerifier()
    result = v.prove_theorem({}, ["x > 0"], "x < 10")
    assert result.status == DiagnosticStatus.BLOCKED
    assert result.constraint_id == "logic_verifier.explicit_declarations_required"


def test_prove_theorem_sanitizer_blocked():
    """Cover line 487: sanitizer blocked."""
    v = LogicVerifier()
    blocked = DiagnosticResult.blocked("test", {"constraint_id": "logic_verifier.sanitizer_unavailable"})
    with patch.object(v, "_ensure_sanitizer", return_value=blocked):
        result = v.prove_theorem({"x": "Int"}, ["x > 0"], "x < 10")
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "logic_verifier.sanitizer_unavailable"


def test_prove_theorem_z3_vars_error():
    """Cover line 496: _create_z3_variables error."""
    v = LogicVerifier()
    with patch.object(v, "_create_z3_variables", return_value=DiagnosticResult.blocked(
        "mock", {"constraint_id": "dsl_compiler.type_validation"}
    )):
        result = v.prove_theorem({"x": "Int"}, ["x > 0"], "x < 10")
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "dsl_compiler.type_validation"


# =========================================================================
# _create_z3_variables: BitVec type + unsupported type
# =========================================================================

def test_create_z3_variables_bitvec():
    """Cover BitVec type path (line 561-575)."""
    v = LogicVerifier()
    result = v._create_z3_variables({"x": "BitVec[8]"})
    assert "x" in result
    from z3 import BitVecSort
    assert result["x"].sort() == BitVecSort(8)


def test_create_z3_variables_unsupported_type():
    """Cover unsupported type error path (line 576-577)."""
    v = LogicVerifier()
    result = v._create_z3_variables({"x": "float"})
    assert isinstance(result, DiagnosticResult)
    assert result.status == DiagnosticStatus.BLOCKED
    assert result.constraint_id == "dsl_compiler.type_validation"


# =========================================================================
# check_equivalence: sanitizer blocked, z3_vars error, unknown
# =========================================================================

def test_equivalence_sanitizer_blocked():
    """Cover line 632: sanitizer blocked."""
    v = LogicVerifier()
    blocked = DiagnosticResult.blocked("test", {"constraint_id": "logic_verifier.sanitizer_unavailable"})
    with patch.object(v, "_ensure_sanitizer", return_value=blocked):
        result = v.check_equivalence({"x": "Int"}, "x > 0", "x < 0")
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "logic_verifier.sanitizer_unavailable"


def test_equivalence_z3_vars_error():
    """Cover line 641: _create_z3_variables error."""
    v = LogicVerifier()
    with patch.object(v, "_create_z3_variables", return_value=DiagnosticResult.blocked(
        "mock", {"constraint_id": "dsl_compiler.type_validation"}
    )):
        result = v.check_equivalence({"x": "Int"}, "x > 0", "x < 0")
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "dsl_compiler.type_validation"


def test_equivalence_unknown():
    """Cover line 671-672: solver.check() unknown for equivalence."""
    v = LogicVerifier()
    with patch("qwed_new.core.logic_verifier.Solver") as mock_solver_cls:
        mock_solver = MagicMock()
        mock_solver_cls.return_value = mock_solver
        from z3 import unknown
        mock_solver.check.return_value = unknown
        result = v.check_equivalence({"x": "Int"}, "x > 0", "x < 0")
        assert result.status == DiagnosticStatus.UNVERIFIABLE
        assert result.developer_fields.get("deterministic_verdict") == "UNKNOWN"


# =========================================================================
# verify_optimization: sanitizer blocked, z3_vars error, unbounded, unknown
# =========================================================================

def test_optimization_sanitizer_blocked():
    """Cover line 704: sanitizer blocked."""
    v = LogicVerifier()
    blocked = DiagnosticResult.blocked("test", {"constraint_id": "logic_verifier.sanitizer_unavailable"})
    with patch.object(v, "_ensure_sanitizer", return_value=blocked):
        result = v.verify_optimization({"x": "Int"}, ["x >= 0"], "x")
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "logic_verifier.sanitizer_unavailable"


def test_optimization_z3_vars_error():
    """Cover line 712: _create_z3_variables error."""
    v = LogicVerifier()
    with patch.object(v, "_create_z3_variables", return_value=DiagnosticResult.blocked(
        "mock", {"constraint_id": "dsl_compiler.type_validation"}
    )):
        result = v.verify_optimization({"x": "Int"}, ["x >= 0"], "x")
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "dsl_compiler.type_validation"


def test_optimization_unbounded():
    """Cover line 735-736: unbounded objective."""
    v = LogicVerifier()
    result = v.verify_optimization({"x": "Int"}, [], "x", maximize=True)
    assert result.status == DiagnosticStatus.UNVERIFIABLE
    assert result.developer_fields.get("deterministic_verdict") == "UNBOUNDED"


def test_optimization_unknown():
    """Cover line 760-761: solver.check() unknown for optimization."""
    v = LogicVerifier()
    with patch("qwed_new.core.logic_verifier.Optimize") as mock_opt_cls:
        mock_opt = MagicMock()
        mock_opt_cls.return_value = mock_opt
        from z3 import unknown
        mock_opt.check.return_value = unknown
        from z3 import Int
        mock_z3 = {"x": Int("x")}
        with patch.object(v, "_create_z3_variables", return_value=mock_z3):
            result = v.verify_optimization({"x": "Int"}, ["x >= 0"], "x")
            assert result.status == DiagnosticStatus.UNVERIFIABLE
            assert result.developer_fields.get("deterministic_verdict") == "UNKNOWN"


# =========================================================================
# check_vacuity: sanitizer blocked, z3_vars error, unknown
# =========================================================================

def test_vacuity_sanitizer_blocked():
    """Cover line 788: sanitizer blocked."""
    v = LogicVerifier()
    blocked = DiagnosticResult.blocked("test", {"constraint_id": "logic_verifier.sanitizer_unavailable"})
    with patch.object(v, "_ensure_sanitizer", return_value=blocked):
        result = v.check_vacuity({"x": "Int"}, "x > 0")
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "logic_verifier.sanitizer_unavailable"


def test_vacuity_z3_vars_error():
    """Cover line 796: _create_z3_variables error."""
    v = LogicVerifier()
    with patch.object(v, "_create_z3_variables", return_value=DiagnosticResult.blocked(
        "mock", {"constraint_id": "dsl_compiler.type_validation"}
    )):
        result = v.check_vacuity({"x": "Int"}, "x > 0")
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "dsl_compiler.type_validation"


def test_vacuity_unknown():
    """Cover line 824-825: solver.check() unknown for vacuity."""
    v = LogicVerifier()
    with patch("qwed_new.core.logic_verifier.Solver") as mock_solver_cls:
        mock_solver = MagicMock()
        mock_solver_cls.return_value = mock_solver
        from z3 import unknown
        mock_solver.check.return_value = unknown
        result = v.check_vacuity({"x": "Int"}, "x > 0")
        assert result.status == DiagnosticStatus.UNVERIFIABLE
        assert result.developer_fields.get("deterministic_verdict") == "UNKNOWN"


# =========================================================================
# Remaining uncovered lines: cross-qf conflict, sanitizer in qf loop, BitVec width
# =========================================================================

def test_quantifiers_cross_qf_bound_var_conflict():
    """Cover line 289: cross-quantifier bound variable conflict."""
    v = LogicVerifier()
    qf1 = QuantifiedFormula("forall", [("x", "Int")], "x == x")
    qf2 = QuantifiedFormula("forall", [("x", "Real")], "x == x")
    result = v.verify_with_quantifiers({}, [qf1, qf2])
    assert result.status == DiagnosticStatus.BLOCKED
    assert result.constraint_id == "logic_verifier.bound_variable_conflict"


def test_quantifiers_sanitizer_blocked_in_qf_loop():
    """Cover line 307: sanitizer blocked inside qf loop."""
    v = LogicVerifier()
    blocked = DiagnosticResult.blocked("test", {"constraint_id": "logic_verifier.sanitizer_unavailable"})
    qf = QuantifiedFormula("forall", [("x", "Int")], "x == x")
    with patch.object(v, "_ensure_sanitizer", return_value=blocked):
        result = v.verify_with_quantifiers({"x": "Int"}, [qf])
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "logic_verifier.sanitizer_unavailable"


def test_bitvector_invalid_width():
    """Cover line 391: malformed BitVec width."""
    v = LogicVerifier()
    result = v.verify_bitvector({"x": 0}, [])
    assert result.status == DiagnosticStatus.BLOCKED
    assert result.constraint_id == "dsl_compiler.type_validation"


# =========================================================================
# Remaining uncovered lines: 237, 258, 567
# =========================================================================

def test_quantifiers_scope_z3_error():
    """Cover line 300: scope_z3 _create_z3_variables error."""
    v = LogicVerifier()
    from z3 import Int
    blocked = DiagnosticResult.blocked("mock", {"constraint_id": "logic_verifier.explicit_declarations_required"})
    call_n = [0]
    def mock_create(vars_dict):
        call_n[0] += 1
        if call_n[0] == 1:
            return blocked
        return {name: Int(name) for name in vars_dict}
    qf = QuantifiedFormula("forall", [("y", "Int")], "y == y")
    with patch.object(v, "_create_z3_variables", side_effect=mock_create):
        result = v.verify_with_quantifiers({"x": "Int"}, [qf])
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "logic_verifier.explicit_declarations_required"


def test_quantifiers_all_vars_z3_error():
    """Cover z3_vars error for constraints with quantifiers."""
    v = LogicVerifier()
    from z3 import Int
    blocked = DiagnosticResult.blocked("mock", {"constraint_id": "logic_verifier.explicit_declarations_required"})
    call_n = [0]
    def mock_create(vars_dict):
        call_n[0] += 1
        if call_n[0] == 2:
            return blocked
        return {name: Int(name) for name in vars_dict}
    qf = QuantifiedFormula("forall", [("y", "Int")], "y == y")
    with patch.object(v, "_create_z3_variables", side_effect=mock_create):
        result = v.verify_with_quantifiers({"x": "Int"}, [qf], constraints=["x > 0"])
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "logic_verifier.explicit_declarations_required"


def test_create_z3_variables_bitvec_malformed():
    """Cover line 567: malformed BitVec width."""
    v = LogicVerifier()
    result = v._create_z3_variables({"x": "BitVec[0]"})
    assert isinstance(result, DiagnosticResult)
    assert result.status == DiagnosticStatus.BLOCKED


# =========================================================================
# Sanitizer / SafeEvaluator ImportError handlers
# =========================================================================

def test_sanitizer_import_error():
    """Cover ImportError → sanitizer = None."""
    v = LogicVerifier()
    with patch("qwed_new.core.sanitizer.ConstraintSanitizer", side_effect=ImportError("no sanitizer")):
        result = v._ensure_sanitizer()
        assert result is not None
        assert result.status == DiagnosticStatus.BLOCKED
        assert result.constraint_id == "logic_verifier.sanitizer_unavailable"


def test_safe_evaluator_import_error():
    """Cover SafeEvaluator ImportError path."""
    v = LogicVerifier()
    with patch("qwed_new.core.safe_evaluator.SafeEvaluator", side_effect=ImportError("no safe eval")):
        assert v.safe_evaluator is None
