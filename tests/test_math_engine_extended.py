"""
Extended tests for Math Verification Engine.

Tests complex scenarios for JOSS reviewer validation.
"""

import pytest
from qwed_new.core.verifier import VerificationEngine


class TestMathEngineEdgeCases:
    """Edge case tests for math verification."""
    
    @pytest.fixture
    def engine(self):
        return VerificationEngine()
    
    # =========================================================================
    # Basic Arithmetic
    # =========================================================================
    
    def test_simple_addition(self, engine):
        """Basic addition verification."""
        result = engine.verify_math("2 + 2", expected_value=4)
        assert result["is_correct"] is True
    
    def test_incorrect_addition(self, engine):
        """Catch incorrect addition."""
        result = engine.verify_math("2 + 2", expected_value=5)
        assert result["is_correct"] is False
    
    def test_floating_point_precision(self, engine):
        """Handle floating point precision."""
        result = engine.verify_math("0.1 + 0.2", expected_value=0.3, tolerance=0.001)
        assert result["is_correct"] is True
    
    # =========================================================================
    # Financial Calculations
    # =========================================================================
    
    def test_compound_interest_correct(self, engine):
        """Verify correct compound interest."""
        result = engine.verify_compound_interest(
            principal=10000,
            rate=0.05,
            time=5,
            n=1,
            expected=12762.82,
            tolerance=0.01
        )
        assert result["is_correct"] is True
    
    def test_compound_interest_wrong(self, engine):
        """Catch wrong compound interest calculation."""
        result = engine.verify_compound_interest(
            principal=100000,
            rate=0.05,
            time=10,
            n=1,
            expected=150000,  # Wrong! Should be ~162889
            tolerance=0.01
        )
        assert result["is_correct"] is False
        assert result["calculated_amount"] > 150000
    
    def test_npv_calculation(self, engine):
        """Verify NPV calculation."""
        result = engine.verify_npv(
            rate=0.10,
            cash_flows=[-1000, 300, 300, 300, 300, 300],
            expected=136.78,
            tolerance=1.0
        )
        assert result["is_correct"] is True
    
    # =========================================================================
    # Calculus
    # =========================================================================
    
    def test_derivative_polynomial(self, engine):
        """Verify polynomial derivative."""
        result = engine.verify_derivative("x**3", "x", "3*x**2")
        assert result["is_correct"] is True
    
    def test_derivative_wrong(self, engine):
        """Catch incorrect derivative."""
        result = engine.verify_derivative("x**2", "x", "3*x")
        assert result["is_correct"] is False
        assert result["calculated_derivative"] == "2*x"
    
    def test_integral_polynomial(self, engine):
        """Verify polynomial integral."""
        result = engine.verify_integral("2*x", "x", "x**2")
        assert result["is_correct"] is True
    
    def test_definite_integral(self, engine):
        """Verify definite integral."""
        result = engine.verify_integral(
            "x**2", "x", "8/3",
            lower_bound="0", upper_bound="2"
        )
        assert result["is_correct"] is True
    
    # =========================================================================
    # Matrix Operations
    # =========================================================================
    
    def test_matrix_determinant(self, engine):
        """Verify matrix determinant."""
        result = engine.verify_matrix_operation(
            operation="determinant",
            matrices={"A": [[1, 2], [3, 4]]},
            expected=-2
        )
        assert result["is_correct"] is True
    
    def test_matrix_multiplication(self, engine):
        """Verify matrix multiplication."""
        result = engine.verify_matrix_operation(
            operation="multiply",
            matrices={
                "A": [[1, 2], [3, 4]],
                "B": [[5, 6], [7, 8]]
            },
            expected=[[19, 22], [43, 50]]
        )
        assert result["is_correct"] is True
    
    # =========================================================================
    # Statistics
    # =========================================================================
    
    def test_mean_calculation(self, engine):
        """Verify mean calculation."""
        result = engine.verify_statistics(
            data=[10, 20, 30, 40, 50],
            statistic="mean",
            expected=30
        )
        assert result["is_correct"] is True
    
    def test_std_calculation(self, engine):
        """Verify standard deviation."""
        result = engine.verify_statistics(
            data=[2, 4, 4, 4, 5, 5, 7, 9],
            statistic="std",
            expected=2.0,
            tolerance=0.1
        )
        assert result["is_correct"] is True
    
    def test_median_calculation(self, engine):
        """Verify median calculation."""
        result = engine.verify_statistics(
            data=[1, 3, 5, 7, 9],
            statistic="median",
            expected=5
        )
        assert result["is_correct"] is True
    
    # =========================================================================
    # Error Handling
    # =========================================================================
    
    def test_invalid_expression(self, engine):
        """Handle invalid math expressions."""
        result = engine.verify_math("2 *** 2", expected_value=4)  # *** is invalid
        assert result["status"] == "SYNTAX_ERROR" or "error" in result
    
    def test_division_by_zero(self, engine):
        """Handle division by zero."""
        result = engine.verify_math("1/0", expected_value=0)
        # Should either error or return infinity
        assert "error" in result or result["status"] == "ERROR"
    
    def test_empty_data_statistics(self, engine):
        """Handle empty dataset."""
        result = engine.verify_statistics(
            data=[],
            statistic="mean",
            expected=0
        )
        assert result["status"] == "ERROR"

    # =========================================================================
    # Mode ambiguity fail-closed (Issue #129)
    # =========================================================================

    def test_mode_ambiguous_blocked(self, engine):
        """Multi-mode dataset must return BLOCKED, not VERIFIED (Issue #129)."""
        result = engine.verify_statistics(
            data=[1, 1, 2, 2],
            statistic="mode",
            expected=1
        )
        assert result["is_correct"] is False
        assert result["status"] == "BLOCKED"
        assert "Ambiguous mode" in result["error"]
        assert sorted(result["ambiguous_modes"]) == [1, 2]

    def test_mode_ambiguous_blocked_other_claim(self, engine):
        """Multi-mode dataset blocks regardless of which value is claimed."""
        result = engine.verify_statistics(
            data=[1, 1, 2, 2],
            statistic="mode",
            expected=2
        )
        assert result["is_correct"] is False
        assert result["status"] == "BLOCKED"

    def test_mode_unique_verified(self, engine):
        """Unique mode matches claim -> VERIFIED."""
        result = engine.verify_statistics(
            data=[1, 1, 2],
            statistic="mode",
            expected=1
        )
        assert result["is_correct"] is True
        assert result["status"] == "VERIFIED"

    def test_mode_unique_correction_needed(self, engine):
        """Unique mode does NOT match claim -> CORRECTION_NEEDED."""
        result = engine.verify_statistics(
            data=[1, 1, 2],
            statistic="mode",
            expected=2
        )
        assert result["is_correct"] is False
        assert result["status"] == "CORRECTION_NEEDED"

    def test_mode_all_equal_verified(self, engine):
        """All-equal dataset has a unique deterministic mode."""
        result = engine.verify_statistics(
            data=[3, 3, 3],
            statistic="mode",
            expected=3
        )
        assert result["is_correct"] is True
        assert result["status"] == "VERIFIED"

    def test_mode_three_way_tie_blocked(self, engine):
        """Three-way tie must also be BLOCKED."""
        result = engine.verify_statistics(
            data=[1, 2, 3, 1, 2, 3],
            statistic="mode",
            expected=1
        )
        assert result["is_correct"] is False
        assert result["status"] == "BLOCKED"
        assert sorted(result["ambiguous_modes"]) == [1, 2, 3]


class TestPercentageCalculations:
    """Test percentage verification."""
    
    @pytest.fixture
    def engine(self):
        return VerificationEngine()
    
    def test_percentage_of(self, engine):
        """15% of 200 = 30"""
        result = engine.verify_percentage(
            value=200,
            percentage=15,
            expected=30,
            operation="of"
        )
        assert result["is_correct"] is True
    
    def test_percentage_increase(self, engine):
        """100 increased by 25% = 125"""
        result = engine.verify_percentage(
            value=100,
            percentage=25,
            expected=125,
            operation="increase"
        )
        assert result["is_correct"] is True
    
    def test_percentage_decrease(self, engine):
        """100 decreased by 20% = 80"""
        result = engine.verify_percentage(
            value=100,
            percentage=20,
            expected=80,
            operation="decrease"
        )
        assert result["is_correct"] is True


class TestEigenvalueCompleteness:
    """Eigenvalue verification must require complete claims (Issue #130)."""

    @pytest.fixture
    def engine(self):
        return VerificationEngine()

    def test_incomplete_eigenvalue_claim_rejected(self, engine):
        """Claiming [2] for a matrix with eigenvalues [2, 3] must NOT verify."""
        result = engine.verify_matrix_operation(
            operation="eigenvalues",
            matrices={"A": [[2, 0], [0, 3]]},
            expected=[2],
        )
        assert result["is_correct"] is False
        assert result["status"] == "CORRECTION_NEEDED"
        assert "cardinality mismatch" in result["error"]
        assert result["calculated_count"] == 2
        assert result["claimed_count"] == 1

    def test_complete_eigenvalue_claim_verified(self, engine):
        """Claiming [2, 3] for a matrix with eigenvalues [2, 3] must verify."""
        result = engine.verify_matrix_operation(
            operation="eigenvalues",
            matrices={"A": [[2, 0], [0, 3]]},
            expected=[2, 3],
        )
        assert result["is_correct"] is True
        assert result["status"] == "VERIFIED"

    def test_complete_eigenvalue_wrong_values(self, engine):
        """Claiming [2, 4] for eigenvalues [2, 3] -> CORRECTION_NEEDED."""
        result = engine.verify_matrix_operation(
            operation="eigenvalues",
            matrices={"A": [[2, 0], [0, 3]]},
            expected=[2, 4],
        )
        assert result["is_correct"] is False
        assert result["status"] == "CORRECTION_NEEDED"

    def test_overcomplete_eigenvalue_claim_rejected(self, engine):
        """Claiming MORE eigenvalues than exist must also fail."""
        result = engine.verify_matrix_operation(
            operation="eigenvalues",
            matrices={"A": [[2, 0], [0, 3]]},
            expected=[2, 3, 5],
        )
        assert result["is_correct"] is False
        assert result["status"] == "CORRECTION_NEEDED"
        assert result["calculated_count"] == 2
        assert result["claimed_count"] == 3

    def test_single_eigenvalue_verified(self, engine):
        """1x1 matrix with single eigenvalue — complete claim verifies."""
        result = engine.verify_matrix_operation(
            operation="eigenvalues",
            matrices={"A": [[5]]},
            expected=[5],
        )
        assert result["is_correct"] is True
        assert result["status"] == "VERIFIED"

    def test_repeated_eigenvalue_incomplete_rejected(self, engine):
        """diag(2,2) has eigenvalue 2 with multiplicity 2 — claim [2] is incomplete."""
        result = engine.verify_matrix_operation(
            operation="eigenvalues",
            matrices={"A": [[2, 0], [0, 2]]},
            expected=[2],
        )
        assert result["is_correct"] is False
        assert result["status"] == "CORRECTION_NEEDED"
        assert result["calculated_count"] == 2
        assert result["claimed_count"] == 1

    def test_repeated_eigenvalue_complete_verified(self, engine):
        """diag(2,2) with claim [2, 2] accounts for multiplicity — VERIFIED."""
        result = engine.verify_matrix_operation(
            operation="eigenvalues",
            matrices={"A": [[2, 0], [0, 2]]},
            expected=[2, 2],
        )
        assert result["is_correct"] is True
        assert result["status"] == "VERIFIED"
