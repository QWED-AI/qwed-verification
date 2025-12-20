"""
Tests for Enterprise Math Verification Engine.

Tests calculus, matrix, financial, and statistics verification.
"""

import pytest
from qwed_new.core.verifier import VerificationEngine


class TestMathEngineBasics:
    """Test basic math verification."""
    
    @pytest.fixture
    def engine(self):
        return VerificationEngine()
    
    def test_simple_addition(self, engine):
        """Test simple addition."""
        result = engine.verify_math("2 + 2", 4)
        assert result["is_correct"] is True
        assert result["status"] == "VERIFIED"
    
    def test_simple_multiplication(self, engine):
        """Test simple multiplication."""
        result = engine.verify_math("5 * 6", 30)
        assert result["is_correct"] is True
    
    def test_complex_expression(self, engine):
        """Test complex expression."""
        result = engine.verify_math("(10 + 5) * 2 - 5", 25)
        assert result["is_correct"] is True
    
    def test_incorrect_value(self, engine):
        """Test detection of incorrect value."""
        result = engine.verify_math("2 + 2", 5)
        assert result["is_correct"] is False
        assert result["status"] == "CORRECTION_NEEDED"
    
    def test_percentage(self, engine):
        """Test percentage calculation."""
        result = engine.verify_percentage(200, 15, 30, operation="of")
        assert result["is_correct"] is True
    
    def test_percentage_increase(self, engine):
        """Test percentage increase."""
        result = engine.verify_percentage(100, 20, 120, operation="increase")
        assert result["is_correct"] is True


class TestIdentityVerification:
    """Test algebraic identity verification."""
    
    @pytest.fixture
    def engine(self):
        return VerificationEngine()
    
    def test_quadratic_identity(self, engine):
        """Test (x+1)^2 = x^2 + 2x + 1."""
        result = engine.verify_identity("(x+1)**2", "x**2 + 2*x + 1")
        assert result["is_equivalent"] is True
    
    def test_difference_of_squares(self, engine):
        """Test x^2 - 1 = (x-1)(x+1)."""
        result = engine.verify_identity("x**2 - 1", "(x-1)*(x+1)")
        assert result["is_equivalent"] is True
    
    def test_non_equivalent(self, engine):
        """Test non-equivalent expressions."""
        result = engine.verify_identity("x**2", "x**3")
        assert result["is_equivalent"] is False


class TestCalculus:
    """Test calculus operations."""
    
    @pytest.fixture
    def engine(self):
        return VerificationEngine()
    
    # Derivatives
    def test_derivative_power_rule(self, engine):
        """Test d/dx(x^3) = 3x^2."""
        result = engine.verify_derivative("x**3", "x", "3*x**2")
        assert result["is_correct"] is True
    
    def test_derivative_sum(self, engine):
        """Test d/dx(x^2 + 2x + 1) = 2x + 2."""
        result = engine.verify_derivative("x**2 + 2*x + 1", "x", "2*x + 2")
        assert result["is_correct"] is True
    
    def test_derivative_trig(self, engine):
        """Test d/dx(sin(x)) = cos(x)."""
        result = engine.verify_derivative("sin(x)", "x", "cos(x)")
        assert result["is_correct"] is True
    
    def test_second_derivative(self, engine):
        """Test second derivative."""
        result = engine.verify_derivative("x**4", "x", "12*x**2", order=2)
        assert result["is_correct"] is True
    
    # Integrals
    def test_indefinite_integral(self, engine):
        """Test ∫x^2 dx = x^3/3."""
        result = engine.verify_integral("x**2", "x", "x**3/3")
        assert result["is_correct"] is True
    
    def test_definite_integral(self, engine):
        """Test ∫[0,1] x dx = 1/2."""
        result = engine.verify_integral("x", "x", "0.5", lower_bound="0", upper_bound="1")
        assert result["is_correct"] is True
    
    # Limits
    def test_limit_finite(self, engine):
        """Test lim(x→2) x^2 = 4."""
        result = engine.verify_limit("x**2", "x", "2", "4")
        assert result["is_correct"] is True
    
    def test_limit_infinity(self, engine):
        """Test lim(x→∞) 1/x = 0."""
        result = engine.verify_limit("1/x", "x", "oo", "0")
        assert result["is_correct"] is True


class TestMatrixOperations:
    """Test matrix operations."""
    
    @pytest.fixture
    def engine(self):
        return VerificationEngine()
    
    def test_matrix_addition(self, engine):
        """Test matrix addition."""
        result = engine.verify_matrix_operation(
            "add",
            {"A": [[1, 2], [3, 4]], "B": [[5, 6], [7, 8]]},
            [[6, 8], [10, 12]]
        )
        assert result["is_correct"] is True
    
    def test_matrix_multiplication(self, engine):
        """Test matrix multiplication."""
        result = engine.verify_matrix_operation(
            "multiply",
            {"A": [[1, 2], [3, 4]], "B": [[5, 6], [7, 8]]},
            [[19, 22], [43, 50]]
        )
        assert result["is_correct"] is True
    
    def test_matrix_determinant(self, engine):
        """Test matrix determinant."""
        result = engine.verify_matrix_operation(
            "determinant",
            {"A": [[1, 2], [3, 4]]},
            -2
        )
        assert result["is_correct"] is True
    
    def test_matrix_transpose(self, engine):
        """Test matrix transpose."""
        result = engine.verify_matrix_operation(
            "transpose",
            {"A": [[1, 2, 3], [4, 5, 6]]},
            [[1, 4], [2, 5], [3, 6]]
        )
        assert result["is_correct"] is True


class TestFinancialFormulas:
    """Test financial calculations."""
    
    @pytest.fixture
    def engine(self):
        return VerificationEngine()
    
    def test_compound_interest_annual(self, engine):
        """Test compound interest with annual compounding."""
        # $1000 at 5% for 10 years, annual compounding
        # A = 1000 * (1 + 0.05/1)^(1*10) = 1628.89
        result = engine.verify_compound_interest(
            principal=1000,
            rate=0.05,
            time=10,
            n=1,
            expected=1628.89
        )
        assert result["is_correct"] is True
    
    def test_compound_interest_monthly(self, engine):
        """Test compound interest with monthly compounding."""
        # $1000 at 5% for 10 years, monthly compounding
        # A = 1000 * (1 + 0.05/12)^(12*10) = 1647.01
        result = engine.verify_compound_interest(
            principal=1000,
            rate=0.05,
            time=10,
            n=12,
            expected=1647.01,
            tolerance=1
        )
        assert result["is_correct"] is True
    
    def test_npv_calculation(self, engine):
        """Test NPV calculation."""
        # Initial investment -1000, then 300, 400, 500 at 10% rate
        # NPV = -1000 + 300/1.1 + 400/1.21 + 500/1.331 = -21.04
        result = engine.verify_npv(
            rate=0.10,
            cash_flows=[-1000, 300, 400, 500],
            expected=-21.04,
            tolerance=1
        )
        assert result["is_correct"] is True
    
    def test_irr_calculation(self, engine):
        """Test IRR calculation."""
        # -1000, then 500, 400, 300 should have IRR around 10.65%
        result = engine.verify_irr(
            cash_flows=[-1000, 500, 400, 300],
            expected=0.1065,
            tolerance=0.01
        )
        assert result["is_correct"] is True


class TestStatistics:
    """Test statistical calculations."""
    
    @pytest.fixture
    def engine(self):
        return VerificationEngine()
    
    def test_mean(self, engine):
        """Test mean calculation."""
        data = [1, 2, 3, 4, 5]
        result = engine.verify_statistics(data, "mean", 3)
        assert result["is_correct"] is True
    
    def test_median_odd(self, engine):
        """Test median with odd number of elements."""
        data = [1, 2, 3, 4, 5]
        result = engine.verify_statistics(data, "median", 3)
        assert result["is_correct"] is True
    
    def test_median_even(self, engine):
        """Test median with even number of elements."""
        data = [1, 2, 3, 4]
        result = engine.verify_statistics(data, "median", 2.5)
        assert result["is_correct"] is True
    
    def test_variance(self, engine):
        """Test variance calculation."""
        data = [2, 4, 4, 4, 5, 5, 7, 9]
        result = engine.verify_statistics(data, "variance", 4)
        assert result["is_correct"] is True
    
    def test_std(self, engine):
        """Test standard deviation."""
        data = [2, 4, 4, 4, 5, 5, 7, 9]
        result = engine.verify_statistics(data, "std", 2)
        assert result["is_correct"] is True
    
    def test_correlation(self, engine):
        """Test correlation coefficient."""
        x = [1, 2, 3, 4, 5]
        y = [2, 4, 6, 8, 10]  # Perfect positive correlation
        result = engine.verify_correlation(x, y, 1.0)
        assert result["is_correct"] is True


class TestUnitConversion:
    """Test unit conversions."""
    
    @pytest.fixture
    def engine(self):
        return VerificationEngine()
    
    def test_km_to_miles(self, engine):
        """Test kilometers to miles."""
        # 1 km = 0.621371 miles
        result = engine.verify_unit_conversion(1, "km", "mi", 0.621, tolerance=0.01)
        assert result["is_correct"] is True
    
    def test_feet_to_meters(self, engine):
        """Test feet to meters."""
        # 10 feet = 3.048 meters
        result = engine.verify_unit_conversion(10, "ft", "m", 3.048)
        assert result["is_correct"] is True
    
    def test_celsius_to_fahrenheit(self, engine):
        """Test Celsius to Fahrenheit."""
        # 0°C = 32°F
        result = engine.verify_unit_conversion(0, "c", "f", 32)
        assert result["is_correct"] is True
        
        # 100°C = 212°F
        result = engine.verify_unit_conversion(100, "c", "f", 212)
        assert result["is_correct"] is True
    
    def test_pounds_to_kg(self, engine):
        """Test pounds to kilograms."""
        # 1 lb = 0.453592 kg
        result = engine.verify_unit_conversion(1, "lb", "kg", 0.4536, tolerance=0.001)
        assert result["is_correct"] is True
    
    def test_liters_to_gallons(self, engine):
        """Test liters to gallons."""
        # 1 gallon = 3.78541 liters, so 3.78541 L = 1 gal
        result = engine.verify_unit_conversion(3.78541, "l", "gal", 1, tolerance=0.01)
        assert result["is_correct"] is True
