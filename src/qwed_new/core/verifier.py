"""
Enterprise Math Verification Engine.

The deterministic core. It does not guess. It calculates.
Uses Symbolic Math (SymPy) to verify mathematical assertions.

Enterprise Features:
- Calculus (derivatives, integrals, limits)
- Matrix/Linear Algebra
- Financial Formulas (NPV, IRR, compound interest)
- Statistics (mean, stddev, variance, correlation)
- Unit Conversion
- Decimal precision for financial calculations
"""

import sympy
from sympy import (
    Symbol, symbols, Matrix, sqrt, sin, cos, tan, log, exp, pi, E,
    diff, integrate, limit, oo, factorial, binomial, gcd, lcm,
    simplify, expand, factor, solve, Eq, summation, product,
    Rational, Float, N
)
from sympy.parsing.sympy_parser import parse_expr, standard_transformations, implicit_multiplication_application
from sympy.stats import Normal, Exponential, Poisson, Binomial, density, E as ExpectedValue, variance, std
from typing import Any, Dict, List, Optional, Union, Tuple
from decimal import Decimal, ROUND_HALF_UP
from dataclasses import dataclass
import re
import math


@dataclass
class VerificationResult:
    """Result of a verification operation."""
    is_correct: bool
    status: str
    calculated_value: Any = None
    claimed_value: Any = None
    error: Optional[str] = None
    details: Optional[Dict] = None


class VerificationEngine:
    """
    Enterprise-Grade Mathematical Verification Engine.
    
    Uses SymPy for deterministic symbolic computation.
    Supports: Arithmetic, Algebra, Calculus, Matrix, Financial, Statistics.
    """
    
    # Parsing transformations for more natural input
    TRANSFORMATIONS = standard_transformations + (implicit_multiplication_application,)
    
    def __init__(self):
        """Initialize the verification engine."""
        # Pre-define common symbols for faster parsing
        self.common_symbols = {
            'x': Symbol('x'),
            'y': Symbol('y'),
            'z': Symbol('z'),
            'n': Symbol('n', integer=True, positive=True),
            't': Symbol('t'),
            'r': Symbol('r'),
        }
    
    # =========================================================================
    # Core Math Verification
    # =========================================================================
    
    def verify_math(
        self, 
        expression: str, 
        expected_value: float, 
        tolerance: float = 1e-6,
        use_decimal: bool = True
    ) -> Dict[str, Any]:
        """
        Verifies if a mathematical expression evaluates to the expected value.
        
        Args:
            expression: The math string (e.g., "2 * (5 + 10)")
            expected_value: The value the LLM claims it is (e.g., 30)
            tolerance: Floating point tolerance
            use_decimal: If True, use Decimal for exact arithmetic (financial)
            
        Returns:
            Dict containing is_correct, calculated_value, and status.
        """
        try:
            # 1. Parse the expression safely
            expr = parse_expr(expression, transformations=self.TRANSFORMATIONS)
            
            # 2. Evaluate deterministically
            if use_decimal:
                raw_value = expr.evalf()
                calculated_value = Decimal(str(raw_value)).quantize(
                    Decimal("0.000001"),
                    rounding=ROUND_HALF_UP
                )
                expected_decimal = Decimal(str(expected_value))
                
                diff = abs(calculated_value - expected_decimal)
                is_correct = diff <= Decimal(str(tolerance))
                
                return {
                    "is_correct": is_correct,
                    "calculated_value": float(calculated_value),
                    "calculated_precise": str(calculated_value),
                    "claimed_value": expected_value,
                    "diff": float(diff),
                    "precision_mode": "decimal",
                    "status": "VERIFIED" if is_correct else "CORRECTION_NEEDED"
                }
            else:
                calculated_value = float(expr.evalf())
                diff = abs(calculated_value - expected_value)
                is_correct = diff <= tolerance
                
                return {
                    "is_correct": is_correct,
                    "calculated_value": calculated_value,
                    "claimed_value": expected_value,
                    "diff": diff,
                    "precision_mode": "float",
                    "status": "VERIFIED" if is_correct else "CORRECTION_NEEDED"
                }
            
        except Exception as e:
            return {
                "is_correct": False,
                "error": str(e),
                "status": "SYNTAX_ERROR"
            }
    
    def verify_identity(self, lhs: str, rhs: str) -> Dict[str, Any]:
        """
        Verify if two expressions are mathematically equivalent.
        
        Examples:
            verify_identity("(x+1)**2", "x**2 + 2*x + 1")  # True
            verify_identity("sin(x)**2 + cos(x)**2", "1")  # True
        """
        try:
            left = parse_expr(lhs, transformations=self.TRANSFORMATIONS)
            right = parse_expr(rhs, transformations=self.TRANSFORMATIONS)
            
            # Method 1: Simplify difference
            diff = simplify(left - right)
            
            if diff == 0:
                return {
                    "is_equivalent": True,
                    "status": "VERIFIED",
                    "method": "algebraic_simplification"
                }
            
            # Method 2: Try expanding both sides
            if simplify(expand(left) - expand(right)) == 0:
                return {
                    "is_equivalent": True,
                    "status": "VERIFIED",
                    "method": "expansion"
                }
            
            # Method 3: Numerical evaluation at random points
            x = Symbol('x')
            test_values = [0.5, 1, 2, -1, 0.1]
            matches = 0
            for val in test_values:
                try:
                    left_val = float(left.subs(x, val).evalf())
                    right_val = float(right.subs(x, val).evalf())
                    if abs(left_val - right_val) < 1e-10:
                        matches += 1
                except:
                    pass
            
            if matches == len(test_values):
                return {
                    "is_equivalent": True,
                    "status": "LIKELY_EQUIVALENT",
                    "method": "numerical_sampling",
                    "confidence": 0.99
                }
            
            return {
                "is_equivalent": False,
                "status": "NOT_EQUIVALENT",
                "simplified_lhs": str(simplify(left)),
                "simplified_rhs": str(simplify(right))
            }
            
        except Exception as e:
            return {
                "is_equivalent": False,
                "status": "ERROR",
                "error": str(e)
            }
    
    # =========================================================================
    # Calculus Operations
    # =========================================================================
    
    def verify_derivative(
        self, 
        expression: str, 
        variable: str, 
        expected: str,
        order: int = 1
    ) -> Dict[str, Any]:
        """
        Verify a derivative calculation.
        
        Args:
            expression: The function to differentiate (e.g., "x**3 + 2*x")
            variable: The variable to differentiate with respect to
            expected: The claimed derivative
            order: Order of derivative (1 for first, 2 for second, etc.)
        """
        try:
            expr = parse_expr(expression, transformations=self.TRANSFORMATIONS)
            var = Symbol(variable)
            expected_expr = parse_expr(expected, transformations=self.TRANSFORMATIONS)
            
            # Calculate derivative
            actual_derivative = diff(expr, var, order)
            
            # Compare
            difference = simplify(actual_derivative - expected_expr)
            is_correct = difference == 0
            
            return {
                "is_correct": is_correct,
                "status": "VERIFIED" if is_correct else "CORRECTION_NEEDED",
                "calculated_derivative": str(actual_derivative),
                "claimed_derivative": expected,
                "expression": expression,
                "variable": variable,
                "order": order
            }
            
        except Exception as e:
            return {
                "is_correct": False,
                "status": "ERROR",
                "error": str(e)
            }
    
    def verify_integral(
        self, 
        expression: str, 
        variable: str, 
        expected: str,
        lower_bound: Optional[str] = None,
        upper_bound: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verify an integral calculation (definite or indefinite).
        
        Args:
            expression: The integrand
            variable: The variable of integration
            expected: The claimed integral
            lower_bound: Lower bound for definite integral
            upper_bound: Upper bound for definite integral
        """
        try:
            expr = parse_expr(expression, transformations=self.TRANSFORMATIONS)
            var = Symbol(variable)
            expected_expr = parse_expr(expected, transformations=self.TRANSFORMATIONS)
            
            if lower_bound is not None and upper_bound is not None:
                # Definite integral
                lower = parse_expr(lower_bound, transformations=self.TRANSFORMATIONS)
                upper = parse_expr(upper_bound, transformations=self.TRANSFORMATIONS)
                actual_integral = integrate(expr, (var, lower, upper))
                
                # For definite integrals, compare values
                actual_val = float(actual_integral.evalf())
                expected_val = float(expected_expr.evalf())
                is_correct = abs(actual_val - expected_val) < 1e-6
            else:
                # Indefinite integral
                actual_integral = integrate(expr, var)
                
                # For indefinite, derivatives should match (accounts for +C)
                deriv_actual = diff(actual_integral, var)
                deriv_expected = diff(expected_expr, var)
                is_correct = simplify(deriv_actual - deriv_expected) == 0
            
            return {
                "is_correct": is_correct,
                "status": "VERIFIED" if is_correct else "CORRECTION_NEEDED",
                "calculated_integral": str(actual_integral),
                "claimed_integral": expected,
                "integral_type": "definite" if lower_bound else "indefinite"
            }
            
        except Exception as e:
            return {
                "is_correct": False,
                "status": "ERROR",
                "error": str(e)
            }
    
    def verify_limit(
        self, 
        expression: str, 
        variable: str, 
        point: str, 
        expected: str,
        direction: str = "+-"
    ) -> Dict[str, Any]:
        """
        Verify a limit calculation.
        
        Args:
            expression: The expression
            variable: The variable approaching the point
            point: The point being approached (can be "oo" for infinity)
            expected: The claimed limit
            direction: "+" for right, "-" for left, "+-" for both
        """
        try:
            expr = parse_expr(expression, transformations=self.TRANSFORMATIONS)
            var = Symbol(variable)
            expected_expr = parse_expr(expected, transformations=self.TRANSFORMATIONS)
            
            # Parse the point (handle infinity)
            if point.lower() in ['oo', 'inf', 'infinity']:
                pt = oo
            elif point.lower() in ['-oo', '-inf', '-infinity']:
                pt = -oo
            else:
                pt = parse_expr(point, transformations=self.TRANSFORMATIONS)
            
            # Calculate limit
            actual_limit = limit(expr, var, pt, dir=direction)
            
            # Compare
            is_correct = simplify(actual_limit - expected_expr) == 0
            
            return {
                "is_correct": is_correct,
                "status": "VERIFIED" if is_correct else "CORRECTION_NEEDED",
                "calculated_limit": str(actual_limit),
                "claimed_limit": expected,
                "expression": expression,
                "point": point
            }
            
        except Exception as e:
            return {
                "is_correct": False,
                "status": "ERROR",
                "error": str(e)
            }
    
    # =========================================================================
    # Matrix/Linear Algebra
    # =========================================================================
    
    def verify_matrix_operation(
        self, 
        operation: str,
        matrices: Dict[str, List[List[float]]],
        expected: Union[List[List[float]], float, List[float]]
    ) -> Dict[str, Any]:
        """
        Verify matrix operations.
        
        Args:
            operation: One of "add", "multiply", "determinant", "inverse", "transpose", "eigenvalues"
            matrices: Dict of matrix names to their values, e.g., {"A": [[1,2],[3,4]], "B": [[5,6],[7,8]]}
            expected: The expected result
        """
        try:
            # Convert to SymPy matrices
            sympy_matrices = {name: Matrix(mat) for name, mat in matrices.items()}
            
            if operation == "add":
                if len(sympy_matrices) != 2:
                    return {"is_correct": False, "status": "ERROR", "error": "Addition requires exactly 2 matrices"}
                mats = list(sympy_matrices.values())
                result = mats[0] + mats[1]
                expected_mat = Matrix(expected)
                
            elif operation == "multiply":
                if len(sympy_matrices) != 2:
                    return {"is_correct": False, "status": "ERROR", "error": "Multiplication requires exactly 2 matrices"}
                mats = list(sympy_matrices.values())
                result = mats[0] * mats[1]
                expected_mat = Matrix(expected)
                
            elif operation == "determinant":
                mat = list(sympy_matrices.values())[0]
                result = mat.det()
                is_correct = abs(float(result) - float(expected)) < 1e-6
                return {
                    "is_correct": is_correct,
                    "status": "VERIFIED" if is_correct else "CORRECTION_NEEDED",
                    "calculated_determinant": float(result),
                    "claimed_determinant": expected
                }
                
            elif operation == "inverse":
                mat = list(sympy_matrices.values())[0]
                result = mat.inv()
                expected_mat = Matrix(expected)
                
            elif operation == "transpose":
                mat = list(sympy_matrices.values())[0]
                result = mat.T
                expected_mat = Matrix(expected)
                
            elif operation == "eigenvalues":
                mat = list(sympy_matrices.values())[0]
                eigenvals = list(mat.eigenvals().keys())
                eigenvals_float = sorted([complex(v.evalf()).real for v in eigenvals])
                expected_sorted = sorted(expected)
                is_correct = all(
                    abs(a - b) < 1e-6 
                    for a, b in zip(eigenvals_float, expected_sorted)
                )
                return {
                    "is_correct": is_correct,
                    "status": "VERIFIED" if is_correct else "CORRECTION_NEEDED",
                    "calculated_eigenvalues": eigenvals_float,
                    "claimed_eigenvalues": expected
                }
            else:
                return {"is_correct": False, "status": "ERROR", "error": f"Unknown operation: {operation}"}
            
            # Compare matrices
            is_correct = result.equals(expected_mat)
            
            return {
                "is_correct": is_correct,
                "status": "VERIFIED" if is_correct else "CORRECTION_NEEDED",
                "calculated_result": result.tolist(),
                "claimed_result": expected,
                "operation": operation
            }
            
        except Exception as e:
            return {
                "is_correct": False,
                "status": "ERROR",
                "error": str(e)
            }
    
    # =========================================================================
    # Financial Formulas
    # =========================================================================
    
    def verify_compound_interest(
        self,
        principal: float,
        rate: float,
        time: float,
        n: int,  # Compounding frequency per year
        expected: float,
        tolerance: float = 0.01
    ) -> Dict[str, Any]:
        """
        Verify compound interest calculation.
        
        Formula: A = P(1 + r/n)^(nt)
        """
        try:
            # Use Decimal for precision
            P = Decimal(str(principal))
            r = Decimal(str(rate))
            t = Decimal(str(time))
            n_dec = Decimal(str(n))
            
            # Calculate: A = P(1 + r/n)^(nt)
            A = P * (1 + r/n_dec) ** (n_dec * t)
            A = float(A.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
            
            is_correct = abs(A - expected) <= tolerance
            
            return {
                "is_correct": is_correct,
                "status": "VERIFIED" if is_correct else "CORRECTION_NEEDED",
                "calculated_amount": A,
                "claimed_amount": expected,
                "principal": principal,
                "annual_rate": rate,
                "time_years": time,
                "compounding_frequency": n,
                "formula": "A = P(1 + r/n)^(nt)"
            }
            
        except Exception as e:
            return {"is_correct": False, "status": "ERROR", "error": str(e)}
    
    def verify_npv(
        self,
        rate: float,
        cash_flows: List[float],
        expected: float,
        tolerance: float = 0.01
    ) -> Dict[str, Any]:
        """
        Verify Net Present Value calculation.
        
        Formula: NPV = Σ(CF_t / (1+r)^t) for t = 0 to n
        """
        try:
            r = Decimal(str(rate))
            npv = Decimal("0")
            
            for t, cf in enumerate(cash_flows):
                cf_dec = Decimal(str(cf))
                npv += cf_dec / ((1 + r) ** t)
            
            npv = float(npv.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
            is_correct = abs(npv - expected) <= tolerance
            
            return {
                "is_correct": is_correct,
                "status": "VERIFIED" if is_correct else "CORRECTION_NEEDED",
                "calculated_npv": npv,
                "claimed_npv": expected,
                "discount_rate": rate,
                "cash_flows": cash_flows,
                "formula": "NPV = Σ(CF_t / (1+r)^t)"
            }
            
        except Exception as e:
            return {"is_correct": False, "status": "ERROR", "error": str(e)}
    
    def verify_irr(
        self,
        cash_flows: List[float],
        expected: float,
        tolerance: float = 0.001
    ) -> Dict[str, Any]:
        """
        Verify Internal Rate of Return calculation.
        
        IRR is the rate where NPV = 0
        """
        try:
            # Newton-Raphson method to find IRR
            r = Decimal("0.1")  # Initial guess
            
            for _ in range(100):  # Max iterations
                npv = Decimal("0")
                npv_derivative = Decimal("0")
                
                for t, cf in enumerate(cash_flows):
                    cf_dec = Decimal(str(cf))
                    npv += cf_dec / ((1 + r) ** t)
                    if t > 0:
                        npv_derivative -= t * cf_dec / ((1 + r) ** (t + 1))
                
                if abs(npv) < Decimal("0.0001"):
                    break
                    
                if npv_derivative != 0:
                    r = r - npv / npv_derivative
            
            irr = float(r)
            is_correct = abs(irr - expected) <= tolerance
            
            return {
                "is_correct": is_correct,
                "status": "VERIFIED" if is_correct else "CORRECTION_NEEDED",
                "calculated_irr": irr,
                "claimed_irr": expected,
                "cash_flows": cash_flows
            }
            
        except Exception as e:
            return {"is_correct": False, "status": "ERROR", "error": str(e)}
    
    def verify_percentage(
        self,
        value: float,
        percentage: float,
        expected: float,
        operation: str = "of",
        tolerance: float = 0.01
    ) -> Dict[str, Any]:
        """
        Verify percentage calculations.
        
        Operations:
        - "of": X% of Y (e.g., 15% of 200 = 30)
        - "increase": Y increased by X%
        - "decrease": Y decreased by X%
        - "change": Percentage change from value to expected
        """
        try:
            if operation == "of":
                # X% of Y
                calculated = value * (percentage / 100)
            elif operation == "increase":
                calculated = value * (1 + percentage / 100)
            elif operation == "decrease":
                calculated = value * (1 - percentage / 100)
            elif operation == "change":
                # Calculate what percentage change from value to expected
                if value == 0:
                    return {"is_correct": False, "status": "ERROR", "error": "Cannot calculate percentage change from 0"}
                calculated = ((expected - value) / value) * 100
                # In this case, we're checking if the claimed percentage is correct
                is_correct = abs(calculated - percentage) <= tolerance
                return {
                    "is_correct": is_correct,
                    "status": "VERIFIED" if is_correct else "CORRECTION_NEEDED",
                    "calculated_percentage_change": calculated,
                    "claimed_percentage_change": percentage,
                    "from_value": value,
                    "to_value": expected
                }
            else:
                return {"is_correct": False, "status": "ERROR", "error": f"Unknown operation: {operation}"}
            
            is_correct = abs(calculated - expected) <= tolerance
            
            return {
                "is_correct": is_correct,
                "status": "VERIFIED" if is_correct else "CORRECTION_NEEDED",
                "calculated_result": round(calculated, 2),
                "claimed_result": expected,
                "value": value,
                "percentage": percentage,
                "operation": operation
            }
            
        except Exception as e:
            return {"is_correct": False, "status": "ERROR", "error": str(e)}
    
    # =========================================================================
    # Statistics
    # =========================================================================
    
    def verify_statistics(
        self,
        data: List[float],
        statistic: str,
        expected: float,
        tolerance: float = 0.001
    ) -> Dict[str, Any]:
        """
        Verify statistical calculations.
        
        Statistics supported:
        - mean, median, mode
        - variance, std (standard deviation)
        - min, max, range
        - sum, count
        - percentile_25, percentile_50, percentile_75
        """
        try:
            n = len(data)
            if n == 0:
                return {"is_correct": False, "status": "ERROR", "error": "Empty dataset"}
            
            sorted_data = sorted(data)
            
            if statistic == "mean":
                calculated = sum(data) / n
            elif statistic == "median":
                if n % 2 == 0:
                    calculated = (sorted_data[n//2 - 1] + sorted_data[n//2]) / 2
                else:
                    calculated = sorted_data[n//2]
            elif statistic == "mode":
                from collections import Counter
                counter = Counter(data)
                calculated = counter.most_common(1)[0][0]
            elif statistic == "variance":
                mean = sum(data) / n
                calculated = sum((x - mean) ** 2 for x in data) / n
            elif statistic == "std":
                mean = sum(data) / n
                variance = sum((x - mean) ** 2 for x in data) / n
                calculated = math.sqrt(variance)
            elif statistic == "min":
                calculated = min(data)
            elif statistic == "max":
                calculated = max(data)
            elif statistic == "range":
                calculated = max(data) - min(data)
            elif statistic == "sum":
                calculated = sum(data)
            elif statistic == "count":
                calculated = n
            elif statistic.startswith("percentile_"):
                p = int(statistic.split("_")[1])
                k = (n - 1) * (p / 100)
                f = math.floor(k)
                c = math.ceil(k)
                if f == c:
                    calculated = sorted_data[int(k)]
                else:
                    calculated = sorted_data[f] * (c - k) + sorted_data[c] * (k - f)
            else:
                return {"is_correct": False, "status": "ERROR", "error": f"Unknown statistic: {statistic}"}
            
            is_correct = abs(calculated - expected) <= tolerance
            
            return {
                "is_correct": is_correct,
                "status": "VERIFIED" if is_correct else "CORRECTION_NEEDED",
                "calculated_value": round(calculated, 6),
                "claimed_value": expected,
                "statistic": statistic,
                "data_points": n
            }
            
        except Exception as e:
            return {"is_correct": False, "status": "ERROR", "error": str(e)}
    
    def verify_correlation(
        self,
        x_data: List[float],
        y_data: List[float],
        expected: float,
        tolerance: float = 0.001
    ) -> Dict[str, Any]:
        """
        Verify Pearson correlation coefficient.
        """
        try:
            n = len(x_data)
            if n != len(y_data):
                return {"is_correct": False, "status": "ERROR", "error": "Data arrays must have same length"}
            
            mean_x = sum(x_data) / n
            mean_y = sum(y_data) / n
            
            numerator = sum((x - mean_x) * (y - mean_y) for x, y in zip(x_data, y_data))
            
            sum_sq_x = sum((x - mean_x) ** 2 for x in x_data)
            sum_sq_y = sum((y - mean_y) ** 2 for y in y_data)
            
            denominator = math.sqrt(sum_sq_x * sum_sq_y)
            
            if denominator == 0:
                return {"is_correct": False, "status": "ERROR", "error": "Cannot calculate correlation (no variance)"}
            
            r = numerator / denominator
            is_correct = abs(r - expected) <= tolerance
            
            return {
                "is_correct": is_correct,
                "status": "VERIFIED" if is_correct else "CORRECTION_NEEDED",
                "calculated_correlation": round(r, 6),
                "claimed_correlation": expected,
                "data_points": n
            }
            
        except Exception as e:
            return {"is_correct": False, "status": "ERROR", "error": str(e)}
    
    # =========================================================================
    # Unit Conversion
    # =========================================================================
    
    # Conversion factors to base units
    UNIT_CONVERSIONS = {
        # Length (base: meters)
        "m": 1, "meter": 1, "meters": 1,
        "km": 1000, "kilometer": 1000, "kilometers": 1000,
        "cm": 0.01, "centimeter": 0.01, "centimeters": 0.01,
        "mm": 0.001, "millimeter": 0.001, "millimeters": 0.001,
        "mi": 1609.344, "mile": 1609.344, "miles": 1609.344,
        "ft": 0.3048, "foot": 0.3048, "feet": 0.3048,
        "in": 0.0254, "inch": 0.0254, "inches": 0.0254,
        "yd": 0.9144, "yard": 0.9144, "yards": 0.9144,
        
        # Weight (base: kilograms)
        "kg": 1, "kilogram": 1, "kilograms": 1,
        "g": 0.001, "gram": 0.001, "grams": 0.001,
        "mg": 0.000001, "milligram": 0.000001,
        "lb": 0.453592, "pound": 0.453592, "pounds": 0.453592,
        "oz": 0.0283495, "ounce": 0.0283495, "ounces": 0.0283495,
        
        # Temperature handled separately
        
        # Volume (base: liters)
        "l": 1, "liter": 1, "liters": 1, "L": 1,
        "ml": 0.001, "milliliter": 0.001, "milliliters": 0.001,
        "gal": 3.78541, "gallon": 3.78541, "gallons": 3.78541,
        "qt": 0.946353, "quart": 0.946353,
        "pt": 0.473176, "pint": 0.473176,
        "cup": 0.236588, "cups": 0.236588,
        
        # Time (base: seconds)
        "s": 1, "sec": 1, "second": 1, "seconds": 1,
        "min": 60, "minute": 60, "minutes": 60,
        "h": 3600, "hr": 3600, "hour": 3600, "hours": 3600,
        "d": 86400, "day": 86400, "days": 86400,
        "wk": 604800, "week": 604800, "weeks": 604800,
    }
    
    def verify_unit_conversion(
        self,
        value: float,
        from_unit: str,
        to_unit: str,
        expected: float,
        tolerance: float = 0.001
    ) -> Dict[str, Any]:
        """
        Verify unit conversion calculations.
        """
        try:
            from_unit = from_unit.lower()
            to_unit = to_unit.lower()
            
            # Handle temperature separately
            if from_unit in ['c', 'celsius'] or to_unit in ['c', 'celsius']:
                return self._verify_temperature_conversion(value, from_unit, to_unit, expected, tolerance)
            
            if from_unit not in self.UNIT_CONVERSIONS:
                return {"is_correct": False, "status": "ERROR", "error": f"Unknown unit: {from_unit}"}
            if to_unit not in self.UNIT_CONVERSIONS:
                return {"is_correct": False, "status": "ERROR", "error": f"Unknown unit: {to_unit}"}
            
            # Convert: value * (from_factor / to_factor)
            base_value = value * self.UNIT_CONVERSIONS[from_unit]
            calculated = base_value / self.UNIT_CONVERSIONS[to_unit]
            
            is_correct = abs(calculated - expected) <= tolerance * abs(expected) if expected != 0 else abs(calculated) <= tolerance
            
            return {
                "is_correct": is_correct,
                "status": "VERIFIED" if is_correct else "CORRECTION_NEEDED",
                "calculated_value": round(calculated, 6),
                "claimed_value": expected,
                "from_unit": from_unit,
                "to_unit": to_unit
            }
            
        except Exception as e:
            return {"is_correct": False, "status": "ERROR", "error": str(e)}
    
    def _verify_temperature_conversion(
        self, value: float, from_unit: str, to_unit: str, expected: float, tolerance: float
    ) -> Dict[str, Any]:
        """Handle temperature conversions."""
        from_unit = from_unit.lower()
        to_unit = to_unit.lower()
        
        # Normalize unit names
        unit_map = {
            'c': 'celsius', 'celsius': 'celsius',
            'f': 'fahrenheit', 'fahrenheit': 'fahrenheit',
            'k': 'kelvin', 'kelvin': 'kelvin'
        }
        
        from_u = unit_map.get(from_unit)
        to_u = unit_map.get(to_unit)
        
        if not from_u or not to_u:
            return {"is_correct": False, "status": "ERROR", "error": "Invalid temperature unit"}
        
        # Convert to Celsius first
        if from_u == 'celsius':
            celsius = value
        elif from_u == 'fahrenheit':
            celsius = (value - 32) * 5/9
        elif from_u == 'kelvin':
            celsius = value - 273.15
        
        # Convert from Celsius to target
        if to_u == 'celsius':
            calculated = celsius
        elif to_u == 'fahrenheit':
            calculated = celsius * 9/5 + 32
        elif to_u == 'kelvin':
            calculated = celsius + 273.15
        
        is_correct = abs(calculated - expected) <= tolerance
        
        return {
            "is_correct": is_correct,
            "status": "VERIFIED" if is_correct else "CORRECTION_NEEDED",
            "calculated_value": round(calculated, 2),
            "claimed_value": expected,
            "from_unit": from_unit,
            "to_unit": to_unit
        }
    
    # =========================================================================
    # Legacy method for compatibility
    # =========================================================================
    
    def verify_logic_rule(self, rule: str, context: Dict[str, Any]) -> bool:
        """
        Legacy placeholder. Use LogicVerifier instead.
        """
        pass
