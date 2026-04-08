"""
Tests for StatsVerifier - direct statistical operations.

These tests focus on deterministic edge cases for compute_statistics():
1. Empty data arrays
2. Single element arrays
3. Very large numbers
4. Negative numbers in variance/std calculations
5. Basic error handling for missing columns and unknown operations
"""

import requests
import pandas as pd
import sys
import os
import pytest
from decimal import Decimal
from fractions import Fraction

BASE_URL = "http://127.0.0.1:8002"

# Ensure src is in sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from qwed_new.core.stats_verifier import StatsVerifier

class TestStatsVerifierBasic:
    """Basic tests for StatsVerifier."""
    def test_verifier_initialization(self):
        """Test that verifier initializes with defaults."""
        verifier = StatsVerifier()
        assert verifier.preferred_sandbox == "auto"
        assert verifier.timeout_seconds == 30.0
        assert verifier.memory_limit_mb == 128

    def test_verifier_custom_config(self):
        """Test verifier custom config."""
        verifier = StatsVerifier(
            preferred_sandbox="docker",
            timeout_seconds=20.0,
            memory_limit_mb=256
        )
        assert verifier.preferred_sandbox == "docker"
        assert verifier.timeout_seconds == 20.0
        assert verifier.memory_limit_mb == 256

class TestComputeStatistics:
    """Tests for direct statistical operations."""
    def setup_method(self):
        self.verifier = StatsVerifier()

    # -------------------------------------------------------------------------
    # Empty data arrays
    # -------------------------------------------------------------------------

    def test_empty_series_sum(self):
        """Sum of an empty series should be handled consistently."""
        df = pd.DataFrame({"x": []})

        result = self.verifier.compute_statistics(df, "x", "sum")

        assert result["status"] == "SUCCESS"
        assert result["operation"] == "sum"
        assert result["column"] == "x"
        assert result["result"] == 0
    
    def test_empty_series_count(self):
        """Count of an empty series should be zero."""
        df = pd.DataFrame({"x": []})

        result = self.verifier.compute_statistics(df, "x", "count")

        assert result["status"] == "SUCCESS"
        assert result["result"] == 0
    
    def test_empty_series_mode_returns_none(self):
        """Mode of an empty series should return None."""
        df = pd.DataFrame({"x": []})

        result = self.verifier.compute_statistics(df, "x", "mode")

        assert result["status"] == "SUCCESS"
        assert result["result"] is None

    def test_empty_series_mean_is_nan(self):
        """Mean of an empty series should be NaN."""
        df = pd.DataFrame({"x": []})

        result = self.verifier.compute_statistics(df, "x", "mean")

        assert result["status"] == "SUCCESS"
        assert pd.isna(result["result"])

    def test_empty_series_variance_is_nan(self):
        """Variance of an empty series should be NaN."""
        df = pd.DataFrame({"x": []})

        result = self.verifier.compute_statistics(df, "x", "var")

        assert result["status"] == "SUCCESS"
        assert pd.isna(result["result"])


    def test_empty_series_std_is_nan(self):
        """Standard deviation of an empty series should be NaN."""
        df = pd.DataFrame({"x": []})

        result = self.verifier.compute_statistics(df, "x", "std")

        assert result["status"] == "SUCCESS"
        assert pd.isna(result["result"])
    
    def test_empty_series_median_is_nan(self):
        """Median of an empty series should be NaN."""
        df = pd.DataFrame({"x": []})

        result = self.verifier.compute_statistics(df, "x", "median")

        assert result["status"] == "SUCCESS"
        assert pd.isna(result["result"])
    
    def test_empty_series_min_is_nan(self):
        """Min of an empty series should be NaN."""
        df = pd.DataFrame({"x": []})

        result = self.verifier.compute_statistics(df, "x", "min")

        assert result["status"] == "SUCCESS"
        assert pd.isna(result["result"])
    
    def test_empty_series_max_is_nan(self):
        """Max of an empty series should be NaN."""
        df = pd.DataFrame({"x": []})

        result = self.verifier.compute_statistics(df, "x", "max")

        assert result["status"] == "SUCCESS"
        assert pd.isna(result["result"])
    
    
    # -------------------------------------------------------------------------
    # Single element arrays
    # -------------------------------------------------------------------------

    def test_single_element_mean(self):
        """Mean of a single-element series should equal that element."""
        df = pd.DataFrame({"x": [7]})

        result = self.verifier.compute_statistics(df, "x", "mean")

        assert result["status"] == "SUCCESS"
        assert result["result"] == 7

    def test_single_element_sum(self):
        """Sum of a single-element series should equal that element."""
        df = pd.DataFrame({"x": [7]})

        result = self.verifier.compute_statistics(df, "x", "sum")

        assert result["status"] == "SUCCESS"
        assert result["result"] == 7

    def test_single_element_count(self):
        """Count of a single-element series should be 1."""
        df = pd.DataFrame({"x": [7]})

        result = self.verifier.compute_statistics(df, "x", "count")

        assert result["status"] == "SUCCESS"
        assert result["result"] == 1

    def test_single_element_mode(self):
        """Mode of a single-element series should be that element."""
        df = pd.DataFrame({"x": [7]})

        result = self.verifier.compute_statistics(df, "x", "mode")

        assert result["status"] == "SUCCESS"
        assert result["result"] == 7

    def test_single_element_variance_is_nan(self):
        """Variance of a single-element series should be NaN."""
        df = pd.DataFrame({"x": [7]})

        result = self.verifier.compute_statistics(df, "x", "var")

        assert result["status"] == "SUCCESS"
        assert pd.isna(result["result"])

    def test_single_element_std_is_nan(self):
        """Standard deviation of a single-element series should be NaN."""
        df = pd.DataFrame({"x": [7]})

        result = self.verifier.compute_statistics(df, "x", "std")

        assert result["status"] == "SUCCESS"
        assert pd.isna(result["result"])
    
    def test_single_element_median(self):
        """Median of a single-element series should equal that element."""
        df = pd.DataFrame({"x": [7]})

        result = self.verifier.compute_statistics(df, "x", "median")

        assert result["status"] == "SUCCESS"
        assert result["result"] == 7

    def test_single_element_min(self):
        """Min of a single-element series should equal that element."""
        df = pd.DataFrame({"x": [7]})

        result = self.verifier.compute_statistics(df, "x", "min")

        assert result["status"] == "SUCCESS"
        assert result["result"] == 7

    def test_single_element_max(self):
        """Max of a single-element series should equal that element."""
        df = pd.DataFrame({"x": [7]})

        result = self.verifier.compute_statistics(df, "x", "max")

        assert result["status"] == "SUCCESS"
        assert result["result"] == 7

    # -------------------------------------------------------------------------
    # Very large numbers
    # -------------------------------------------------------------------------

    def test_large_numbers_sum(self):
        """Very large numbers should be summed consistently."""
        values = [10**15, 10**15 + 1, 10**15 + 2]
        df = pd.DataFrame({"x": values})

        result = self.verifier.compute_statistics(df, "x", "sum")

        assert result["status"] == "SUCCESS"
        assert result["result"] == sum(values)

    def test_large_numbers_mean(self):
        """Mean of large numbers uses Decimal to avoid float precision loss."""
        values = [10**15, 10**15 + 1, 10**15 + 2]
        df = pd.DataFrame({"x": values})

        result = self.verifier.compute_statistics(df, "x", "mean")

        assert result["status"] == "SUCCESS"
        expected = Decimal(sum(values)) / Decimal(len(values))
        assert Decimal(str(result["result"])) == expected

    def test_large_numbers_variance_is_non_negative(self):
        """Variance should never be negative, even for very large numbers."""
        values = [10**15, 10**15 + 1, 10**15 + 2]
        df = pd.DataFrame({"x": values})

        result = self.verifier.compute_statistics(df, "x", "var")

        assert result["status"] == "SUCCESS"
        assert result["result"] >= 0

    def test_large_numbers_std_is_non_negative(self):
        """Standard deviation should never be negative, even for very large numbers."""
        values = [10**15, 10**15 + 1, 10**15 + 2]
        df = pd.DataFrame({"x": values})

        result = self.verifier.compute_statistics(df, "x", "std")

        assert result["status"] == "SUCCESS"
        assert result["result"] >= 0
    
    def test_large_numbers_median(self):
        """Median of very large numbers should be computed consistently."""
        values = [10**15, 10**15 + 1, 10**15 + 2]
        df = pd.DataFrame({"x": values})

        result = self.verifier.compute_statistics(df, "x", "median")

        assert result["status"] == "SUCCESS"
        assert result["result"] == values[1]
    
    def test_large_numbers_count(self):
        """Count of very large numbers should be computed consistently."""
        values = [10**15, 10**15 + 1, 10**15 + 2]
        df = pd.DataFrame({"x": values})

        result = self.verifier.compute_statistics(df, "x", "count")

        assert result["status"] == "SUCCESS"
        assert result["result"] == len(values)
    
    def test_large_numbers_min(self):
        """Min of very large numbers should be computed consistently."""
        values = [10**15, 10**15 + 1, 10**15 + 2]
        df = pd.DataFrame({"x": values})

        result = self.verifier.compute_statistics(df, "x", "min")

        assert result["status"] == "SUCCESS"
        assert result["result"] == values[0]
    
    def test_large_numbers_max(self):
        """Max of very large numbers should be computed consistently."""
        values = [10**15, 10**15 + 1, 10**15 + 2]
        df = pd.DataFrame({"x": values})

        result = self.verifier.compute_statistics(df, "x", "max")

        assert result["status"] == "SUCCESS"
        assert result["result"] == values[2]

    # -------------------------------------------------------------------------
    # Negative numbers in variance calculations
    # -------------------------------------------------------------------------

    def test_variance_with_negative_values_is_non_negative(self):
        """Variance with negative values should still be non-negative."""
        df = pd.DataFrame({"x": [-5, -1, -4]})

        result = self.verifier.compute_statistics(df, "x", "var")

        assert result["status"] == "SUCCESS"
        assert result["result"] >= 0

    def test_std_with_negative_values_is_non_negative(self):
        """Std with negative values should still be non-negative."""
        df = pd.DataFrame({"x": [-5, -1, -4]})

        result = self.verifier.compute_statistics(df, "x", "std")

        assert result["status"] == "SUCCESS"
        assert result["result"] >= 0

    def test_negative_values_mean_is_correct(self):
        """Mean of [-5, -1, -4] is -10/3 (non-terminating decimal); uses Fraction for exact comparison."""
        df = pd.DataFrame({"x": [-5, -1, -4]})

        result = self.verifier.compute_statistics(df, "x", "mean")

        assert result["status"] == "SUCCESS"
        expected = Fraction(-10, 3)
        assert Fraction(result["result"]).limit_denominator(1000) == expected
    
    def test_negative_values_median_is_correct(self):
        """Median with negative values should be computed correctly."""
        df = pd.DataFrame({"x": [-5, -1, -4]})

        result = self.verifier.compute_statistics(df, "x", "median")

        assert result["status"] == "SUCCESS"
        assert result["result"] == -4
    
    def test_negative_values_min_is_correct(self):
        """Min with negative values should be computed correctly."""
        df = pd.DataFrame({"x": [-5, -1, -4]})

        result = self.verifier.compute_statistics(df, "x", "min")

        assert result["status"] == "SUCCESS"
        assert result["result"] == -5
    
    def test_negative_values_max_is_correct(self):
        """Max with negative values should be computed correctly."""
        df = pd.DataFrame({"x": [-5, -1, -4]})

        result = self.verifier.compute_statistics(df, "x", "max")

        assert result["status"] == "SUCCESS"
        assert result["result"] == -1
    
    def test_negative_values_count_is_correct(self):
        """Count with negative values should be computed correctly."""
        df = pd.DataFrame({"x": [-5, -1, -4]})

        result = self.verifier.compute_statistics(df, "x", "count")

        assert result["status"] == "SUCCESS"
        assert result["result"] == 3
    
    def test_negative_values_mode_is_correct(self):
        """Mode with all unique negative values returns smallest (pandas behavior: all values are modes when equally frequent, .iloc[0] returns first sorted)."""
        df = pd.DataFrame({"x": [-5, -1, -4]})

        result = self.verifier.compute_statistics(df, "x", "mode")

        assert result["status"] == "SUCCESS"
        assert result["result"] == -5
    

    # -------------------------------------------------------------------------
    # NaN handling
    # -------------------------------------------------------------------------

    def test_nan_series_mean_ignores_nan(self):
        """Mean should skip NaN values (pandas default: skipna=True)."""
        df = pd.DataFrame({"x": [1.0, float("nan"), 3.0]})

        result = self.verifier.compute_statistics(df, "x", "mean")

        assert result["status"] == "SUCCESS"
        assert result["result"] == pytest.approx(2.0)

    def test_nan_series_count_ignores_nan(self):
        """Count should not include NaN entries."""
        df = pd.DataFrame({"x": [1.0, float("nan"), 3.0]})

        result = self.verifier.compute_statistics(df, "x", "count")

        assert result["status"] == "SUCCESS"
        assert result["result"] == 2

    def test_all_nan_mode_returns_none(self):
        """Mode of an all-NaN series returns None (s.mode() is empty)."""
        df = pd.DataFrame({"x": [float("nan"), float("nan")]})

        result = self.verifier.compute_statistics(df, "x", "mode")

        assert result["status"] == "SUCCESS"
        assert result["result"] is None

    # -------------------------------------------------------------------------
    # Mode edge cases
    # -------------------------------------------------------------------------

    def test_mode_unique_winner(self):
        """Mode returns the single most-frequent value."""
        df = pd.DataFrame({"x": [1, 2, 2, 3]})

        result = self.verifier.compute_statistics(df, "x", "mode")

        assert result["status"] == "SUCCESS"
        assert result["result"] == 2

    def test_mode_multimodal_returns_first(self):
        """When multiple modes exist, implementation returns the first value from pandas mode output"""
        df = pd.DataFrame({"x": [1, 1, 2, 2, 3]})

        result = self.verifier.compute_statistics(df, "x", "mode")

        assert result["status"] == "SUCCESS"
        assert result["result"] == 1

    # -------------------------------------------------------------------------
    # Error handling
    # -------------------------------------------------------------------------

    def test_missing_column_returns_error(self):
        """Missing column should return an ERROR result with available columns."""
        df = pd.DataFrame({"x": [1, 2, 3]})

        result = self.verifier.compute_statistics(df, "y", "mean")

        assert result["status"] == "ERROR"
        assert "not found" in result["error"]
        assert "available_columns" in result
        assert result["available_columns"] == ["x"]

    def test_unknown_operation_returns_error(self):
        """Unknown operation should return an ERROR result with valid operations."""
        df = pd.DataFrame({"x": [1, 2, 3]})

        result = self.verifier.compute_statistics(df, "x", "skewness")

        assert result["status"] == "ERROR"
        assert "Unknown operation" in result["error"]
        assert "available_operations" in result
        assert "mean" in result["available_operations"]
        assert "var" in result["available_operations"]

# -------------------------------------------------------------------------
# Integration tests
# -------------------------------------------------------------------------

@pytest.mark.skipif(
    not os.getenv("INTEGRATION_TESTS"),
    reason="requires a live server at 127.0.0.1:8002 — set INTEGRATION_TESTS=1 to run"
)
def test_stats_verification():
    """End-to-end: POST a CSV to /verify/stats and assert the correct sales total is returned."""
    # 1. Create a dummy CSV
    csv_content = """Date,Product,Sales,Region
2023-01-01,Widget A,100,North
2023-01-02,Widget B,150,South
2023-01-03,Widget A,120,North
2023-01-04,Widget C,200,East
2023-01-05,Widget B,130,South
"""

    # 2. Define Query
    query = "What is the total sales for Widget A?"
    expected_answer = "220" # 100 + 120
    
    print(f"\nQuery: {query}")
    print("Uploading CSV...")

    # 3. Send Request
    files = {
        'file': ('sales.csv', csv_content, 'text/csv')
    }
    data = {
        'query': query,
        'provider': 'azure_openai'
    }

    try:
        response = requests.post(
            f"{BASE_URL}/verify/stats",
            files=files,
            data=data,
            timeout=10,
        )
    except requests.exceptions.RequestException as e:
        pytest.fail(f"Connection to {BASE_URL} failed: {e}")

    assert response.status_code == 200, (
        f"Expected HTTP 200 from /verify/stats, got {response.status_code}: {response.text}"
    )

    result = response.json()
    assert str(result["result"]) == expected_answer, (
        f"Expected total sales {expected_answer}, got {result['result']!r}"
    )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])