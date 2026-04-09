"""
Tests for StatsVerifier.compute_statistics().

Verifies fail-closed semantics: operations return ERROR when the input is
empty, lacks valid observations, or produces an undefined or ambiguous result.

Coverage:
  1. Empty series (all operations)
  2. Single-element series
  3. Large numeric values
  4. Negative values
  5. Mixed valid/NaN inputs
  6. All-NaN series
  7. Mode ambiguity (multimodal)
  8. Missing columns and unknown operations
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
    """Tests for StatsVerifier initialization."""

    def test_verifier_initialization(self):
        """Verify default configuration values."""
        verifier = StatsVerifier()
        assert verifier.preferred_sandbox == "auto"
        assert verifier.timeout_seconds == 30.0
        assert verifier.memory_limit_mb == 128

    def test_verifier_custom_config(self):
        """Verify custom configuration parameters."""
        verifier = StatsVerifier(
            preferred_sandbox="docker",
            timeout_seconds=20.0,
            memory_limit_mb=256
        )
        assert verifier.preferred_sandbox == "docker"
        assert verifier.timeout_seconds == 20.0
        assert verifier.memory_limit_mb == 256

class TestComputeStatistics:
    """Tests for compute_statistics() operations."""

    def setup_method(self):
        self.verifier = StatsVerifier()

    # -------------------------------------------------------------------------
    # Empty series - all operations must fail closed
    # -------------------------------------------------------------------------

    def test_empty_series_sum_is_error(self):
        """Sum on an empty series returns ERROR."""
        df = pd.DataFrame({"x": []})

        result = self.verifier.compute_statistics(df, "x", "sum")

        assert result["status"] == "ERROR"
        assert result.get("error")

    def test_empty_series_count_is_error(self):
        """Count on an empty series returns ERROR."""
        df = pd.DataFrame({"x": []})

        result = self.verifier.compute_statistics(df, "x", "count")

        assert result["status"] == "ERROR"
        assert result.get("error")

    def test_empty_series_mode_is_error(self):
        """Mode on an empty series returns ERROR."""
        df = pd.DataFrame({"x": []})

        result = self.verifier.compute_statistics(df, "x", "mode")

        assert result["status"] == "ERROR"
        assert result.get("error")

    def test_empty_series_mean_is_error(self):
        """Mean on an empty series returns ERROR."""
        df = pd.DataFrame({"x": []})

        result = self.verifier.compute_statistics(df, "x", "mean")

        assert result["status"] == "ERROR"
        assert result.get("error")

    def test_empty_series_variance_is_error(self):
        """Variance on an empty series returns ERROR."""
        df = pd.DataFrame({"x": []})

        result = self.verifier.compute_statistics(df, "x", "var")

        assert result["status"] == "ERROR"
        assert result.get("error")

    def test_empty_series_std_is_error(self):
        """Standard deviation on an empty series returns ERROR."""
        df = pd.DataFrame({"x": []})

        result = self.verifier.compute_statistics(df, "x", "std")

        assert result["status"] == "ERROR"
        assert result.get("error")

    def test_empty_series_median_is_error(self):
        """Median on an empty series returns ERROR."""
        df = pd.DataFrame({"x": []})

        result = self.verifier.compute_statistics(df, "x", "median")

        assert result["status"] == "ERROR"
        assert result.get("error")

    def test_empty_series_min_is_error(self):
        """Min on an empty series returns ERROR."""
        df = pd.DataFrame({"x": []})

        result = self.verifier.compute_statistics(df, "x", "min")

        assert result["status"] == "ERROR"
        assert result.get("error")

    def test_empty_series_max_is_error(self):
        """Max on an empty series returns ERROR."""
        df = pd.DataFrame({"x": []})

        result = self.verifier.compute_statistics(df, "x", "max")

        assert result["status"] == "ERROR"
        assert result.get("error")

    # -------------------------------------------------------------------------
    # Single-element series
    # -------------------------------------------------------------------------

    def test_single_element_mean(self):
        """Mean of a single-element series is the element itself."""
        df = pd.DataFrame({"x": [7]})

        result = self.verifier.compute_statistics(df, "x", "mean")

        assert result["status"] == "SUCCESS"
        assert result["result"] == 7

    def test_single_element_sum(self):
        """Sum of a single-element series is the element itself."""
        df = pd.DataFrame({"x": [7]})

        result = self.verifier.compute_statistics(df, "x", "sum")

        assert result["status"] == "SUCCESS"
        assert result["result"] == 7

    def test_single_element_count(self):
        """Count of a single-element series is 1."""
        df = pd.DataFrame({"x": [7]})

        result = self.verifier.compute_statistics(df, "x", "count")

        assert result["status"] == "SUCCESS"
        assert result["result"] == 1

    def test_single_element_mode(self):
        """Mode of a single-element series is the element itself."""
        df = pd.DataFrame({"x": [7]})

        result = self.verifier.compute_statistics(df, "x", "mode")

        assert result["status"] == "SUCCESS"
        assert result["result"] == 7

    def test_single_element_variance_is_error(self):
        """Variance on a single-element series returns ERROR."""
        df = pd.DataFrame({"x": [7]})

        result = self.verifier.compute_statistics(df, "x", "var")

        assert result["status"] == "ERROR"
        assert result.get("error")

    def test_single_element_std_is_error(self):
        """Standard deviation on a single-element series returns ERROR."""
        df = pd.DataFrame({"x": [7]})

        result = self.verifier.compute_statistics(df, "x", "std")

        assert result["status"] == "ERROR"
        assert result.get("error")

    def test_single_element_median(self):
        """Median of a single-element series is the element itself."""
        df = pd.DataFrame({"x": [7]})

        result = self.verifier.compute_statistics(df, "x", "median")

        assert result["status"] == "SUCCESS"
        assert result["result"] == 7

    def test_single_element_min(self):
        """Min of a single-element series is the element itself."""
        df = pd.DataFrame({"x": [7]})

        result = self.verifier.compute_statistics(df, "x", "min")

        assert result["status"] == "SUCCESS"
        assert result["result"] == 7

    def test_single_element_max(self):
        """Max of a single-element series is the element itself."""
        df = pd.DataFrame({"x": [7]})

        result = self.verifier.compute_statistics(df, "x", "max")

        assert result["status"] == "SUCCESS"
        assert result["result"] == 7

    # -------------------------------------------------------------------------
    # Very large numbers
    # -------------------------------------------------------------------------

    def test_large_numbers_sum(self):
        """Sum of large integers matches exact arithmetic total."""
        values = [10**15, 10**15 + 1, 10**15 + 2]
        df = pd.DataFrame({"x": values})

        result = self.verifier.compute_statistics(df, "x", "sum")

        assert result["status"] == "SUCCESS"
        assert result["result"] == sum(values)

    def test_large_numbers_mean(self):
        """Mean of large integers preserves precision."""
        values = [10**15, 10**15 + 1, 10**15 + 2]
        df = pd.DataFrame({"x": values})

        result = self.verifier.compute_statistics(df, "x", "mean")

        assert result["status"] == "SUCCESS"
        expected = Decimal(sum(values)) / Decimal(len(values))
        assert Decimal(str(result["result"])) == expected

    def test_large_numbers_variance_is_non_negative(self):
        """Variance of large integers is non-negative."""
        values = [10**15, 10**15 + 1, 10**15 + 2]
        df = pd.DataFrame({"x": values})

        result = self.verifier.compute_statistics(df, "x", "var")

        assert result["status"] == "SUCCESS"
        assert result["result"] >= 0

    def test_large_numbers_std_is_non_negative(self):
        """Standard deviation of large integers is non-negative."""
        values = [10**15, 10**15 + 1, 10**15 + 2]
        df = pd.DataFrame({"x": values})

        result = self.verifier.compute_statistics(df, "x", "std")

        assert result["status"] == "SUCCESS"
        assert result["result"] >= 0

    def test_large_numbers_median(self):
        """Median of large integers matches middle value."""
        values = [10**15, 10**15 + 1, 10**15 + 2]
        df = pd.DataFrame({"x": values})

        result = self.verifier.compute_statistics(df, "x", "median")

        assert result["status"] == "SUCCESS"
        assert result["result"] == values[1]

    def test_large_numbers_count(self):
        """Count of large integers returns number of observations."""
        values = [10**15, 10**15 + 1, 10**15 + 2]
        df = pd.DataFrame({"x": values})

        result = self.verifier.compute_statistics(df, "x", "count")

        assert result["status"] == "SUCCESS"
        assert result["result"] == len(values)

    def test_large_numbers_min(self):
        """Min identifies the smallest value in a series."""
        values = [10**15, 10**15 + 1, 10**15 + 2]
        df = pd.DataFrame({"x": values})

        result = self.verifier.compute_statistics(df, "x", "min")

        assert result["status"] == "SUCCESS"
        assert result["result"] == values[0]

    def test_large_numbers_max(self):
        """Max identifies the largest value in a series."""
        values = [10**15, 10**15 + 1, 10**15 + 2]
        df = pd.DataFrame({"x": values})

        result = self.verifier.compute_statistics(df, "x", "max")

        assert result["status"] == "SUCCESS"
        assert result["result"] == values[2]

    # -------------------------------------------------------------------------
    # Negative numbers
    # -------------------------------------------------------------------------

    def test_negative_values_variance_is_non_negative(self):
        """Variance of negative values is non-negative."""
        df = pd.DataFrame({"x": [-5, -1, -4]})

        result = self.verifier.compute_statistics(df, "x", "var")

        assert result["status"] == "SUCCESS"
        assert result["result"] >= 0

    def test_negative_values_std_is_non_negative(self):
        """Standard deviation of negative values is non-negative."""
        df = pd.DataFrame({"x": [-5, -1, -4]})

        result = self.verifier.compute_statistics(df, "x", "std")

        assert result["status"] == "SUCCESS"
        assert result["result"] >= 0

    def test_negative_values_mean_is_correct(self):
        """Mean of negative values is correct."""
        df = pd.DataFrame({"x": [-5, -1, -4]})

        result = self.verifier.compute_statistics(df, "x", "mean")

        assert result["status"] == "SUCCESS"
        expected = Fraction(-10, 3)
        assert Fraction(result["result"]).limit_denominator(1000) == expected

    def test_negative_values_median_is_correct(self):
        """Median of negative values is correct."""
        df = pd.DataFrame({"x": [-5, -1, -4]})

        result = self.verifier.compute_statistics(df, "x", "median")

        assert result["status"] == "SUCCESS"
        assert result["result"] == -4

    def test_negative_values_min_is_correct(self):
        """Min of negative values is correct."""
        df = pd.DataFrame({"x": [-5, -1, -4]})

        result = self.verifier.compute_statistics(df, "x", "min")

        assert result["status"] == "SUCCESS"
        assert result["result"] == -5

    def test_negative_values_max_is_correct(self):
        """Max of negative values is correct."""
        df = pd.DataFrame({"x": [-5, -1, -4]})

        result = self.verifier.compute_statistics(df, "x", "max")

        assert result["status"] == "SUCCESS"
        assert result["result"] == -1

    def test_negative_values_count_is_correct(self):
        """Count of negative values is correct."""
        df = pd.DataFrame({"x": [-5, -1, -4]})

        result = self.verifier.compute_statistics(df, "x", "count")

        assert result["status"] == "SUCCESS"
        assert result["result"] == 3

    def test_negative_unique_values_mode_is_error(self):
        """Multimodal negative values return ERROR."""
        df = pd.DataFrame({"x": [-5, -1, -4]})

        result = self.verifier.compute_statistics(df, "x", "mode")

        assert result["status"] == "ERROR"
        assert result.get("error")

    # -------------------------------------------------------------------------
    # Mixed valid/NaN inputs - NaNs are excluded
    # -------------------------------------------------------------------------

    def test_mixed_nan_mean_uses_valid_observations(self):
        """Mean excludes NaN values."""
        df = pd.DataFrame({"x": [1.0, float("nan"), 3.0]})

        result = self.verifier.compute_statistics(df, "x", "mean")

        assert result["status"] == "SUCCESS"
        assert result["result"] == pytest.approx(2.0)

    def test_mixed_nan_count_uses_valid_observations(self):
        """Count excludes NaN values."""
        df = pd.DataFrame({"x": [1.0, float("nan"), 3.0]})

        result = self.verifier.compute_statistics(df, "x", "count")

        assert result["status"] == "SUCCESS"
        assert result["result"] == 2

    def test_mixed_nan_sum_uses_valid_observations(self):
        """Sum excludes NaN values."""
        df = pd.DataFrame({"x": [1.0, float("nan"), 3.0]})

        result = self.verifier.compute_statistics(df, "x", "sum")

        assert result["status"] == "SUCCESS"
        assert result["result"] == pytest.approx(4.0)

    def test_mixed_nan_var_uses_valid_observations(self):
        """Variance excludes NaN values."""
        df = pd.DataFrame({"x": [1.0, float("nan"), 3.0]})

        result = self.verifier.compute_statistics(df, "x", "var")

        assert result["status"] == "SUCCESS"
        assert result["result"] == pytest.approx(2.0)

    def test_mixed_nan_std_uses_valid_observations(self):
        """Standard deviation excludes NaN values."""
        df = pd.DataFrame({"x": [1.0, float("nan"), 3.0]})

        result = self.verifier.compute_statistics(df, "x", "std")

        assert result["status"] == "SUCCESS"
        assert result["result"] == pytest.approx(2.0 ** 0.5)

    def test_mixed_nan_median_uses_valid_observations(self):
        """Median excludes NaN values."""
        df = pd.DataFrame({"x": [1.0, float("nan"), 3.0]})

        result = self.verifier.compute_statistics(df, "x", "median")

        assert result["status"] == "SUCCESS"
        assert result["result"] == pytest.approx(2.0)

    def test_mixed_nan_min_uses_valid_observations(self):
        """Min excludes NaN values."""
        df = pd.DataFrame({"x": [1.0, float("nan"), 3.0]})

        result = self.verifier.compute_statistics(df, "x", "min")

        assert result["status"] == "SUCCESS"
        assert result["result"] == pytest.approx(1.0)

    def test_mixed_nan_max_uses_valid_observations(self):
        """Max excludes NaN values."""
        df = pd.DataFrame({"x": [1.0, float("nan"), 3.0]})

        result = self.verifier.compute_statistics(df, "x", "max")

        assert result["status"] == "SUCCESS"
        assert result["result"] == pytest.approx(3.0)

    def test_mixed_nan_var_single_valid_observation_is_error(self):
        """Variance with single valid observation returns ERROR."""
        df = pd.DataFrame({"x": [1.0, float("nan")]})

        result = self.verifier.compute_statistics(df, "x", "var")

        assert result["status"] == "ERROR"
        assert result.get("error")

    def test_mixed_nan_std_single_valid_observation_is_error(self):
        """Standard deviation with single valid observation returns ERROR."""
        df = pd.DataFrame({"x": [1.0, float("nan")]})

        result = self.verifier.compute_statistics(df, "x", "std")

        assert result["status"] == "ERROR"
        assert result.get("error")

    # -------------------------------------------------------------------------
    # All-NaN inputs
    # -------------------------------------------------------------------------

    def test_all_nan_series_count_is_error(self):
        """Count on all-NaN series returns ERROR."""
        df = pd.DataFrame({"x": [float("nan"), float("nan")]})

        result = self.verifier.compute_statistics(df, "x", "count")

        assert result["status"] == "ERROR"
        assert result.get("error")

    def test_all_nan_series_sum_is_error(self):
        """Sum on all-NaN series returns ERROR."""
        df = pd.DataFrame({"x": [float("nan"), float("nan")]})

        result = self.verifier.compute_statistics(df, "x", "sum")

        assert result["status"] == "ERROR"
        assert result.get("error")

    def test_all_nan_series_mean_is_error(self):
        """Mean on all-NaN series returns ERROR."""
        df = pd.DataFrame({"x": [float("nan"), float("nan")]})

        result = self.verifier.compute_statistics(df, "x", "mean")

        assert result["status"] == "ERROR"
        assert result.get("error")

    def test_all_nan_series_var_is_error(self):
        """Variance on all-NaN series returns ERROR."""
        df = pd.DataFrame({"x": [float("nan"), float("nan")]})

        result = self.verifier.compute_statistics(df, "x", "var")

        assert result["status"] == "ERROR"
        assert result.get("error")

    def test_all_nan_series_std_is_error(self):
        """Standard deviation on all-NaN series returns ERROR."""
        df = pd.DataFrame({"x": [float("nan"), float("nan")]})

        result = self.verifier.compute_statistics(df, "x", "std")

        assert result["status"] == "ERROR"
        assert result.get("error")

    def test_all_nan_series_median_is_error(self):
        """Median on all-NaN series returns ERROR."""
        df = pd.DataFrame({"x": [float("nan"), float("nan")]})

        result = self.verifier.compute_statistics(df, "x", "median")

        assert result["status"] == "ERROR"
        assert result.get("error")

    def test_all_nan_series_min_is_error(self):
        """Min on all-NaN series returns ERROR."""
        df = pd.DataFrame({"x": [float("nan"), float("nan")]})

        result = self.verifier.compute_statistics(df, "x", "min")

        assert result["status"] == "ERROR"
        assert result.get("error")

    def test_all_nan_series_max_is_error(self):
        """Max on all-NaN series returns ERROR."""
        df = pd.DataFrame({"x": [float("nan"), float("nan")]})

        result = self.verifier.compute_statistics(df, "x", "max")

        assert result["status"] == "ERROR"
        assert result.get("error")

    def test_all_nan_series_mode_is_error(self):
        """Mode on all-NaN series returns ERROR."""
        df = pd.DataFrame({"x": [float("nan"), float("nan")]})

        result = self.verifier.compute_statistics(df, "x", "mode")

        assert result["status"] == "ERROR"
        assert result.get("error")

    # -------------------------------------------------------------------------
    # Mode edge cases
    # -------------------------------------------------------------------------

    def test_mode_unique_winner(self):
        """Unambiguous mode returns SUCCESS."""
        df = pd.DataFrame({"x": [1, 2, 2, 3]})

        result = self.verifier.compute_statistics(df, "x", "mode")

        assert result["status"] == "SUCCESS"
        assert result["result"] == 2

    def test_mode_with_nan_unique_winner(self):
        """Mode excludes NaNs and returns valid unique winner."""
        df = pd.DataFrame({"x": [1, 1, float("nan"), 2]})

        result = self.verifier.compute_statistics(df, "x", "mode")

        assert result["status"] == "SUCCESS"
        assert result["result"] == 1

    def test_mode_multimodal_is_error(self):
        """Multimodal series returns ERROR."""
        df = pd.DataFrame({"x": [1, 1, 2, 2, 3]})

        result = self.verifier.compute_statistics(df, "x", "mode")

        assert result["status"] == "ERROR"
        assert result.get("error")

    def test_mode_with_nan_multimodal_is_error(self):
        """Multimodal series (after excluding NaNs) returns ERROR."""
        df = pd.DataFrame({"x": [1, 1, 2, 2, float("nan")]})

        result = self.verifier.compute_statistics(df, "x", "mode")

        assert result["status"] == "ERROR"
        assert result.get("error")

    # -------------------------------------------------------------------------
    # Error handling - missing column / unknown operation
    # -------------------------------------------------------------------------

    def test_missing_column_returns_error(self):
        """Missing column returns ERROR with available columns."""
        df = pd.DataFrame({"x": [1, 2, 3]})

        result = self.verifier.compute_statistics(df, "y", "mean")

        assert result["status"] == "ERROR"
        assert result.get("error")
        assert "available_columns" in result
        assert result["available_columns"] == ["x"]

    def test_unknown_operation_returns_error(self):
        """Unknown operation returns ERROR with available operations."""
        df = pd.DataFrame({"x": [1, 2, 3]})

        result = self.verifier.compute_statistics(df, "x", "skewness")

        assert result["status"] == "ERROR"
        assert result.get("error")
        assert "available_operations" in result
        assert "mean" in result["available_operations"]
        assert "var" in result["available_operations"]

# -------------------------------------------------------------------------
# Integration tests
# -------------------------------------------------------------------------

@pytest.mark.skipif(
    os.getenv("INTEGRATION_TESTS", "").strip().lower() not in {"1", "true", "yes"},
    reason="requires a live server at 127.0.0.1:8002 - set INTEGRATION_TESTS=1 to run"
)
def test_stats_verification():
    """Verify end-to-end statistics computation via API."""
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