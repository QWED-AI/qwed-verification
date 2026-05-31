"""
conftest.py for benchmarks directory.

Provides a stub `benchmark` fixture when pytest-codspeed is NOT installed,
so that benchmark tests are gracefully skipped in regular CI environments
(CircleCI, Buildkite) that do not install pytest-codspeed.

When pytest-codspeed IS installed (CodSpeed CI workflow), the real
`benchmark` fixture from the plugin takes precedence over this stub.
"""
import importlib.util

import pytest


def pytest_configure(config):
    """Register the benchmark marker so it is always recognized."""
    config.addinivalue_line(
        "markers",
        "benchmark: mark test as a CodSpeed performance benchmark",
    )


_CODSPEED_AVAILABLE = importlib.util.find_spec("pytest_codspeed") is not None

if not _CODSPEED_AVAILABLE:

    @pytest.fixture
    def benchmark():
        """
        Stub benchmark fixture for environments without pytest-codspeed.

        Benchmark tests are skipped in regular CI (CircleCI, Buildkite)
        because pytest-codspeed is not installed there. The real benchmark
        fixture is provided by pytest-codspeed in the dedicated CodSpeed workflow.
        """
        pytest.skip(
            "pytest-codspeed is not installed. "
            "Benchmark tests only run in the CodSpeed CI workflow."
        )