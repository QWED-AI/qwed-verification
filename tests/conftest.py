import os
import pytest

# Inject test secrets before any module imports happen
os.environ["QWED_JWT_SECRET_KEY"] = "test_secret_for_deterministic_hashing"

@pytest.fixture(autouse=True)
def setup_test_env():
    """Ensure environment is deterministic for all tests."""
    os.environ["QWED_JWT_SECRET_KEY"] = "test_secret_for_deterministic_hashing"
