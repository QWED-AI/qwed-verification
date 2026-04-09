import os
from uuid import uuid4
import pytest


def _test_secret_material(prefix: str) -> str:
    """Generate non-production secret material for test-only environment wiring."""
    return f"{prefix}-{uuid4().hex}"


TEST_JWT_MATERIAL = _test_secret_material("unit-test-jwt")
TEST_API_KEY_MATERIAL = _test_secret_material("unit-test-api")

# Inject test secrets before any module imports happen
os.environ["QWED_JWT_SECRET_KEY"] = TEST_JWT_MATERIAL
os.environ["QWED_CORS_ORIGINS"] = "http://localhost:3000"
os.environ["API_KEY_SECRET"] = TEST_API_KEY_MATERIAL

@pytest.fixture(autouse=True)
def setup_test_env():
    """Ensure environment is deterministic for all tests."""
    os.environ["QWED_JWT_SECRET_KEY"] = TEST_JWT_MATERIAL
    os.environ["QWED_CORS_ORIGINS"] = "http://localhost:3000"
    os.environ["API_KEY_SECRET"] = TEST_API_KEY_MATERIAL
