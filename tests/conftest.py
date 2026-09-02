import os
from uuid import uuid4
import pytest


def _test_secret_material(prefix: str) -> str:
    """Generate non-production secret material for test-only environment wiring."""
    return f"{prefix}-{uuid4().hex}"


TEST_JWT_MATERIAL = _test_secret_material("unit-test-jwt")
TEST_API_KEY_MATERIAL = _test_secret_material("unit-test-api")
# Fixed, not uuid-derived, so verification runs are byte-for-byte
# reproducible (CodeRabbit on PR #345 round 3). Deliberately distinct from
# TEST_JWT_MATERIAL: security.py refuses to boot when the two are equal.
TEST_LOOKUP_MATERIAL = "unit-test-lookup-material"

# Inject test secrets before any module imports happen
os.environ["QWED_JWT_SECRET_KEY"] = TEST_JWT_MATERIAL
os.environ["QWED_CORS_ORIGINS"] = "http://localhost:3000"
os.environ["API_KEY_SECRET"] = TEST_API_KEY_MATERIAL
# Required at import by qwed_new.auth.security (fail closed — no JWT-secret
# fallback, CodeRabbit on PR #345 round 2)
os.environ["QWED_API_KEY_LOOKUP_SECRET"] = TEST_LOOKUP_MATERIAL

@pytest.fixture(autouse=True)
def setup_test_env():
    """Ensure environment is deterministic for all tests."""
    os.environ["QWED_JWT_SECRET_KEY"] = TEST_JWT_MATERIAL
    os.environ["QWED_CORS_ORIGINS"] = "http://localhost:3000"
    os.environ["API_KEY_SECRET"] = TEST_API_KEY_MATERIAL
    os.environ["QWED_API_KEY_LOOKUP_SECRET"] = TEST_LOOKUP_MATERIAL
