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
TEST_AUDIT_MATERIAL = _test_secret_material("unit-test-audit")

# Inject test secrets before any module imports happen
os.environ["QWED_JWT_SECRET_KEY"] = TEST_JWT_MATERIAL
os.environ["QWED_CORS_ORIGINS"] = "http://localhost:3000"
os.environ["API_KEY_SECRET"] = TEST_API_KEY_MATERIAL
# Required at import by qwed_new.auth.security (fail closed — no JWT-secret
# fallback, CodeRabbit on PR #345 round 2)
os.environ["QWED_API_KEY_LOOKUP_SECRET"] = TEST_LOOKUP_MATERIAL
# Required by the audit chain every verify endpoint appends to (fail closed)
os.environ["QWED_AUDIT_SECRET_KEY"] = TEST_AUDIT_MATERIAL

@pytest.fixture(autouse=True)
def setup_test_env():
    """Ensure environment is deterministic for all tests."""
    os.environ["QWED_JWT_SECRET_KEY"] = TEST_JWT_MATERIAL
    os.environ["QWED_CORS_ORIGINS"] = "http://localhost:3000"
    os.environ["API_KEY_SECRET"] = TEST_API_KEY_MATERIAL
    os.environ["QWED_API_KEY_LOOKUP_SECRET"] = TEST_LOOKUP_MATERIAL
    os.environ["QWED_AUDIT_SECRET_KEY"] = TEST_AUDIT_MATERIAL


@pytest.fixture(autouse=True)
def isolated_audit_chain(tmp_path, monkeypatch):
    """Give each test its own audit-chain database and a fresh AuditLogger.

    Verify endpoints append to the signed chain through the process-wide
    AuditLogger, which writes with ``qwed_new.core.audit_logger.engine``
    rather than the request session most tests mock. Without this, those
    appends would land in ./qwed.db, and the logger's in-memory chain head
    would leak from one test into the next.
    """
    from sqlmodel import SQLModel, create_engine

    from qwed_new.core import audit_logger as audit_module
    from qwed_new.core.models import VerificationLog

    engine = create_engine(
        f"sqlite:///{tmp_path / 'audit-chain.db'}",
        connect_args={"check_same_thread": False},
    )
    SQLModel.metadata.create_all(engine, tables=[VerificationLog.__table__])
    monkeypatch.setattr(audit_module, "engine", engine)
    monkeypatch.setattr(audit_module, "_default_logger", None)
    yield engine
    engine.dispose()
