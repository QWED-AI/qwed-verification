import sys
from datetime import datetime
from pathlib import Path

import pytest
from sqlmodel import SQLModel, Session, create_engine

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from qwed_new.core import audit_logger as audit_module
from qwed_new.core.audit_logger import AUDIT_SECRET_ENV_VAR, AuditLogger, SecurityError
from qwed_new.core.models import VerificationLog


def _make_test_engine(tmp_path):
    db_path = tmp_path / "audit-test.db"
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    SQLModel.metadata.create_all(engine)
    return engine


def _configure_audit_logger(monkeypatch, tmp_path, audit_value="audit-fixture-value"):
    engine = _make_test_engine(tmp_path)
    monkeypatch.setattr(audit_module, "engine", engine)
    monkeypatch.setenv(AUDIT_SECRET_ENV_VAR, audit_value)
    return engine


def test_audit_logger_requires_explicit_secret(monkeypatch, tmp_path):
    _make_test_engine(tmp_path)
    monkeypatch.delenv(AUDIT_SECRET_ENV_VAR, raising=False)

    with pytest.raises(SecurityError, match=AUDIT_SECRET_ENV_VAR):
        AuditLogger()


def test_audit_logger_restores_chain_head_from_persisted_log(monkeypatch, tmp_path):
    engine = _configure_audit_logger(monkeypatch, tmp_path)

    logger_one = AuditLogger()
    first_log_id = logger_one.log_verification(
        organization_id=1,
        user_id=None,
        query="2 + 2",
        result={"value": 4},
        is_verified=True,
        domain="math",
    )

    with Session(engine) as session:
        first_log = session.get(VerificationLog, int(first_log_id))
        assert first_log is not None
        persisted_first_hash = first_log.entry_hash

    logger_two = AuditLogger()

    second_log_id = logger_two.log_verification(
        organization_id=1,
        user_id=None,
        query="3 + 3",
        result={"value": 6},
        is_verified=True,
        domain="math",
    )

    with Session(engine) as session:
        second_log = session.get(VerificationLog, int(second_log_id))
        assert second_log is not None
        assert second_log.previous_hash == persisted_first_hash
        assert logger_two._last_hash_by_org[1] == second_log.entry_hash
        assert logger_two.last_hash == second_log.entry_hash


def test_audit_logger_rejects_invalid_root_continuation(monkeypatch, tmp_path):
    _configure_audit_logger(monkeypatch, tmp_path)

    logger = AuditLogger()
    logger.log_verification(
        organization_id=1,
        user_id=None,
        query="2 + 2",
        result={"value": 4},
        is_verified=True,
        domain="math",
    )

    diverged_logger = AuditLogger()
    diverged_logger._last_hash_by_org[1] = "tampered-chain-head"

    with pytest.raises(SecurityError, match="continuity mismatch"):
        diverged_logger.log_verification(
            organization_id=1,
            user_id=None,
            query="4 + 4",
            result={"value": 8},
            is_verified=True,
            domain="math",
        )


def test_audit_logger_detects_broken_previous_hash_during_verification(monkeypatch, tmp_path):
    engine = _configure_audit_logger(monkeypatch, tmp_path)
    logger = AuditLogger()

    first_log_id = logger.log_verification(
        organization_id=1,
        user_id=None,
        query="2 + 2",
        result={"value": 4},
        is_verified=True,
        domain="math",
    )

    with Session(engine) as session:
        first_log = session.get(VerificationLog, int(first_log_id))
        tampered_payload = {
            "organization_id": 1,
            "user_id": None,
            "query": "4 + 4",
            "result": {"value": 8},
            "is_verified": True,
            "domain": "math",
            "timestamp": first_log.timestamp.isoformat(),
            "previous_hash": "wrong-previous-hash",
        }
        entry_hash = logger._compute_hash(tampered_payload)
        signature = logger._compute_hmac(entry_hash)

        bad_log = VerificationLog(
            organization_id=1,
            user_id=None,
            query="4 + 4",
            result='{"value": 8}',
            is_verified=True,
            domain="math",
            timestamp=first_log.timestamp,
            entry_hash=entry_hash,
            hmac_signature=signature,
            previous_hash="wrong-previous-hash",
        )
        session.add(bad_log)
        session.commit()
        session.refresh(bad_log)

        verification = logger.verify_log_entry(bad_log.id, session)

    assert verification["valid"] is False
    assert verification["checks"]["chain_valid"] is False
    assert "Hash chain broken: previous hash doesn't match" in verification["errors"]


def test_audit_logger_detects_missing_entry_hash(monkeypatch, tmp_path):
    engine = _configure_audit_logger(monkeypatch, tmp_path)
    logger = AuditLogger()

    with Session(engine) as session:
        broken_log = VerificationLog(
            organization_id=1,
            user_id=None,
            query="2 + 2",
            result='{"value": 4}',
            is_verified=True,
            domain="math",
            hmac_signature="not-a-real-signature",
            previous_hash=None,
        )
        session.add(broken_log)
        session.commit()
        session.refresh(broken_log)

        verification = logger.verify_log_entry(broken_log.id, session)

    assert verification["valid"] is False
    assert verification["checks"]["hash_valid"] is False
    assert verification["checks"]["signature_valid"] is False
    assert "Hash missing from audit entry" in verification["errors"]


def test_audit_logger_rejects_malformed_result_payload(monkeypatch, tmp_path):
    engine = _configure_audit_logger(monkeypatch, tmp_path)
    logger = AuditLogger()

    with Session(engine) as session:
        broken_log = VerificationLog(
            organization_id=1,
            user_id=None,
            query="2 + 2",
            result="{not-json",
            is_verified=True,
            domain="math",
            entry_hash="placeholder-hash",
            hmac_signature="placeholder-signature",
            previous_hash=None,
        )
        session.add(broken_log)
        session.commit()
        session.refresh(broken_log)

        with pytest.raises(SecurityError, match="malformed"):
            logger.verify_log_entry(broken_log.id, session)


def test_audit_logger_detects_raw_llm_output_tampering(monkeypatch, tmp_path):
    engine = _configure_audit_logger(monkeypatch, tmp_path)
    logger = AuditLogger()

    log_id = logger.log_verification(
        organization_id=1,
        user_id=None,
        query="2 + 2",
        result={"value": 4},
        is_verified=True,
        domain="math",
        raw_llm_output="original output",
    )

    with Session(engine) as session:
        log_entry = session.get(VerificationLog, int(log_id))
        assert log_entry is not None
        log_entry.raw_llm_output = "tampered output"
        session.add(log_entry)
        session.commit()
        session.refresh(log_entry)

        verification = logger.verify_log_entry(log_entry.id, session)

    assert verification["valid"] is False
    assert verification["checks"]["hash_valid"] is False


def test_audit_logger_verifies_legacy_hash_payload(monkeypatch, tmp_path):
    engine = _configure_audit_logger(monkeypatch, tmp_path)
    logger = AuditLogger()

    legacy_payload = {
        "organization_id": 1,
        "user_id": None,
        "query": "2 + 2",
        "result": {"value": 4},
        "is_verified": True,
        "domain": "math",
        "timestamp": "2026-05-08T00:00:00",
        "previous_hash": None,
    }
    entry_hash = logger._compute_hash(legacy_payload)
    signature = logger._compute_hmac(entry_hash)

    with Session(engine) as session:
        legacy_log = VerificationLog(
            organization_id=1,
            user_id=None,
            query="2 + 2",
            result='{"value": 4}',
            is_verified=True,
            domain="math",
            timestamp=datetime.fromisoformat(legacy_payload["timestamp"]),
            entry_hash=entry_hash,
            hmac_signature=signature,
            previous_hash=None,
            raw_llm_output="legacy raw output not covered by original hash",
        )
        session.add(legacy_log)
        session.commit()
        session.refresh(legacy_log)

        verification = logger.verify_log_entry(legacy_log.id, session)

    assert verification["valid"] is True


def test_audit_logger_keeps_chains_isolated_per_organization(monkeypatch, tmp_path):
    engine = _configure_audit_logger(monkeypatch, tmp_path)
    logger = AuditLogger()

    org_one_first = logger.log_verification(
        organization_id=1,
        user_id=None,
        query="2 + 2",
        result={"value": 4},
        is_verified=True,
        domain="math",
    )
    org_two_first = logger.log_verification(
        organization_id=2,
        user_id=None,
        query="5 + 5",
        result={"value": 10},
        is_verified=True,
        domain="math",
    )
    org_one_second = logger.log_verification(
        organization_id=1,
        user_id=None,
        query="3 + 3",
        result={"value": 6},
        is_verified=True,
        domain="math",
    )

    with Session(engine) as session:
        org_one_first_log = session.get(VerificationLog, int(org_one_first))
        org_two_first_log = session.get(VerificationLog, int(org_two_first))
        org_one_second_log = session.get(VerificationLog, int(org_one_second))

        assert org_one_first_log is not None
        assert org_two_first_log is not None
        assert org_one_second_log is not None
        assert org_two_first_log.previous_hash is None
        assert org_one_second_log.previous_hash == org_one_first_log.entry_hash
        assert org_one_second_log.previous_hash != org_two_first_log.entry_hash

        org_one_trail = logger.verify_audit_trail(1)
        org_two_trail = logger.verify_audit_trail(2)

    assert org_one_trail["valid"] is True
    assert org_two_trail["valid"] is True


def test_audit_logger_rejects_tampered_persisted_head_before_append(monkeypatch, tmp_path):
    engine = _configure_audit_logger(monkeypatch, tmp_path)
    logger = AuditLogger()

    log_id = logger.log_verification(
        organization_id=1,
        user_id=None,
        query="2 + 2",
        result={"value": 4},
        is_verified=True,
        domain="math",
    )

    with Session(engine) as session:
        log_entry = session.get(VerificationLog, int(log_id))
        assert log_entry is not None
        log_entry.raw_llm_output = "tampered persisted head"
        session.add(log_entry)
        session.commit()

    fresh_logger = AuditLogger()
    with pytest.raises(SecurityError, match="Persisted audit chain head failed integrity verification"):
        fresh_logger.log_verification(
            organization_id=1,
            user_id=None,
            query="3 + 3",
            result={"value": 6},
            is_verified=True,
            domain="math",
        )
