"""#484: the audit log routes report the stored verdict and the chain entry.

GET /audit/logs and GET /audit/logs/{id} returned only ``status``, derived
from ``is_verified``: an UNVERIFIABLE result read "blocked", and what
``is_verified`` means differs by route. They now also return ``verdict``,
read from the stored result and never worked out from ``is_verified``, and
the chain fields VerificationLog already stores: ``entry_hash`` on the list,
and ``entry_hash``, ``previous_hash`` and ``hmac_signature`` on the detail.
``status`` stays as it was, for existing clients.
"""

import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine

from qwed_new.api import main
from qwed_new.auth.audit_routes import stored_verdict
from qwed_new.auth.security import create_access_token
from qwed_new.core.models import Organization, User, VerificationLog


def diagnostic(status, **extra):
    return json.dumps({"status": status, "agent_message": "m", "developer_fields": {}, "proof_ref": None, **extra})


def context_document(verdict):
    return json.dumps({"spec_version": "1.0", "context": {"decision": {"admission": "ADMIT"}}, "verdict": verdict})


def batch_row(inner):
    return json.dumps({
        "batch_job_id": "j1",
        "batch_item_id": "j1-0",
        "batch_item_type": "math",
        "item_status": "completed",
        "details": {"result": inner, "error": None},
    })


# ---------------------------------------------------------------- stored_verdict

@pytest.mark.parametrize("result, verdict", [
    (diagnostic("VERIFIED"), "VERIFIED"),
    (diagnostic("UNVERIFIABLE"), "UNVERIFIABLE"),
    (diagnostic("BLOCKED"), "BLOCKED"),
    (context_document("UNVERIFIABLE"), "UNVERIFIABLE"),
    (batch_row({"status": "BLOCKED"}), "BLOCKED"),
])
def test_reads_the_verdict_from_each_stored_shape(result, verdict):
    assert stored_verdict(result) == verdict


@pytest.mark.parametrize("result", [
    # Values outside the three verdicts: a logic engine's SAT, a
    # lower-case spelling, an admission in the verdict's place.
    diagnostic("SAT"),
    diagnostic("verified"),
    context_document("ADMIT"),
    batch_row({"status": "SAT"}),
    # A batch row's own item_status is not a verdict.
    batch_row(None),
    # Shapes with no verdict to read.
    json.dumps({"truncated": True, "preview": "{'status': 'VERIFIED'"}),
    json.dumps({"sample": True}),
    json.dumps(["VERIFIED"]),
    json.dumps({"status": None}),
    "not json",
    "",
])
def test_anything_else_has_no_verdict(result):
    assert stored_verdict(result) is None


def test_a_document_verdict_wins_over_a_stray_status():
    doc = json.loads(context_document("BLOCKED"))
    doc["status"] = "VERIFIED"
    assert stored_verdict(json.dumps(doc)) == "BLOCKED"


# ---------------------------------------------------------------- the routes

@pytest.fixture
def env(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'audit.db'}")
    SQLModel.metadata.create_all(engine)
    session = Session(engine)

    def add(obj):
        session.add(obj)
        session.commit()
        session.refresh(obj)
        return obj

    org = add(Organization(name="acme", display_name="Acme"))
    viewer = add(User(email="viewer@test", password_hash="x", organization_id=org.id, role="viewer"))

    # is_verified=False on an UNVERIFIABLE result is what made "status" read
    # "blocked"; the verdict must come from the result instead.
    unverifiable = add(VerificationLog(
        organization_id=org.id, query="q1", result=diagnostic("UNVERIFIABLE"), is_verified=False,
        domain="MATH", entry_hash="h1", previous_hash="0" * 64, hmac_signature="s1",
    ))
    truncated = add(VerificationLog(
        organization_id=org.id, query="q2", result=json.dumps({"truncated": True, "preview": ""}),
        is_verified=True, domain="STATS", entry_hash="h2", previous_hash="h1", hmac_signature="s2",
    ))
    # What /verify/math stores for a false identity: the check ran to a
    # proof, so the verdict is VERIFIED, and is_verified is False.
    disproven = add(VerificationLog(
        organization_id=org.id, query="(a + b)**2 = a**2 + b**2",
        result=diagnostic("VERIFIED", agent_message="Identity is false",
                          developer_fields={"is_valid": False}, proof_ref="sha256:p"),
        is_verified=False, domain="MATH", entry_hash="h3", previous_hash="h2", hmac_signature="s3",
    ))

    main.app.dependency_overrides[main.get_session] = lambda: session
    client = TestClient(main.app)
    token = create_access_token({"sub": str(viewer.id)})

    def get(path):
        response = client.get(path, headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200, response.text
        return response.json()

    yield SimpleNamespace(get=get, unverifiable=unverifiable, truncated=truncated, disproven=disproven)
    main.app.dependency_overrides.clear()
    session.close()


def test_the_list_reports_the_stored_verdict_and_the_entry_hash(env):
    rows = {row["id"]: row for row in env.get("/audit/logs")["logs"]}

    first = rows[str(env.unverifiable.id)]
    assert first["verdict"] == "UNVERIFIABLE"
    assert first["status"] == "blocked"  # unchanged, for existing clients
    assert first["entry_hash"] == "h1"

    second = rows[str(env.truncated.id)]
    assert second["verdict"] is None
    assert second["entry_hash"] == "h2"


def test_a_disproven_claim_is_verified_but_not_admitted(env):
    # The verdict is not an admission: a false identity is VERIFIED, and the
    # route's own flag still says "blocked". Neither route claims to return
    # an admission, since these rows do not store one.
    row = next(r for r in env.get("/audit/logs")["logs"] if r["id"] == str(env.disproven.id))
    detail = env.get(f"/audit/logs/{env.disproven.id}")

    for body in (row, detail):
        assert body["verdict"] == "VERIFIED"
        assert body["status"] == "blocked"
        assert "admission" not in body


def test_the_list_does_not_return_the_link_or_signature(env):
    row = env.get("/audit/logs")["logs"][0]
    assert "previous_hash" not in row
    assert "hmac_signature" not in row


def test_the_detail_returns_the_whole_chain_entry(env):
    detail = env.get(f"/audit/logs/{env.unverifiable.id}")

    assert detail["verdict"] == "UNVERIFIABLE"
    assert detail["status"] == "blocked"
    assert detail["entry_hash"] == "h1"
    assert detail["previous_hash"] == "0" * 64
    assert detail["hmac_signature"] == "s1"


def test_the_detail_of_a_truncated_result_has_no_verdict(env):
    detail = env.get(f"/audit/logs/{env.truncated.id}")

    assert detail["verdict"] is None
    assert detail["previous_hash"] == "h1"
