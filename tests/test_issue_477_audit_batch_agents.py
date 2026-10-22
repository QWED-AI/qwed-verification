"""#477: /verify/batch and /agents/{id}/verify wrote no rows to the audit chain.

Every single /verify/* route appends a chained, signed VerificationLog row and
returns 500 if the append fails. The batch route ran up to 100 items and wrote
no row, and the agent route logged only to AgentActivity, which is neither
chained nor signed. A key holder could run verifications that never appeared
in the audit trail.

Now each batch item appends one row (job and item id, type, outcome), and an
item whose append fails is returned as failed without its result. The agent
route appends the row /verify/natural_language writes, plus the agent id, and
returns 500 if the append fails.
"""

import asyncio
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine, select

from qwed_new.api import batch_audit, main
from qwed_new.auth.security import generate_api_key
from qwed_new.core import audit_logger as audit_module
from qwed_new.core.agent_models import AgentActivity
from qwed_new.core.agent_registry import agent_registry
from qwed_new.core.audit_logger import AUDIT_SECRET_ENV_VAR
from qwed_new.core.batch import BatchItem, VerificationType
from qwed_new.core.diagnostics import DiagnosticResult
from qwed_new.core.models import ApiKey, Organization, User, VerificationLog

PROOF = "sha256:" + "a" * 64


@pytest.fixture
def env(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'audit477.db'}")
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(audit_module, "engine", engine)
    monkeypatch.setenv(AUDIT_SECRET_ENV_VAR, "audit-fixture-value")
    monkeypatch.setattr(audit_module, "_default_logger", None)
    session = Session(engine)
    org = Organization(name="acme", display_name="Acme")
    session.add(org)
    session.commit()
    session.refresh(org)
    user = User(email="member@test", password_hash="x", organization_id=org.id, role="member")
    session.add(user)
    session.commit()
    session.refresh(user)
    raw, digest = generate_api_key()
    session.add(ApiKey(key_hash=digest, key_preview=raw[:8], organization_id=org.id, user_id=user.id))
    session.commit()

    main.app.dependency_overrides[main.get_session] = lambda: session
    client = TestClient(main.app)
    yield SimpleNamespace(engine=engine, session=session, org=org, user=user, key=raw, client=client)
    main.app.dependency_overrides.clear()
    session.close()


def _rows(env):
    env.session.expire_all()
    return env.session.exec(
        select(VerificationLog).where(VerificationLog.organization_id == env.org.id).order_by(VerificationLog.id)
    ).all()


def _trail_is_valid(env):
    return audit_module.get_audit_logger().verify_audit_trail(env.org.id)["valid"]


def _break_the_audit_append(monkeypatch):
    class _Broken:
        def log_verification(self, **kwargs):
            raise RuntimeError("database unavailable")

    monkeypatch.setattr(main, "get_audit_logger", lambda: _Broken())


# ---------------------------------------------------------------- batch

@pytest.fixture
def fake_items(monkeypatch):
    async def verify(item, organization_id):
        if item.query == "boom":
            raise ValueError("engine failed")
        if item.query == "1+1=2":
            return {"status": "VERIFIED", "proof_ref": PROOF, "developer_fields": {"is_valid": True}}
        return {"status": "UNVERIFIABLE", "proof_ref": None, "developer_fields": {}}

    monkeypatch.setattr(main.batch_service, "_verify_item", verify)


def _batch(env, items):
    return env.client.post("/verify/batch", json={"items": items}, headers={"x-api-key": env.key})


def test_each_batch_item_appends_one_chained_row(env, fake_items):
    response = _batch(env, [
        {"query": "1+1=2", "type": "math"},
        {"query": "(AND (GT x 5))", "type": "logic"},
        {"query": "select 1", "type": "sql"},
    ])

    assert response.status_code == 200
    body = response.json()
    rows = _rows(env)
    assert len(rows) == 3
    assert _trail_is_valid(env)
    by_item = {json.loads(r.result)["batch_item_id"]: r for r in rows}
    assert set(by_item) == {item["id"] for item in body["items"]}
    for item in body["items"]:
        row = by_item[item["id"]]
        payload = json.loads(row.result)
        assert payload["batch_job_id"] == body["job_id"]
        assert payload["batch_item_type"] == item["type"]
        assert payload["item_status"] == "completed"
        assert row.query == item["query"]
        # user_id: no /verify/* route records the caller yet (#484).
    assert {r.domain for r in rows} == {"MATH", "LOGIC", "SQL"}
    assert [r.is_verified for r in rows if r.domain == "MATH"] == [True]
    assert [r.is_verified for r in rows if r.domain != "MATH"] == [False, False]


def test_a_failed_item_still_appends_its_row(env, fake_items):
    response = _batch(env, [{"query": "boom", "type": "math"}])

    assert response.json()["items"][0]["status"] == "failed"
    (row,) = _rows(env)
    payload = json.loads(row.result)
    assert payload["item_status"] == "failed"
    assert payload["details"] == {"result": None, "error": "engine failed"}
    assert row.is_verified is False


def test_an_item_whose_append_fails_is_failed_without_its_result(env, fake_items, monkeypatch):
    _break_the_audit_append(monkeypatch)

    response = _batch(env, [{"query": "1+1=2", "type": "math"}, {"query": "2+2", "type": "math"}])

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "failed"
    assert body["failed_items"] == 2
    for item in body["items"]:
        assert item["status"] == "failed"
        assert item["result"] is None
        assert item["error"] == "audit persistence failed"
    assert _rows(env) == []


def _nl(semantics_verified):
    dr = DiagnosticResult.verified(
        "Identity verified",
        developer_fields={"query_semantics_verified": semantics_verified, "is_valid": True},
        evidence={"left": "2+2", "right": "4"},
        proof_data="2+2=4",
    )
    return {"diagnostic": dr.to_dict()}


@pytest.mark.parametrize("vtype, status, result, verified", [
    # math and code: VERIFIED with is_valid True, as /verify/math and /verify/code record.
    ("math", "completed", {"status": "VERIFIED", "proof_ref": PROOF, "developer_fields": {"is_valid": True}}, True),
    ("math", "completed", {"status": "UNVERIFIABLE", "proof_ref": None, "developer_fields": {"is_valid": True}}, False),
    ("math", "completed", {"status": "VERIFIED", "proof_ref": PROOF, "developer_fields": {}}, False),
    ("math", "failed", None, False),
    ("code", "completed", {"status": "VERIFIED", "proof_ref": PROOF, "developer_fields": {"is_valid": True}}, True),
    # Code proven unsafe is VERIFIED but not valid.
    ("code", "completed", {"status": "VERIFIED", "proof_ref": PROOF, "developer_fields": {"is_valid": False}}, False),
    # logic: SAT, which /verify/logic turns into VERIFIED with a proof_ref.
    ("logic", "completed", {"status": "SAT"}, True),
    ("logic", "completed", {"status": "UNSAT"}, False),
    # fact and sql: is_authoritative; a proven-malicious query is VERIFIED.
    ("sql", "completed", {"status": "VERIFIED", "proof_ref": PROOF, "developer_fields": {"is_valid": False}}, True),
    ("sql", "completed", {"status": "VERIFIED", "proof_ref": None}, False),
    ("fact", "completed", {"status": "VERIFIED", "proof_ref": PROOF}, True),
    ("fact", "completed", {"status": "UNVERIFIABLE", "proof_ref": None}, False),
    # natural language: the /verify/natural_language admission rule.
    ("natural_language", "completed", _nl(True), True),
    ("natural_language", "completed", _nl(False), False),
    ("natural_language", "completed", {"status": "VERIFIED", "proof_ref": PROOF}, False),
    ("natural_language", "completed", {"diagnostic": {"status": "VERIFIED"}}, False),
])
def test_a_batch_row_is_verified_as_its_route_records(vtype, status, result, verified):
    item = BatchItem(id="j-0", query="q", verification_type=VerificationType(vtype), status=status, result=result)

    assert batch_audit.batch_item_is_verified(item) is verified


def test_the_batch_ids_survive_a_result_over_the_cap(env, monkeypatch):
    async def huge(item, organization_id):
        return {"status": "UNVERIFIABLE", "issues": [f"issue {i} " + "x" * 200 for i in range(2000)]}

    monkeypatch.setattr(main.batch_service, "_verify_item", huge)

    body = _batch(env, [{"query": "big", "type": "code"}]).json()

    (row,) = _rows(env)
    payload = json.loads(row.result)
    assert payload["batch_job_id"] == body["job_id"]
    assert payload["batch_item_id"] == body["items"][0]["id"]
    assert payload["batch_item_type"] == "code"
    assert payload["item_status"] == "completed"
    assert len(row.result) <= main._MAX_LOG_RESULT_CHARS
    assert _trail_is_valid(env)


# ---------------------------------------------------------------- agents

@pytest.fixture
def agent(env, monkeypatch):
    registered, token = agent_registry.register_agent(env.session, env.org.id, "bot")

    async def nl(query, organization_id=None, preferred_provider=None):
        return {"diagnostic": DiagnosticResult.unverifiable("not proven").to_dict()}

    monkeypatch.setattr(main.control_plane, "process_natural_language", nl)
    return SimpleNamespace(id=registered.id, token=token)


def _agent_verify(env, agent):
    return env.client.post(
        f"/agents/{agent.id}/verify", json={"query": "what is 2+2"}, headers={"x-agent-token": agent.token}
    )


def test_an_agent_verification_appends_a_chained_row(env, agent):
    response = _agent_verify(env, agent)

    assert response.status_code == 200
    (row,) = _rows(env)
    assert _trail_is_valid(env)
    payload = json.loads(row.result)
    assert payload["agent_id"] == agent.id
    assert payload["status"] == "UNVERIFIABLE"
    assert row.query == "what is 2+2"
    assert row.is_verified is False
    assert row.domain == "MATH"
    # The natural-language admission the route decided (#307).
    assert row.admission == "BLOCKED"


def test_the_agent_append_runs_off_the_event_loop(env, agent, monkeypatch):
    seen = []
    real = main._safe_commit_log

    def commit(log):
        try:
            asyncio.get_running_loop()
            seen.append("on the event loop")
        except RuntimeError:
            seen.append("in a worker thread")
        real(log)

    monkeypatch.setattr(main, "_safe_commit_log", commit)

    assert _agent_verify(env, agent).status_code == 200
    assert seen == ["in a worker thread"]


def test_an_agent_verification_is_not_returned_if_the_append_fails(env, agent, monkeypatch):
    _break_the_audit_append(monkeypatch)

    response = _agent_verify(env, agent)

    assert response.status_code == 500
    assert response.json()["detail"] == "audit persistence failed"
    assert _rows(env) == []
    env.session.expire_all()
    assert env.session.exec(select(AgentActivity).where(AgentActivity.agent_id == agent.id)).all() == []
