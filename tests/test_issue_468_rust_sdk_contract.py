"""#468: the Rust SDK could not parse the server's responses.

The Rust SDK's contract tests (``sdk-rust/tests/contract.rs``) parse responses
captured from the server and stored in ``sdk-rust/tests/fixtures/``. This
test sends the same requests the SDK sends and checks that the server still
answers with the shape stored there, so a change to the envelope fails here
instead of silently breaking the SDK.

Only deterministic endpoints are compared. The natural-language, logic and
fact fixtures depend on which LLM provider is configured, so they are kept
as examples of fail-closed answers and checked by the Rust tests alone.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from qwed_new.api.main import app, get_current_tenant, get_session

FIXTURES = Path(__file__).resolve().parent.parent / "sdk-rust" / "tests" / "fixtures"

# The request body each fixture was captured with, as sdk-rust/src/lib.rs sends it.
REQUESTS = {
    "math_verified": ("/verify/math", {"expression": "2 + 2 = 4"}),
    "math_false": ("/verify/math", {"expression": "2 + 2 = 5"}),
    "math_ambiguous": ("/verify/math", {"expression": "1/2(3+1)"}),
    "code_safe": ("/verify/code", {"code": "x = 1 + 1", "language": "python"}),
    "code_unsafe": ("/verify/code", {"code": "import os\nos.system('rm -rf /')", "language": "python"}),
    "sql": (
        "/verify/sql",
        {"query": "SELECT id FROM users", "schema_ddl": "CREATE TABLE users (id INT)", "dialect": "sqlite"},
    ),
    "batch": (
        "/verify/batch",
        {"items": [{"query": "2 + 2 = 4", "type": "math"}, {"query": "2 + 2 = 5", "type": "math"}]},
    ),
}

ENVIRONMENT_DEPENDENT = {"natural_language", "logic", "fact"}

# The JSON types VerificationResponse in sdk-rust/src/lib.rs reads. A field
# of another type makes the Rust call fail with Error::Serialization.
NONE = type(None)
RUST_FIELD_TYPES = {
    "status": (str,),
    "admission": (str, NONE),
    "proof_ref": (str, NONE),
    "agent_message": (str, NONE),
    "is_authoritative": (bool, NONE),
    "constraint_id": (str, NONE),
    "developer_fields": (dict, NONE),
}
# BatchResult and BatchResponse fields, the same way.
BATCH_ITEM_TYPES = {
    "id": (str,),
    "status": (str,),
    "query": (str, NONE),
    "type": (str, NONE),
    "result": (dict, NONE),
    "latency_ms": (int, float, NONE),
}
BATCH_JOB_TYPES = {
    "job_id": (str,),
    "status": (str,),
    "progress_percent": (int, float, NONE),
    "total_items": (int, NONE),
    "completed_items": (int, NONE),
    "failed_items": (int, NONE),
    "items": (list,),
}


def _assert_types(answer, types, where):
    for field, allowed in types.items():
        if field in answer:
            value = answer[field]
            # bool is an int in Python; Rust's integers do not accept it.
            ok = isinstance(value, allowed) and not (isinstance(value, bool) and bool not in allowed)
            assert ok, f"{where}: {field} is {type(value).__name__}, the Rust SDK reads {allowed}"
    assert "status" not in types or "status" in answer, f"{where}: no status"


def _mock_session():
    # A named function, not the MagicMock class: FastAPI reads a dependency's
    # signature, and MagicMock's own parameters would become request fields.
    return MagicMock()


@pytest.fixture
def client():
    tenant = MagicMock(organization_id=123, api_key=MagicMock(name="tenant_api_key"), user_id=456)
    app.dependency_overrides[get_current_tenant] = lambda: tenant
    app.dependency_overrides[get_session] = _mock_session
    try:
        with patch("qwed_new.api.main.check_rate_limit"):
            yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


def _fixture(name):
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def _post(client, name):
    path, body = REQUESTS[name]
    response = client.post(path, json=body)
    assert response.status_code == 200, response.text
    return response.json()


def test_every_fixture_is_accounted_for():
    on_disk = {p.stem for p in FIXTURES.glob("*.json")}
    assert on_disk == set(REQUESTS) | ENVIRONMENT_DEPENDENT


@pytest.mark.parametrize("name", [n for n in REQUESTS if n != "batch"])
def test_the_server_still_answers_with_the_stored_envelope(client, isolated_audit_chain, name):
    stored = _fixture(name)
    live = _post(client, name)

    assert live["status"] == stored["status"]
    assert live.get("admission") == stored.get("admission")
    assert (live["proof_ref"] is None) == (stored["proof_ref"] is None)
    assert set(live) == set(stored)
    _assert_types(live, RUST_FIELD_TYPES, name)


def test_the_server_still_answers_batches_with_the_stored_shape(client, isolated_audit_chain):
    stored = _fixture("batch")
    live = _post(client, "batch")

    assert live["status"] == stored["status"]
    assert set(live) == set(stored)
    _assert_types(live, BATCH_JOB_TYPES, "batch")
    assert len(live["items"]) == len(stored["items"])
    for index, (live_item, stored_item) in enumerate(zip(live["items"], stored["items"])):
        where = f"batch item {index}"
        assert set(live_item) == set(stored_item)
        _assert_types(live_item, BATCH_ITEM_TYPES, where)
        live_result, stored_result = live_item["result"], stored_item["result"]
        assert live_result["status"] == stored_result["status"]
        assert live_result.get("admission") == stored_result.get("admission")
        assert (live_result["proof_ref"] is None) == (stored_result["proof_ref"] is None)
        _assert_types(live_result, RUST_FIELD_TYPES, where)


@pytest.mark.parametrize(
    "answer, field",
    [
        ({"status": "VERIFIED", "proof_ref": {"sha256": "ab"}}, "proof_ref"),
        ({"status": "VERIFIED", "is_authoritative": "true"}, "is_authoritative"),
        ({"status": "VERIFIED", "admission": True}, "admission"),
        ({"status": 1}, "status"),
    ],
)
def test_the_type_check_catches_a_field_rust_cannot_read(answer, field):
    with pytest.raises(AssertionError, match=field):
        _assert_types(answer, RUST_FIELD_TYPES, "example")


@pytest.mark.parametrize("name", sorted(set(REQUESTS) | ENVIRONMENT_DEPENDENT))
def test_fixtures_hold_the_fields_the_rust_sdk_relies_on(name):
    stored = _fixture(name)
    answers = [item["result"] for item in stored["items"]] if name == "batch" else [stored]
    for answer in answers:
        _assert_types(answer, RUST_FIELD_TYPES, name)
        assert answer["status"] in {"VERIFIED", "UNVERIFIABLE", "BLOCKED"}
        assert answer.get("admission") in {None, "ADMIT", "BLOCKED"}
        # VERIFIED carries a proof; nothing else does.
        assert (answer["proof_ref"] is not None) == (answer["status"] == "VERIFIED")
        if answer.get("admission") == "ADMIT":
            assert answer["status"] == "VERIFIED"
