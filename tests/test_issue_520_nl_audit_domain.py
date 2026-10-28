"""#520: natural-language audit rows are stored with their own domain.

``/verify/natural_language``, ``/agents/{agent_id}/verify`` and the
natural-language items of ``/verify/batch`` wrote ``domain="MATH"``, while
their response and attestation say ``natural_language``. The ledger grouped
these requests under maths and could not tell them apart from
``/verify/math``.

Now they write ``NATURAL_LANGUAGE``. ``/verify/math`` and batch maths items
still write ``MATH``. Rows already written keep the domain they were signed
with: the domain is part of each signed, chained entry.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from qwed_new.api import main as api_main
from qwed_new.api.batch_audit import BATCH_AUDIT_DOMAIN
from qwed_new.core import audit_logger as audit_module
from qwed_new.core.diagnostics import DiagnosticResult
from qwed_new.core.models import VerificationLog
from qwed_new.core.tenant_context import TenantContext

ORG_ID = 1
NL_OUTPUT = {"diagnostic": DiagnosticResult.unverifiable("not proven").to_dict()}


@pytest.fixture
def client(isolated_audit_chain):
    tenant = TenantContext(organization_id=ORG_ID, organization_name="Org", tier="free", api_key="k")

    def _mock_session():
        # A plain function: FastAPI would read MagicMock's own parameters as
        # query parameters.
        return MagicMock()

    async def fake_nl(query, organization_id=None, preferred_provider=None):
        return dict(NL_OUTPUT)

    api_main.app.dependency_overrides[api_main.get_current_tenant] = lambda: tenant
    api_main.app.dependency_overrides[api_main.get_session] = _mock_session
    try:
        with patch("qwed_new.api.main.check_rate_limit"), \
                patch.object(api_main.control_plane, "process_natural_language", fake_nl), \
                patch.object(api_main.batch_service.control_plane, "process_natural_language", fake_nl):
            yield TestClient(api_main.app)
    finally:
        api_main.app.dependency_overrides.clear()


def _rows(engine):
    with Session(engine) as session:
        return session.exec(select(VerificationLog).order_by(VerificationLog.id)).all()


def test_the_natural_language_route_stores_its_own_domain(client, isolated_audit_chain):
    assert client.post("/verify/natural_language", json={"query": "what is 2+2"}).status_code == 200

    (row,) = _rows(isolated_audit_chain)
    assert row.domain == "NATURAL_LANGUAGE"
    assert row.query == "what is 2+2"


def test_a_batch_natural_language_item_stores_the_same_domain(client, isolated_audit_chain):
    client.post("/verify/batch", json={"items": [
        {"query": "what is 2+2", "type": "natural_language"},
        {"query": "2+2=4", "type": "math"},
    ]})

    domains = {json.loads(r.result)["batch_item_type"]: r.domain for r in _rows(isolated_audit_chain)}
    # Natural language no longer shares MATH with a maths item.
    assert domains == {"natural_language": "NATURAL_LANGUAGE", "math": "MATH"}


def test_the_new_domain_is_signed_and_chained(client, isolated_audit_chain):
    # The rows verify with their new domain, and rewriting it breaks the
    # chain: why rows written before this change keep MATH.
    client.post("/verify/batch", json={"items": [
        {"query": "what is 2+2", "type": "natural_language"},
        {"query": "2+2=4", "type": "math"},
    ]})
    logger = audit_module.get_audit_logger()
    assert logger.verify_audit_trail(ORG_ID)["valid"] is True

    nl_row = next(r for r in _rows(isolated_audit_chain) if r.domain == "NATURAL_LANGUAGE")
    with Session(isolated_audit_chain) as session:
        stored = session.get(VerificationLog, nl_row.id)
        stored.domain = "MATH"
        session.add(stored)
        session.commit()

    trail = logger.verify_audit_trail(ORG_ID)
    assert trail["valid"] is False
    assert nl_row.id in trail["failed_entries"]


def test_verify_math_still_stores_math(client, isolated_audit_chain):
    assert client.post("/verify/math", json={"expression": "2+2=4"}).status_code == 200

    (row,) = _rows(isolated_audit_chain)
    assert row.domain == "MATH"


def test_the_batch_map_gives_each_type_its_route_domain():
    assert BATCH_AUDIT_DOMAIN["natural_language"] == "NATURAL_LANGUAGE"
    assert BATCH_AUDIT_DOMAIN["math"] == "MATH"
    # Each type has its own domain: none is filed under another's.
    assert len(set(BATCH_AUDIT_DOMAIN.values())) == len(BATCH_AUDIT_DOMAIN)
