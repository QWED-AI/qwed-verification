"""#320: non-maths verify routes emitted authoritative VERIFIED without attestation.

The control plane's maths path signs every VERIFIED result and enforces the
attestation as mandatory. Every other verify route went through
``_enforce_trust``, hard-coded to ``require_attestation=False``, so a VERIFIED
result with a proof_ref left the server with no attestation ever issued or
checked, and a consumer applying the admission rule would admit it.

Now ``_enforce_trust`` signs the VERIFIED result (binding its proof_ref and
the query) and enforces the attestation as mandatory (core/trust.py). A
result that is not VERIFIED passes through unchanged; a VERIFIED result whose
attestation cannot be issued, or does not check out, is BLOCKED.
"""

import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from qwed_new.api import main as api_main
from qwed_new.core import trust
from qwed_new.core.attestation import (
    AttestationResult,
    AttestationStatus,
    create_verification_attestation,
)
from qwed_new.core.diagnostics import DiagnosticResult, DiagnosticStatus
from qwed_new.core.tenant_context import TenantContext
from qwed_new.core.trust import attest_and_enforce

PROOF = "sha256:" + "b" * 64


def _verified(proof_ref=PROOF, **fields):
    return DiagnosticResult(
        status=DiagnosticStatus.VERIFIED,
        agent_message="proven",
        developer_fields={"is_valid": True, **fields},
        proof_ref=proof_ref,
    )


def _signing_fails(monkeypatch):
    def fail(**kwargs):
        return AttestationResult(status=AttestationStatus.BLOCKED, token=None, error_code="SIGNING_FAILURE", error="x")

    monkeypatch.setattr(trust, "create_verification_attestation", fail)


# ---------------------------------------------------------------- the helper

def test_a_verified_result_is_signed_and_stays_verified():
    out = attest_and_enforce(_verified(), engine="logic", query="(GT x 5)")

    assert out.status is DiagnosticStatus.VERIFIED
    assert out.proof_ref == PROOF


@pytest.mark.parametrize("dr", [
    DiagnosticResult.unverifiable("not proven"),
    DiagnosticResult.blocked("refused", {"constraint_id": "x"}),
])
def test_a_result_that_is_not_verified_passes_through_unchanged(dr):
    out = attest_and_enforce(dr, engine="logic", query="q")

    assert out.status is dr.status
    assert out.agent_message == dr.agent_message


def test_verified_is_blocked_when_the_attestation_cannot_be_issued(monkeypatch):
    _signing_fails(monkeypatch)

    out = attest_and_enforce(_verified(), engine="fact", query="claim")

    assert out.status is DiagnosticStatus.BLOCKED
    assert out.developer_fields["constraint_id"] == "api.attestation.signing_error"
    assert out.proof_ref is None


def test_verified_is_blocked_when_the_attestation_is_for_another_query(monkeypatch):
    def for_another_query(**kwargs):
        return create_verification_attestation(**{**kwargs, "query": "something else"})

    monkeypatch.setattr(trust, "create_verification_attestation", for_another_query)

    out = attest_and_enforce(_verified(), engine="sql", query="SELECT 1")

    assert out.status is DiagnosticStatus.BLOCKED


def test_verified_with_a_malformed_proof_ref_is_blocked():
    out = attest_and_enforce(_verified(proof_ref="not-a-hash"), engine="code", query="x = 1")

    assert out.status is DiagnosticStatus.BLOCKED


# ---------------------------------------------------------------- the attestation

def test_an_attestation_binds_a_given_proof_hash_as_is():
    from qwed_new.core.attestation import get_attestation_service

    issued = create_verification_attestation(
        status="VERIFIED", verified=True, engine="logic", query="q", proof_hash=PROOF,
    )

    assert issued.status is AttestationStatus.ISSUED
    claims = get_attestation_service().verify_attestation(issued.token)[1]
    assert claims["qwed"]["proof_hash"] == PROOF


@pytest.mark.parametrize("bad", ["sha256:xyz", "md5:" + "a" * 32, "sha256:" + "A" * 64])
def test_a_malformed_proof_hash_is_not_signed(bad):
    issued = create_verification_attestation(
        status="VERIFIED", verified=True, engine="logic", query="q", proof_hash=bad,
    )

    assert issued.status is AttestationStatus.BLOCKED
    assert issued.error_code == "INVALID_PROOF_HASH"


# ---------------------------------------------------------------- the routes

@pytest.fixture
def client(isolated_audit_chain):
    tenant = TenantContext(organization_id=1, organization_name="Org", tier="free", api_key="k")

    def _mock_session():
        # A plain function, not MagicMock itself: FastAPI would read MagicMock's
        # constructor parameters as query parameters.
        return MagicMock()

    api_main.app.dependency_overrides[api_main.get_current_tenant] = lambda: tenant
    api_main.app.dependency_overrides[api_main.get_session] = _mock_session
    try:
        with patch("qwed_new.api.main.check_rate_limit"):
            yield TestClient(api_main.app)
    finally:
        api_main.app.dependency_overrides.clear()


def _logic_sat():
    async def sat(query, organization_id=None, preferred_provider=None):
        return {"status": "SAT", "model": {"x": "6"}, "dsl_code": "(GT x 5)"}

    return patch.object(api_main.control_plane, "process_logic_query", sat)


def _post(client, route):
    if route == "logic":
        with _logic_sat():
            return client.post("/verify/logic", json={"query": "(GT x 5)"}).json()
    if route == "math":
        return client.post("/verify/math", json={"expression": "2+2=4"}).json()
    raise AssertionError(route)


@pytest.mark.parametrize("route", ["logic", "math"])
def test_a_route_returns_verified_when_the_attestation_checks_out(client, route):
    body = _post(client, route)

    assert body["status"] == "VERIFIED"
    assert body["proof_ref"]


@pytest.mark.parametrize("route", ["logic", "math"])
def test_a_route_blocks_verified_when_signing_fails(client, monkeypatch, route):
    # Before #320 the advisory wrapper returned these VERIFIED regardless.
    _signing_fails(monkeypatch)

    body = _post(client, route)

    assert body["status"] == "BLOCKED"
    assert body["proof_ref"] is None


def test_no_route_enforces_attestation_as_advisory():
    source = Path(api_main.__file__).read_text(encoding="utf-8")

    assert not re.search(r"require_attestation\s*=\s*False", source)
    assert "advisory until #265" not in source
