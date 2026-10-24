"""#319 (part 3): the Python SDK reads and verifies attestations.

The server now returns ``attestation`` with every VERIFIED answer and
publishes its key at ``/.well-known/jwks.json``. The SDK keeps the token on
VerificationResult and verifies it: the ES256 signature with the key its
``kid`` names, the issuer and expiry, a VERIFIED status, and that it is this
answer's token (``proof_hash`` is the answer's ``proof_ref``; optionally,
``query_hash`` is the statement's).

Tokens are issued at test time, by the server's own code; none is stored in
the repository.
"""

import asyncio
import base64
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from qwed_new.api import main as api_main
from qwed_new.core import attestation as server_attestation
from qwed_new.core.attestation import AttestationService
from qwed_new.core.attestation import VerificationResult as ServerResult
from qwed_new.core.tenant_context import TenantContext
from qwed_sdk import (
    AttestationError,
    QWEDAsyncClient,
    QWEDClient,
    VerificationResult,
    verify_attestation,
)
from qwed_sdk.attestation import KeyMismatchError, KeysUnavailableError, statement_hash

PROOF = "sha256:" + "e" * 64
QUERY = "2+2=4"


def _pem():
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


@pytest.fixture
def server():
    """A server-side service with a configured key, and its JWKS."""
    service = AttestationService(key_continuity_policy="configured", private_key_pem=_pem(), validity_seconds=3600)
    jwks = {"keys": [{**k, "alg": "ES256", "use": "sig"} for k in service.get_issuer_info()["public_keys"]]}
    return service, jwks


def _token(service, status="VERIFIED", proof_hash=PROOF, query=QUERY, issued_at=None):
    result = ServerResult(status=status, verified=True, engine="math")
    return service.create_attestation(result, query, proof_hash=proof_hash, issued_at=issued_at, store=False).jwt_token


# ---------------------------------------------------------------- verify_attestation

def test_a_genuine_attestation_verifies(server):
    service, jwks = server

    claims = verify_attestation(_token(service), jwks, proof_ref=PROOF, query=QUERY)

    assert claims["qwed"]["proof_hash"] == PROOF
    assert claims["qwed"]["query_hash"] == statement_hash(QUERY)


def test_another_answers_token_is_refused(server):
    service, jwks = server

    token = _token(service)

    with pytest.raises(AttestationError, match="another answer"):
        verify_attestation(token, jwks, proof_ref="sha256:" + "f" * 64)


def test_a_token_for_another_statement_is_refused(server):
    service, jwks = server

    token = _token(service)

    with pytest.raises(AttestationError, match="another statement"):
        verify_attestation(token, jwks, proof_ref=PROOF, query="2+2=5")


def test_a_token_that_does_not_attest_verified_is_refused(server):
    service, jwks = server

    token = _token(service, status="BLOCKED")

    with pytest.raises(AttestationError, match="VERIFIED"):
        verify_attestation(token, jwks, proof_ref=PROOF)


def test_an_expired_token_is_refused(server):
    service, jwks = server
    token = _token(service, issued_at=int(time.time()) - 7200)  # lived 3600 s

    with pytest.raises(AttestationError, match="expired"):
        verify_attestation(token, jwks, proof_ref=PROOF)


def test_a_token_from_another_key_is_refused(server):
    _, jwks = server
    stranger = AttestationService(key_continuity_policy="configured", private_key_pem=_pem())

    token = _token(stranger)  # its kid is its own thumbprint, not in this JWKS

    with pytest.raises(KeyMismatchError):
        verify_attestation(token, jwks, proof_ref=PROOF)


def test_a_token_signed_by_another_key_under_the_right_kid_is_refused(server):
    service, jwks = server
    forger = ec.generate_private_key(ec.SECP256R1())
    claims = verify_attestation(_token(service), jwks, proof_ref=PROOF)
    forged = jwt.encode(claims, forger, algorithm="ES256",
                        headers={"kid": service.key_id, "typ": "qwed-attestation+jwt"})

    with pytest.raises(KeyMismatchError, match="signature"):
        verify_attestation(forged, jwks, proof_ref=PROOF)


def test_a_token_used_before_its_nbf_is_refused(server):
    # The server sets no nbf, but a token that carries one is held to it, as
    # in the TypeScript SDK (#512 review).
    service, jwks = server
    claims = verify_attestation(_token(service), jwks, proof_ref=PROOF)
    early = jwt.encode({**claims, "nbf": int(time.time()) + 600}, service._key_pair._private_key,
                       algorithm="ES256", headers={"kid": service.key_id, "typ": "qwed-attestation+jwt"})

    with pytest.raises(AttestationError, match="not yet valid"):
        verify_attestation(early, jwks, proof_ref=PROOF)


@pytest.mark.parametrize("alg", ["none", "HS256"])
def test_a_token_naming_another_algorithm_is_refused_before_any_key_is_used(server, alg):
    service, jwks = server
    claims = verify_attestation(_token(service), jwks, proof_ref=PROOF)
    header = {"kid": service.key_id, "typ": "qwed-attestation+jwt"}
    token = jwt.encode(claims, "k" * 32, algorithm="HS256", headers=header) if alg == "HS256" else \
        jwt.encode(claims, None, algorithm="none", headers=header)

    with pytest.raises(AttestationError, match="ES256"):
        verify_attestation(token, jwks, proof_ref=PROOF)


def test_another_issuer_is_refused(server):
    service, jwks = server

    token = _token(service)

    with pytest.raises(AttestationError, match="claims"):
        verify_attestation(token, jwks, proof_ref=PROOF, issuer="did:example:other")


@pytest.mark.parametrize("token", ["", "not.a.jwt", None, "W10.e30.c2ln"])  # W10: a header of []
def test_no_token_or_a_malformed_one_is_refused(server, token):
    _, jwks = server

    with pytest.raises(AttestationError):
        verify_attestation(token, jwks, proof_ref=PROOF)


def test_a_jwks_key_that_is_not_es256_p256_is_refused(server):
    service, jwks = server
    bad = {"keys": [{**jwks["keys"][0], "crv": "P-384"}]}
    token = _token(service)

    with pytest.raises(KeyMismatchError, match="ES256 P-256"):
        verify_attestation(token, bad, proof_ref=PROOF)


def test_keys_of_another_type_or_broken_ones_in_the_jwks_are_skipped(server):
    service, jwks = server
    other = {"kty": "RSA", "kid": "rsa-key", "n": "AQAB", "e": "AQAB"}
    broken = {**jwks["keys"][0], "kid": "broken", "x": "not-a-coordinate"}

    claims = verify_attestation(_token(service), {"keys": [other, broken, *jwks["keys"]]}, proof_ref=PROOF)

    assert claims["qwed"]["proof_hash"] == PROOF


def test_a_kid_that_does_not_name_the_signing_key_is_refused(server):
    # Two keys during a rotation: the token verifies with one but its
    # header names the other.
    service, jwks = server
    other = AttestationService(key_continuity_policy="configured", private_key_pem=_pem())
    both = {"keys": [*jwks["keys"], *({**k, "alg": "ES256"} for k in other.get_issuer_info()["public_keys"])]}
    claims = verify_attestation(_token(service), jwks, proof_ref=PROOF)
    token = jwt.encode(claims, service._key_pair._private_key, algorithm="ES256",
                       headers={"kid": other.key_id, "typ": "qwed-attestation+jwt"})

    with pytest.raises(AttestationError, match="does not name the key"):
        verify_attestation(token, both, proof_ref=PROOF)


def test_a_header_nested_too_deeply_to_parse_is_refused(server):
    # The JSON parser raises RecursionError, not ValueError (#512 review).
    _, jwks = server
    header = base64.urlsafe_b64encode(b"[" * 100_000).rstrip(b"=").decode()

    with pytest.raises(AttestationError, match="not a JWT"):
        verify_attestation(f"{header}.e30.c2ln", jwks, proof_ref=PROOF)


def test_a_recursion_error_from_pyjwt_is_an_attestation_error(server, monkeypatch):
    # PyJWT 2.14 reports deep nesting as DecodeError; a version that lets
    # the RecursionError through still gives an AttestationError.
    service, jwks = server

    def deep(*args, **kwargs):
        raise RecursionError("maximum recursion depth exceeded")

    token = _token(service)
    monkeypatch.setattr(jwt, "decode_complete", deep)

    with pytest.raises(AttestationError, match="not a JWT"):
        verify_attestation(token, jwks, proof_ref=PROOF)


def test_a_token_issued_a_moment_in_the_future_still_verifies(server):
    # A client whose clock is behind the server's: iat is required but not
    # compared with the clock, as in the TypeScript SDK (#512 review).
    service, jwks = server
    token = _token(service, issued_at=int(time.time()) + 120)

    assert verify_attestation(token, jwks, proof_ref=PROOF)["iat"] > time.time()


def test_a_signed_token_that_is_not_a_qwed_attestation_is_refused(server):
    service, jwks = server
    claims = verify_attestation(_token(service), jwks, proof_ref=PROOF)
    private = service._key_pair._private_key
    other = jwt.encode(claims, private, algorithm="ES256", headers={"kid": service.key_id, "typ": "JWT"})

    with pytest.raises(AttestationError, match="not a QWED attestation"):
        verify_attestation(other, jwks, proof_ref=PROOF)


@pytest.mark.parametrize("header", [{"alg": "ES256"}, {"alg": "ES256", "kid": ""}])
def test_a_token_that_names_no_key_is_refused(server, header):
    service, jwks = server
    claims = verify_attestation(_token(service), jwks, proof_ref=PROOF)
    token = jwt.encode(claims, service._key_pair._private_key, algorithm="ES256", headers=header)

    with pytest.raises(AttestationError, match="no key"):
        verify_attestation(token, jwks, proof_ref=PROOF)


@pytest.mark.parametrize("jwks", [{}, {"keys": "x"}, []])
def test_a_jwks_without_a_key_list_is_refused(server, jwks):
    service, _ = server
    token = _token(service)

    with pytest.raises(AttestationError, match="no keys"):
        verify_attestation(token, jwks, proof_ref=PROOF)


def test_an_unusable_jwks_key_is_refused(server):
    service, jwks = server
    broken = {"keys": [{**jwks["keys"][0], "x": "not-a-coordinate"}]}
    token = _token(service)

    with pytest.raises(AttestationError, match="unusable"):
        verify_attestation(token, broken, proof_ref=PROOF)


@pytest.mark.parametrize("proof_ref", ["", None])
def test_an_answer_without_a_proof_ref_cannot_be_bound(server, proof_ref):
    service, jwks = server
    token = _token(service)

    with pytest.raises(AttestationError, match="no proof_ref"):
        verify_attestation(token, jwks, proof_ref=proof_ref)


# ---------------------------------------------------------------- the result type

def test_a_result_keeps_its_attestation_and_proof_ref():
    typed = VerificationResult.from_dict({"status": "VERIFIED", "attestation": "t", "proof_ref": PROOF})
    untyped = VerificationResult.from_dict({"status": "BLOCKED", "attestation": 1})

    assert (typed.attestation, typed.proof_ref) == ("t", PROOF)
    assert (untyped.attestation, untyped.proof_ref) == (None, None)


# ---------------------------------------------------------------- the client, against the server

@pytest.fixture
def live(isolated_audit_chain, monkeypatch):
    """A QWEDClient talking to the app in process, with a configured key."""
    monkeypatch.setattr(server_attestation, "_default_service", None)
    monkeypatch.setenv(server_attestation.SIGNING_KEY_ENV, _pem().decode())
    tenant = TenantContext(organization_id=1, organization_name="Org", tier="free", api_key="k")

    def _mock_session():
        from unittest.mock import MagicMock
        return MagicMock()

    api_main.app.dependency_overrides[api_main.get_current_tenant] = lambda: tenant
    api_main.app.dependency_overrides[api_main.get_session] = _mock_session
    monkeypatch.setattr(api_main, "check_rate_limit", lambda *a, **k: None)
    client = QWEDClient(api_key="k", base_url="http://testserver")
    client._client = TestClient(api_main.app)
    try:
        yield client
    finally:
        api_main.app.dependency_overrides.clear()


def test_the_client_verifies_a_live_answer_end_to_end(live):
    result = live.verify_math(QUERY)

    assert result.status == "VERIFIED"
    claims = live.verify_attestation(result, query=QUERY)
    assert claims["qwed"]["proof_hash"] == result.proof_ref


def test_the_client_refuses_a_live_answer_whose_proof_ref_was_changed(live):
    answer = live.verify_math(QUERY).result
    answer["proof_ref"] = "sha256:" + "0" * 64

    with pytest.raises(AttestationError, match="another answer"):
        live.verify_attestation(answer)


def _client_with_cached(jwks_cached, age, handler):
    """A client holding ``jwks_cached`` as fetched ``age`` seconds ago."""
    client = QWEDClient(api_key="k", base_url="http://qwed.test")
    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    client._jwks = jwks_cached
    client._jwks_fetched_at = client._jwks_attempted_at = time.monotonic() - age
    return client


def test_the_client_fetches_the_jwks_again_when_the_kid_is_unknown(server):
    # The cache is older than the 30 s minimum (an old key; the server has
    # rotated): one more fetch picks up the new key.
    service, jwks = server
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, json=jwks)

    client = _client_with_cached({"keys": []}, 60, handler)
    claims = client.verify_attestation({"attestation": _token(service), "proof_ref": PROOF})

    assert claims["qwed"]["proof_hash"] == PROOF
    assert calls == ["/.well-known/jwks.json"]


def test_an_unknown_kid_does_not_refetch_a_fresh_jwks(server):
    # A stream of tokens with made-up kids cannot turn each into a request
    # (#512 review): within 30 s of the last fetch, no refetch.
    service, _ = server
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, json={"keys": []})

    client = _client_with_cached({"keys": []}, 5, handler)
    answer = {"attestation": _token(service), "proof_ref": PROOF}

    for _ in range(3):
        with pytest.raises(KeyMismatchError):
            client.verify_attestation(answer)
    assert calls == []


def _replaced_key(service, jwks):
    """The JWKS a server published before it restarted with a new
    ephemeral key: the same kid, another key (#512 review)."""
    other = AttestationService(key_continuity_policy="configured", private_key_pem=_pem())
    old = {**other.get_issuer_info()["public_keys"][0], "kid": service.key_id, "alg": "ES256", "use": "sig"}
    return {"keys": [old]}


def test_the_client_fetches_the_jwks_again_when_the_kids_key_was_replaced(server):
    service, jwks = server
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, json=jwks)

    client = _client_with_cached(_replaced_key(service, jwks), 60, handler)
    claims = client.verify_attestation({"attestation": _token(service), "proof_ref": PROOF})

    assert claims["qwed"]["proof_hash"] == PROOF
    assert calls == ["/.well-known/jwks.json"]


def test_a_signature_failure_does_not_refetch_a_fresh_jwks(server):
    # A stream of forged tokens under a real kid cannot turn each into a
    # request either.
    service, jwks = server
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, json=jwks)

    client = _client_with_cached(_replaced_key(service, jwks), 5, handler)
    answer = {"attestation": _token(service), "proof_ref": PROOF}

    for _ in range(3):
        with pytest.raises(KeyMismatchError):
            client.verify_attestation(answer)
    assert calls == []


def test_the_client_tries_keys_another_caller_fetched_meanwhile(server, monkeypatch):
    # One caller verifies against the old keys while another refreshes them
    # (#512 review): the first retries with the new keys, without a fetch,
    # although the last fetch was just now.
    service, jwks = server
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, json=jwks)

    client = _client_with_cached(jwks, 0, handler)
    monkeypatch.setattr(client, "get_jwks", lambda refresh=False: _replaced_key(service, jwks))

    claims = client.verify_attestation({"attestation": _token(service), "proof_ref": PROOF})

    assert claims["qwed"]["proof_hash"] == PROOF
    assert calls == []


def test_a_failed_refresh_also_waits_30_seconds(server):
    # An unreachable key endpoint is not asked again for every token none of
    # the cached keys verifies (#512 review).
    service, jwks = server
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(503)

    client = _client_with_cached(_replaced_key(service, jwks), 60, handler)
    answer = {"attestation": _token(service), "proof_ref": PROOF}

    with pytest.raises(KeysUnavailableError):
        client.verify_attestation(answer)
    with pytest.raises(KeyMismatchError):
        client.verify_attestation(answer)
    assert calls == ["/.well-known/jwks.json"]


def test_a_failed_fetch_is_shared_for_30_seconds(server):
    # Callers queued behind a failed fetch, and those after it, get its
    # failure without a request each (#512 review); after 30 s, one more.
    service, jwks = server
    calls = []

    def handler(request):
        calls.append(request.url.path)
        time.sleep(0.05)
        return httpx.Response(503) if len(calls) == 1 else httpx.Response(200, json=jwks)

    client = _client_with_cached(None, 0, handler)
    answer = {"attestation": _token(service), "proof_ref": PROOF}

    def attempt(_):
        try:
            return client.verify_attestation(answer)
        except KeysUnavailableError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = list(pool.map(attempt, range(4)))

    assert all(isinstance(outcome, KeysUnavailableError) for outcome in outcomes)
    assert len(calls) == 1
    client._jwks_attempted_at -= 60
    assert client.verify_attestation(answer)["qwed"]["proof_hash"] == PROOF
    assert len(calls) == 2


def test_an_unreadable_jwks_is_unavailable_keys():
    client = _client_with_cached(None, 0, lambda request: httpx.Response(200, text="not json"))

    with pytest.raises(KeysUnavailableError):
        client.get_jwks()


def test_concurrent_callers_share_one_fetch(server):
    service, jwks = server
    calls = []

    def handler(request):
        calls.append(request.url.path)
        time.sleep(0.05)
        return httpx.Response(200, json=jwks)

    client = _client_with_cached(None, 0, handler)
    answer = {"attestation": _token(service), "proof_ref": PROOF}

    with ThreadPoolExecutor(max_workers=4) as pool:
        verified = list(pool.map(lambda _: client.verify_attestation(answer), range(4)))

    assert len(verified) == 4
    assert calls == ["/.well-known/jwks.json"]


@pytest.mark.parametrize("answer", [{"proof_ref": PROOF}, {"attestation": "t"}])
def test_the_client_checks_the_answer_before_fetching_keys(answer):
    # A missing token or proof_ref is an AttestationError, not a network
    # error from the JWKS fetch (#512 review).
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(503)

    client = _client_with_cached(None, 0, handler)

    with pytest.raises(AttestationError, match="^no "):
        client.verify_attestation(answer)
    assert calls == []


def test_the_client_takes_only_a_result_or_a_response_dict():
    client = QWEDClient(api_key="k", base_url="http://qwed.test")

    with pytest.raises(TypeError):
        client.verify_attestation("a token on its own")


def test_a_consensus_answer_keeps_its_token():
    # verify_consensus builds its result by hand; it carries the token too
    # (#512 review).
    data = {"meets_requirement": True, "status": "VERIFIED", "attestation": "t", "proof_ref": PROOF}
    client = QWEDClient(api_key="k", base_url="http://qwed.test")
    client._client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=data)))

    result = client.verify_consensus("2+2")

    assert (result.attestation, result.proof_ref) == ("t", PROOF)


def test_the_client_reuses_the_jwks_within_its_lifetime(server):
    service, jwks = server
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, json=jwks)

    client = QWEDClient(api_key="k", base_url="http://qwed.test")
    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    answer = {"attestation": _token(service), "proof_ref": PROOF}

    client.verify_attestation(answer)
    client.verify_attestation(answer)

    assert len(calls) == 1


def test_the_async_client_verifies_too(server):
    service, jwks = server

    async def run():
        async with QWEDAsyncClient(api_key="k", base_url="http://qwed.test") as client:
            await client._client.aclose()
            client._client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=jwks)))
            return await client.verify_attestation({"attestation": _token(service), "proof_ref": PROOF}, query=QUERY)

    assert asyncio.run(run())["qwed"]["proof_hash"] == PROOF


def _async_run(jwks_cached, age, handler, call):
    """Run ``call(client)`` on an async client holding ``jwks_cached`` as
    fetched ``age`` seconds ago."""
    async def run():
        async with QWEDAsyncClient(api_key="k", base_url="http://qwed.test") as client:
            await client._client.aclose()
            client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            client._jwks = jwks_cached
            client._jwks_fetched_at = client._jwks_attempted_at = time.monotonic() - age
            return await call(client)

    return asyncio.run(run())


def test_the_async_client_refetches_a_stale_jwks_for_an_unknown_kid(server):
    service, jwks = server
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, json=jwks)

    answer = {"attestation": _token(service), "proof_ref": PROOF}
    claims = _async_run({"keys": []}, 60, handler, lambda client: client.verify_attestation(answer))

    assert claims["qwed"]["proof_hash"] == PROOF
    assert calls == ["/.well-known/jwks.json"]


def test_the_async_client_does_not_refetch_a_fresh_jwks(server):
    service, _ = server
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, json={"keys": []})

    answer = {"attestation": _token(service), "proof_ref": PROOF}

    with pytest.raises(KeyMismatchError):
        _async_run({"keys": []}, 5, handler, lambda client: client.verify_attestation(answer))
    assert calls == []


def test_the_async_client_refetches_when_the_kids_key_was_replaced(server):
    service, jwks = server
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, json=jwks)

    answer = {"attestation": _token(service), "proof_ref": PROOF}
    claims = _async_run(_replaced_key(service, jwks), 60, handler, lambda client: client.verify_attestation(answer))

    assert claims["qwed"]["proof_hash"] == PROOF
    assert calls == ["/.well-known/jwks.json"]


def test_the_async_client_checks_the_answer_before_fetching_keys():
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(503)

    with pytest.raises(AttestationError, match="no proof_ref"):
        _async_run(None, 0, handler, lambda client: client.verify_attestation({"attestation": "t"}))
    assert calls == []


def test_concurrent_async_callers_share_one_fetch(server):
    # Sentry, #512 review: without a lock each coroutine fetched.
    service, jwks = server
    calls = []

    async def handler(request):
        calls.append(request.url.path)
        await asyncio.sleep(0.05)
        return httpx.Response(200, json=jwks)

    answer = {"attestation": _token(service), "proof_ref": PROOF}

    async def verify_four(client):
        return await asyncio.gather(*(client.verify_attestation(answer) for _ in range(4)))

    assert len(_async_run(None, 0, handler, verify_four)) == 4
    assert calls == ["/.well-known/jwks.json"]


def test_the_async_client_tries_keys_another_caller_fetched_meanwhile(server):
    service, jwks = server
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, json=jwks)

    answer = {"attestation": _token(service), "proof_ref": PROOF}

    async def call(client):
        async def stale(refresh=False):
            return _replaced_key(service, jwks)
        client.get_jwks = stale
        return await client.verify_attestation(answer)

    assert _async_run(jwks, 0, handler, call)["qwed"]["proof_hash"] == PROOF
    assert calls == []


def test_a_failed_async_fetch_is_shared_for_30_seconds(server):
    service, _ = server
    calls = []

    async def handler(request):
        calls.append(request.url.path)
        await asyncio.sleep(0.05)
        return httpx.Response(503)

    answer = {"attestation": _token(service), "proof_ref": PROOF}

    async def verify_four(client):
        return await asyncio.gather(*(client.verify_attestation(answer) for _ in range(4)), return_exceptions=True)

    outcomes = _async_run(None, 0, handler, verify_four)

    assert all(isinstance(outcome, KeysUnavailableError) for outcome in outcomes)
    assert calls == ["/.well-known/jwks.json"]


def test_the_async_client_needs_its_context_to_fetch_keys():
    client = QWEDAsyncClient(api_key="k", base_url="http://qwed.test")

    fetch = client.get_jwks()

    with pytest.raises(RuntimeError, match="async with"):
        asyncio.run(fetch)


def test_an_async_consensus_answer_keeps_its_token():
    data = {"meets_requirement": True, "status": "VERIFIED", "attestation": "t", "proof_ref": PROOF}

    result = _async_run(None, 0, lambda r: httpx.Response(200, json=data), lambda client: client.verify_consensus("2+2"))

    assert (result.attestation, result.proof_ref) == ("t", PROOF)
