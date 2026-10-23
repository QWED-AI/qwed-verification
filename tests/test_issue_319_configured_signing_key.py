"""#319 (part 1), #188: a signing key that survives restarts and is shared by replicas.

Every VERIFIED result is signed (#320), but the key was generated per
process ("ephemeral", the only policy): a restart, or a second replica, had a
different key, so no token could be verified outside the process that issued
it. Delivering tokens to consumers (the rest of #319) is pointless until a
token outlives its process.

The operator can now configure the key (``QWED_SIGNING_KEY`` or
``..._FILE``, an EC P-256 PEM). Its key ID is its RFC 7638 thumbprint. A
configured key that cannot be used is never replaced by a generated one:
signing fails, so every VERIFIED result is BLOCKED. Unset, the key is
generated as before, with a warning.
"""

import logging

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from qwed_new.core import attestation
from qwed_new.core.attestation import (
    SIGNING_KEY_ENV,
    SIGNING_KEY_FILE_ENV,
    AttestationService,
    AttestationStatus,
    IssuerKeyPair,
    SigningKeyError,
    VerificationResult,
    create_verification_attestation,
    get_attestation_service,
    jwk_thumbprint,
)
from qwed_new.core.diagnostics import DiagnosticResult, DiagnosticStatus
from qwed_new.core.trust import attest_and_enforce

PROOF = "sha256:" + "c" * 64


def _pem(key=None, password=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    encryption = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)


@pytest.fixture
def fresh_service(monkeypatch):
    """No default service yet, and neither setting set."""
    monkeypatch.setattr(attestation, "_default_service", None)
    monkeypatch.delenv(SIGNING_KEY_ENV, raising=False)
    monkeypatch.delenv(SIGNING_KEY_FILE_ENV, raising=False)
    return monkeypatch


def _sign(service):
    result = VerificationResult(status="VERIFIED", verified=True, engine="math")
    return service.create_attestation(result, "2+2=4", proof_hash=PROOF, store=False).jwt_token


# ---------------------------------------------------------------- one key across processes

def test_a_token_from_one_replica_verifies_on_another_with_the_same_key():
    pem = _pem()
    issuer, other = AttestationService(key_continuity_policy="configured", private_key_pem=pem), \
        AttestationService(key_continuity_policy="configured", private_key_pem=pem)

    valid, claims, _ = other.verify_attestation(_sign(issuer))

    assert valid is True
    assert claims["qwed"]["proof_hash"] == PROOF


def test_generated_keys_do_not_verify_each_others_tokens():
    # The problem: two processes, or one before and after a restart.
    valid, _, _ = AttestationService().verify_attestation(_sign(AttestationService()))

    assert valid is False


def test_the_key_id_is_the_keys_thumbprint_everywhere():
    key = ec.generate_private_key(ec.SECP256R1())
    a = AttestationService(key_continuity_policy="configured", private_key_pem=_pem(key))
    b = AttestationService(key_continuity_policy="configured", private_key_pem=_pem(key))
    expected = f"did:qwed:node:local#{jwk_thumbprint(key.public_key())}"

    assert a.key_id == b.key_id == expected
    assert jwt.get_unverified_header(_sign(a))["kid"] == expected
    assert a.get_issuer_info()["public_keys"][0]["kid"] == expected


def test_the_thumbprint_is_rfc_7638():
    # The key with private value 1 has the P-256 generator G as its public
    # key (SEC 2, section 2.4.2), so its JWK members are fixed constants. The
    # thumbprint is the SHA-256 of their canonical JSON: required members
    # only, sorted, no whitespace (RFC 7638, section 3).
    import base64
    import hashlib

    public_key = ec.derive_private_key(1, ec.SECP256R1()).public_key()
    x = "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY"
    y = "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"
    canonical = f'{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}'
    expected = base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).decode().rstrip("=")

    assert attestation._jwk_coordinates(public_key) == {"crv": "P-256", "kty": "EC", "x": x, "y": y}
    assert jwk_thumbprint(public_key) == expected


def test_the_issuer_info_says_the_key_was_loaded_not_generated():
    info = AttestationService(key_continuity_policy="configured", private_key_pem=_pem()).get_issuer_info()

    assert info["key_continuity_policy"] == "configured"
    assert info["key_generated_at"] is None
    assert isinstance(info["key_loaded_at"], int)


# ---------------------------------------------------------------- the settings

def test_the_server_signs_with_the_configured_key(fresh_service):
    pem = _pem()
    fresh_service.setenv(SIGNING_KEY_ENV, pem.decode())

    issued = create_verification_attestation(
        status="VERIFIED", verified=True, engine="math", query="2+2=4", proof_hash=PROOF,
    )
    # A service built later from the same key, as after a restart.
    restarted = AttestationService(key_continuity_policy="configured", private_key_pem=pem)

    assert get_attestation_service().key_continuity_policy == "configured"
    assert restarted.verify_attestation(issued.token)[0] is True


def test_the_key_can_be_a_file(fresh_service, tmp_path):
    path = tmp_path / "attestation-key.pem"
    path.write_bytes(_pem())
    fresh_service.setenv(SIGNING_KEY_FILE_ENV, str(path))

    assert get_attestation_service().key_continuity_policy == "configured"


def test_the_pem_can_have_escaped_newlines_as_in_an_env_file(fresh_service):
    fresh_service.setenv(SIGNING_KEY_ENV, _pem().decode().replace("\n", "\\n"))

    assert get_attestation_service().key_continuity_policy == "configured"


def test_unset_the_key_is_generated_with_a_warning(fresh_service, caplog):
    with caplog.at_level(logging.WARNING, logger="qwed_new.core.attestation"):
        service = get_attestation_service()

    assert service.key_continuity_policy == "ephemeral"
    assert "attestation.ephemeral_key" in caplog.text


@pytest.mark.parametrize("value", ["", "   "])
def test_an_empty_setting_is_unset(fresh_service, value):
    fresh_service.setenv(SIGNING_KEY_ENV, value)

    assert get_attestation_service().key_continuity_policy == "ephemeral"


# ---------------------------------------------------------------- an unusable key fails closed

def _bad_settings():
    return {
        "not a key": {SIGNING_KEY_ENV: "not a key"},
        "P-384": {SIGNING_KEY_ENV: _pem(ec.generate_private_key(ec.SECP384R1())).decode()},
        "RSA": {SIGNING_KEY_ENV: _pem(rsa.generate_private_key(public_exponent=65537, key_size=2048)).decode()},
        "encrypted": {SIGNING_KEY_ENV: _pem(password=b"pw").decode()},
        "both set": {SIGNING_KEY_ENV: _pem().decode(), SIGNING_KEY_FILE_ENV: "/some/file.pem"},
        "missing file": {SIGNING_KEY_FILE_ENV: "/no/such/attestation-key.pem"},
    }


@pytest.mark.parametrize("case", list(_bad_settings()))
def test_an_unusable_configured_key_blocks_signing_and_is_not_replaced(fresh_service, caplog, case):
    settings = _bad_settings()[case]
    for name, value in settings.items():
        fresh_service.setenv(name, value)

    with caplog.at_level(logging.INFO, logger="qwed_new.core.attestation"):
        issued = create_verification_attestation(
            status="VERIFIED", verified=True, engine="math", query="2+2=4", proof_hash=PROOF,
        )

    assert issued.status is AttestationStatus.BLOCKED
    assert issued.token is None
    # Never a generated key in its place (#188): none was made, none kept.
    assert "attestation.key_generated" not in caplog.text
    assert attestation._default_service is None
    # No key material in the log.
    assert "PRIVATE KEY" not in caplog.text


def test_a_verified_result_is_blocked_while_the_key_is_unusable(fresh_service):
    fresh_service.setenv(SIGNING_KEY_ENV, "not a key")
    dr = DiagnosticResult(
        status=DiagnosticStatus.VERIFIED, agent_message="proven",
        developer_fields={"is_valid": True}, proof_ref=PROOF,
    )

    out = attest_and_enforce(dr, engine="math", query="2+2=4")

    assert out.status is DiagnosticStatus.BLOCKED
    assert out.proof_ref is None


def test_the_error_never_carries_the_key():
    pem = _pem(ec.generate_private_key(ec.SECP384R1()))

    with pytest.raises(SigningKeyError) as raised:
        AttestationService(key_continuity_policy="configured", private_key_pem=pem)

    assert "PRIVATE KEY" not in str(raised.value)
    assert raised.value.__cause__ is None


# ---------------------------------------------------------------- the key pair

def test_a_configured_policy_needs_a_key_and_an_ephemeral_one_takes_none():
    key, pem = ec.generate_private_key(ec.SECP256R1()), _pem()

    with pytest.raises(ValueError):
        IssuerKeyPair("did:test", "k", key_continuity_policy="configured")
    with pytest.raises(ValueError):
        IssuerKeyPair("did:test", "k", private_key=key)
    with pytest.raises(ValueError):
        AttestationService(key_continuity_policy="configured")
    with pytest.raises(ValueError):
        AttestationService(private_key_pem=pem)


def test_a_key_pair_refuses_another_curve_at_construction():
    # It used to accept one and fail later, building the JWK (#510 review).
    p384 = ec.generate_private_key(ec.SECP384R1())

    with pytest.raises(ValueError, match="P-256"):
        IssuerKeyPair("did:test", "k", key_continuity_policy="configured", private_key=p384)


def test_a_configured_key_is_loaded_when_the_service_is_built(caplog):
    # key_loaded_at and the log line are the load, not the first signing
    # (#510 review).
    with caplog.at_level(logging.INFO, logger="qwed_new.core.attestation"):
        service = AttestationService(key_continuity_policy="configured", private_key_pem=_pem())

    assert "attestation.key_loaded" in caplog.text
    assert service._key_pair is not None
    assert service.get_issuer_info()["key_loaded_at"] == service._key_pair.loaded_at


def test_a_configured_key_needs_the_crypto_package(monkeypatch):
    monkeypatch.setattr(attestation, "HAS_CRYPTO", False)
    pem = _pem()

    with pytest.raises(RuntimeError, match="cryptography"):
        AttestationService(key_continuity_policy="configured", private_key_pem=pem)


# ---------------------------------------------------------------- the key file

def test_a_key_file_must_be_a_regular_file(fresh_service, tmp_path):
    fresh_service.setenv(SIGNING_KEY_FILE_ENV, str(tmp_path))  # a directory

    with pytest.raises(SigningKeyError, match="not a regular file"):
        attestation.configured_signing_key_pem()


def test_a_key_file_larger_than_a_key_is_refused(fresh_service, tmp_path):
    path = tmp_path / "huge.pem"
    path.write_bytes(b"x" * (attestation._MAX_KEY_FILE_BYTES + 1))
    fresh_service.setenv(SIGNING_KEY_FILE_ENV, str(path))

    with pytest.raises(SigningKeyError, match="too large"):
        attestation.configured_signing_key_pem()


# ---------------------------------------------------------------- revocation

def test_revocation_is_per_service_until_it_is_shared():
    """Pins a known limit (#510 review): revocation is held in memory, so a
    service sharing the key still accepts a token another revoked. Nothing
    revokes today and no token leaves the server; this must change before
    tokens are delivered (#319), and this test with it."""
    pem = _pem()
    a = AttestationService(key_continuity_policy="configured", private_key_pem=pem)
    b = AttestationService(key_continuity_policy="configured", private_key_pem=pem)
    token = _sign(a)
    a.revoke_attestation(jwt.decode(token, options={"verify_signature": False})["jti"])

    assert a.verify_attestation(token)[0] is False
    assert b.verify_attestation(token)[0] is True
