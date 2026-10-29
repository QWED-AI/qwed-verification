"""#524: ``qwed init`` can create an organisation whose owner can sign in.

``qwed init`` signed up with a generated email and password that it never
showed or saved, so nobody could sign in to the organisation it created, and
qwed-dashboard could not show its records.

Now ``--owner-email`` (or QWED_OWNER_EMAIL) names the owner, and the password
is prompted for with hidden input and a confirmation. With
``--non-interactive`` the password comes from QWED_OWNER_PASSWORD, and
without an owner email the old generated owner is kept, with a warning.
"""

import json
import uuid
from pathlib import Path
from typing import ClassVar
from unittest.mock import patch

import click
import pytest
from click.testing import CliRunner

from qwed_sdk.cli import _bootstrap_api_key, _ensure_local_server_running, init
from qwed_sdk.init_owner import owner_password_problem, resolve_owner
from tests.test_cli_init import (  # noqa: F401  (autouse fixtures: hermetic env, stubbed handshake)
    TEST_TOKEN_MARKER,
    _engine_report,
    _provider_map,
    _stub_lookup_secret,
    _stub_server_identity,
)

EMAIL = "owner@acme.example.com"
# Made per run, like the markers in test_cli_init.py: no fixed secret in the source.
OWNER_SECRET = f"owner-{uuid.uuid4().hex}"


@pytest.fixture(autouse=True)
def _no_owner_env(monkeypatch):
    monkeypatch.delenv("QWED_OWNER_EMAIL", raising=False)
    monkeypatch.delenv("QWED_OWNER_PASSWORD", raising=False)


class _Response:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


class _Client:
    """httpx.Client stand-in that records the signup payload."""

    signups: ClassVar[list] = []
    signup_reply: ClassVar[tuple] = (200, {"access_token": "token-123"})

    def __init__(self, timeout):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def post(self, url, json=None, headers=None):
        if url.endswith("/auth/signup"):
            _Client.signups.append(json)
            return _Response(*_Client.signup_reply)
        return _Response(200, {"key": "qwed_live_bootstrap"})


@pytest.fixture
def signups(monkeypatch):
    _Client.signups = []
    _Client.signup_reply = (200, {"access_token": "token-123"})
    monkeypatch.setattr("httpx.Client", _Client)
    return _Client.signups


# ---------------------------------------------------------------- signing up

def test_the_owner_signs_up_with_the_given_email_and_password(signups):
    key, org = _bootstrap_api_key("http://localhost:8000", "Acme", (EMAIL, OWNER_SECRET))

    assert (key, org) == ("qwed_live_bootstrap", "Acme")
    assert signups == [{"email": EMAIL, "password": OWNER_SECRET, "organization_name": "Acme"}]


def test_without_an_owner_the_email_and_password_are_generated(signups):
    _bootstrap_api_key("http://localhost:8000", "Acme")

    (payload,) = signups
    assert payload["email"].startswith("acme-")
    assert payload["email"].endswith("@example.com")
    assert payload["password"]
    assert payload["password"] != OWNER_SECRET


def test_an_owner_already_registered_is_told_how_to_go_on(signups):
    # e.g. an earlier init signed this owner up, then failed to create the key.
    _Client.signup_reply = (400, {"detail": "Email already registered"})

    with pytest.raises(RuntimeError) as refused:
        _bootstrap_api_key("http://localhost:8000", "Acme", (EMAIL, OWNER_SECRET))

    message = str(refused.value)
    assert message.startswith("Signup failed: Email already registered")
    assert "sign in with it" in message
    assert "use another email" in message
    assert OWNER_SECRET not in message


def test_the_server_process_never_gets_the_owner_password(monkeypatch):
    monkeypatch.setenv("QWED_OWNER_PASSWORD", OWNER_SECRET)
    checks = iter([False, True])
    popen = {}
    monkeypatch.setattr("qwed_sdk.cli._check_server_health", lambda _url, timeout=2.0: next(checks))
    monkeypatch.setattr("qwed_sdk.cli._src_path", lambda: "src")
    monkeypatch.setattr("qwed_sdk.cli._resolve_server_runtime_dir", lambda: Path("runtime-dir"))
    monkeypatch.setattr("qwed_sdk.cli.time.sleep", lambda _s: None)
    monkeypatch.setattr("qwed_sdk.cli.subprocess.Popen", lambda c, **k: popen.update(kwargs=k))

    assert _ensure_local_server_running("http://127.0.0.1:9001", "jwt-value", "lookup-value") == (True, True)

    assert "QWED_OWNER_PASSWORD" not in popen["kwargs"]["env"]
    # Init itself still has it, for the signup request.
    assert resolve_owner(EMAIL, non_interactive=True) == (EMAIL, OWNER_SECRET)


# ---------------------------------------------------------------- non-interactive

def test_non_interactive_without_an_email_keeps_the_generated_owner():
    assert resolve_owner(None, non_interactive=True) is None


def test_non_interactive_reads_the_password_from_the_environment(monkeypatch):
    monkeypatch.setenv("QWED_OWNER_PASSWORD", OWNER_SECRET)

    assert resolve_owner(EMAIL, non_interactive=True) == (EMAIL, OWNER_SECRET)


def test_the_email_can_come_from_the_environment(monkeypatch):
    monkeypatch.setenv("QWED_OWNER_EMAIL", EMAIL)
    monkeypatch.setenv("QWED_OWNER_PASSWORD", OWNER_SECRET)

    assert resolve_owner(None, non_interactive=True) == (EMAIL, OWNER_SECRET)


def test_the_flag_wins_over_the_environment(monkeypatch):
    monkeypatch.setenv("QWED_OWNER_EMAIL", "other@acme.example.com")
    monkeypatch.setenv("QWED_OWNER_PASSWORD", OWNER_SECRET)

    assert resolve_owner(EMAIL, non_interactive=True) == (EMAIL, OWNER_SECRET)


@pytest.mark.parametrize("flag", ["", "   "])
def test_an_explicit_empty_flag_is_refused_not_replaced_by_the_environment(monkeypatch, flag):
    monkeypatch.setenv("QWED_OWNER_EMAIL", EMAIL)
    monkeypatch.setenv("QWED_OWNER_PASSWORD", OWNER_SECRET)

    with pytest.raises(RuntimeError, match="Not an email address"):
        resolve_owner(flag, non_interactive=True)


def test_non_interactive_with_an_email_but_no_password_is_refused():
    with pytest.raises(RuntimeError, match="QWED_OWNER_PASSWORD"):
        resolve_owner(EMAIL, non_interactive=True)


@pytest.mark.parametrize("email", [
    "owner", "owner@", "@acme.example.com", "owner@localhost", "own er@acme.example.com",
    "owner@@acme.example.com", "owner@acme@example.com", "owner@acme.", "owner@.com",
])
def test_non_interactive_refuses_what_is_not_an_email(monkeypatch, email):
    monkeypatch.setenv("QWED_OWNER_PASSWORD", OWNER_SECRET)

    with pytest.raises(RuntimeError, match="Not an email address"):
        resolve_owner(email, non_interactive=True)


def test_an_empty_password_is_refused():
    assert owner_password_problem("") == "The owner password must not be empty."


def test_a_password_longer_than_bcrypt_reads_is_refused(monkeypatch):
    # 72 bytes is bcrypt's limit; "é" is 2 bytes in UTF-8.
    monkeypatch.setenv("QWED_OWNER_PASSWORD", "é" * 37)

    with pytest.raises(RuntimeError, match="at most 72 bytes"):
        resolve_owner(EMAIL, non_interactive=True)


# ---------------------------------------------------------------- interactive

@click.command()
@click.option("--owner-email", default=None)
def _owner_command(owner_email):
    click.echo(f"resolved={resolve_owner(owner_email, non_interactive=False)!r}")


def test_interactive_asks_for_the_email_and_a_hidden_confirmed_password():
    result = CliRunner().invoke(_owner_command, [], input=f"{EMAIL}\n{OWNER_SECRET}\n{OWNER_SECRET}\n")

    assert result.exit_code == 0
    assert "Owner email" in result.output
    assert "Repeat for confirmation" in result.output
    assert f"resolved={(EMAIL, OWNER_SECRET)!r}" in result.output
    # Hidden input: the password is never echoed back at the prompts.
    assert result.output.count(OWNER_SECRET) == 1  # only in the test's own "resolved=" line


def test_interactive_with_the_flag_asks_only_for_the_password():
    result = CliRunner().invoke(_owner_command, ["--owner-email", EMAIL], input=f"{OWNER_SECRET}\n{OWNER_SECRET}\n")

    assert result.exit_code == 0
    assert "Owner email" not in result.output
    assert f"resolved={(EMAIL, OWNER_SECRET)!r}" in result.output


def test_interactive_asks_for_the_email_when_the_flag_is_empty(monkeypatch):
    monkeypatch.setenv("QWED_OWNER_EMAIL", "other@acme.example.com")

    result = CliRunner().invoke(
        _owner_command, ["--owner-email", " "], input=f"{EMAIL}\n{OWNER_SECRET}\n{OWNER_SECRET}\n"
    )

    assert result.exit_code == 0
    assert "Owner email" in result.output
    assert f"resolved={(EMAIL, OWNER_SECRET)!r}" in result.output


def test_interactive_asks_again_for_a_bad_email_or_password():
    too_long = "x" * 73
    result = CliRunner().invoke(
        _owner_command, [],
        input=f"not-an-email\n{EMAIL}\n{too_long}\n{too_long}\n{OWNER_SECRET}\n{OWNER_SECRET}\n",
    )

    assert result.exit_code == 0
    assert "Not an email address" in result.output
    assert "at most 72 bytes" in result.output
    assert f"resolved={(EMAIL, OWNER_SECRET)!r}" in result.output


# ---------------------------------------------------------------- the init command

def _run_init(args, input=None):
    with patch("qwed_sdk.cli._bootstrap_api_key", return_value=("qwed_live_test_key", "demo-org")) as bootstrap, \
            patch("qwed_sdk.cli._ensure_local_server_running", return_value=(True, True)), \
            patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_provider_map()), \
            patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report())), \
            patch("qwed_sdk.cli._ensure_gitignore_protection_noninteractive"), \
            patch("qwed_sdk.cli._ensure_gitignore_protection"), \
            patch("qwed_sdk.cli._load_dotenv_if_available"), \
            patch("qwed_new.providers.key_validator.validate_key_format", return_value=(True, "ok")), \
            patch("qwed_new.providers.key_validator.test_connection", return_value=(True, "Connected")), \
            patch("qwed_new.providers.credential_store.write_env_file", return_value=".env"), \
            patch("qwed_new.config.ensure_jwt_secret", return_value=TEST_TOKEN_MARKER):
        result = CliRunner().invoke(init, args, input=input)
    return result, bootstrap


PROVIDER_ARGS = ["--provider", "openai", "--api-key", "sk-test-key", "--organization-name", "demo-org", "--skip-tests"]


def test_init_creates_an_owner_who_can_sign_in(monkeypatch):
    monkeypatch.setenv("QWED_OWNER_PASSWORD", OWNER_SECRET)

    result, bootstrap = _run_init([*PROVIDER_ARGS, "--owner-email", EMAIL, "--non-interactive"])

    assert result.exit_code == 0, result.output
    bootstrap.assert_called_once_with("http://localhost:8000", "demo-org", (EMAIL, OWNER_SECRET))
    assert f"[ok] Owner: {EMAIL}" in result.output
    assert "nobody can sign in" not in result.output
    assert OWNER_SECRET not in result.output


def test_init_without_an_owner_email_warns_that_nobody_can_sign_in():
    result, bootstrap = _run_init([*PROVIDER_ARGS, "--non-interactive"])

    assert result.exit_code == 0, result.output
    bootstrap.assert_called_once_with("http://localhost:8000", "demo-org", None)
    assert "nobody can sign in to this organisation" in result.output
    assert "--owner-email" in result.output


def test_interactive_init_prompts_for_the_owner_and_never_prints_the_password():
    result, bootstrap = _run_init(PROVIDER_ARGS, input=f"{EMAIL}\n{OWNER_SECRET}\n{OWNER_SECRET}\n")

    assert result.exit_code == 0, result.output
    bootstrap.assert_called_once_with("http://localhost:8000", "demo-org", (EMAIL, OWNER_SECRET))
    assert OWNER_SECRET not in result.output


def test_non_interactive_init_without_the_password_stops_before_the_server():
    with patch("qwed_sdk.cli._start_server_and_bootstrap") as start:
        result, _bootstrap = _run_init([*PROVIDER_ARGS, "--owner-email", EMAIL, "--non-interactive"])

    assert result.exit_code == 1
    assert "QWED_OWNER_PASSWORD" in result.output
    start.assert_not_called()
