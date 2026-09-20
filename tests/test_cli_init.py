import os
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

# Original helper, bound at collection before the autouse stub below patches
# the module attribute (CodeRabbit on #375).
from qwed_new.config import ensure_lookup_secret as _REAL_ENSURE_LOOKUP_SECRET

from qwed_sdk.cli import _seed_server_secrets_from_project_root as _REAL_SEED_FROM_ROOT

from qwed_sdk.cli import (
    OnboardingProvider,
    _bootstrap_api_key,
    _check_server_health,
    _ensure_gitignore_protection_noninteractive,
    _ensure_local_server_running,
    _looks_like_placeholder_api_key,
    _persist_onboarding_env,
    _required_engine_report,
    _resolve_provider_api_key,
    _resolve_server_runtime_dir,
    _run_init_smoke_suite,
    _runtime_sqlite_database_url,
    _test_gemini_connection,
    _validate_local_server_target,
    init,
)

TEST_TOKEN_MARKER = f"fixture-{uuid.uuid4().hex}"
TEST_LOOKUP_MARKER = f"lookup-{uuid.uuid4().hex}"


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture(autouse=True)
def _stub_lookup_secret():
    """Pin the lookup secret and root seeding so init-path tests never mint
    real randomness into the process env and never read the developer's real
    .env (issue #372). The preset markers also model the retained-secret
    rerun, so the stale-server hard stop only triggers in tests that
    explicitly clear them. The full environ snapshot makes the file hermetic:
    onboarding writes directly to os.environ, which monkeypatch cannot track,
    and leaked keys (provider/API/lookup) have historically perturbed later
    tests in full-suite runs. Tests needing other behavior patch over this."""
    before = dict(os.environ)
    with patch("qwed_new.config.ensure_lookup_secret", return_value=TEST_LOOKUP_MARKER):
        with patch("qwed_sdk.cli._seed_server_secrets_from_project_root", return_value=set()):
            with patch.dict(os.environ, {
                "QWED_JWT_SECRET_KEY": TEST_TOKEN_MARKER,
                "QWED_API_KEY_LOOKUP_SECRET": TEST_LOOKUP_MARKER,
            }, clear=False):
                yield
    os.environ.clear()
    os.environ.update(before)


def _engine_report():
    return [
        {"name": "SymPy", "ready": True, "detail": "math engine ready", "install_hint": "", "version": "1.14.0"},
        {"name": "Z3", "ready": True, "detail": "logic engine ready", "install_hint": "", "version": "4.13.3"},
        {"name": "AST", "ready": True, "detail": "code engine ready", "install_hint": "", "version": "built-in"},
        {"name": "SQLGlot", "ready": True, "detail": "sql engine ready", "install_hint": "", "version": "30.0.0"},
    ]


def _provider_map():
    return {
        "openai": OnboardingProvider(
            slug="openai",
            name="OpenAI",
            active_provider="openai",
            key_env="OPENAI_API_KEY",
            model_env="OPENAI_MODEL",
            base_url_env=None,
            default_model="gpt-4o-mini",
            default_base_url=None,
            connection_slug="openai",
            key_pattern=r"^sk-",
        )
    }


def _custom_provider_map(default_base_url="https://api.example.com/v1", default_model="model-1"):
    return {
        "custom": OnboardingProvider(
            slug="custom",
            name="Custom Provider",
            active_provider="openai_compat",
            key_env="CUSTOM_API_KEY",
            model_env="CUSTOM_MODEL",
            base_url_env="CUSTOM_BASE_URL",
            default_model=default_model,
            default_base_url=default_base_url,
            connection_slug="openai-compatible",
            key_pattern=None,
        )
    }


def _gemini_provider_map():
    return {
        "gemini": OnboardingProvider(
            slug="gemini",
            name="Google Gemini",
            active_provider="gemini",
            key_env="GOOGLE_API_KEY",
            model_env="GEMINI_MODEL",
            base_url_env=None,
            default_model="gemini-1.5-pro",
            default_base_url=None,
            connection_slug="gemini",
            key_pattern=None,
        )
    }


@patch("qwed_sdk.cli._import_init_dependencies", side_effect=RuntimeError("API_KEY_SECRET missing"))
def test_init_exits_cleanly_when_core_config_invalid(
    _mock_imports,
    runner,
):
    """Sentry on #375: config import-time failures (e.g. missing
    API_KEY_SECRET) must fail closed with guidance, not a traceback."""
    result = runner.invoke(init, ["--non-interactive", "--skip-tests"])
    assert result.exit_code == 1
    assert "QWED core misconfigured" in result.output


@patch("qwed_sdk.cli._bootstrap_api_key", return_value=("qwed_live_test_key", "demo-org"))
@patch("qwed_sdk.cli._ensure_local_server_running", return_value=(True, True))
@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_provider_map())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._ensure_gitignore_protection_noninteractive")
@patch("qwed_sdk.cli._ensure_gitignore_protection")
@patch("qwed_sdk.cli._load_dotenv_if_available")
@patch("qwed_new.providers.key_validator.validate_key_format", return_value=(True, "ok"))
@patch("qwed_new.providers.key_validator.test_connection", return_value=(True, "Connected"))
@patch("qwed_new.providers.credential_store.write_env_file", return_value=".env")
@patch("qwed_new.config.ensure_jwt_secret", return_value=TEST_TOKEN_MARKER)
def test_init_non_interactive_success(
    _mock_jwt,
    _mock_write_env,
    _mock_test_connection,
    _mock_validate,
    _mock_load_dotenv,
    _mock_gitignore_interactive,
    _mock_gitignore,
    _mock_required_engines,
    _mock_provider_map,
    _mock_server,
    _mock_bootstrap,
    runner,
):
    result = runner.invoke(
        init,
        [
            "--provider",
            "openai",
            "--api-key",
            "sk-test-key",
            "--organization-name",
            "demo-org",
            "--non-interactive",
        ],
    )

    assert result.exit_code == 0
    assert "Step 1/3: LLM Provider Setup" in result.output
    assert "Step 2/3: API Key" in result.output
    assert "Step 3/3: Generate QWED API Key" in result.output
    assert "qwed_live_test_key" in result.output


@patch("qwed_sdk.cli._bootstrap_api_key", return_value=("qwed_live_test_key", "demo-org"))
@patch("qwed_sdk.cli._ensure_local_server_running", return_value=(True, False))
@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_provider_map())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._ensure_gitignore_protection_noninteractive")
@patch("qwed_sdk.cli._ensure_gitignore_protection")
@patch("qwed_sdk.cli._load_dotenv_if_available")
@patch("qwed_new.providers.key_validator.validate_key_format", return_value=(True, "ok"))
@patch("qwed_new.providers.key_validator.test_connection", return_value=(True, "Connected"))
@patch("qwed_new.providers.credential_store.write_env_file", return_value=".env")
@patch("qwed_new.config.ensure_jwt_secret", return_value="fresh-jwt-value")
def test_init_stops_when_healthy_server_predates_fresh_secrets(
    _mock_jwt,
    _mock_write_env,
    _mock_test_connection,
    _mock_validate,
    _mock_load_dotenv,
    _mock_gitignore_interactive,
    _mock_gitignore,
    _mock_required_engines,
    _mock_provider_map,
    _mock_server,
    _mock_bootstrap,
    runner,
    monkeypatch,
):
    """Greptile P1 on #375: freshly generated secrets + an already-healthy
    server means bootstrapping would issue a key the restarted server cannot
    resolve (proven 200-then-401). Stop before bootstrapping instead."""
    monkeypatch.delenv("QWED_JWT_SECRET_KEY", raising=False)
    monkeypatch.delenv("QWED_API_KEY_LOOKUP_SECRET", raising=False)
    with patch("qwed_new.config.ensure_lookup_secret", return_value="fresh-lookup-value"):
        result = runner.invoke(
            init,
            ["--provider", "openai", "--api-key", "sk-test-key",
             "--organization-name", "demo-org", "--non-interactive"],
        )
    assert result.exit_code == 1
    assert "already running with older secrets" in result.output


@patch("qwed_sdk.cli._bootstrap_api_key", return_value=("qwed_live_test_key", "demo-org"))
@patch("qwed_sdk.cli._ensure_local_server_running", return_value=(True, False))
@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_provider_map())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._ensure_gitignore_protection_noninteractive")
@patch("qwed_sdk.cli._ensure_gitignore_protection")
@patch("qwed_sdk.cli._load_dotenv_if_available")
@patch("qwed_new.providers.key_validator.validate_key_format", return_value=(True, "ok"))
@patch("qwed_new.providers.key_validator.test_connection", return_value=(True, "Connected"))
@patch("qwed_new.providers.credential_store.write_env_file", return_value=".env")
@patch("qwed_new.config.ensure_jwt_secret", return_value="seeded-jwt-value")
def test_init_proceeds_when_secrets_seeded_from_root(
    _mock_jwt,
    _mock_write_env,
    _mock_test_connection,
    _mock_validate,
    _mock_load_dotenv,
    _mock_gitignore_interactive,
    _mock_gitignore,
    _mock_required_engines,
    _mock_provider_map,
    _mock_server,
    _mock_bootstrap,
    runner,
    monkeypatch,
):
    """Seeded-from-root values are retained, not fresh: a healthy server must
    NOT trip the stale guard (this is the false positive Sentry's literal
    suggestion would introduce)."""
    monkeypatch.delenv("QWED_JWT_SECRET_KEY", raising=False)
    monkeypatch.delenv("QWED_API_KEY_LOOKUP_SECRET", raising=False)

    def _fake_seed_sets_env():
        os.environ.setdefault("QWED_JWT_SECRET_KEY", "seeded-jwt-value")
        os.environ.setdefault("QWED_API_KEY_LOOKUP_SECRET", "seeded-lookup-value")
        return {"QWED_JWT_SECRET_KEY", "QWED_API_KEY_LOOKUP_SECRET"}

    with patch(
        "qwed_sdk.cli._seed_server_secrets_from_project_root",
        side_effect=_fake_seed_sets_env,
    ):
        with patch("qwed_new.config.ensure_lookup_secret", return_value="seeded-lookup-value"):
            result = runner.invoke(
                init,
                ["--provider", "openai", "--api-key", "sk-test-key",
                 "--organization-name", "demo-org", "--non-interactive"],
            )
    assert result.exit_code == 0
    assert "already running with older secrets" not in result.output


@patch("qwed_sdk.cli._bootstrap_api_key", return_value=("qwed_live_test_key", "demo-org"))
@patch("qwed_sdk.cli._ensure_local_server_running", return_value=(True, False))
@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_provider_map())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._ensure_gitignore_protection_noninteractive")
@patch("qwed_sdk.cli._ensure_gitignore_protection")
@patch("qwed_sdk.cli._load_dotenv_if_available")
@patch("qwed_new.providers.key_validator.validate_key_format", return_value=(True, "ok"))
@patch("qwed_new.providers.key_validator.test_connection", return_value=(True, "Connected"))
@patch("qwed_new.providers.credential_store.write_env_file", return_value=".env")
@patch("qwed_new.config.ensure_jwt_secret", return_value="nested-jwt-value")
def test_init_proceeds_when_secrets_come_from_nested_dotenv(
    _mock_jwt,
    _mock_write_env,
    _mock_test_connection,
    _mock_validate,
    _mock_load_dotenv,
    _mock_gitignore_interactive,
    _mock_gitignore,
    _mock_required_engines,
    _mock_provider_map,
    _mock_server,
    _mock_bootstrap,
    runner,
    monkeypatch,
):
    """Greptile P1 + Sentry on #375: secrets present ONLY via the nested
    .env (loaded after capture base) count as retained — a healthy server
    must not trip the stale guard for them."""
    monkeypatch.delenv("QWED_JWT_SECRET_KEY", raising=False)
    monkeypatch.delenv("QWED_API_KEY_LOOKUP_SECRET", raising=False)

    def _fake_dotenv():
        os.environ.setdefault("QWED_JWT_SECRET_KEY", "nested-jwt-value")
        os.environ.setdefault("QWED_API_KEY_LOOKUP_SECRET", "nested-lookup-value")

    with patch("qwed_sdk.cli._load_dotenv_if_available", side_effect=_fake_dotenv):
        with patch("qwed_new.config.ensure_lookup_secret", return_value="nested-lookup-value"):
            result = runner.invoke(
                init,
                ["--provider", "openai", "--api-key", "sk-test-key",
                 "--organization-name", "demo-org", "--non-interactive"],
            )
    assert result.exit_code == 0
    assert "already running with older secrets" not in result.output


@patch("qwed_sdk.cli._bootstrap_api_key", return_value=("qwed_live_test_key", "demo-org"))
@patch("qwed_sdk.cli._ensure_local_server_running", return_value=(True, False))
@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_provider_map())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._ensure_gitignore_protection_noninteractive")
@patch("qwed_sdk.cli._ensure_gitignore_protection")
@patch("qwed_sdk.cli._load_dotenv_if_available")
@patch("qwed_new.providers.key_validator.validate_key_format", return_value=(True, "ok"))
@patch("qwed_new.providers.key_validator.test_connection", return_value=(True, "Connected"))
@patch("qwed_new.providers.credential_store.write_env_file", return_value=".env")
@patch("qwed_new.config.ensure_jwt_secret", return_value="retained-jwt-value")
def test_init_no_warning_when_server_matches_retained_secrets(
    _mock_jwt,
    _mock_write_env,
    _mock_test_connection,
    _mock_validate,
    _mock_load_dotenv,
    _mock_gitignore_interactive,
    _mock_gitignore,
    _mock_required_engines,
    _mock_provider_map,
    _mock_server,
    _mock_bootstrap,
    runner,
    monkeypatch,
):
    """Retained secrets + healthy server: nothing stale, proceeds cleanly."""
    monkeypatch.setenv("QWED_JWT_SECRET_KEY", "retained-jwt-value")
    monkeypatch.setenv("QWED_API_KEY_LOOKUP_SECRET", "retained-lookup-value")
    result = runner.invoke(
        init,
        ["--provider", "openai", "--api-key", "sk-test-key",
         "--organization-name", "demo-org", "--non-interactive"],
    )
    assert result.exit_code == 0
    assert "already running with older secrets" not in result.output


@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_provider_map())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._load_dotenv_if_available")
@patch("qwed_new.providers.key_validator.validate_key_format", return_value=(True, "ok"))
@patch("qwed_new.providers.key_validator.test_connection", return_value=(False, "Auth failed"))
def test_init_non_interactive_connection_failure(
    _mock_test_connection,
    _mock_validate,
    _mock_load_dotenv,
    _mock_required_engines,
    _mock_provider_map,
    runner,
):
    result = runner.invoke(
        init,
        [
            "--provider",
            "openai",
            "--api-key",
            "sk-test-key",
            "--organization-name",
            "demo-org",
            "--non-interactive",
            "--skip-tests",
        ],
    )

    assert result.exit_code == 1
    assert "Auth failed" in result.output


@patch("qwed_sdk.cli._bootstrap_api_key", return_value=("qwed_live_test_key", "demo-org"))
@patch("qwed_sdk.cli._ensure_local_server_running", return_value=(True, False))
@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_provider_map())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._ensure_gitignore_protection_noninteractive")
@patch("qwed_sdk.cli._ensure_gitignore_protection")
@patch("qwed_sdk.cli._load_dotenv_if_available")
@patch("qwed_new.providers.key_validator.validate_key_format", return_value=(True, "ok"))
@patch("qwed_new.providers.key_validator.test_connection", return_value=(True, "Connected"))
@patch("qwed_new.providers.credential_store.write_env_file", return_value=".env")
@patch("qwed_new.config.ensure_jwt_secret", return_value=TEST_TOKEN_MARKER)
def test_init_persists_jwt_secret_in_env_write(
    _mock_jwt,
    mock_write_env,
    _mock_test_connection,
    _mock_validate,
    _mock_load_dotenv,
    _mock_gitignore_interactive,
    _mock_gitignore,
    _mock_required_engines,
    _mock_provider_map,
    _mock_server,
    _mock_bootstrap,
    runner,
):
    result = runner.invoke(
        init,
        [
            "--provider",
            "openai",
            "--api-key",
            "sk-test-key",
            "--organization-name",
            "demo-org",
            "--non-interactive",
            "--skip-tests",
        ],
    )

    assert result.exit_code == 0
    args, kwargs = mock_write_env.call_args
    env_vars = args[0]
    assert env_vars["QWED_JWT_SECRET_KEY"] == TEST_TOKEN_MARKER
    assert kwargs["active_provider"] == "openai"


def test_bootstrap_api_key_success(monkeypatch):
    class _Response:
        def __init__(self, status_code, payload):
            self.status_code = status_code
            self._payload = payload
            self.text = ""

        def json(self):
            return self._payload

    class _Client:
        def __init__(self, timeout):
            self.timeout = timeout
            self.calls = []

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return False

        def post(self, url, json=None, headers=None):
            self.calls.append((url, json, headers))
            if url.endswith("/auth/signup"):
                return _Response(200, {"access_token": "token-123"})
            if url.endswith("/auth/api-keys"):
                assert headers == {"Authorization": "Bearer token-123"}
                return _Response(200, {"key": "qwed_live_bootstrap"})
            return _Response(404, {"detail": "not found"})

    monkeypatch.setattr("httpx.Client", _Client)
    monkeypatch.setattr("qwed_sdk.cli.secrets.token_hex", lambda n: "abc12345")
    monkeypatch.setattr("qwed_sdk.cli.secrets.token_urlsafe", lambda n: "pw-token")

    key, org = _bootstrap_api_key("http://localhost:8000", "Acme Org")
    assert key == "qwed_live_bootstrap"
    assert org == "Acme Org"


def test_bootstrap_api_key_retries_with_alias_when_org_taken(monkeypatch):
    class _Response:
        def __init__(self, status_code, payload, text=""):
            self.status_code = status_code
            self._payload = payload
            self.text = text

        def json(self):
            return self._payload

    class _Client:
        def __init__(self, timeout):
            self.timeout = timeout
            self.signup_calls = 0

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return False

        def post(self, url, json=None, headers=None):
            if url.endswith("/auth/signup"):
                self.signup_calls += 1
                if self.signup_calls == 1:
                    return _Response(400, {"detail": "Organization already taken"}, text='{"detail":"Organization already taken"}')
                return _Response(200, {"access_token": "token-123"})
            if url.endswith("/auth/api-keys"):
                return _Response(200, {"key": "qwed_live_bootstrap"})
            return _Response(404, {"detail": "not found"})

    monkeypatch.setattr("httpx.Client", _Client)
    monkeypatch.setattr("qwed_sdk.cli.secrets.token_hex", lambda n: "ab12")
    monkeypatch.setattr("qwed_sdk.cli.secrets.token_urlsafe", lambda n: "pw-token")

    key, org = _bootstrap_api_key("http://localhost:8000", "Acme Org")
    assert key == "qwed_live_bootstrap"
    assert org == "Acme Org-ab12"


def test_bootstrap_api_key_fails_when_signup_returns_no_token(monkeypatch):
    class _Response:
        def __init__(self, status_code, payload):
            self.status_code = status_code
            self._payload = payload
            self.text = ""

        def json(self):
            return self._payload

    class _Client:
        def __init__(self, timeout):
            self.timeout = timeout

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return False

        def post(self, url, json=None, headers=None):
            if url.endswith("/auth/signup"):
                return _Response(200, {})
            return _Response(404, {})

    monkeypatch.setattr("httpx.Client", _Client)
    monkeypatch.setattr("qwed_sdk.cli.secrets.token_hex", lambda n: "abc12345")
    monkeypatch.setattr("qwed_sdk.cli.secrets.token_urlsafe", lambda n: "pw-token")

    with pytest.raises(RuntimeError, match="no access token"):
        _bootstrap_api_key("http://localhost:8000", "Acme Org")


def test_bootstrap_api_key_fails_when_api_key_endpoint_errors(monkeypatch):
    class _Response:
        def __init__(self, status_code, payload, text=""):
            self.status_code = status_code
            self._payload = payload
            self.text = text

        def json(self):
            return self._payload

    class _Client:
        def __init__(self, timeout):
            self.timeout = timeout

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return False

        def post(self, url, json=None, headers=None):
            if url.endswith("/auth/signup"):
                return _Response(200, {"access_token": "token-123"})
            if url.endswith("/auth/api-keys"):
                return _Response(500, {"detail": "boom"}, text='{"detail":"boom"}')
            return _Response(404, {})

    monkeypatch.setattr("httpx.Client", _Client)
    monkeypatch.setattr("qwed_sdk.cli.secrets.token_hex", lambda n: "abc12345")
    monkeypatch.setattr("qwed_sdk.cli.secrets.token_urlsafe", lambda n: "pw-token")

    with pytest.raises(RuntimeError, match="API key generation failed"):
        _bootstrap_api_key("http://localhost:8000", "Acme Org")


def test_bootstrap_api_key_fails_when_key_missing(monkeypatch):
    class _Response:
        def __init__(self, status_code, payload):
            self.status_code = status_code
            self._payload = payload
            self.text = ""

        def json(self):
            return self._payload

    class _Client:
        def __init__(self, timeout):
            self.timeout = timeout

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return False

        def post(self, url, json=None, headers=None):
            if url.endswith("/auth/signup"):
                return _Response(200, {"access_token": "token-123"})
            if url.endswith("/auth/api-keys"):
                return _Response(200, {})
            return _Response(404, {})

    monkeypatch.setattr("httpx.Client", _Client)
    monkeypatch.setattr("qwed_sdk.cli.secrets.token_hex", lambda n: "abc12345")
    monkeypatch.setattr("qwed_sdk.cli.secrets.token_urlsafe", lambda n: "pw-token")

    with pytest.raises(RuntimeError, match="returned no key"):
        _bootstrap_api_key("http://localhost:8000", "Acme Org")


def test_bootstrap_api_key_fails_when_alias_signup_still_fails(monkeypatch):
    class _Response:
        def __init__(self, status_code, payload, text=""):
            self.status_code = status_code
            self._payload = payload
            self.text = text

        def json(self):
            return self._payload

    class _Client:
        def __init__(self, timeout):
            self.timeout = timeout
            self.signup_calls = 0

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return False

        def post(self, url, json=None, headers=None):
            if url.endswith("/auth/signup"):
                self.signup_calls += 1
                return _Response(400, {"detail": "Organization already taken"}, text='{"detail":"Organization already taken"}')
            return _Response(404, {}, text='{"detail":"not found"}')

    monkeypatch.setattr("httpx.Client", _Client)
    monkeypatch.setattr("qwed_sdk.cli.secrets.token_hex", lambda n: "abcd")
    monkeypatch.setattr("qwed_sdk.cli.secrets.token_urlsafe", lambda n: "pw-token")

    with pytest.raises(RuntimeError, match="Signup failed"):
        _bootstrap_api_key("http://localhost:8000", "Acme Org")


def test_bootstrap_api_key_fails_on_non_retryable_signup_error(monkeypatch):
    class _Response:
        def __init__(self, status_code, payload, text=""):
            self.status_code = status_code
            self._payload = payload
            self.text = text

        def json(self):
            return self._payload

    class _Client:
        def __init__(self, timeout):
            self.timeout = timeout

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return False

        def post(self, url, json=None, headers=None):
            if url.endswith("/auth/signup"):
                return _Response(500, {"detail": "server error"}, text='{"detail":"server error"}')
            return _Response(404, {}, text='{"detail":"not found"}')

    monkeypatch.setattr("httpx.Client", _Client)
    monkeypatch.setattr("qwed_sdk.cli.secrets.token_hex", lambda n: "abcd")
    monkeypatch.setattr("qwed_sdk.cli.secrets.token_urlsafe", lambda n: "pw-token")

    with pytest.raises(RuntimeError, match="Signup failed: server error"):
        _bootstrap_api_key("http://localhost:8000", "Acme Org")


def test_ensure_local_server_running_applies_pythonpath_guard(monkeypatch):
    checks = iter([False, True])
    popen_capture = {}
    expected_src = str(Path("repo") / "src")
    runtime_dir = Path("runtime-dir")

    monkeypatch.setattr("qwed_sdk.cli._check_server_health", lambda _url, timeout=2.0: next(checks))
    monkeypatch.setattr("qwed_sdk.cli._src_path", lambda: expected_src)
    monkeypatch.setattr("qwed_sdk.cli._resolve_server_runtime_dir", lambda: runtime_dir)
    monkeypatch.setattr("qwed_sdk.cli.time.sleep", lambda _s: None)

    def _fake_popen(command, **kwargs):
        popen_capture["command"] = command
        popen_capture["kwargs"] = kwargs
        return None

    monkeypatch.setattr("qwed_sdk.cli.subprocess.Popen", _fake_popen)

    jwt_value = "test-token-value"
    ready, started = _ensure_local_server_running("http://127.0.0.1:9001", jwt_value)
    assert ready is True
    assert started is True
    assert popen_capture["command"][-2:] == ["--port", "9001"]
    env = popen_capture["kwargs"]["env"]
    assert env["QWED_JWT_SECRET_KEY"] == jwt_value
    assert env["DATABASE_URL"] == _runtime_sqlite_database_url(runtime_dir)
    assert env["PYTHONPATH"].split(os.pathsep)[0] == expected_src
    assert popen_capture["kwargs"]["cwd"] == str(runtime_dir)


def test_ensure_local_server_running_threads_lookup_secret(monkeypatch):
    """Issue #372: the child server env must carry the lookup secret or the
    fail-closed import crashes the fresh boot."""
    checks = iter([False, True])
    popen_capture = {}
    runtime_dir = Path("runtime-dir")

    monkeypatch.setattr("qwed_sdk.cli._check_server_health", lambda _url, timeout=2.0: next(checks))
    monkeypatch.setattr("qwed_sdk.cli._src_path", lambda: "src")
    monkeypatch.setattr("qwed_sdk.cli._resolve_server_runtime_dir", lambda: runtime_dir)
    monkeypatch.setattr("qwed_sdk.cli.time.sleep", lambda _s: None)
    monkeypatch.setattr("qwed_sdk.cli.subprocess.Popen", lambda c, **k: popen_capture.update(kwargs=k))

    ready, started = _ensure_local_server_running(
        "http://127.0.0.1:9001", "jwt-value", "lookup-value"
    )
    assert (ready, started) == (True, True)
    env = popen_capture["kwargs"]["env"]
    assert env["QWED_JWT_SECRET_KEY"] == "jwt-value"
    assert env["QWED_API_KEY_LOOKUP_SECRET"] == "lookup-value"


def test_ensure_local_server_running_falls_back_to_parent_env(monkeypatch):
    """Legacy two-arg callers still work via the parent environment."""
    checks = iter([False, True])
    popen_capture = {}
    runtime_dir = Path("runtime-dir")

    monkeypatch.setattr("qwed_sdk.cli._check_server_health", lambda _url, timeout=2.0: next(checks))
    monkeypatch.setattr("qwed_sdk.cli._src_path", lambda: "src")
    monkeypatch.setattr("qwed_sdk.cli._resolve_server_runtime_dir", lambda: runtime_dir)
    monkeypatch.setattr("qwed_sdk.cli.time.sleep", lambda _s: None)
    monkeypatch.setattr("qwed_sdk.cli.subprocess.Popen", lambda c, **k: popen_capture.update(kwargs=k))
    monkeypatch.setenv("QWED_API_KEY_LOOKUP_SECRET", "parent-lookup")

    ready, _ = _ensure_local_server_running("http://127.0.0.1:9001", "jwt-value")
    assert ready is True
    assert popen_capture["kwargs"]["env"]["QWED_API_KEY_LOOKUP_SECRET"] == "parent-lookup"


def test_persist_onboarding_env_stores_distinct_lookup_secret(monkeypatch, tmp_path):
    """Issue #372: persist must store a lookup secret distinct from JWT and
    return it for the child env; re-running must retain, not rotate."""
    monkeypatch.delenv("QWED_API_KEY_LOOKUP_SECRET", raising=False)
    monkeypatch.setenv("QWED_JWT_SECRET_KEY", "jwt-secret-value")
    written = {}

    profile = _provider_map()["openai"]
    jwt_secret, lookup_secret, _env_path = _persist_onboarding_env(
        profile=profile,
        resolved_key="sk-test-key",
        resolved_base_url="",
        resolved_model="gpt-4o-mini",
        ensure_jwt_secret=lambda: "jwt-secret-value",
        ensure_lookup_secret=_REAL_ENSURE_LOOKUP_SECRET,
        verify_gitignore=lambda: True,
        add_env_to_gitignore=lambda: True,
        write_env_file=lambda vars, active_provider=None: written.update(vars) or str(tmp_path / ".env"),
        non_interactive=True,
    )
    assert jwt_secret == "jwt-secret-value"
    assert lookup_secret
    assert lookup_secret != jwt_secret
    assert written["QWED_API_KEY_LOOKUP_SECRET"] == lookup_secret
    assert written["QWED_JWT_SECRET_KEY"] == jwt_secret
    assert os.environ["QWED_API_KEY_LOOKUP_SECRET"] == lookup_secret

    # Re-running with the stored value must retain it verbatim.
    stored = written["QWED_API_KEY_LOOKUP_SECRET"]
    monkeypatch.setenv("QWED_API_KEY_LOOKUP_SECRET", stored)
    _, lookup_again, _ = _persist_onboarding_env(
        profile=profile,
        resolved_key="sk-test-key",
        resolved_base_url="",
        resolved_model="gpt-4o-mini",
        ensure_jwt_secret=lambda: "jwt-secret-value",
        ensure_lookup_secret=_REAL_ENSURE_LOOKUP_SECRET,
        verify_gitignore=lambda: True,
        add_env_to_gitignore=lambda: True,
        write_env_file=lambda vars, active_provider=None: str(tmp_path / ".env"),
        non_interactive=True,
    )
    assert lookup_again == stored


def test_persist_onboarding_env_lookup_failure_blocks(monkeypatch, tmp_path):
    """A lookup-secret failure must fail the persist loudly (fail closed)."""
    profile = _provider_map()["openai"]

    def _boom():
        raise RuntimeError("vault unreachable")

    with pytest.raises(RuntimeError, match="Failed to prepare lookup secret"):
        _persist_onboarding_env(
            profile=profile,
            resolved_key="sk-test-key",
            resolved_base_url="",
            resolved_model="gpt-4o-mini",
            ensure_jwt_secret=lambda: "jwt-secret-value",
            ensure_lookup_secret=_boom,
            verify_gitignore=lambda: True,
            add_env_to_gitignore=lambda: True,
            write_env_file=lambda vars, active_provider=None: str(tmp_path / ".env"),
            non_interactive=True,
        )


def test_persist_onboarding_env_rejects_equal_lookup_secret(monkeypatch, tmp_path):
    """Collision surfaces with the fix instruction, not a bare type name."""
    monkeypatch.setenv("QWED_JWT_SECRET_KEY", "same-value")
    monkeypatch.setenv("QWED_API_KEY_LOOKUP_SECRET", "same-value")
    profile = _provider_map()["openai"]

    with pytest.raises(RuntimeError, match="must differ"):
        _persist_onboarding_env(
            profile=profile,
            resolved_key="sk-test-key",
            resolved_base_url="",
            resolved_model="gpt-4o-mini",
            ensure_jwt_secret=lambda: "same-value",
            ensure_lookup_secret=_REAL_ENSURE_LOOKUP_SECRET,
            verify_gitignore=lambda: True,
            add_env_to_gitignore=lambda: True,
            write_env_file=lambda vars, active_provider=None: str(tmp_path / ".env"),
            non_interactive=True,
        )


def test_ensure_local_server_running_without_any_lookup_secret(monkeypatch):
    """Legacy path with no lookup anywhere: child env carries no lookup key,
    preserving the old (crashing, fail-closed) behavior for non-onboarded use."""
    checks = iter([False, True])
    popen_capture = {}
    runtime_dir = Path("runtime-dir")

    monkeypatch.setattr("qwed_sdk.cli._check_server_health", lambda _url, timeout=2.0: next(checks))
    monkeypatch.setattr("qwed_sdk.cli._src_path", lambda: "src")
    monkeypatch.setattr("qwed_sdk.cli._resolve_server_runtime_dir", lambda: runtime_dir)
    monkeypatch.setattr("qwed_sdk.cli.time.sleep", lambda _s: None)
    monkeypatch.setattr("qwed_sdk.cli.subprocess.Popen", lambda c, **k: popen_capture.update(kwargs=k))
    monkeypatch.delenv("QWED_API_KEY_LOOKUP_SECRET", raising=False)

    ready, _ = _ensure_local_server_running("http://127.0.0.1:9001", "jwt-value")
    assert ready is True
    assert "QWED_API_KEY_LOOKUP_SECRET" not in popen_capture["kwargs"]["env"]


def test_seed_server_secrets_from_nested_directory(monkeypatch, tmp_path):
    """Greptile P1 on #375: init from a subdirectory must see (and retain)
    the project-root secrets instead of generating overwrites."""
    root = tmp_path / "proj"
    nested = root / "sub" / "dir"
    nested.mkdir(parents=True)
    (root / "pyproject.toml").write_text("[project]\nname = 'proj'\n", encoding="utf-8")
    (root / ".env").write_text(
        "QWED_JWT_SECRET_KEY=root-jwt\nQWED_API_KEY_LOOKUP_SECRET=root-lookup\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(nested)
    monkeypatch.delenv("QWED_JWT_SECRET_KEY", raising=False)
    monkeypatch.delenv("QWED_API_KEY_LOOKUP_SECRET", raising=False)

    _REAL_SEED_FROM_ROOT()

    assert os.getenv("QWED_JWT_SECRET_KEY") == "root-jwt"
    assert os.getenv("QWED_API_KEY_LOOKUP_SECRET") == "root-lookup"


def test_seed_reports_filled_names(monkeypatch, tmp_path):
    """The filled-set lets the stale-server guard tell retained apart from
    freshly generated (Sentry on #375)."""
    root = tmp_path / "proj"
    root.mkdir()
    (root / "pyproject.toml").write_text("[project]\nname = 'proj'\n", encoding="utf-8")
    (root / ".env").write_text("QWED_JWT_SECRET_KEY=root-jwt\n", encoding="utf-8")
    monkeypatch.chdir(root)
    monkeypatch.delenv("QWED_JWT_SECRET_KEY", raising=False)
    monkeypatch.delenv("QWED_API_KEY_LOOKUP_SECRET", raising=False)

    filled = _REAL_SEED_FROM_ROOT()

    assert filled == {"QWED_JWT_SECRET_KEY"}


def test_seed_prefers_root_over_nested_dotenv(monkeypatch, tmp_path):
    """CodeRabbit on #375: with dotenv loading the nested .env afterwards
    (override=False), the seeded root values must already hold so the
    nested file cannot outrank them."""
    root = tmp_path / "proj"
    nested = root / "sub"
    nested.mkdir(parents=True)
    (root / "pyproject.toml").write_text("[project]\nname = 'proj'\n", encoding="utf-8")
    (root / ".env").write_text("QWED_API_KEY_LOOKUP_SECRET=root-lookup\n", encoding="utf-8")
    (nested / ".env").write_text("QWED_API_KEY_LOOKUP_SECRET=nested-lookup\n", encoding="utf-8")
    monkeypatch.chdir(nested)
    monkeypatch.delenv("QWED_API_KEY_LOOKUP_SECRET", raising=False)

    filled = _REAL_SEED_FROM_ROOT()

    assert filled == {"QWED_API_KEY_LOOKUP_SECRET"}
    assert os.getenv("QWED_API_KEY_LOOKUP_SECRET") == "root-lookup"


def test_seed_server_secrets_keeps_explicit_env(monkeypatch, tmp_path):
    """Explicit environment still wins over the root .env (setdefault)."""
    root = tmp_path / "proj"
    root.mkdir()
    (root / "pyproject.toml").write_text("[project]\nname = 'proj'\n", encoding="utf-8")
    (root / ".env").write_text("QWED_JWT_SECRET_KEY=root-jwt\n", encoding="utf-8")
    monkeypatch.chdir(root)
    monkeypatch.setenv("QWED_JWT_SECRET_KEY", "explicit-jwt")

    _REAL_SEED_FROM_ROOT()

    assert os.getenv("QWED_JWT_SECRET_KEY") == "explicit-jwt"


def test_seed_server_secrets_degrades_quietly(monkeypatch):
    """Missing credential_store or unreadable root .env: seeding is best
    effort — onboarding falls back to plain env + generation.

    The missing-module arm uses patch.dict (no re-import happens inside),
    NEVER sys.modules replace + re-import: that leaves the parent package
    attribute pointing at a ghost copy, so later mock.patch calls
    (getattr-walk) and production from-imports (sys.modules) diverge for
    the rest of the session (broke 3 tests on 3.10).
    """
    with patch.dict(
        sys.modules, {"qwed_new.providers.credential_store": None}
    ):
        _REAL_SEED_FROM_ROOT()  # must not raise

    import qwed_new.providers.credential_store as credential_store

    monkeypatch.setattr(
        credential_store, "_find_project_root", lambda *a, **k: (_ for _ in ()).throw(OSError("denied"))
    )
    _REAL_SEED_FROM_ROOT()  # must not raise


def test_seed_server_secrets_survives_malformed_dotenv(monkeypatch, tmp_path):
    """Sentry MEDIUM on #375: non-UTF-8 bytes in the root .env raise
    UnicodeDecodeError (a ValueError, not OSError) — seeding must swallow it."""
    root = tmp_path / "proj"
    root.mkdir()
    (root / "pyproject.toml").write_text("[project]\nname = 'proj'\n", encoding="utf-8")
    (root / ".env").write_bytes(b"QWED_JWT_SECRET_KEY=\xff\xfe-broken\n")
    monkeypatch.chdir(root)
    monkeypatch.delenv("QWED_JWT_SECRET_KEY", raising=False)

    _REAL_SEED_FROM_ROOT()  # must not raise

    assert os.getenv("QWED_JWT_SECRET_KEY", "") == ""


def test_fresh_provisioned_server_import_gate(monkeypatch, tmp_path):
    """The exact gate from issue #372, in a real interpreter: with freshly
    provisioned secrets in env, `qwed_new.api.main:app` imports without the
    fail-closed RuntimeError. No ports, no uvicorn — the import IS the gate."""
    import subprocess
    import sys

    from qwed_new.config import ensure_jwt_secret as fresh_jwt

    monkeypatch.delenv("QWED_JWT_SECRET_KEY", raising=False)
    monkeypatch.delenv("QWED_API_KEY_LOOKUP_SECRET", raising=False)
    jwt_secret = fresh_jwt()
    # Module-level unpatched binding (the autouse fixture stubs the module
    # attribute — a local import here would bind the mock).
    lookup_secret = _REAL_ENSURE_LOOKUP_SECRET()
    assert jwt_secret != lookup_secret

    repo_src = Path(__file__).resolve().parents[1] / "src"
    # Ambient env plus overrides: the gate only cares about the two secrets,
    # but the import chain needs HOME etc. (Path.home() in config load).
    env = dict(os.environ)
    env.update(
        {
            "PYTHONPATH": str(repo_src),
            "QWED_JWT_SECRET_KEY": jwt_secret,
            "QWED_API_KEY_LOOKUP_SECRET": lookup_secret,
        }
    )
    code = "from qwed_new.api.main import app; print(type(app).__name__)"
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        cwd=str(tmp_path),
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert "FastAPI" in proc.stdout


def test_ensure_local_server_running_terminates_on_timeout(monkeypatch):
    popen_capture = {}
    expected_src = str(Path("repo") / "src")
    runtime_dir = Path("runtime-dir")

    class _FakeProcess:
        def __init__(self):
            self.terminated = False
            self.killed = False

        def terminate(self):
            self.terminated = True

        def kill(self):
            self.killed = True

    process = _FakeProcess()

    monkeypatch.setattr("qwed_sdk.cli._check_server_health", lambda _url, timeout=2.0: False)
    monkeypatch.setattr("qwed_sdk.cli._src_path", lambda: expected_src)
    monkeypatch.setattr("qwed_sdk.cli._resolve_server_runtime_dir", lambda: runtime_dir)
    monkeypatch.setattr("qwed_sdk.cli.time.sleep", lambda _s: None)

    def _fake_popen(command, **kwargs):
        popen_capture["command"] = command
        popen_capture["kwargs"] = kwargs
        return process

    monkeypatch.setattr("qwed_sdk.cli.subprocess.Popen", _fake_popen)

    ready, started = _ensure_local_server_running("http://127.0.0.1:9001", "jwt-token")
    assert ready is False
    assert started is True
    assert process.terminated is True
    assert process.killed is False
    assert popen_capture["command"][-2:] == ["--port", "9001"]


def test_ensure_local_server_running_kills_process_when_terminate_fails(monkeypatch):
    expected_src = str(Path("repo") / "src")
    runtime_dir = Path("runtime-dir")

    class _FakeProcess:
        def __init__(self):
            self.killed = False

        def terminate(self):
            raise RuntimeError("terminate failed")

        def kill(self):
            self.killed = True

    process = _FakeProcess()
    monkeypatch.setattr("qwed_sdk.cli._check_server_health", lambda _url, timeout=2.0: False)
    monkeypatch.setattr("qwed_sdk.cli._src_path", lambda: expected_src)
    monkeypatch.setattr("qwed_sdk.cli._resolve_server_runtime_dir", lambda: runtime_dir)
    monkeypatch.setattr("qwed_sdk.cli.time.sleep", lambda _s: None)
    monkeypatch.setattr("qwed_sdk.cli.subprocess.Popen", lambda *_args, **_kwargs: process)

    ready, started = _ensure_local_server_running("http://127.0.0.1:9001", "jwt-token")
    assert ready is False
    assert started is True
    assert process.killed is True


def test_resolve_server_runtime_dir_prefers_cwd_when_writable(monkeypatch):
    cwd_path = Path("writable-dir")
    monkeypatch.setattr("qwed_sdk.cli.Path.cwd", lambda: cwd_path)
    monkeypatch.setattr("qwed_sdk.cli.os.access", lambda _path, _mode: True)

    assert _resolve_server_runtime_dir() == cwd_path.resolve()


def test_resolve_server_runtime_dir_falls_back_to_home_when_unwritable(monkeypatch):
    cwd_path = Path("readonly-dir")
    home_path = Path("home-dir")
    mkdir_calls = []

    monkeypatch.setattr("qwed_sdk.cli.Path.cwd", lambda: cwd_path)
    monkeypatch.setattr("qwed_sdk.cli.Path.home", lambda: home_path)
    monkeypatch.setattr("qwed_sdk.cli.os.access", lambda _path, _mode: False)

    def _fake_mkdir(self, parents=True, exist_ok=True):
        mkdir_calls.append((self, parents, exist_ok))

    monkeypatch.setattr("qwed_sdk.cli.Path.mkdir", _fake_mkdir)

    expected = (home_path / "qwed-demo").resolve()
    assert _resolve_server_runtime_dir() == expected
    assert len(mkdir_calls) == 1
    created_path, parents, exist_ok = mkdir_calls[0]
    assert created_path.resolve() == expected
    assert parents is True
    assert exist_ok is True


def test_validate_local_server_target_rejects_non_loopback():
    with pytest.raises(ValueError, match="loopback"):
        _validate_local_server_target("http://10.0.0.9:8000")


def test_validate_local_server_target_rejects_out_of_range_port():
    with pytest.raises(ValueError, match="1024-65535"):
        _validate_local_server_target("http://127.0.0.1:80")


def test_ensure_gitignore_protection_noninteractive_raises_when_update_fails():
    with pytest.raises(RuntimeError, match=r"Failed to update \.gitignore"):
        _ensure_gitignore_protection_noninteractive(lambda: False, lambda: False)


def test_ensure_gitignore_protection_noninteractive_noop_when_already_safe():
    called = {"add": False}

    def _add():
        called["add"] = True
        return True

    _ensure_gitignore_protection_noninteractive(lambda: True, _add)
    assert called["add"] is False


def test_test_gemini_connection_success(monkeypatch):
    class _Response:
        status_code = 200

    monkeypatch.setattr("httpx.get", lambda *args, **kwargs: _Response())
    success, message = _test_gemini_connection("gem-test")
    assert success is True
    assert "Connected to Gemini API" in message


def test_test_gemini_connection_auth_failure(monkeypatch):
    class _Response:
        status_code = 401

    monkeypatch.setattr("httpx.get", lambda *args, **kwargs: _Response())
    success, message = _test_gemini_connection("gem-test")
    assert success is False
    assert "Authentication failed" in message


def test_test_gemini_connection_timeout(monkeypatch):
    import httpx

    def _raise_timeout(*_args, **_kwargs):
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr("httpx.get", _raise_timeout)
    success, message = _test_gemini_connection("gem-test")
    assert success is False
    assert "timed out" in message


def test_test_gemini_connection_connect_error(monkeypatch):
    import httpx

    def _raise_connect(*_args, **_kwargs):
        raise httpx.ConnectError("offline")

    monkeypatch.setattr("httpx.get", _raise_connect)
    success, message = _test_gemini_connection("gem-test")
    assert success is False
    assert "Cannot connect" in message


def test_test_gemini_connection_other_http_status(monkeypatch):
    class _Response:
        status_code = 429

    monkeypatch.setattr("httpx.get", lambda *args, **kwargs: _Response())
    success, message = _test_gemini_connection("gem-test")
    assert success is False
    assert "status 429" in message


def test_check_server_health_handles_exception(monkeypatch):
    import httpx

    def _raise(*_args, **_kwargs):
        raise httpx.ConnectError("down")

    monkeypatch.setattr("httpx.get", _raise)
    assert _check_server_health("http://127.0.0.1:9001") is False


def test_check_server_health_true_on_200(monkeypatch):
    class _Response:
        status_code = 200

    monkeypatch.setattr("httpx.get", lambda *_args, **_kwargs: _Response())
    assert _check_server_health("http://127.0.0.1:9001") is True


def test_required_engine_report_handles_missing_dependency(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def _fake_import(name, *args, **kwargs):
        if name == "sqlglot":
            raise ImportError("missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", _fake_import)

    all_ready, report = _required_engine_report()
    assert all_ready is False
    assert any(item["name"] == "SQLGlot" and item["ready"] is False for item in report)


def test_run_init_smoke_suite_returns_all_checks():
    suite = _run_init_smoke_suite()
    labels = [item["label"] for item in suite]
    assert labels == ["2+2=5", "x>5 AND x<3", "SELECT * WHERE 1=1", "eval(user_input)"]
    assert all(item["passed"] for item in suite)


def test_ensure_local_server_running_returns_when_already_healthy(monkeypatch):
    monkeypatch.setattr("qwed_sdk.cli._check_server_health", lambda _url, timeout=2.0: True)
    ready, started = _ensure_local_server_running("http://127.0.0.1:9001", "jwt-token")
    assert ready is True
    assert started is False


def test_init_non_interactive_openai_does_not_use_nvidia_fallback(
    monkeypatch,
    runner,
):
    provider_map = {
        "openai": OnboardingProvider(
            slug="openai",
            name="OpenAI",
            active_provider="openai",
            key_env="OPENAI_API_KEY",
            model_env="OPENAI_MODEL",
            base_url_env=None,
            default_model="gpt-4o-mini",
            default_base_url=None,
            connection_slug="openai",
            key_pattern=None,
        )
    }

    monkeypatch.setenv("NVIDIA_API_KEY", "nv-api-key")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr("qwed_sdk.cli._load_dotenv_if_available", lambda: None)
    monkeypatch.setattr("qwed_sdk.cli._required_engine_report", lambda: (True, _engine_report()))
    monkeypatch.setattr("qwed_sdk.cli._build_onboarding_provider_map", lambda _get_provider: provider_map)

    result = runner.invoke(
        init,
        [
            "--provider",
            "openai",
            "--organization-name",
            "demo-org",
            "--non-interactive",
            "--skip-tests",
        ],
    )

    assert result.exit_code == 1
    assert "OPENAI_API_KEY is required" in result.output


def test_resolve_provider_api_key_ignores_nvidia_placeholder_env(monkeypatch):
    profile = OnboardingProvider(
        slug="nvidia",
        name="NVIDIA NIM",
        active_provider="openai_compat",
        key_env="CUSTOM_API_KEY",
        model_env="CUSTOM_MODEL",
        base_url_env="CUSTOM_BASE_URL",
        default_model="nvidia/nemotron-3-super-120b-a12b",
        default_base_url="https://integrate.api.nvidia.com/v1",
        connection_slug="openai-compatible",
        key_pattern=None,
    )
    monkeypatch.setenv("CUSTOM_API_KEY", "nvapi-xxxx")
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    assert _resolve_provider_api_key(profile, None) == ""


def test_resolve_provider_api_key_uses_nvidia_fallback_when_primary_is_placeholder(monkeypatch):
    profile = OnboardingProvider(
        slug="nvidia",
        name="NVIDIA NIM",
        active_provider="openai_compat",
        key_env="CUSTOM_API_KEY",
        model_env="CUSTOM_MODEL",
        base_url_env="CUSTOM_BASE_URL",
        default_model="nvidia/nemotron-3-super-120b-a12b",
        default_base_url="https://integrate.api.nvidia.com/v1",
        connection_slug="openai-compatible",
        key_pattern=None,
    )
    monkeypatch.setenv("CUSTOM_API_KEY", "nvapi-xxxx")
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-real-key-0123456789abcdef")
    assert _resolve_provider_api_key(profile, None) == "nvapi-real-key-0123456789abcdef"


def test_resolve_provider_api_key_ignores_generic_placeholder_for_any_provider(monkeypatch):
    profile = OnboardingProvider(
        slug="openai",
        name="OpenAI",
        active_provider="openai",
        key_env="OPENAI_API_KEY",
        model_env="OPENAI_MODEL",
        base_url_env=None,
        default_model="gpt-4o-mini",
        default_base_url=None,
        connection_slug="openai",
        key_pattern=None,
    )
    monkeypatch.setenv("OPENAI_API_KEY", "your-api-key")
    assert _resolve_provider_api_key(profile, None) == ""


def test_resolve_provider_api_key_ignores_placeholder_cli_argument(monkeypatch):
    profile = OnboardingProvider(
        slug="openai",
        name="OpenAI",
        active_provider="openai",
        key_env="OPENAI_API_KEY",
        model_env="OPENAI_MODEL",
        base_url_env=None,
        default_model="gpt-4o-mini",
        default_base_url=None,
        connection_slug="openai",
        key_pattern=None,
    )
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-from-env")
    assert _resolve_provider_api_key(profile, "your-api-key") == "sk-real-from-env"


def test_resolve_provider_api_key_ignores_placeholder_nvidia_fallback(monkeypatch):
    profile = OnboardingProvider(
        slug="nvidia",
        name="NVIDIA NIM",
        active_provider="openai_compat",
        key_env="CUSTOM_API_KEY",
        model_env="CUSTOM_MODEL",
        base_url_env="CUSTOM_BASE_URL",
        default_model="nvidia/nemotron-3-super-120b-a12b",
        default_base_url="https://integrate.api.nvidia.com/v1",
        connection_slug="openai-compatible",
        key_pattern=None,
    )
    monkeypatch.delenv("CUSTOM_API_KEY", raising=False)
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-xxxx")
    assert _resolve_provider_api_key(profile, None) == ""


@pytest.mark.parametrize(
    ("candidate", "provider_slug"),
    [
        ("token-placeholder-value", "openai"),
        ("please-changeme-now", "openai"),
        ("replace-prod-key-now", "openai"),
        ("x*x", "openai"),
    ],
)
def test_placeholder_detector_catches_pattern_variants(candidate, provider_slug):
    assert _looks_like_placeholder_api_key(candidate, provider_slug) is True


@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value={"custom": _custom_provider_map()["custom"]})
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._load_dotenv_if_available")
def test_init_exits_for_unsupported_provider_slug(
    _mock_load_dotenv,
    _mock_required_engines,
    _mock_provider_map,
    runner,
):
    result = runner.invoke(
        init,
        [
            "--provider",
            "openai",
            "--organization-name",
            "demo-org",
            "--non-interactive",
            "--skip-tests",
        ],
    )
    assert result.exit_code == 1
    assert "Unsupported provider 'openai'" in result.output


@patch("qwed_sdk.cli._bootstrap_api_key", return_value=("qwed_live_test_key", "demo-org"))
@patch("qwed_sdk.cli._ensure_local_server_running", return_value=(True, False))
@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_custom_provider_map())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._ensure_gitignore_protection_noninteractive")
@patch("qwed_sdk.cli._ensure_gitignore_protection")
@patch("qwed_sdk.cli._load_dotenv_if_available")
@patch("qwed_new.providers.key_validator.validate_key_format", return_value=(True, "ok"))
@patch("qwed_new.providers.key_validator.test_connection", return_value=(True, "Connected"))
@patch("qwed_new.providers.credential_store.write_env_file", return_value=".env")
@patch("qwed_new.config.ensure_jwt_secret", return_value=TEST_TOKEN_MARKER)
def test_init_non_interactive_custom_uses_default_base_url(
    _mock_jwt,
    mock_write_env,
    _mock_test_connection,
    _mock_validate,
    _mock_load_dotenv,
    _mock_gitignore_interactive,
    _mock_gitignore,
    _mock_required_engines,
    _mock_provider_map,
    _mock_server,
    _mock_bootstrap,
    runner,
    monkeypatch,
):
    # Drop ambient CUSTOM_BASE_URL (e.g. a developer's real .env loaded at
    # collection): the point is the *default* is used when nothing provides one.
    monkeypatch.delenv("CUSTOM_BASE_URL", raising=False)
    result = runner.invoke(
        init,
        [
            "--provider",
            "custom",
            "--api-key",
            "custom-key",
            "--organization-name",
            "demo-org",
            "--non-interactive",
            "--skip-tests",
        ],
    )

    assert result.exit_code == 0
    env_vars = mock_write_env.call_args.args[0]
    assert env_vars["CUSTOM_BASE_URL"] == "https://api.example.com/v1"


@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_custom_provider_map(default_base_url=None))
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._load_dotenv_if_available")
def test_init_non_interactive_custom_requires_base_url_if_no_default(
    _mock_load_dotenv,
    _mock_required_engines,
    _mock_provider_map,
    monkeypatch,
    runner,
):
    monkeypatch.delenv("CUSTOM_BASE_URL", raising=False)
    result = runner.invoke(
        init,
        [
            "--provider",
            "custom",
            "--api-key",
            "custom-key",
            "--organization-name",
            "demo-org",
            "--non-interactive",
            "--skip-tests",
        ],
    )

    assert result.exit_code == 1
    assert "CUSTOM_BASE_URL is required" in result.output


@patch("qwed_sdk.cli._bootstrap_api_key", return_value=("qwed_live_test_key", "demo-org"))
@patch("qwed_sdk.cli._ensure_local_server_running", return_value=(True, False))
@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_gemini_provider_map())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._ensure_gitignore_protection_noninteractive")
@patch("qwed_sdk.cli._ensure_gitignore_protection")
@patch("qwed_sdk.cli._load_dotenv_if_available")
@patch("qwed_new.providers.key_validator.validate_key_format", return_value=(True, "ok"))
@patch("qwed_new.providers.credential_store.write_env_file", return_value=".env")
@patch("qwed_new.config.ensure_jwt_secret", return_value=TEST_TOKEN_MARKER)
@patch("qwed_sdk.cli._test_gemini_connection", return_value=(True, "Connected to Gemini API."))
def test_init_uses_gemini_connection_path(
    _mock_gemini_conn,
    _mock_jwt,
    _mock_write_env,
    _mock_validate,
    _mock_load_dotenv,
    _mock_gitignore_interactive,
    _mock_gitignore,
    _mock_required_engines,
    _mock_provider_map,
    _mock_server,
    _mock_bootstrap,
    runner,
):
    result = runner.invoke(
        init,
        [
            "--provider",
            "gemini",
            "--api-key",
            "gem-key",
            "--organization-name",
            "demo-org",
            "--non-interactive",
            "--skip-tests",
        ],
    )

    assert result.exit_code == 0
    _mock_gemini_conn.assert_called_once_with("gem-key")


@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_provider_map())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._load_dotenv_if_available")
@patch("qwed_new.providers.key_validator.validate_key_format", return_value=(False, "bad format"))
def test_init_non_interactive_invalid_key_format_exits(
    _mock_validate,
    _mock_load_dotenv,
    _mock_required_engines,
    _mock_provider_map,
    runner,
):
    result = runner.invoke(
        init,
        [
            "--provider",
            "openai",
            "--api-key",
            "bad-key",
            "--organization-name",
            "demo-org",
            "--non-interactive",
            "--skip-tests",
        ],
    )

    assert result.exit_code == 1
    assert "Key validation failed: bad format" in result.output


@patch("qwed_sdk.cli._bootstrap_api_key", return_value=("qwed_live_test_key", "demo-org"))
@patch("qwed_sdk.cli._ensure_local_server_running", return_value=(True, False))
@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_provider_map())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._ensure_gitignore_protection_noninteractive")
@patch("qwed_sdk.cli._ensure_gitignore_protection")
@patch("qwed_sdk.cli._load_dotenv_if_available")
@patch("qwed_new.providers.key_validator.validate_key_format", return_value=(True, "ok"))
@patch("qwed_new.providers.key_validator.test_connection", return_value=(True, "Connected"))
@patch("qwed_new.providers.credential_store.write_env_file", return_value=".env")
@patch("qwed_new.config.ensure_jwt_secret", side_effect=RuntimeError("jwt fail"))
def test_init_exits_when_jwt_creation_fails(
    _mock_jwt,
    _mock_write_env,
    _mock_test_connection,
    _mock_validate,
    _mock_load_dotenv,
    _mock_gitignore_interactive,
    _mock_gitignore,
    _mock_required_engines,
    _mock_provider_map,
    _mock_server,
    _mock_bootstrap,
    runner,
):
    result = runner.invoke(
        init,
        [
            "--provider",
            "openai",
            "--api-key",
            "sk-test-key",
            "--organization-name",
            "demo-org",
            "--non-interactive",
            "--skip-tests",
        ],
    )
    assert result.exit_code == 1
    assert "Failed to prepare JWT secret" in result.output


@patch("qwed_sdk.cli._bootstrap_api_key", return_value=("qwed_live_test_key", "demo-org"))
@patch("qwed_sdk.cli._ensure_local_server_running", return_value=(True, False))
@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_provider_map())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._ensure_gitignore_protection_noninteractive")
@patch("qwed_sdk.cli._ensure_gitignore_protection")
@patch("qwed_sdk.cli._load_dotenv_if_available")
@patch("qwed_new.providers.key_validator.validate_key_format", return_value=(True, "ok"))
@patch("qwed_new.providers.key_validator.test_connection", return_value=(True, "Connected"))
@patch("qwed_new.providers.credential_store.write_env_file", side_effect=RuntimeError("disk full"))
@patch("qwed_new.config.ensure_jwt_secret", return_value=TEST_TOKEN_MARKER)
def test_init_exits_when_env_write_fails(
    _mock_jwt,
    _mock_write_env,
    _mock_test_connection,
    _mock_validate,
    _mock_load_dotenv,
    _mock_gitignore_interactive,
    _mock_gitignore,
    _mock_required_engines,
    _mock_provider_map,
    _mock_server,
    _mock_bootstrap,
    runner,
):
    result = runner.invoke(
        init,
        [
            "--provider",
            "openai",
            "--api-key",
            "sk-test-key",
            "--organization-name",
            "demo-org",
            "--non-interactive",
            "--skip-tests",
        ],
    )
    assert result.exit_code == 1
    assert "Failed to store credentials securely" in result.output


@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_provider_map())
@patch(
    "qwed_sdk.cli._required_engine_report",
    return_value=(
        False,
        [
            {"name": "SymPy", "ready": True, "detail": "math engine ready", "install_hint": "", "version": "1.14.0"},
            {"name": "SQLGlot", "ready": False, "detail": "missing", "install_hint": "pip install sqlglot", "version": None},
        ],
    ),
)
@patch("qwed_sdk.cli._load_dotenv_if_available")
def test_init_exits_when_engine_not_ready(
    _mock_load_dotenv,
    _mock_required_engines,
    _mock_provider_map,
    runner,
):
    result = runner.invoke(
        init,
        [
            "--provider",
            "openai",
            "--api-key",
            "sk-test-key",
            "--organization-name",
            "demo-org",
            "--non-interactive",
        ],
    )
    assert result.exit_code == 1
    assert "Engine initialization failed" in result.output


@patch("qwed_sdk.cli._run_init_smoke_suite", return_value=[{"label": "x", "passed": False, "result": "FAILED"}])
@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_provider_map())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._load_dotenv_if_available")
def test_init_exits_when_smoke_suite_fails(
    _mock_load_dotenv,
    _mock_required_engines,
    _mock_provider_map,
    _mock_smoke,
    runner,
):
    result = runner.invoke(
        init,
        [
            "--provider",
            "openai",
            "--api-key",
            "sk-test-key",
            "--organization-name",
            "demo-org",
            "--non-interactive",
        ],
    )
    assert result.exit_code == 1
    assert "Built-in verification suite failed" in result.output


@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_provider_map())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._load_dotenv_if_available")
def test_init_interactive_invalid_provider_choice_exits(
    _mock_load_dotenv,
    _mock_required_engines,
    _mock_provider_map,
    runner,
):
    result = runner.invoke(init, ["--skip-tests"], input="7\n")
    assert result.exit_code == 1
    assert "Invalid provider selection." in result.output


def test_init_exits_when_core_import_fails(monkeypatch, runner):
    import builtins

    real_import = builtins.__import__

    def _fake_import(name, *args, **kwargs):
        if name == "qwed_new.providers.registry":
            raise ImportError("registry missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", _fake_import)

    result = runner.invoke(
        init,
        [
            "--provider",
            "openai",
            "--api-key",
            "sk-test-key",
            "--organization-name",
            "demo-org",
            "--non-interactive",
            "--skip-tests",
        ],
    )
    assert result.exit_code == 1
    assert "QWED core not found" in result.output


@patch("qwed_sdk.cli._bootstrap_api_key", return_value=("qwed_live_test_key", "demo-org"))
@patch("qwed_sdk.cli._ensure_local_server_running", return_value=(True, False))
@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_provider_map())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._ensure_gitignore_protection_noninteractive")
@patch("qwed_sdk.cli._ensure_gitignore_protection")
@patch("qwed_sdk.cli._load_dotenv_if_available")
@patch("qwed_new.providers.key_validator.validate_key_format", return_value=(True, "ok"))
@patch("qwed_new.providers.key_validator.test_connection", return_value=(False, "bad creds"))
@patch("qwed_new.providers.credential_store.write_env_file", return_value=".env")
@patch("qwed_new.config.ensure_jwt_secret", return_value=TEST_TOKEN_MARKER)
def test_init_interactive_aborts_when_retry_declined(
    _mock_jwt,
    _mock_write_env,
    _mock_test_connection,
    _mock_validate,
    _mock_load_dotenv,
    _mock_gitignore_interactive,
    _mock_gitignore,
    _mock_required_engines,
    _mock_provider_map,
    _mock_server,
    _mock_bootstrap,
    runner,
):
    result = runner.invoke(
        init,
        ["--skip-tests"],
        input="2\nsk-first\nn\n",
    )
    assert result.exit_code == 1


@patch("qwed_sdk.cli._bootstrap_api_key", return_value=("qwed_live_test_key", "demo-org"))
@patch("qwed_sdk.cli._ensure_local_server_running", return_value=(True, False))
@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_provider_map())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._ensure_gitignore_protection_noninteractive")
@patch("qwed_sdk.cli._ensure_gitignore_protection")
@patch("qwed_sdk.cli._load_dotenv_if_available")
@patch("qwed_new.providers.key_validator.validate_key_format", return_value=(False, "bad format"))
@patch("qwed_new.providers.key_validator.test_connection", return_value=(True, "Connected"))
@patch("qwed_new.providers.credential_store.write_env_file", return_value=".env")
@patch("qwed_new.config.ensure_jwt_secret", return_value=TEST_TOKEN_MARKER)
def test_init_interactive_shows_warning_on_invalid_key_format(
    _mock_jwt,
    _mock_write_env,
    _mock_test_connection,
    _mock_validate,
    _mock_load_dotenv,
    _mock_gitignore_interactive,
    _mock_gitignore,
    _mock_required_engines,
    _mock_provider_map,
    _mock_server,
    _mock_bootstrap,
    runner,
):
    result = runner.invoke(
        init,
        ["--skip-tests"],
        input="2\nsk-first\ndemo-org\n",
    )
    assert result.exit_code == 0
    assert "Warning: bad format" in result.output


@patch("qwed_sdk.cli._bootstrap_api_key", return_value=("qwed_live_test_key", "demo-org"))
@patch("qwed_sdk.cli._ensure_local_server_running", return_value=(True, False))
@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_custom_provider_map(default_model=""))
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._ensure_gitignore_protection_noninteractive")
@patch("qwed_sdk.cli._ensure_gitignore_protection")
@patch("qwed_sdk.cli._load_dotenv_if_available")
@patch("qwed_new.providers.key_validator.validate_key_format", return_value=(True, "ok"))
@patch("qwed_new.providers.key_validator.test_connection", return_value=(True, "Connected"))
@patch("qwed_new.providers.credential_store.write_env_file", return_value=".env")
@patch("qwed_new.config.ensure_jwt_secret", return_value=TEST_TOKEN_MARKER)
def test_init_interactive_prompts_for_model_when_default_empty(
    _mock_jwt,
    _mock_write_env,
    _mock_test_connection,
    _mock_validate,
    _mock_load_dotenv,
    _mock_gitignore_interactive,
    _mock_gitignore,
    _mock_required_engines,
    _mock_provider_map,
    _mock_server,
    _mock_bootstrap,
    monkeypatch,
    runner,
):
    monkeypatch.delenv("CUSTOM_API_KEY", raising=False)
    monkeypatch.delenv("CUSTOM_BASE_URL", raising=False)
    monkeypatch.delenv("CUSTOM_MODEL", raising=False)

    result = runner.invoke(
        init,
        ["--provider", "custom", "--skip-tests"],
        input="custom-key\nhttps://custom.example/v1\nmodel-x\ndemo-org\n",
    )
    assert result.exit_code == 0


@patch("qwed_sdk.cli._bootstrap_api_key", return_value=("qwed_live_test_key", "demo-org"))
@patch("qwed_sdk.cli._ensure_local_server_running", return_value=(True, False))
@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_custom_provider_map())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._ensure_gitignore_protection_noninteractive")
@patch("qwed_sdk.cli._ensure_gitignore_protection")
@patch("qwed_sdk.cli._load_dotenv_if_available")
@patch("qwed_new.providers.key_validator.validate_key_format", return_value=(True, "ok"))
@patch(
    "qwed_new.providers.key_validator.test_connection",
    side_effect=[(False, "bad creds"), (True, "Connected")],
)
@patch("qwed_new.providers.credential_store.write_env_file", return_value=".env")
@patch("qwed_new.config.ensure_jwt_secret", return_value=TEST_TOKEN_MARKER)
def test_init_interactive_custom_retry_prompts_base_url_again(
    _mock_jwt,
    _mock_write_env,
    mock_test_connection,
    _mock_validate,
    _mock_load_dotenv,
    _mock_gitignore_interactive,
    _mock_gitignore,
    _mock_required_engines,
    _mock_provider_map,
    _mock_server,
    _mock_bootstrap,
    monkeypatch,
    runner,
):
    monkeypatch.delenv("CUSTOM_API_KEY", raising=False)
    monkeypatch.delenv("CUSTOM_BASE_URL", raising=False)
    monkeypatch.delenv("CUSTOM_MODEL", raising=False)

    result = runner.invoke(
        init,
        ["--provider", "custom", "--skip-tests"],
        input="custom-key\nhttps://custom.example/v1\ny\ncustom-key-2\nhttps://custom2.example/v1\nmodel-y\ndemo-org\n",
    )
    assert result.exit_code == 0
    assert mock_test_connection.call_count == 2


@patch("qwed_sdk.cli._bootstrap_api_key", side_effect=RuntimeError("signup failed"))
@patch("qwed_sdk.cli._ensure_local_server_running", return_value=(True, True))
@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_provider_map())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._ensure_gitignore_protection_noninteractive")
@patch("qwed_sdk.cli._ensure_gitignore_protection")
@patch("qwed_sdk.cli._load_dotenv_if_available")
@patch("qwed_new.providers.key_validator.validate_key_format", return_value=(True, "ok"))
@patch("qwed_new.providers.key_validator.test_connection", return_value=(True, "Connected"))
@patch("qwed_new.providers.credential_store.write_env_file", return_value=".env")
@patch("qwed_new.config.ensure_jwt_secret", return_value=TEST_TOKEN_MARKER)
def test_init_exits_when_bootstrap_fails(
    _mock_jwt,
    _mock_write_env,
    _mock_test_connection,
    _mock_validate,
    _mock_load_dotenv,
    _mock_gitignore_interactive,
    _mock_gitignore,
    _mock_required_engines,
    _mock_provider_map,
    _mock_server,
    _mock_bootstrap,
    runner,
):
    result = runner.invoke(
        init,
        [
            "--provider",
            "openai",
            "--api-key",
            "sk-test-key",
            "--organization-name",
            "demo-org",
            "--non-interactive",
            "--skip-tests",
        ],
    )

    assert result.exit_code == 1
    assert "API key bootstrap failed" in result.output


@patch("qwed_sdk.cli._bootstrap_api_key", return_value=("qwed_live_test_key", "alias-org"))
@patch("qwed_sdk.cli._ensure_local_server_running", return_value=(True, False))
@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_provider_map())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._ensure_gitignore_protection_noninteractive")
@patch("qwed_sdk.cli._ensure_gitignore_protection")
@patch("qwed_sdk.cli._load_dotenv_if_available")
@patch("qwed_new.providers.key_validator.validate_key_format", return_value=(True, "ok"))
@patch("qwed_new.providers.key_validator.test_connection", return_value=(True, "Connected"))
@patch("qwed_new.providers.credential_store.write_env_file", return_value=".env")
@patch("qwed_new.config.ensure_jwt_secret", return_value=TEST_TOKEN_MARKER)
def test_init_prints_org_alias_when_bootstrap_renames_org(
    _mock_jwt,
    _mock_write_env,
    _mock_test_connection,
    _mock_validate,
    _mock_load_dotenv,
    _mock_gitignore_interactive,
    _mock_gitignore,
    _mock_required_engines,
    _mock_provider_map,
    _mock_server,
    _mock_bootstrap,
    runner,
):
    result = runner.invoke(
        init,
        [
            "--provider",
            "openai",
            "--api-key",
            "sk-test-key",
            "--organization-name",
            "demo-org",
            "--non-interactive",
            "--skip-tests",
        ],
    )
    assert result.exit_code == 0
    assert "Organization alias used: alias-org" in result.output


@patch("qwed_sdk.cli._bootstrap_api_key", return_value=("qwed_live_test_key", "qwed-beef"))
@patch("qwed_sdk.cli._ensure_local_server_running", return_value=(True, False))
@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_provider_map())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._ensure_gitignore_protection_noninteractive")
@patch("qwed_sdk.cli._ensure_gitignore_protection")
@patch("qwed_sdk.cli._load_dotenv_if_available")
@patch("qwed_sdk.cli.secrets.token_hex", return_value="beef")
@patch("qwed_new.providers.key_validator.validate_key_format", return_value=(True, "ok"))
@patch("qwed_new.providers.key_validator.test_connection", return_value=(True, "Connected"))
@patch("qwed_new.providers.credential_store.write_env_file", return_value=".env")
@patch("qwed_new.config.ensure_jwt_secret", return_value=TEST_TOKEN_MARKER)
def test_init_non_interactive_autogenerates_org_name_when_missing(
    _mock_jwt,
    _mock_write_env,
    _mock_test_connection,
    _mock_validate,
    _mock_token_hex,
    _mock_load_dotenv,
    _mock_gitignore_interactive,
    _mock_gitignore,
    _mock_required_engines,
    _mock_provider_map,
    _mock_server,
    _mock_bootstrap,
    runner,
):
    result = runner.invoke(
        init,
        [
            "--provider",
            "openai",
            "--api-key",
            "sk-test-key",
            "--non-interactive",
            "--skip-tests",
        ],
    )
    assert result.exit_code == 0
    _mock_bootstrap.assert_called_once_with("http://localhost:8000", "qwed-beef")


@patch("qwed_sdk.cli._bootstrap_api_key", return_value=("qwed_live_test_key", "demo-org"))
@patch("qwed_sdk.cli._ensure_local_server_running", return_value=(True, False))
@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_provider_map())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._ensure_gitignore_protection_noninteractive")
@patch("qwed_sdk.cli._ensure_gitignore_protection")
@patch("qwed_sdk.cli._load_dotenv_if_available")
@patch("qwed_new.providers.key_validator.validate_key_format", return_value=(True, "ok"))
@patch("qwed_new.providers.key_validator.test_connection", return_value=(True, "Connected"))
@patch("qwed_new.providers.credential_store.write_env_file", return_value=".env")
@patch("qwed_new.config.ensure_jwt_secret", return_value=TEST_TOKEN_MARKER)
def test_init_interactive_requires_org_name(
    _mock_jwt,
    _mock_write_env,
    _mock_test_connection,
    _mock_validate,
    _mock_load_dotenv,
    _mock_gitignore_interactive,
    _mock_gitignore,
    _mock_required_engines,
    _mock_provider_map,
    _mock_server,
    _mock_bootstrap,
    runner,
):
    result = runner.invoke(
        init,
        ["--provider", "openai", "--api-key", "sk-test-key", "--skip-tests"],
        input="   \n",
    )
    assert result.exit_code == 1
    assert "Organization name is required." in result.output


@patch("qwed_sdk.cli._ensure_local_server_running", side_effect=ValueError("bad host"))
@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_provider_map())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._ensure_gitignore_protection_noninteractive")
@patch("qwed_sdk.cli._ensure_gitignore_protection")
@patch("qwed_sdk.cli._load_dotenv_if_available")
@patch("qwed_new.providers.key_validator.validate_key_format", return_value=(True, "ok"))
@patch("qwed_new.providers.key_validator.test_connection", return_value=(True, "Connected"))
@patch("qwed_new.providers.credential_store.write_env_file", return_value=".env")
@patch("qwed_new.config.ensure_jwt_secret", return_value=TEST_TOKEN_MARKER)
def test_init_exits_on_invalid_server_url(
    _mock_jwt,
    _mock_write_env,
    _mock_test_connection,
    _mock_validate,
    _mock_load_dotenv,
    _mock_gitignore_interactive,
    _mock_gitignore,
    _mock_required_engines,
    _mock_provider_map,
    _mock_server,
    runner,
):
    result = runner.invoke(
        init,
        [
            "--provider",
            "openai",
            "--api-key",
            "sk-test-key",
            "--organization-name",
            "demo-org",
            "--non-interactive",
            "--skip-tests",
        ],
    )
    assert result.exit_code == 1
    assert "Invalid server URL" in result.output


@patch("qwed_sdk.cli._ensure_local_server_running", return_value=(False, True))
@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_provider_map())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._ensure_gitignore_protection_noninteractive")
@patch("qwed_sdk.cli._ensure_gitignore_protection")
@patch("qwed_sdk.cli._load_dotenv_if_available")
@patch("qwed_new.providers.key_validator.validate_key_format", return_value=(True, "ok"))
@patch("qwed_new.providers.key_validator.test_connection", return_value=(True, "Connected"))
@patch("qwed_new.providers.credential_store.write_env_file", return_value=".env")
@patch("qwed_new.config.ensure_jwt_secret", return_value=TEST_TOKEN_MARKER)
def test_init_exits_when_local_server_not_ready(
    _mock_jwt,
    _mock_write_env,
    _mock_test_connection,
    _mock_validate,
    _mock_load_dotenv,
    _mock_gitignore_interactive,
    _mock_gitignore,
    _mock_required_engines,
    _mock_provider_map,
    _mock_server,
    runner,
):
    result = runner.invoke(
        init,
        [
            "--provider",
            "openai",
            "--api-key",
            "sk-test-key",
            "--organization-name",
            "demo-org",
            "--non-interactive",
            "--skip-tests",
        ],
    )
    assert result.exit_code == 1
    assert "Failed to start local server" in result.output


@patch("qwed_sdk.cli._bootstrap_api_key", return_value=("qwed_live_test_key", "demo-org"))
@patch("qwed_sdk.cli._ensure_local_server_running", return_value=(True, False))
@patch("qwed_sdk.cli._build_onboarding_provider_map", return_value=_provider_map())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _engine_report()))
@patch("qwed_sdk.cli._ensure_gitignore_protection_noninteractive")
@patch("qwed_sdk.cli._ensure_gitignore_protection")
@patch("qwed_sdk.cli._load_dotenv_if_available")
@patch("qwed_new.providers.key_validator.validate_key_format", return_value=(True, "ok"))
@patch(
    "qwed_new.providers.key_validator.test_connection",
    side_effect=[(False, "Auth failed"), (True, "Connected")],
)
@patch("qwed_new.providers.credential_store.write_env_file", return_value=".env")
@patch("qwed_new.config.ensure_jwt_secret", return_value=TEST_TOKEN_MARKER)
def test_init_interactive_retries_connection_until_success(
    _mock_jwt,
    _mock_write_env,
    mock_test_connection,
    _mock_validate,
    _mock_load_dotenv,
    _mock_gitignore_interactive,
    _mock_gitignore,
    _mock_required_engines,
    _mock_provider_map,
    _mock_server,
    _mock_bootstrap,
    runner,
):
    result = runner.invoke(
        init,
        ["--skip-tests"],
        input="2\nsk-first\ny\nsk-second\n\ndemo-org\n",
    )

    assert result.exit_code == 0
    assert mock_test_connection.call_count == 2
    assert _mock_gitignore_interactive.called
    assert not _mock_gitignore.called
