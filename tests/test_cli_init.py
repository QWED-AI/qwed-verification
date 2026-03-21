import os
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from qwed_sdk.cli import (
    OnboardingProvider,
    _bootstrap_api_key,
    _ensure_local_server_running,
    init,
)

TEST_JWT_VALUE = "test-value-123"


@pytest.fixture
def runner():
    return CliRunner()


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
@patch("qwed_new.config.ensure_jwt_secret", return_value=TEST_JWT_VALUE)
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
@patch("qwed_new.config.ensure_jwt_secret", return_value=TEST_JWT_VALUE)
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
    assert env_vars["QWED_JWT_SECRET_KEY"] == TEST_JWT_VALUE
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


def test_ensure_local_server_running_applies_pythonpath_guard(monkeypatch):
    checks = iter([False, True])
    popen_capture = {}
    expected_src = str(Path("repo") / "src")

    monkeypatch.setattr("qwed_sdk.cli._check_server_health", lambda _url, timeout=2.0: next(checks))
    monkeypatch.setattr("qwed_sdk.cli._src_path", lambda: expected_src)
    monkeypatch.setattr("qwed_sdk.cli._project_root", lambda: Path("repo"))
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
    assert env["PYTHONPATH"].split(os.pathsep)[0] == expected_src


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
@patch("qwed_new.config.ensure_jwt_secret", return_value=TEST_JWT_VALUE)
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
