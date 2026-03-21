import json
import os
from unittest.mock import patch

from click.testing import CliRunner

from qwed_sdk.cli import _active_provider_status, _database_health, _doctor_report, _doctor_server_url, cli


def _required_ok_report():
    return [
        {"name": "SymPy", "ready": True, "detail": "math verification", "install_hint": "", "version": "1.14.0"},
        {"name": "Z3", "ready": True, "detail": "logic verification", "install_hint": "", "version": "4.13.3"},
        {"name": "AST", "ready": True, "detail": "code verification", "install_hint": "", "version": "built-in"},
        {"name": "SQLGlot", "ready": True, "detail": "sql verification", "install_hint": "", "version": "30.0.2"},
    ]


def _optional_report():
    return [
        {"name": "OpenCV", "ready": False, "detail": "image verification", "install_hint": "pip install qwed[vision]", "version": None},
    ]


@patch("qwed_sdk.cli._database_health", return_value={"healthy": True, "location": "qwed.db"})
@patch("qwed_sdk.cli._check_server_health", return_value=True)
@patch("qwed_sdk.cli._active_provider_status", return_value={"ok": True, "label": "NVIDIA NIM", "message": "Connected"})
@patch("qwed_sdk.cli._optional_engine_report", return_value=_optional_report())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _required_ok_report()))
def test_doctor_json_output(
    _mock_required,
    _mock_optional,
    _mock_provider,
    _mock_server,
    _mock_db,
):
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["provider"]["ok"] is True
    assert payload["server"]["running"] is True
    assert payload["database"]["healthy"] is True
    assert payload["engines"][0]["name"] == "SymPy"
    assert payload["status"].startswith("OPERATIONAL")


@patch("qwed_sdk.cli._database_health", return_value={"healthy": False, "location": "qwed.db"})
@patch("qwed_sdk.cli._check_server_health", return_value=False)
@patch("qwed_sdk.cli._active_provider_status", return_value={"ok": False, "label": "openai", "message": "Authentication failed"})
@patch("qwed_sdk.cli._optional_engine_report", return_value=_optional_report())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _required_ok_report()))
def test_doctor_degraded_exits_nonzero(
    _mock_required,
    _mock_optional,
    _mock_provider,
    _mock_server,
    _mock_db,
):
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor"])

    assert result.exit_code == 1
    assert "Status: DEGRADED" in result.output


@patch("qwed_sdk.cli._database_health", return_value={"healthy": True, "location": "qwed.db"})
@patch("qwed_sdk.cli._check_server_health", return_value=True)
@patch("qwed_sdk.cli._active_provider_status", return_value={"ok": True, "label": "NVIDIA NIM", "message": "Connected"})
@patch("qwed_sdk.cli._optional_engine_report", return_value=_optional_report())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _required_ok_report()))
def test_doctor_text_operational_with_optional_missing(
    _mock_required,
    _mock_optional,
    _mock_provider,
    _mock_server,
    _mock_db,
):
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor"])

    assert result.exit_code == 0
    assert "Status: OPERATIONAL" in result.output
    assert "OpenCV" in result.output


@patch.dict(os.environ, {"ACTIVE_PROVIDER": "auto"})
def test_active_provider_status_auto_mode():
    status = _active_provider_status()
    assert status["ok"] is False
    assert status["label"] == "AUTO"


@patch.dict(os.environ, {"ACTIVE_PROVIDER": "openai", "OPENAI_API_KEY": ""})
def test_active_provider_status_missing_key():
    status = _active_provider_status()
    assert status["ok"] is False
    assert "OPENAI_API_KEY" in status["message"]


@patch.dict(os.environ, {"ACTIVE_PROVIDER": "ollama", "OLLAMA_BASE_URL": ""})
@patch("qwed_new.providers.key_validator.test_connection", return_value=(True, "Connected"))
def test_active_provider_status_ollama_uses_default_base_url(mock_test_connection):
    status = _active_provider_status()

    assert status["ok"] is True
    assert status["label"] == "Ollama"
    _, kwargs = mock_test_connection.call_args
    assert kwargs["base_url"] == "http://localhost:11434/v1"


@patch.dict(os.environ, {"ACTIVE_PROVIDER": "unknown_provider"})
def test_active_provider_status_unknown_provider():
    status = _active_provider_status()
    assert status["ok"] is False
    assert "Unsupported provider" in status["message"]


@patch.dict(os.environ, {"ACTIVE_PROVIDER": "openai", "OPENAI_API_KEY": "fixture_value"})
@patch("qwed_new.providers.key_validator.test_connection", side_effect=RuntimeError("boom"))
def test_active_provider_status_connection_exception(_mock_test_connection):
    status = _active_provider_status()
    assert status["ok"] is False
    assert "Connection check failed" in status["message"]


@patch.dict(os.environ, {"ACTIVE_PROVIDER": "gemini", "GOOGLE_API_KEY": "fixture_value"})
@patch("qwed_sdk.cli._test_gemini_connection", return_value=(True, "Connected"))
def test_active_provider_status_gemini_connection(_mock_gemini):
    status = _active_provider_status()
    assert status["ok"] is True
    assert status["label"] == "Google Gemini"


@patch.dict(os.environ, {"ACTIVE_PROVIDER": "openai_compat", "CUSTOM_API_KEY": "fixture_value", "CUSTOM_BASE_URL": ""})
def test_active_provider_status_openai_compat_requires_base_url():
    status = _active_provider_status()
    assert status["ok"] is False
    assert "CUSTOM_BASE_URL" in status["message"]


@patch.dict(os.environ, {"QWED_SERVER_URL": "http://10.0.0.9:8000"})
@patch("qwed_sdk.cli._check_server_health", return_value=True)
@patch("qwed_sdk.cli._database_health", return_value={"healthy": True, "location": "qwed.db"})
@patch("qwed_sdk.cli._active_provider_status", return_value={"ok": True, "label": "NVIDIA NIM", "message": "Connected"})
@patch("qwed_sdk.cli._optional_engine_report", return_value=_optional_report())
@patch("qwed_sdk.cli._required_engine_report", return_value=(True, _required_ok_report()))
def test_doctor_report_allows_remote_server_url(
    _mock_required,
    _mock_optional,
    _mock_provider,
    _mock_db,
    _mock_health,
):
    report = _doctor_report()
    assert report["server"]["running"] is True
    assert report["server"]["url"] == "http://10.0.0.9:8000"
    assert report["status"].startswith("OPERATIONAL")


@patch("qwed_new.config.settings", new=type("Settings", (), {"DATABASE_URL": "postgresql://db.example/qwed"}))
@patch("qwed_sdk.cli.socket.create_connection")
def test_database_health_non_sqlite_url(mock_create_connection):
    status = _database_health()
    assert status["healthy"] is True
    assert status["location"] == "postgresql://db.example/qwed"
    mock_create_connection.assert_called_once_with(("db.example", 5432), timeout=2.0)


@patch("qwed_new.config.settings", new=type("Settings", (), {"DATABASE_URL": "postgresql://db.example/qwed"}))
@patch("qwed_sdk.cli.socket.create_connection", side_effect=OSError("down"))
def test_database_health_non_sqlite_url_connection_failure(_mock_create_connection):
    status = _database_health()
    assert status["healthy"] is False
    assert status["location"] == "postgresql://db.example/qwed"
    assert "error" in status


@patch("qwed_new.config.settings", new=type("Settings", (), {"DATABASE_URL": "postgresql:///qwed"}))
def test_database_health_non_sqlite_url_missing_hostname():
    status = _database_health()
    assert status["healthy"] is False
    assert status["error"] == "Missing hostname"


def test_database_health_sqlite_relative_path(tmp_path, monkeypatch):
    db_file = tmp_path / "qwed.db"
    db_file.write_text("")
    monkeypatch.setattr("qwed_sdk.cli._project_root", lambda: tmp_path)
    with patch("qwed_new.config.settings", new=type("Settings", (), {"DATABASE_URL": "sqlite:///./qwed.db"})):
        status = _database_health()
    assert status["healthy"] is True
    assert status["location"].endswith("qwed.db")


@patch.dict(os.environ, {"QWED_SERVER_URL": "10.0.0.9:8000"})
def test_doctor_server_url_adds_http_scheme():
    assert _doctor_server_url() == "http://10.0.0.9:8000"
