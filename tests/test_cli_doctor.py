import json
import os
from unittest.mock import patch

from click.testing import CliRunner

from qwed_sdk.cli import _active_provider_status, cli


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


@patch.dict(os.environ, {"ACTIVE_PROVIDER": "auto"}, clear=True)
def test_active_provider_status_auto_mode():
    status = _active_provider_status()
    assert status["ok"] is False
    assert status["label"] == "AUTO"


@patch.dict(os.environ, {"ACTIVE_PROVIDER": "openai"}, clear=True)
def test_active_provider_status_missing_key():
    status = _active_provider_status()
    assert status["ok"] is False
    assert "OPENAI_API_KEY" in status["message"]
