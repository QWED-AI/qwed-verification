import json

from click.testing import CliRunner

from qwed_new.core.diagnostics import DiagnosticResult
from qwed_new.core.verification_context_bridge import (
    verification_context_from_diagnostic_result,
)
from qwed_sdk.cli import cli


def test_context_validate_and_resolve(tmp_path):
    result = DiagnosticResult.unverifiable(
        agent_message="Claim could not be verified.",
        developer_fields={"is_valid": False},
    )
    document = verification_context_from_diagnostic_result(
        result,
        formal_statement="mean of a == 2",
        verifier="TestVerifier",
    )
    path = tmp_path / "context.json"
    path.write_text(json.dumps(document.to_dict()), encoding="utf-8")

    runner = CliRunner()
    validate_result = runner.invoke(cli, ["context", "validate", str(path)])
    assert validate_result.exit_code == 0
    assert json.loads(validate_result.output)["valid"] is True

    resolve_result = runner.invoke(cli, ["context", "resolve", str(path)])
    assert resolve_result.exit_code == 0
    assert json.loads(resolve_result.output)["resolved"] is False


def test_context_validate_invalid_document(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps({"spec_version": "1.0"}), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["context", "validate", str(path)])
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["valid"] is False
    assert "error" in payload


def test_context_from_diagnostic(tmp_path):
    diagnostic_path = tmp_path / "diagnostic.json"
    diagnostic_path.write_text(
        json.dumps(
            {
                "status": "UNVERIFIABLE",
                "agent_message": "Claim could not be verified.",
                "developer_fields": {"is_valid": False},
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "context",
            "from-diagnostic",
            "--diagnostic-file",
            str(diagnostic_path),
            "--query",
            "mean of a == 2",
            "--verifier",
            "TestVerifier",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["verdict"] == "UNVERIFIABLE"
    assert payload["context"]["evidence"]["proof_ref"] is None
    assert payload["context"]["decision"]["admission"] == "DENY"


def test_context_from_diagnostic_non_object_diagnostic_fails_closed(tmp_path):
    diagnostic_path = tmp_path / "diagnostic.json"
    diagnostic_path.write_text(json.dumps(["not", "object"]), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "context",
            "from-diagnostic",
            "--diagnostic-file",
            str(diagnostic_path),
            "--query",
            "mean of a == 2",
            "--verifier",
            "TestVerifier",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["verdict"] == "BLOCKED"
    assert payload["context"]["evidence"]["proof_ref"] is None
    assert payload["context"]["decision"]["admission"] == "DENY"


def test_context_validate_invalid_json_file(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text("{", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["context", "validate", str(path)])
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["valid"] is False
    assert payload["error"] == "invalid_document_file"


def test_context_from_diagnostic_unexpected_bridge_error(monkeypatch, tmp_path):
    diagnostic_path = tmp_path / "diagnostic.json"
    diagnostic_path.write_text(
        json.dumps(
            {
                "status": "UNVERIFIABLE",
                "agent_message": "Claim could not be verified.",
                "developer_fields": {"is_valid": False},
            }
        ),
        encoding="utf-8",
    )

    def _raise(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "qwed_new.core.verification_context_bridge.verification_context_from_diagnostic_result",
        _raise,
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "context",
            "from-diagnostic",
            "--diagnostic-file",
            str(diagnostic_path),
            "--query",
            "mean of a == 2",
            "--verifier",
            "TestVerifier",
        ],
    )
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["valid"] is False
    assert payload["error"] == "internal_error"
