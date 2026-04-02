from unittest.mock import MagicMock, patch

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from qwed_new.api.main import app, get_current_tenant, get_session
from qwed_new.core.consensus_verifier import ConsensusVerifier
from qwed_new.core.stats_verifier import (
    SECURE_STATS_BLOCKED_CODE,
    SECURE_STATS_SANDBOX_REQUIRED,
    RestrictedExecutor,
    StatsVerifier,
    WasmSandbox,
)


@pytest.fixture
def client():
    mock_tenant = MagicMock(organization_id=1, api_key="placeholder", organization_name="Test Org")
    mock_session = MagicMock(add=MagicMock(), commit=MagicMock())

    app.dependency_overrides[get_current_tenant] = lambda: mock_tenant
    app.dependency_overrides[get_session] = lambda: mock_session

    yield TestClient(app)

    app.dependency_overrides.clear()


def test_wasm_stats_fallback_is_fail_closed():
    result = WasmSandbox().execute("result = 1", {})

    assert result.success is False
    assert result.result is None
    assert result.sandbox_type == "wasm_disabled"
    assert result.error == SECURE_STATS_SANDBOX_REQUIRED


def test_restricted_stats_fallback_is_fail_closed():
    result = RestrictedExecutor().execute("result = 1", {})

    assert result.success is False
    assert result.result is None
    assert result.sandbox_type == "restricted_disabled"
    assert result.error == SECURE_STATS_SANDBOX_REQUIRED


def test_stats_verifier_blocks_without_secure_docker_runtime():
    verifier = StatsVerifier()
    verifier._translator = MagicMock()
    verifier._translator.translate_stats.return_value = "result = df['value'].mean()"
    verifier._code_verifier = MagicMock()
    verifier._code_verifier.verify_code.return_value = {"is_safe": True}
    verifier._docker_executor = MagicMock()
    verifier._docker_executor.is_available.return_value = False

    df = pd.DataFrame({"value": [1, 2, 3]})

    result = verifier.verify_stats("What is the mean of value?", df)

    assert result["status"] == "BLOCKED"
    assert result["error"] == SECURE_STATS_BLOCKED_CODE


def test_stats_sandbox_info_reports_fail_closed_without_docker():
    verifier = StatsVerifier()
    verifier._docker_executor = MagicMock()
    verifier._docker_executor.is_available.return_value = False

    info = verifier.get_sandbox_info()

    assert info["docker_available"] is False
    assert info["wasm_available"] is False
    assert info["restricted_available"] is False
    assert info["current"] == "blocked"


def test_stats_api_masks_secure_runtime_unavailability(client):
    with patch("qwed_new.core.stats_verifier.StatsVerifier.verify_stats") as mock_verify_stats:
        mock_verify_stats.return_value = {
            "status": "BLOCKED",
            "error": SECURE_STATS_BLOCKED_CODE,
        }
        response = client.post(
            "/verify/stats",
            files={"file": ("data.csv", b"value\n1\n2\n", "text/csv")},
            data={"query": "What is the mean of value?"},
            headers={"x-api-key": "fake-key"},
        )

    assert response.status_code == 503
    assert response.json()["detail"] == "Service temporarily unavailable"


def test_consensus_code_engine_requires_secure_executor():
    verifier = ConsensusVerifier(enable_circuit_breaker=False)
    verifier._code_verifier = MagicMock()
    verifier._code_verifier.verify_code.return_value = {"is_safe": True}

    with (
        patch.object(ConsensusVerifier, "_generate_verification_code", return_value="result = 4"),
        patch("qwed_new.core.secure_code_executor.SecureCodeExecutor") as mock_executor_cls,
    ):
        mock_executor = mock_executor_cls.return_value
        mock_executor.execute.return_value = (
            False,
            "Docker is not available. Cannot execute code securely.",
            None,
        )
        result = verifier._verify_with_code("What is 2+2?")

    assert result.success is False
    assert result.result is None
    assert "Docker is not available" in result.error


def test_consensus_code_engine_uses_secure_executor_output():
    verifier = ConsensusVerifier(enable_circuit_breaker=False)
    verifier._code_verifier = MagicMock()
    verifier._code_verifier.verify_code.return_value = {"is_safe": True}

    with (
        patch.object(ConsensusVerifier, "_generate_verification_code", return_value="result = 4"),
        patch("qwed_new.core.secure_code_executor.SecureCodeExecutor") as mock_executor_cls,
    ):
        mock_executor = mock_executor_cls.return_value
        mock_executor.execute.return_value = (True, None, "4")
        result = verifier._verify_with_code("What is 2+2?")

    assert result.success is True
    assert result.result == "4"
    assert result.engine_name == "Python"


def test_consensus_codegen_assigns_result_variable():
    verifier = ConsensusVerifier(enable_circuit_breaker=False)
    with patch("qwed_new.core.translator.TranslationLayer") as mock_translator_cls:
        mock_translator = mock_translator_cls.return_value
        mock_translator.translate.return_value = MagicMock(expression="2 + 2")
        code = verifier._generate_verification_code("What is 2+2?")

    assert code == "result = 2 + 2"
