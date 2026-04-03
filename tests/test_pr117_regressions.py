from unittest.mock import MagicMock, patch

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from qwed_new.api.main import app, get_current_tenant, get_session
from qwed_new.core.consensus_verifier import (
    SECURE_EXECUTION_REQUIRED,
    ConsensusVerifier,
    EngineResult,
)
from qwed_new.core.secure_code_executor import SECURE_RUNTIME_UNAVAILABLE
from qwed_new.core.stats_verifier import (
    INTERNAL_VERIFICATION_ERROR,
    SECURE_STATS_BLOCKED_CODE,
    SECURE_STATS_SANDBOX_REQUIRED,
    SECURE_STATS_RUNTIME_UNAVAILABLE,
    RestrictedExecutor,
    StatsVerifier,
    WasmSandbox,
)


@pytest.fixture
def client():
    previous_overrides = app.dependency_overrides.copy()
    mock_tenant = MagicMock(organization_id=1, api_key="placeholder", organization_name="Test Org")
    mock_session = MagicMock(add=MagicMock(), commit=MagicMock())

    app.dependency_overrides[get_current_tenant] = lambda: mock_tenant
    app.dependency_overrides[get_session] = lambda: mock_session

    yield TestClient(app)

    app.dependency_overrides = previous_overrides


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


def test_stats_verifier_masks_translation_exceptions():
    verifier = StatsVerifier()
    verifier._translator = MagicMock()
    verifier._translator.translate_stats.side_effect = RuntimeError(
        "boom /tmp/secret api_key=sk-test-123"
    )

    df = pd.DataFrame({"value": [1, 2, 3]})

    result = verifier.verify_stats("What is the mean of value?", df)

    assert result["status"] == "ERROR"
    assert result["error"] == INTERNAL_VERIFICATION_ERROR
    assert "secret" not in result["error"]


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


def test_stats_api_preserves_security_policy_blocks(client):
    with patch("qwed_new.core.stats_verifier.StatsVerifier.verify_stats") as mock_verify_stats:
        mock_verify_stats.return_value = {
            "status": "BLOCKED",
            "error": "Code failed security validation",
        }
        response = client.post(
            "/verify/stats",
            files={"file": ("data.csv", b"value\n1\n2\n", "text/csv")},
            data={"query": "What is the mean of value?"},
            headers={"x-api-key": "fake-key"},
        )

    assert response.status_code == 403
    assert response.json()["detail"] == "Verification blocked by security policy"


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
            SECURE_RUNTIME_UNAVAILABLE,
            None,
        )
        result = verifier._verify_with_code("What is 2+2?")

    assert result.success is False
    assert result.result is None
    assert result.error == SECURE_EXECUTION_REQUIRED


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
    verifier._translator = MagicMock()
    verifier._translator.translate.return_value = MagicMock(expression="2 + 2")

    code = verifier._generate_verification_code("What is 2+2?")

    assert code == "result = 2 + 2"


def test_consensus_blocks_when_secure_execution_is_required():
    verifier = ConsensusVerifier(enable_circuit_breaker=False)
    results = [
        EngineResult("SymPy", "symbolic_math", "4", 1.0, 1.0, True),
        EngineResult("Python", "code_execution", None, 0.0, 1.0, False, SECURE_EXECUTION_REQUIRED),
    ]

    consensus = verifier._calculate_consensus(results)

    assert consensus["answer"] is None
    assert consensus["confidence"] == 0.0
    assert consensus["status"] == "blocked_secure_execution"


def test_consensus_api_masks_secure_execution_block(client):
    fake_result = MagicMock(
        confidence=0.0,
        final_answer=None,
        engines_used=2,
        agreement_status="blocked_secure_execution",
        verification_chain=[],
        total_latency_ms=5.0,
    )

    with patch("qwed_new.api.main.consensus_verifier.verify_with_consensus", return_value=fake_result):
        response = client.post(
            "/verify/consensus",
            json={"query": "2+2", "verification_mode": "high", "min_confidence": 0.95},
            headers={"x-api-key": "fake-key"},
        )

    assert response.status_code == 503
    assert response.json()["detail"] == "Service temporarily unavailable"


def test_stats_verifier_blocks_if_docker_drops_after_selection():
    verifier = StatsVerifier()
    verifier._translator = MagicMock()
    verifier._translator.translate_stats.return_value = "result = df['value'].mean()"
    verifier._code_verifier = MagicMock()
    verifier._code_verifier.verify_code.return_value = {"is_safe": True}
    verifier._docker_executor = MagicMock()
    verifier._docker_executor.is_available.return_value = True
    verifier._docker_executor.execute.return_value = (False, SECURE_RUNTIME_UNAVAILABLE, None)

    df = pd.DataFrame({"value": [1, 2, 3]})

    result = verifier.verify_stats("What is the mean of value?", df)

    assert result["status"] == "BLOCKED"
    assert result["error"] == SECURE_STATS_BLOCKED_CODE


def test_stats_execute_docker_marks_runtime_unavailable():
    verifier = StatsVerifier()
    verifier._docker_executor = MagicMock()
    verifier._docker_executor.execute.return_value = (False, SECURE_RUNTIME_UNAVAILABLE, None)

    result = verifier._execute_docker("result = 1", {"df": pd.DataFrame({"value": [1]})})

    assert result.success is False
    assert result.error == SECURE_STATS_RUNTIME_UNAVAILABLE


def test_consensus_preserves_none_answer_value():
    verifier = ConsensusVerifier(enable_circuit_breaker=False)
    results = [
        EngineResult("SymPy", "symbolic_math", None, 1.0, 1.0, True),
        EngineResult("Stats", "statistical_analysis", None, 0.98, 1.0, True),
    ]

    consensus = verifier._calculate_consensus(results)

    assert consensus["answer"] is None
    assert consensus["status"] == "unanimous"
