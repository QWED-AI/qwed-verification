from unittest.mock import AsyncMock, MagicMock, patch

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
    SECURE_STATS_BLOCKED_CODE,
    SECURE_STATS_SANDBOX_REQUIRED,
    SECURE_STATS_RUNTIME_UNAVAILABLE,
    RestrictedExecutor,
    StatsVerifier,
    WasmSandbox,
)
from qwed_new.core.diagnostics import DiagnosticResult


def _safe_code_verifier_result():
    """A real DiagnosticResult for a safe snippet (consensus/stats mock helper)."""
    return DiagnosticResult.verified(
        agent_message="The code passed security verification and is safe to use.",
        developer_fields={
            "constraint_id": "code_verifier.code_safe",
            "is_valid": True,
            "is_safe": True,
            "critical_count": 0,
            "warning_count": 0,
            "issues": [],
        },
        evidence={"engine": "test", "language": "python", "code": "safe", "is_safe": True},
    )


def _unsafe_code_verifier_result():
    """A real DiagnosticResult for a dangerous snippet — no proof, must fail closed."""
    return DiagnosticResult.blocked(
        agent_message="The code failed security verification.",
        developer_fields={
            "constraint_id": "code_verifier.dangerous_pattern",
            "is_valid": False,
            "is_safe": False,
            "critical_count": 1,
            "warning_count": 0,
            "issues": [{"type": "dangerous", "description": "blocked bypass"}],
        },
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
    verifier._code_verifier.verify_code.return_value = _safe_code_verifier_result()
    verifier._docker_executor = MagicMock()
    verifier._docker_executor.is_available.return_value = False

    df = pd.DataFrame({"value": [1, 2, 3]})

    result = verifier.verify_stats("What is the mean of value?", df)

    assert result.status.value == "BLOCKED"
    assert result.developer_fields["error_code"] == SECURE_STATS_BLOCKED_CODE
    assert result.constraint_id == "stats_verifier.runtime_unavailable"
    assert result.is_fail_closed is True


def test_stats_verifier_masks_translation_exceptions(caplog):
    verifier = StatsVerifier()
    verifier._translator = MagicMock()
    verifier._translator.translate_stats.side_effect = RuntimeError(
        "boom /tmp/secret api_key=sk-test-123"
    )

    df = pd.DataFrame({"value": [1, 2, 3]})

    with caplog.at_level("ERROR"):
        result = verifier.verify_stats("What is the mean of value?", df)

    assert result.status.value == "BLOCKED"
    assert result.constraint_id == "stats_verifier.validation_error"
    assert "secret" not in result.agent_message
    assert "secret" not in str(result.developer_fields)
    assert "secret" not in caplog.text
    assert "/tmp/secret" not in caplog.text
    assert "sk-test-123" not in caplog.text
    assert "api_key=" not in caplog.text


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
    blocked_dr = DiagnosticResult.blocked(
        "Service temporarily unavailable",
        developer_fields={
            "constraint_id": "stats_verifier.runtime_unavailable",
            "error_code": SECURE_STATS_BLOCKED_CODE,
        },
    )
    with patch("qwed_new.core.stats_verifier.StatsVerifier.verify_stats", return_value=blocked_dr):
        response = client.post(
            "/verify/stats",
            files={"file": ("data.csv", b"value\n1\n2\n", "text/csv")},
            data={"query": "What is the mean of value?"},
            headers={"x-api-key": "fake-key"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "BLOCKED"
    assert data["agent_message"] == "Service temporarily unavailable"
    assert data["proof_ref"] is None
    assert data["constraint_id"] == "stats_verifier.runtime_unavailable"
    assert data["error_code"] == SECURE_STATS_BLOCKED_CODE


def test_stats_api_preserves_security_policy_blocks(client):
    blocked_dr = DiagnosticResult.blocked(
        "blocked by security policy",
        developer_fields={
            "constraint_id": "stats_verifier.validation_error",
            "is_valid": False,
        },
    )
    with patch("qwed_new.core.stats_verifier.StatsVerifier.verify_stats", return_value=blocked_dr):
        response = client.post(
            "/verify/stats",
            files={"file": ("data.csv", b"value\n1\n2\n", "text/csv")},
            data={"query": "What is the mean of value?"},
            headers={"x-api-key": "fake-key"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "BLOCKED"
    assert data["agent_message"] == "blocked by security policy"
    assert data["proof_ref"] is None
    assert data["constraint_id"] == "stats_verifier.validation_error"
    assert data["is_valid"] is False


def test_consensus_code_engine_requires_secure_executor():
    verifier = ConsensusVerifier(enable_circuit_breaker=False)
    verifier._code_verifier = MagicMock()
    verifier._code_verifier.verify_code.return_value = _safe_code_verifier_result()

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
    verifier._code_verifier.verify_code.return_value = _safe_code_verifier_result()

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
    assert result.status == "UNVERIFIABLE"  # Code execution is advisory-only (#269)


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

    with patch("qwed_new.api.main.consensus_verifier.verify_async", new_callable=AsyncMock, return_value=fake_result):
        response = client.post(
            "/verify/consensus",
            json={"query": "2+2", "verification_mode": "high", "min_confidence": 0.95},
            headers={"x-api-key": "fake-key"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "BLOCKED"
    assert data["is_authoritative"] is False


def test_stats_verifier_blocks_if_docker_drops_after_selection():
    verifier = StatsVerifier()
    verifier._translator = MagicMock()
    verifier._translator.translate_stats.return_value = "result = df['value'].mean()"
    verifier._code_verifier = MagicMock()
    verifier._code_verifier.verify_code.return_value = _safe_code_verifier_result()
    verifier._docker_executor = MagicMock()
    verifier._docker_executor.is_available.return_value = True
    verifier._docker_executor.execute.return_value = (False, SECURE_RUNTIME_UNAVAILABLE, None)

    df = pd.DataFrame({"value": [1, 2, 3]})

    result = verifier.verify_stats("What is the mean of value?", df)

    assert result.status.value == "BLOCKED"
    assert result.developer_fields["error_code"] == SECURE_STATS_BLOCKED_CODE
    assert result.constraint_id == "stats_verifier.runtime_unavailable"


def test_stats_execute_docker_marks_runtime_unavailable():
    verifier = StatsVerifier()
    verifier._docker_executor = MagicMock()
    verifier._docker_executor.execute.return_value = (False, SECURE_RUNTIME_UNAVAILABLE, None)

    result = verifier._execute_docker("result = 1", {"df": pd.DataFrame({"value": [1]})})

    assert result.success is False
    assert result.error == SECURE_STATS_RUNTIME_UNAVAILABLE


def test_compute_statistics_rejects_all_nan_results():
    verifier = StatsVerifier()
    df = pd.DataFrame({"value": [float("nan"), float("nan")]})

    result = verifier.compute_statistics(df, "value", "mean")

    assert result["status"] == "ERROR"
    assert "undefined result" in result["error"]


def test_compute_statistics_rejects_ambiguous_mode():
    verifier = StatsVerifier()
    df = pd.DataFrame({"value": [1, 1, 2, 2]})

    result = verifier.compute_statistics(df, "value", "mode")

    assert result["status"] == "ERROR"
    assert "ambiguous" in result["error"]


def test_stats_verifier_success_if_no_claim_eval_is_unverifiable():
    """Cover the execution-success -> UNVERIFIABLE branch of verify_stats."""
    verifier = StatsVerifier()
    verifier._translator = MagicMock()
    verifier._translator.translate_stats.return_value = "result = df['value'].mean()"
    verifier._code_verifier = MagicMock()
    verifier._code_verifier.verify_code.return_value = _safe_code_verifier_result()
    verifier._docker_executor = MagicMock()
    verifier._docker_executor.is_available.return_value = True
    verifier._docker_executor.execute.return_value = (
        True,
        None,
        2.0,
    )

    df = pd.DataFrame({"value": [1, 2, 3]})

    result = verifier.verify_stats("What is the mean of value?", df)

    assert result.status.value == "UNVERIFIABLE"
    assert result.constraint_id == "stats_verifier.claim_not_verified"
    assert result.developer_fields["is_valid"] is False
    assert result.developer_fields["observed_result"] == 2.0
    assert result.is_fail_closed is True
    # Execution evidence binds the specific dataset that was analyzed.
    fingerprint = result.developer_fields["dataset_sha256"]
    assert isinstance(fingerprint, str)
    assert len(fingerprint) == 64


def test_stats_verifier_dataset_fingerprint_binds_data():
    """The dataset fingerprint must differ when the underlying data changes."""
    from qwed_new.core.stats_verifier import _dataset_fingerprint

    df_a = pd.DataFrame({"value": [1, 2, 3]})
    df_b = pd.DataFrame({"value": [1, 2, 4]})

    fp_a = _dataset_fingerprint(df_a)
    fp_b = _dataset_fingerprint(df_b)

    assert fp_a is not None
    assert fp_b is not None
    # Same data -> same fingerprint (deterministic).
    assert fp_a == _dataset_fingerprint(pd.DataFrame({"value": [1, 2, 3]}))
    # Different data -> different fingerprint.
    assert fp_a != fp_b


def test_stats_verifier_fingerprint_failure_blocks(monkeypatch):
    """A dataset-fingerprint failure must fail closed to BLOCKED, not degrade."""
    from qwed_new.core import stats_verifier

    def _boom(*args, **kwargs):
        raise TypeError("unhashable dataset")

    monkeypatch.setattr(stats_verifier.pd.util, "hash_pandas_object", _boom)

    verifier = StatsVerifier()
    verifier._translator = MagicMock()
    verifier._translator.translate_stats.return_value = "result = df['value'].mean()"
    verifier._code_verifier = MagicMock()
    verifier._code_verifier.verify_code.return_value = _safe_code_verifier_result()
    verifier._docker_executor = MagicMock()
    verifier._docker_executor.is_available.return_value = True
    verifier._docker_executor.execute.return_value = (True, None, 2.0)

    df = pd.DataFrame({"value": [1, 2, 3]})

    result = verifier.verify_stats("What is the mean of value?", df)

    assert result.status.value == "BLOCKED"
    assert result.constraint_id == "stats_verifier.evidence_failure"
    assert result.proof_ref is None
    assert result.is_fail_closed is True


def test_stats_verifier_non_serializable_result_stays_unverifiable():
    """A non-JSON-serializable execution result must not downgrade UNVERIFIABLE.

    The Docker sandbox can return any object the generated code assigns to
    ``result``. ``enforce_trust_decision`` snapshots developer_fields and fails
    closed on non-serializable values; the engine must coerce observed_result so
    a legitimate UNVERIFIABLE verdict survives the trust gate (Sentry MEDIUM).
    """
    from qwed_new.core.diagnostics import enforce_trust_decision

    class Opaque:
        def __repr__(self):
            return "<opaque dataframe>"

    verifier = StatsVerifier()
    verifier._translator = MagicMock()
    verifier._translator.translate_stats.return_value = "result = compute()"
    verifier._code_verifier = MagicMock()
    verifier._code_verifier.verify_code.return_value = _safe_code_verifier_result()
    verifier._docker_executor = MagicMock()
    verifier._docker_executor.is_available.return_value = True
    verifier._docker_executor.execute.return_value = (True, None, Opaque())

    df = pd.DataFrame({"value": [1, 2, 3]})

    result = verifier.verify_stats("What is the mean of value?", df)

    assert result.status.value == "UNVERIFIABLE"
    # observed_result is coerced to a JSON-safe string, not the raw object.
    assert result.developer_fields["observed_result"] == "<opaque dataframe>"

    # The verdict must survive trust-boundary enforcement (no silent BLOCKED).
    enforced = enforce_trust_decision(result, require_attestation=False)
    assert enforced.status.value == "UNVERIFIABLE"
    assert enforced.constraint_id == "stats_verifier.claim_not_verified"


def test_stats_verifier_blocks_on_security_validation():
    verifier = StatsVerifier()
    verifier._translator = MagicMock()
    verifier._translator.translate_stats.return_value = "result = df['value'].mean()"
    verifier._code_verifier = MagicMock()
    verifier._code_verifier.verify_code.return_value = _unsafe_code_verifier_result()
    verifier._docker_executor = MagicMock()
    verifier._docker_executor.is_available.return_value = True
    verifier._docker_executor.execute.return_value = (
        True,
        None,
        2.0,
    )

    df = pd.DataFrame({"value": [1, 2, 3]})

    result = verifier.verify_stats("What is the mean of value?", df)

    assert result.status.value == "BLOCKED"
    assert result.constraint_id == "stats_verifier.validation_error"
    assert result.developer_fields["is_valid"] is False
    assert result.is_fail_closed is True
    verifier._docker_executor.execute.assert_not_called()


def test_stats_verifier_blocks_security_exception():
    verifier = StatsVerifier()
    verifier._translator = MagicMock()
    verifier._translator.translate_stats.return_value = "result = df['value'].mean()"
    verifier._code_verifier = MagicMock()
    verifier._code_verifier.verify_code.side_effect = RuntimeError("security engine crash")
    verifier._docker_executor = MagicMock()

    df = pd.DataFrame({"value": [1, 2, 3]})

    result = verifier.verify_stats("What is the mean of value?", df)

    assert result.status.value == "BLOCKED"
    assert result.constraint_id == "stats_verifier.validation_error"
    assert result.is_fail_closed is True
    verifier._docker_executor.execute.assert_not_called()


def test_stats_verifier_execution_failure_is_blocked():
    verifier = StatsVerifier()
    verifier._translator = MagicMock()
    verifier._translator.translate_stats.return_value = "result = df['value'].mean()"
    verifier._code_verifier = MagicMock()
    verifier._code_verifier.verify_code.return_value = _safe_code_verifier_result()
    verifier._docker_executor = MagicMock()
    verifier._docker_executor.is_available.return_value = True
    verifier._docker_executor.execute.return_value = (False, "exec boom", None)

    df = pd.DataFrame({"value": [1, 2, 3]})

    result = verifier.verify_stats("What is the mean of value?", df)

    assert result.status.value == "BLOCKED"
    assert result.constraint_id == "stats_verifier.execution_failure"
    assert result.developer_fields["error"] == "exec boom"
    assert result.is_fail_closed is True


def test_consensus_preserves_none_answer_value():
    verifier = ConsensusVerifier(enable_circuit_breaker=False)
    results = [
        EngineResult("SymPy", "symbolic_math", None, 1.0, 1.0, True),
        EngineResult("Stats", "statistical_analysis", None, 0.98, 1.0, True),
    ]

    consensus = verifier._calculate_consensus(results)

    assert consensus["answer"] is None
    assert consensus["status"] == "unanimous"
