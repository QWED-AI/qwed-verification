"""Coverage tests for DiagnosticResult integration in API endpoints.

Targets uncovered code paths reported by SonarQube for #264.
"""
import os
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient

from qwed_new.core.diagnostics import DiagnosticResult, DiagnosticStatus


@pytest.fixture
def client():
    from qwed_new.api.main import app, get_current_tenant, get_session

    mock_tenant = MagicMock(organization_id=1, api_key=os.environ.get("QWED_TEST_API_KEY", "sentinel"), organization_name="Test Org")
    mock_session = MagicMock(add=MagicMock(), commit=MagicMock())

    app.dependency_overrides[get_current_tenant] = lambda: mock_tenant
    app.dependency_overrides[get_session] = lambda: mock_session

    yield TestClient(app)

    app.dependency_overrides.clear()


def test_verify_natural_language_success_path(client):
    """Cover from_legacy_dict success path, _enforce_trust, and VerificationLog."""
    mock_result = {
        "verification": {"is_correct": True},
        "proof_ref": "abc123",
    }
    with patch("qwed_new.api.main.control_plane.process_natural_language", new_callable=AsyncMock, return_value=mock_result), \
         patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/natural_language",
            json={"query": "test query"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "UNVERIFIABLE"
    assert data["proof_ref"] is None


def test_verify_natural_language_legacy_conversion_fails(client):
    """Cover from_legacy_dict ValueError -> UNVERIFIABLE (fail-closed)."""
    mock_result = {
        "verification": {"is_correct": True, "status": "VERIFIED"},
    }
    with patch("qwed_new.api.main.control_plane.process_natural_language", new_callable=AsyncMock, return_value=mock_result), \
         patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/natural_language",
            json={"query": "test query"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "UNVERIFIABLE"
    assert data["proof_ref"] is None


def test_verify_natural_language_legacy_unrecognized(client):
    """Cover from_legacy_dict ValueError -> UNVERIFIABLE for unrecognized legacy."""
    mock_result = {
        "verification": {"is_correct": True, "status": "XYZZY"},
    }
    with patch("qwed_new.api.main.control_plane.process_natural_language", new_callable=AsyncMock, return_value=mock_result), \
         patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/natural_language",
            json={"query": "test query"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "UNVERIFIABLE"
    assert data["proof_ref"] is None


def test_verify_logic_sat_path(client):
    """Cover SAT path with DiagnosticResult.verified, _enforce_trust, logging."""
    mock_result = {
        "status": "SAT",
        "model": {"x": 6},
        "dsl_code": "(GT x 5)",
        "error": None,
        "provider_used": None,
    }
    with patch("qwed_new.api.main.control_plane.process_logic_query", new_callable=AsyncMock, return_value=mock_result), \
         patch("qwed_new.api.main.check_rate_limit"), \
         patch("qwed_new.api.main.control_plane.router.route", return_value="openai"):
        response = client.post(
            "/verify/logic",
            json={"query": "x > 5"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "VERIFIED"
    assert data["agent_message"] == "Logic constraints are satisfiable"
    assert data["proof_ref"]


def test_verify_logic_unsat_path(client):
    """Cover UNSAT path with DiagnosticResult.unverifiable."""
    mock_result = {
        "status": "UNSAT",
        "model": {},
        "dsl_code": "(NOT (GT x 5))",
        "error": None,
        "provider_used": None,
    }
    with patch("qwed_new.api.main.control_plane.process_logic_query", new_callable=AsyncMock, return_value=mock_result), \
         patch("qwed_new.api.main.check_rate_limit"), \
         patch("qwed_new.api.main.control_plane.router.route", return_value="openai"):
        response = client.post(
            "/verify/logic",
            json={"query": "x <= 5"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "UNVERIFIABLE"
    assert data["agent_message"] == "Logic constraints are unsatisfiable"
    assert data["proof_ref"] is None


def test_verify_stats_success_unverifiable(client):
    """Cover stats SUCCESS -> VERIFIED (execution result IS the evidence)."""
    with patch("qwed_new.core.stats_verifier.StatsVerifier.verify_stats", return_value={"status": "SUCCESS", "analysis": "mean=2.0"}), \
         patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/stats",
            files={"file": ("data.csv", b"value\n1\n2\n3\n", "text/csv")},
            data={"query": "What is the mean?"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "VERIFIED"
    assert data["is_authoritative"] is True
    assert data["proof_ref"]


def test_verify_fact_preserves_diagnostic_result(client):
    """Cover isinstance(result, DiagnosticResult) pass-through in fact endpoint."""
    dr = DiagnosticResult(
        status=DiagnosticStatus.BLOCKED,
        agent_message="Fact refuted by evidence",
        developer_fields={"verdict": "REFUTED", "confidence": 0.95},
        proof_ref=None,
    )
    with patch("qwed_new.core.fact_verifier.FactVerifier.verify_fact", return_value=dr), \
         patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/fact",
            json={"claim": "Sky is green", "context": "Sky is blue"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "BLOCKED"
    assert data["agent_message"] == "Fact refuted by evidence"
    assert data["verdict"] == "REFUTED"
    assert data["proof_ref"] is None


def test_verify_fact_legacy_object_verified(client):
    """Cover fact endpoint hasattr(result, 'to_dict') with is_verified=True."""
    mock_result = MagicMock()
    mock_result.to_dict.return_value = {"verdict": "SUPPORTED", "confidence": 0.95}
    mock_result.is_verified = True
    mock_result.verdict = "SUPPORTED"

    with patch("qwed_new.core.fact_verifier.FactVerifier.verify_fact", return_value=mock_result), \
         patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/fact",
            json={"claim": "Sky is blue", "context": "Sky is blue"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "VERIFIED"
    assert data["proof_ref"]


def test_verify_fact_legacy_object_unverified(client):
    """Cover fact endpoint hasattr(result, 'to_dict') with is_verified=False."""
    mock_result = MagicMock()
    mock_result.to_dict.return_value = {"verdict": "NEUTRAL", "confidence": 0.5}
    mock_result.is_verified = False

    with patch("qwed_new.core.fact_verifier.FactVerifier.verify_fact", return_value=mock_result), \
         patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/fact",
            json={"claim": "maybe", "context": "uncertain"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "UNVERIFIABLE"
    assert data["proof_ref"] is None


def test_verify_fact_unknown_result(client):
    """Cover fact endpoint else branch (bare string result)."""
    with patch("qwed_new.core.fact_verifier.FactVerifier.verify_fact", return_value="plain string result"), \
         patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/fact",
            json={"claim": "test", "context": "test context"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "UNVERIFIABLE"
    assert data["proof_ref"] is None


def test_verify_sql_unverified(client):
    """Cover SQL endpoint is_valid=False -> BLOCKED."""
    with patch("qwed_new.core.sql_verifier.SQLVerifier.verify_sql", return_value={"is_valid": False, "message": "Invalid syntax"}), \
         patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/sql",
            json={"query": "SELECT *", "schema_ddl": "CREATE TABLE t (id int)", "type": "postgres"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "BLOCKED"
        assert data["proof_ref"] is None


def test_verify_code_missing_code_returns_400(client):
    """Cover HTTPException from missing code field in verify_code."""
    with patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/code",
            json={"language": "python"},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "Missing 'code'"


def test_verify_code_review_status(client):
    """Cover REVIEW status -> UNVERIFIABLE."""
    with patch("qwed_new.core.code_verifier.CodeVerifier.verify_code", return_value={"status": "REVIEW", "is_safe": True, "message": "Minor warnings"}), \
         patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/code",
            json={"code": "x = 1", "language": "python"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "UNVERIFIABLE"
    assert data["proof_ref"] is None


def test_verify_consensus_blocked_status(client):
    """Cover consensus agreement_status=unanimous with result.status=BLOCKED."""
    from qwed_new.core.consensus_verifier import ConsensusResult

    fake = MagicMock(spec=ConsensusResult)
    fake.final_answer = None
    fake.confidence = 0.0
    fake.engines_used = 2
    fake.agreement_status = "unanimous"
    fake.status = "BLOCKED"
    fake.verification_chain = []
    fake.total_latency_ms = 5.0

    with patch("qwed_new.api.main.consensus_verifier.verify_with_consensus", return_value=fake), \
         patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/consensus",
            json={"query": "test", "verification_mode": "high", "min_confidence": 0.0},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "BLOCKED"
    assert data["is_authoritative"] is False
    assert data["final_answer"] is None
    assert data["proof_ref"] is None


def test_verify_consensus_unverifiable_status(client):
    """Cover consensus agreement_status=unanimous with result.status=UNVERIFIABLE."""
    from qwed_new.core.consensus_verifier import ConsensusResult

    fake = MagicMock(spec=ConsensusResult)
    fake.final_answer = "maybe"
    fake.confidence = 0.5
    fake.engines_used = 2
    fake.agreement_status = "unanimous"
    fake.status = "UNVERIFIABLE"
    fake.verification_chain = []
    fake.total_latency_ms = 5.0

    with patch("qwed_new.api.main.consensus_verifier.verify_with_consensus", return_value=fake), \
         patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/consensus",
            json={"query": "test", "verification_mode": "high", "min_confidence": 0.0},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "UNVERIFIABLE"
    assert data["proof_ref"] is None
    assert data["is_authoritative"] is False
    assert data["final_answer"] == "maybe"


def test_verify_consensus_no_agreement(client):
    """Cover else branch (no_consensus/split) -> UNVERIFIABLE."""
    from qwed_new.core.consensus_verifier import ConsensusResult

    fake = MagicMock(spec=ConsensusResult)
    fake.final_answer = None
    fake.confidence = 0.3
    fake.engines_used = 3
    fake.agreement_status = "split"
    fake.status = None
    fake.verification_chain = []
    fake.total_latency_ms = 10.0

    with patch("qwed_new.api.main.consensus_verifier.verify_with_consensus", return_value=fake), \
         patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/consensus",
            json={"query": "test", "verification_mode": "high", "min_confidence": 0.0},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "UNVERIFIABLE"
    assert data["is_authoritative"] is False
    assert data["proof_ref"] is None
