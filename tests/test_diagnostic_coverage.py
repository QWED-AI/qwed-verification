"""Coverage tests for DiagnosticResult integration in API endpoints.

Targets uncovered code paths reported by SonarQube for #264.
"""
import os
import secrets
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient
from fastapi import HTTPException

from qwed_new.core.diagnostics import DiagnosticResult, DiagnosticStatus


@pytest.fixture
def client():
    from qwed_new.api.main import app, get_current_tenant, get_session

    mock_tenant = MagicMock(organization_id=1, api_key=os.environ.get("QWED_TEST_API_KEY", "sentinel"), organization_name="Test Org")
    mock_session = MagicMock(add=MagicMock(), commit=MagicMock())

    app.dependency_overrides[get_current_tenant] = lambda: mock_tenant
    app.dependency_overrides[get_session] = lambda: mock_session

    yield TestClient(app)

    del app.dependency_overrides[get_current_tenant]
    del app.dependency_overrides[get_session]


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


def test_verify_natural_language_internal_error(client):
    """Cover process_natural_language exception -> BLOCKED."""
    with patch("qwed_new.api.main.control_plane.process_natural_language", new_callable=AsyncMock, side_effect=Exception("Engine down")), \
         patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/natural_language",
            json={"query": "test query"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "BLOCKED"
    assert data["agent_message"] == "Internal verification error"
    assert data["proof_ref"] is None
    assert "Engine down" not in response.text


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


def test_verify_stats_verified_pass_through(client):
    """Cover stats endpoint pass-through of a VERIFIED DiagnosticResult."""
    dr = DiagnosticResult.verified(
        "Statistical claim verified",
        developer_fields={
            "constraint_id": "stats_verifier.verified",
            "is_valid": True,
            "claim_supported": True,
        },
        evidence={"engine": "stats", "claim": "mean", "result": 2.0},
    )
    with patch("qwed_new.core.stats_verifier.StatsVerifier.verify_stats", return_value=dr), \
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
    assert data["constraint_id"] == "stats_verifier.verified"
    assert data["is_valid"] is True
    assert data["claim_supported"] is True


def test_verify_stats_unverifiable_pass_through(client):
    """Cover stats endpoint pass-through of an UNVERIFIABLE DiagnosticResult (execution != proof)."""
    dr = DiagnosticResult.unverifiable(
        "Statistical analysis completed, but the claim could not be deterministically verified.",
        developer_fields={
            "constraint_id": "stats_verifier.claim_not_verified",
            "is_valid": False,
            "claim_supported": False,
        },
    )
    with patch("qwed_new.core.stats_verifier.StatsVerifier.verify_stats", return_value=dr), \
         patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/stats",
            files={"file": ("data.csv", b"value\n1\n2\n3\n", "text/csv")},
            data={"query": "What is the mean?"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "UNVERIFIABLE"
    assert data["proof_ref"] is None
    assert data["is_authoritative"] is False
    assert data["constraint_id"] == "stats_verifier.claim_not_verified"
    assert data["is_valid"] is False
    assert data["claim_supported"] is False


def test_verify_fact_heuristic_supported_never_returns_verified(client):
    """Cover that real FactVerifier SUPPORTED verdict cannot produce VERIFIED #267.
    Uses a claim-context pair that reliably triggers the SUPPORTED heuristic path — never mocks the engine."""
    with patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/fact",
            json={
                "claim": "Rayleigh scattering causes the sky to appear blue during the daytime.",
                "context": "The sky appears blue because Rayleigh scattering scatters short-wavelength blue light more than other colors.",
            },
        )

    assert response.status_code == 200
    data = response.json()
    # Assert #267 SUPPORTED heuristic branch was exercised (not insufficient-evidence / neutral fallthrough)
    assert data["status"] == "UNVERIFIABLE"
    assert data["proof_ref"] is None
    assert data["is_authoritative"] is False
    assert data["deterministic_verdict"] == "SUPPORTED"  # reached the changed branch
    assert data["constraint_id"] == "fact_verifier.heuristic_supported"
    assert any(c["name"] == "heuristic_supported" for c in data["advisory_checks"])  # advisory present
    assert data["status"] != "VERIFIED"  # Never verified for heuristic work (#267)


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
    """Engine is_valid=False (VERIFIED-as-malicious) -> endpoint returns verdict unchanged
    but exposes an explicit BLOCKED admission decision (Greptile P1)."""
    malicious = DiagnosticResult.verified(
        "The SQL query failed security verification and is not safe to execute.",
        {"constraint_id": "sql_verifier.malicious", "is_valid": False},
        {"query": "SELECT *"},
    )
    with patch("qwed_new.core.sql_verifier.SQLVerifier.verify_sql", return_value=malicious), \
         patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/sql",
            json={"query": "SELECT *", "schema_ddl": "CREATE TABLE t (id int)", "type": "postgres"},
        )

        assert response.status_code == 200
        data = response.json()
        # Verification truth preserved unchanged.
        assert data["status"] == "VERIFIED"
        assert data["proof_ref"] is not None
        assert data["developer_fields"]["constraint_id"] == "sql_verifier.malicious"
        assert data["developer_fields"]["is_valid"] is False
        # Admission is a SEPARATE, fail-closed decision.
        assert data["admission"] == "BLOCKED"


def test_verify_sql_engine_blocked_passthrough(client):
    """Engine returns BLOCKED (e.g. parse error) -> endpoint passes it through as BLOCKED."""
    blocked = DiagnosticResult.blocked(
        "SQL verification could not be completed because the query could not be parsed.",
        {"constraint_id": "sql_verifier.parse_error", "is_valid": False},
    )
    with patch("qwed_new.core.sql_verifier.SQLVerifier.verify_sql", return_value=blocked), \
         patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/sql",
            json={"query": "SELECT *", "schema_ddl": "CREATE TABLE t (id int)", "type": "postgres"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "BLOCKED"
        assert data["proof_ref"] is None
        assert data["developer_fields"]["constraint_id"] == "sql_verifier.parse_error"
        assert data["admission"] == "BLOCKED"


def test_verify_sql_safe_passthrough_verified(client):
    """Engine returns VERIFIED-as-safe -> endpoint returns VERIFIED and ADMIT."""
    safe = DiagnosticResult.verified(
        "The SQL query passed verification and is safe to execute.",
        {"constraint_id": "sql_verifier.sql_valid", "is_valid": True},
        {"query": "SELECT *"},
    )
    with patch("qwed_new.core.sql_verifier.SQLVerifier.verify_sql", return_value=safe), \
         patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/sql",
            json={"query": "SELECT *", "schema_ddl": "CREATE TABLE t (id int)", "type": "postgres"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "VERIFIED"
        assert data["proof_ref"] is not None
        assert data["developer_fields"]["is_valid"] is True
        assert data["admission"] == "ADMIT"


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
    """Cover warning-only (formerly REVIEW) code -> VERIFIED safe with warnings."""
    from qwed_new.core.diagnostics import DiagnosticResult

    fake = DiagnosticResult.verified(
        "The code passed security verification and is safe to use.",
        {
            "constraint_id": "code_verifier.code_safe",
            "is_valid": True,
            "is_safe": True,
            "critical_count": 0,
            "warning_count": 1,
            "issues": [],
        },
        {"engine": "test", "language": "python", "code": "x = 1", "is_safe": True},
    )
    with patch("qwed_new.core.code_verifier.CodeVerifier.verify_code", return_value=fake), \
         patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/code",
            json={"code": "x = 1", "language": "python"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "VERIFIED"
    assert data["proof_ref"] is not None
    assert data["developer_fields"]["is_valid"] is True


def test_verify_consensus_blocked_status(client):
    """Cover consensus agreement_status=unanimous with result.status=BLOCKED."""
    from qwed_new.core.consensus_verifier import ConsensusResult

    fake = ConsensusResult(
        final_answer=None,
        confidence=0.0,
        engines_used=2,
        agreement_status="unanimous",
        verification_chain=[],
        total_latency_ms=5.0,
        status=DiagnosticStatus.BLOCKED,
    )

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

    fake = ConsensusResult(
        final_answer="maybe",
        confidence=0.5,
        engines_used=2,
        agreement_status="unanimous",
        verification_chain=[],
        total_latency_ms=5.0,
        status=DiagnosticStatus.UNVERIFIABLE,
    )

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


def test_verify_consensus_verified_with_proof_ref(client):
    """Cover VERIFIED consensus with proof_ref included in response (#266)."""
    from qwed_new.core.consensus_verifier import ConsensusResult

    fake = ConsensusResult(
        final_answer="4",
        confidence=0.99,
        engines_used=2,
        agreement_status="unanimous",
        verification_chain=[],
        total_latency_ms=5.0,
        status=DiagnosticStatus.VERIFIED,
        verified_evidence={"agreement_status": "unanimous", "confidence": 0.99},
    )

    with patch("qwed_new.api.main.consensus_verifier.verify_with_consensus", return_value=fake), \
         patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/consensus",
            json={"query": "test", "verification_mode": "high", "min_confidence": 0.0},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "VERIFIED"
    assert data["proof_ref"] is not None
    assert data["proof_ref"].startswith("sha256:")
    assert data["is_authoritative"] is True


def test_verify_consensus_all_engines_blocked(client):
    """Cover consensus agreement_status=blocked -> BLOCKED (fail-closed)."""
    from qwed_new.core.consensus_verifier import ConsensusResult

    fake = ConsensusResult(
        final_answer=None,
        confidence=0.0,
        engines_used=2,
        agreement_status="blocked",
        verification_chain=[],
        total_latency_ms=5.0,
        status=DiagnosticStatus.BLOCKED,
    )

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
    assert data["proof_ref"] is None


def test_verify_consensus_unverifiable_with_high_confidence_not_requirements_met(client):
    """Cover that high confidence alone cannot flip UNVERIFIABLE consensus to meets_requirement (#269)."""
    from qwed_new.core.consensus_verifier import ConsensusResult

    fake = ConsensusResult(
        final_answer="2",
        confidence=0.99,
        engines_used=2,
        agreement_status="unanimous",
        verification_chain=[],
        total_latency_ms=5.0,
        status=DiagnosticStatus.UNVERIFIABLE,
    )

    with patch("qwed_new.api.main.consensus_verifier.verify_with_consensus", return_value=fake), \
         patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/consensus",
            json={"query": "test", "verification_mode": "high", "min_confidence": 0.95},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "UNVERIFIABLE"
    assert data["meets_requirement"] is False
    assert data["is_authoritative"] is False


def test_verify_consensus_unverifiable_no_blocked_engines_message(client):
    """Cover unanimous + UNVERIFIABLE with zero blocked engines (#266) — message reflects source, not blocked fallback."""
    from qwed_new.core.consensus_verifier import ConsensusResult, EngineResult

    fake = ConsensusResult(
        final_answer="2",
        confidence=0.98,
        engines_used=1,
        agreement_status="unanimous",
        verification_chain=[
            EngineResult(
                engine_name="Stats", method="statistical_analysis", result=2,
                confidence=0.98, latency_ms=1.0, success=True, status="UNVERIFIABLE",
            ),
        ],
        total_latency_ms=5.0,
        status=DiagnosticStatus.UNVERIFIABLE,
    )

    with patch("qwed_new.api.main.consensus_verifier.verify_with_consensus", return_value=fake), \
         patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/consensus",
            json={"query": "test", "verification_mode": "high", "min_confidence": 0.0},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "UNVERIFIABLE"
    assert "blocked" not in data["agent_message"].lower()
    assert "advisory" in data["agent_message"] or "support conditions unmet" in data["agent_message"]


def test_verify_consensus_no_results_gives_specific_message(client):
    """Cover agreement_status=no_results -> specific message, not blocked-engine one."""
    from qwed_new.core.consensus_verifier import ConsensusResult

    fake = ConsensusResult(
        final_answer=None,
        confidence=0.0,
        engines_used=0,
        agreement_status="no_results",
        verification_chain=[],
        total_latency_ms=1.0,
        status=DiagnosticStatus.UNVERIFIABLE,
    )

    with patch("qwed_new.api.main.consensus_verifier.verify_with_consensus", return_value=fake), \
         patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/consensus",
            json={"query": "test", "verification_mode": "high", "min_confidence": 0.0},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "UNVERIFIABLE"
    assert data["agent_message"] == "Consensus verification: no engine results available"


def test_verify_consensus_all_failed_gives_specific_message(client):
    """Cover agreement_status=all_failed -> specific message, not blocked-engine one."""
    from qwed_new.core.consensus_verifier import ConsensusResult

    fake = ConsensusResult(
        final_answer=None,
        confidence=0.0,
        engines_used=2,
        agreement_status="all_failed",
        verification_chain=[],
        total_latency_ms=5.0,
        status=DiagnosticStatus.UNVERIFIABLE,
    )

    with patch("qwed_new.api.main.consensus_verifier.verify_with_consensus", return_value=fake), \
         patch("qwed_new.api.main.check_rate_limit"):
        response = client.post(
            "/verify/consensus",
            json={"query": "test", "verification_mode": "high", "min_confidence": 0.0},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "UNVERIFIABLE"
    assert data["agent_message"] == "Consensus verification: all engines failed"


def test_verify_consensus_no_agreement(client):
    """Cover else branch (no_consensus/split) -> UNVERIFIABLE."""
    from qwed_new.core.consensus_verifier import ConsensusResult

    fake = ConsensusResult(
        final_answer=None,
        confidence=0.3,
        engines_used=3,
        agreement_status="split",
        verification_chain=[],
        total_latency_ms=10.0,
        status=None,
    )

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


# --- Direct unit tests for auth functions (SonarQube uncovered paths) ---


def test_get_optional_current_user_success():
    """Cover get_optional_current_user success path: return user."""
    from qwed_new.api.main import get_optional_current_user

    mock_user = MagicMock()
    mock_session = MagicMock()
    mock_session.get.return_value = mock_user

    with patch("qwed_new.api.main.get_current_user_token", return_value={"sub": "42"}):
        result = get_optional_current_user(
            authorization="Bearer my.jwt.token",
            session=mock_session,
        )

    assert result is mock_user
    mock_session.get.assert_called_once()


def test_get_optional_api_key_record_success():
    """Cover get_optional_api_key_record success path: return api_key."""
    from qwed_new.api.main import get_optional_api_key_record

    # expires_at/revoked_at must be None explicitly: a bare MagicMock makes
    # them auto-truthy and the liveness check (PR #349) rejects the key.
    mock_api_key = MagicMock(expires_at=None, revoked_at=None)
    mock_session = MagicMock()
    mock_session.execute.return_value.scalars.return_value.first.return_value = mock_api_key

    fake_hash = secrets.token_hex(8)
    fake_key = secrets.token_hex(8)
    with patch("qwed_new.api.main.hash_api_key", return_value=fake_hash):
        result = get_optional_api_key_record(
            x_api_key=fake_key,
            session=mock_session,
        )

    assert result is mock_api_key
    mock_session.execute.assert_called_once()


def test_require_metrics_access_authentication_required():
    """Cover require_metrics_access 401 branch: no user, no api key."""
    from qwed_new.api.main import require_metrics_access

    mock_session = MagicMock()

    with pytest.raises(HTTPException) as exc_info:
        require_metrics_access(
            current_user=None,
            api_key_record=None,
            session=mock_session,
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Authentication required"
