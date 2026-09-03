"""Issue #347: binary floating-point constants in math/stats verification
surface as a precision ADVISORY (`developer_fields.advisory_checks`), never
a rejection — QWED_RULES.md: flag floating-point math, suggest
decimal.Decimal / sympy. Adjudicated on PR #346: execution-safety gates
decide what may run, not what is exact."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from qwed_new.core.diagnostics import AdvisoryCheck, DiagnosticResult
from qwed_new.core.stats_verifier import StatsVerifier


class TestFloatPrecisionAdvisoryHelper:
    def test_float_expression_produces_advisory(self):
        advisory = AdvisoryCheck.float_precision("0.1 + 0.2")
        assert advisory is not None
        assert advisory.advisory_only is True
        assert advisory.constraint_id == "precision.float-constants"
        assert any("0.1" in c for c in advisory.details["constants"])
        assert "Decimal" in advisory.details["suggestion"]

    def test_exact_integer_expression_is_clean(self):
        assert AdvisoryCheck.float_precision("2 + 2") is None

    def test_decimal_construction_is_clean(self):
        # A Decimal call carries a string, not a float constant — exactly
        # the shape the advisory recommends.
        assert AdvisoryCheck.float_precision('Decimal("0.1") + Decimal("0.2")') is None

    def test_scientific_notation_flagged(self):
        assert AdvisoryCheck.float_precision("1e9 * 2") is not None

    def test_unparsable_source_returns_none(self):
        # Parse failures are the security gates' business, not this
        # advisory's.
        assert AdvisoryCheck.float_precision("import !!") is None

    def test_exec_mode_source(self):
        advisory = AdvisoryCheck.float_precision("df.fillna(0.5)", expression_mode=False)
        assert advisory is not None
        assert any("0.5" in c for c in advisory.details["constants"])

    def test_advisory_serializes_into_developer_fields(self):
        advisory = AdvisoryCheck.float_precision("0.1")
        dr = DiagnosticResult.verified("ok", evidence={}, developer_fields={"is_valid": True})
        dr.developer_fields.setdefault("advisory_checks", []).append(advisory)
        check = dr.to_dict()["developer_fields"]["advisory_checks"][0]
        assert check["advisory_only"] is True
        assert check["constraint_id"] == "precision.float-constants"


class TestVerifyMathEndpointAdvisory:
    @pytest.fixture()
    def client(self):
        from qwed_new.api.main import app, get_session
        from qwed_new.core.tenant_context import TenantContext, get_current_tenant

        def _fake_tenant():
            # api_key value is unused — the dependency is overridden.
            return TenantContext(
                organization_id=1, organization_name="test-org",
                tier="free", api_key="k-1",
            )

        def _fake_session():
            return MagicMock()

        app.dependency_overrides[get_current_tenant] = _fake_tenant
        app.dependency_overrides[get_session] = _fake_session
        yield TestClient(app)
        app.dependency_overrides.pop(get_current_tenant, None)
        app.dependency_overrides.pop(get_session, None)

    def test_float_expression_carries_advisory(self, client):
        resp = client.post("/verify/math", json={"expression": "0.1 + 0.2"})
        assert resp.status_code == 200, resp.text
        checks = resp.json().get("developer_fields", {}).get("advisory_checks", [])
        assert any(c.get("constraint_id") == "precision.float-constants" for c in checks)

    def test_exact_expression_carries_no_float_advisory(self, client):
        resp = client.post("/verify/math", json={"expression": "2 + 3"})
        assert resp.status_code == 200, resp.text
        checks = resp.json().get("developer_fields", {}).get("advisory_checks", [])
        assert not any(c.get("constraint_id") == "precision.float-constants" for c in checks)


class TestStatsCompletedAnalysisAdvisory:
    def test_completed_analysis_carries_float_advisory(self):
        """The one stats completion path (claim not deterministically
        verified) attaches the advisory when the generated code uses
        floats — the expected shape for numpy/pandas code."""
        verifier = StatsVerifier()
        verifier._translator = SimpleNamespace(
            translate_stats=lambda query, columns, provider=None:
                "result = float(df['a'].mean() * 0.5)"
        )
        verifier._select_sandbox = lambda: ("docker", object())
        verifier._execute_docker = lambda code, context: SimpleNamespace(
            success=True, error=None, result=1.0, execution_time_ms=1.0,
        )
        result = verifier.verify_stats("What is half the mean of a?", pd.DataFrame({"a": [1, 2, 3]}))
        checks = result.developer_fields.get("advisory_checks", [])
        assert any(c.constraint_id == "precision.float-constants" for c in checks)
        assert all(c.advisory_only is True for c in checks)

    def test_float_free_code_carries_no_advisory(self):
        verifier = StatsVerifier()
        verifier._translator = SimpleNamespace(
            translate_stats=lambda query, columns, provider=None:
                "result = df['a'].sum()"
        )
        verifier._select_sandbox = lambda: ("docker", object())
        verifier._execute_docker = lambda code, context: SimpleNamespace(
            success=True, error=None, result=6, execution_time_ms=1.0,
        )
        result = verifier.verify_stats("What is the sum of a?", pd.DataFrame({"a": [1, 2, 3]}))
        assert not any(
            c.constraint_id == "precision.float-constants"
            for c in result.developer_fields.get("advisory_checks", [])
        )
