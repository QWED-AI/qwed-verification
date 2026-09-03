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

    def test_equality_expression_sides_flagged(self):
        # CodeAnt on #348: `0.1 + 0.2 = 0.3` is not one eval-mode
        # expression — the two sides are parsed separately and both
        # surfaces' float constants are reported.
        advisory = AdvisoryCheck.float_precision("0.1 + 0.2 = 0.3")
        assert advisory is not None
        constants = advisory.details["constants"]
        assert any("0.1" in c for c in constants)
        assert any("0.3" in c for c in constants)

    def test_equality_with_clean_side_still_flags_float_side(self):
        advisory = AdvisoryCheck.float_precision("0.5 = x")
        assert advisory is not None
        assert advisory.details["constants"] == ["0.5"]

    def test_explicit_multiplication_equality_flagged(self):
        # Greptile on #348: 0.5*x = 0.5*x
        advisory = AdvisoryCheck.float_precision("0.5*x = 0.5*x")
        assert advisory is not None
        assert advisory.details["constants"] == ["0.5"]

    def test_implicit_multiplication_equality_flagged(self):
        # Greptile on #348: 0.5x = 0.5x
        advisory = AdvisoryCheck.float_precision("0.5x = 0.5x")
        assert advisory is not None
        assert advisory.details["constants"] == ["0.5"]

    def test_whitespace_implicit_multiplication_flagged(self):
        # Greptile P1 on #348: `0.5 x = 0.5 x` verifies as an identity,
        # so the advisory must surface its float constants too.
        advisory = AdvisoryCheck.float_precision("0.5 x = 0.5 x")
        assert advisory is not None
        assert advisory.details["constants"] == ["0.5"]

    def test_implicit_function_application_flagged(self):
        # Greptile P1 on #348: `sin 0.5 = sin 0.5` verifies; the advisory
        # must still surface the float constant.
        advisory = AdvisoryCheck.float_precision("sin 0.5 = sin 0.5")
        assert advisory is not None
        assert advisory.details["constants"] == ["0.5"]

    def test_function_application_with_trailing_operand_flagged(self):
        # Sentry on #348: `sin 0.5x` normalized to `sin(0.5)x` — a syntax
        # error that lost the advisory. The trailing operand needs `*`.
        advisory = AdvisoryCheck.float_precision("sin 0.5x = sin 0.5x")
        assert advisory is not None
        assert advisory.details["constants"] == ["0.5"]
        advisory = AdvisoryCheck.float_precision("sin 0.5 x = sin 0.5 x")
        assert advisory is not None
        assert advisory.details["constants"] == ["0.5"]

    def test_implicit_mul_with_paren_flagged(self):
        # Same implicit-multiplication class, paren form: `0.5(x+1)`.
        advisory = AdvisoryCheck.float_precision("0.5(x+1) = 0.5(x+1)")
        assert advisory is not None
        assert advisory.details["constants"] == ["0.5"]

    def test_keywords_are_never_implicit_mul_operands(self):
        # `0.5 in [0.5, 1]` parses today; rewriting `in` as an operand
        # would break the parse and lose the advisory.
        advisory = AdvisoryCheck.float_precision("0.5 in [0.5, 1]")
        assert advisory is not None
        assert advisory.details["constants"] == ["0.5"]
        # No floats anywhere: still None, and no crash.
        assert AdvisoryCheck.float_precision("3 in x = 3 in x") is None

    def test_oversized_side_skips_advisory(self):
        # Advisory-only path: oversized sides skip normalization rather
        # than burn CPU — absence of an advisory is always safe.
        assert AdvisoryCheck.float_precision("0 " * 5000 + "= 1") is None

    def test_symbolic_simplification_preserves_lexical_floats(self):
        # Greptile on #348: 0.0*x = 0.0*x and 0.5**0 = 1 collapse symbolically
        # to 0 = 0 and 1 = 1, but must retain their lexical float advisories.
        adv1 = AdvisoryCheck.float_precision("0.0*x = 0.0*x")
        assert adv1 is not None
        assert adv1.details["constants"] == ["0.0"]

        adv2 = AdvisoryCheck.float_precision("0.5**0 = 1")
        assert adv2 is not None
        assert adv2.details["constants"] == ["0.5"]

    def test_equality_literal_flagged(self):
        # CodeRabbit on #348: 0.1 = 0.1
        advisory = AdvisoryCheck.float_precision("0.1 = 0.1")
        assert advisory is not None
        assert advisory.details["constants"] == ["0.1"]

    def test_complex_literals_flagged(self):
        # CodeAnt nitpick: 1.0j is an AST complex constant, not float.
        advisory = AdvisoryCheck.float_precision("1.0j * 2")
        assert advisory is not None
        assert any("j" in c for c in advisory.details["constants"])

    def test_scientific_notation_equation_preserves_advisory(self):
        # CodeRabbit on #348: 1e3x = 1e3x consumes the exponent before implicit multiplication
        advisory = AdvisoryCheck.float_precision("1e3x = 1e3x")
        assert advisory is not None
        assert any("1000" in c for c in advisory.details["constants"])

    def test_malformed_equality_returns_none(self):
        # CodeRabbit on #348: return None if either side cannot be parsed
        assert AdvisoryCheck.float_precision("!! = ??") is None
        assert AdvisoryCheck.float_precision("0.1 = ??") is None
        assert AdvisoryCheck.float_precision("?? = 0.1") is None

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

    def test_from_dict_normalizes_missing_constraint_id(self):
        # CodeRabbit nitpick on #348: to_dict must emit a string per the
        # field contract even when the payload omits constraint_id.
        check = AdvisoryCheck.from_dict({"name": "x", "advisory_only": True})
        assert check.constraint_id == ""
        assert check.to_dict()["constraint_id"] == ""


class TestVerifyMathEndpointAdvisory:
    @pytest.fixture
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

    def test_equation_expression_carries_float_advisory(self, client):
        # Greptile / CodeRabbit / Sentry on #348: equations like
        # 0.5*x = 0.5*x and 0.5x = 0.5x must carry precision advisory.
        resp = client.post("/verify/math", json={"expression": "0.5*x = 0.5*x"})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data.get("status") == "VERIFIED"
        checks = data.get("developer_fields", {}).get("advisory_checks", [])
        adv = next((c for c in checks if c.get("constraint_id") == "precision.float-constants"), None)
        assert adv is not None
        assert "0.5" in adv["details"]["constants"]

    def test_implicit_multiplication_equation_carries_float_advisory(self, client):
        # Greptile on #348: 0.5x = 0.5x
        resp = client.post("/verify/math", json={"expression": "0.5x = 0.5x"})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data.get("status") == "VERIFIED"
        checks = data.get("developer_fields", {}).get("advisory_checks", [])
        adv = next((c for c in checks if c.get("constraint_id") == "precision.float-constants"), None)
        assert adv is not None
        assert "0.5" in adv["details"]["constants"]

    def test_literal_equation_carries_float_advisory(self, client):
        # CodeRabbit on #348: 0.1 = 0.1
        resp = client.post("/verify/math", json={"expression": "0.1 = 0.1"})
        assert resp.status_code == 200, resp.text
        checks = resp.json().get("developer_fields", {}).get("advisory_checks", [])
        assert any(c.get("constraint_id") == "precision.float-constants" for c in checks)

    def test_collapsing_equation_preserves_float_advisory(self, client):
        # Greptile on #348: 0.0*x = 0.0*x simplifies to 0 = 0, but advisory must retain 0.0
        resp = client.post("/verify/math", json={"expression": "0.0*x = 0.0*x"})
        assert resp.status_code == 200, resp.text
        checks = resp.json().get("developer_fields", {}).get("advisory_checks", [])
        adv = next((c for c in checks if c.get("constraint_id") == "precision.float-constants"), None)
        assert adv is not None
        assert "0.0" in adv["details"]["constants"]

        # 0.5**0 = 1 simplifies to 1 = 1, but advisory must retain 0.5
        resp2 = client.post("/verify/math", json={"expression": "0.5**0 = 1"})
        assert resp2.status_code == 200, resp2.text
        checks2 = resp2.json().get("developer_fields", {}).get("advisory_checks", [])
        adv2 = next((c for c in checks2 if c.get("constraint_id") == "precision.float-constants"), None)
        assert adv2 is not None
        assert "0.5" in adv2["details"]["constants"]

    def test_exact_equation_carries_no_float_advisory(self, client):
        resp = client.post("/verify/math", json={"expression": "x = x"})
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
