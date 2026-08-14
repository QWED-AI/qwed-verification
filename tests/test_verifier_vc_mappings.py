"""Tests for to_verification_context on all verifiers."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from qwed_new.core.diagnostics import DiagnosticResult
from qwed_new.core.verification_context import Verdict


def _unverifiable_result():
    return DiagnosticResult.unverifiable(
        agent_message="Test unverifiable",
        developer_fields={"test": True},
    )


def _blocked_result():
    return DiagnosticResult.blocked(
        agent_message="Test blocked",
        developer_fields={"test": True},
    )


class TestCodeVerifierVC:
    def test_to_verification_context_unverifiable(self):
        from qwed_new.core.code_verifier import CodeVerifier
        v = CodeVerifier()
        vc = v.to_verification_context(_unverifiable_result(), "test query")
        assert vc.verdict == Verdict.UNVERIFIABLE

    def test_to_verification_context_blocked(self):
        from qwed_new.core.code_verifier import CodeVerifier
        v = CodeVerifier()
        vc = v.to_verification_context(_blocked_result(), "test query")
        assert vc.verdict == Verdict.BLOCKED


class TestConsensusVerifierVC:
    def test_to_verification_context(self):
        from qwed_new.core.consensus_verifier import ConsensusVerifier
        v = ConsensusVerifier()
        vc = v.to_verification_context(_unverifiable_result(), "test query")
        assert vc.verdict == Verdict.UNVERIFIABLE


class TestFactVerifierVC:
    def test_to_verification_context(self):
        from qwed_new.core.fact_verifier import FactVerifier
        v = FactVerifier()
        vc = v.to_verification_context(_unverifiable_result(), "test query")
        assert vc.verdict == Verdict.UNVERIFIABLE


class TestGraphFactVerifierVC:
    def test_to_verification_context(self):
        from qwed_new.core.graph_fact_verifier import GraphFactVerifier
        v = GraphFactVerifier()
        vc = v.to_verification_context(_unverifiable_result(), "test query")
        assert vc.verdict == Verdict.UNVERIFIABLE


class TestImageVerifierVC:
    def test_to_verification_context(self):
        from qwed_new.core.image_verifier import ImageVerifier
        v = ImageVerifier()
        vc = v.to_verification_context(_unverifiable_result(), "test query")
        assert vc.verdict == Verdict.UNVERIFIABLE


class TestLogicVerifierVC:
    def test_to_verification_context(self):
        from qwed_new.core.logic_verifier import LogicVerifier
        v = LogicVerifier()
        vc = v.to_verification_context(_unverifiable_result(), "test query")
        assert vc.verdict == Verdict.UNVERIFIABLE


class TestReasoningVerifierVC:
    def test_to_verification_context(self):
        from qwed_new.core.reasoning_verifier import ReasoningVerifier
        v = ReasoningVerifier()
        vc = v.to_verification_context(_unverifiable_result(), "test query")
        assert vc.verdict == Verdict.UNVERIFIABLE


class TestSchemaVerifierVC:
    def test_to_verification_context(self):
        from qwed_new.core.schema_verifier import SchemaVerifier
        v = SchemaVerifier()
        vc = v.to_verification_context(_unverifiable_result(), "test query")
        assert vc.verdict == Verdict.UNVERIFIABLE


class TestSQLVerifierVC:
    def test_to_verification_context(self):
        from qwed_new.core.sql_verifier import SQLVerifier
        v = SQLVerifier()
        vc = v.to_verification_context(_unverifiable_result(), "test query")
        assert vc.verdict == Verdict.UNVERIFIABLE


class TestSymbolicVerifierVC:
    def test_to_verification_context(self):
        from qwed_new.core.symbolic_verifier import SymbolicVerifier
        v = SymbolicVerifier()
        vc = v.to_verification_context(_unverifiable_result(), "test query")
        assert vc.verdict == Verdict.UNVERIFIABLE


class TestDSLLogicVerifierVC:
    def test_to_verification_context(self):
        from qwed_new.core.dsl_logic_verifier import DSLLogicVerifier
        v = DSLLogicVerifier()
        vc = v.to_verification_context(_unverifiable_result(), "test query")
        assert vc.verdict == Verdict.UNVERIFIABLE