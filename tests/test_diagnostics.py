"""
Tests for Issue #204: Structured Verification Diagnostics — 3-Layer Model.

Covers:
- DiagnosticStatus enum (tri-state, no proliferation)
- DiagnosticResult construction (VERIFIED / UNVERIFIABLE / BLOCKED)
- Layer 1: agent_message (agent-safe, mandatory, non-empty)
- Layer 2: developer_fields (constraint_id, advisory_checks, evidence)
- Layer 3: proof_ref (authority bit, hash binding, None for non-pass)
- Authority contract: proof_ref presence = admissible for control flow
- Fail-closed enforcement: VERIFIED requires proof_ref, non-VERIFIED rejects it
- AdvisoryCheck: advisory_only enforcement, serialization
- compute_proof_ref: deterministic hashing, JSON serialization
- to_dict / from_dict round-trip
- from_legacy_dict: migration from ad-hoc engine dicts (fail-closed states only)
- Constraint violations raise ValueError
"""

import hashlib
import unittest
from unittest.mock import MagicMock, patch
from src.qwed_new.core.diagnostics import (
    DiagnosticStatus,
    DiagnosticResult,
    AdvisoryCheck,
    compute_proof_ref,
    enforce_trust_decision,
)


# ---------------------------------------------------------------------------
# DiagnosticStatus enum
# ---------------------------------------------------------------------------

class TestDiagnosticStatus(unittest.TestCase):
    """Status taxonomy must be exactly three states — no proliferation."""

    def test_exactly_three_statuses(self):
        self.assertEqual(len(DiagnosticStatus), 3)

    def test_verified_exists(self):
        self.assertEqual(DiagnosticStatus.VERIFIED.value, "VERIFIED")

    def test_unverifiable_exists(self):
        self.assertEqual(DiagnosticStatus.UNVERIFIABLE.value, "UNVERIFIABLE")

    def test_blocked_exists(self):
        self.assertEqual(DiagnosticStatus.BLOCKED.value, "BLOCKED")

    def test_no_heuristic_status(self):
        self.assertFalse(hasattr(DiagnosticStatus, "HEURISTIC"))

    def test_no_ambiguous_status(self):
        self.assertFalse(hasattr(DiagnosticStatus, "AMBIGUOUS"))

    def test_no_correction_needed_status(self):
        self.assertFalse(hasattr(DiagnosticStatus, "CORRECTION_NEEDED"))

    def test_status_is_str_enum(self):
        self.assertIsInstance(DiagnosticStatus.VERIFIED, str)


# ---------------------------------------------------------------------------
# Layer 1 — agent_message (agent-safe)
# ---------------------------------------------------------------------------

class TestAgentMessage(unittest.TestCase):
    """Layer 1: agent_message is mandatory, non-empty, agent-safe."""

    def test_empty_agent_message_raises(self):
        with self.assertRaises(ValueError):
            DiagnosticResult.unverifiable("", {})

    def test_whitespace_only_agent_message_raises(self):
        with self.assertRaises(ValueError):
            DiagnosticResult.unverifiable("   ", {})

    def test_agent_message_present_on_verified(self):
        r = DiagnosticResult.verified("Claim verified", {}, {"a": 1})
        self.assertEqual(r.agent_message, "Claim verified")

    def test_agent_message_present_on_unverifiable(self):
        r = DiagnosticResult.unverifiable("Cannot verify", {})
        self.assertEqual(r.agent_message, "Cannot verify")

    def test_agent_message_present_on_blocked(self):
        r = DiagnosticResult.blocked("Blocked", {})
        self.assertEqual(r.agent_message, "Blocked")


# ---------------------------------------------------------------------------
# Layer 3 — proof_ref (authority bit)
# ---------------------------------------------------------------------------

class TestProofRef(unittest.TestCase):
    """Layer 3: proof_ref is the authority bit — present only for VERIFIED."""

    def test_verified_has_proof_ref(self):
        r = DiagnosticResult.verified("ok", {}, {"evidence": True})
        self.assertIsNotNone(r.proof_ref)
        self.assertTrue(r.proof_ref.startswith("sha256:"))

    def test_unverifiable_has_no_proof_ref(self):
        r = DiagnosticResult.unverifiable("no", {})
        self.assertIsNone(r.proof_ref)

    def test_blocked_has_no_proof_ref(self):
        r = DiagnosticResult.blocked("blocked", {})
        self.assertIsNone(r.proof_ref)

    def test_verified_without_proof_ref_raises(self):
        with self.assertRaises(ValueError):
            DiagnosticResult(
                status=DiagnosticStatus.VERIFIED,
                agent_message="ok",
                developer_fields={},
                proof_ref=None,
            )

    def test_unverifiable_with_proof_ref_raises(self):
        with self.assertRaises(ValueError):
            DiagnosticResult(
                status=DiagnosticStatus.UNVERIFIABLE,
                agent_message="no",
                developer_fields={},
                proof_ref="sha256:abc",
            )

    def test_blocked_with_proof_ref_raises(self):
        with self.assertRaises(ValueError):
            DiagnosticResult(
                status=DiagnosticStatus.BLOCKED,
                agent_message="blocked",
                developer_fields={},
                proof_ref="sha256:abc",
            )

    def test_is_authoritative_true_for_verified(self):
        r = DiagnosticResult.verified("ok", {}, {"e": 1})
        self.assertTrue(r.is_authoritative)

    def test_is_authoritative_false_for_unverifiable(self):
        r = DiagnosticResult.unverifiable("no", {})
        self.assertFalse(r.is_authoritative)

    def test_is_authoritative_false_for_blocked(self):
        r = DiagnosticResult.blocked("blocked", {})
        self.assertFalse(r.is_authoritative)


# ---------------------------------------------------------------------------
# Authority contract — downstream gate mechanical rule
# ---------------------------------------------------------------------------

class TestAuthorityContract(unittest.TestCase):
    """Downstream gates use is_authoritative as the control-flow admission rule."""

    def test_authoritative_verifies_claim(self):
        r = DiagnosticResult.verified("ok", {"constraint_id": "test"}, {"e": 1})
        self.assertTrue(r.is_authoritative)
        self.assertTrue(r.is_verified)

    def test_non_authoritative_rejected_for_control_flow(self):
        unverifiable = DiagnosticResult.unverifiable("no", {})
        blocked = DiagnosticResult.blocked("blocked", {})
        self.assertFalse(unverifiable.is_authoritative)
        self.assertFalse(blocked.is_authoritative)

    def test_mechanical_rule_proof_ref_none_means_reject(self):
        results = [
            DiagnosticResult.verified("ok", {}, {"e": 1}),
            DiagnosticResult.unverifiable("no", {}),
            DiagnosticResult.blocked("blocked", {}),
        ]
        admissible = [r for r in results if r.proof_ref is not None]
        self.assertEqual(len(admissible), 1)
        self.assertTrue(admissible[0].is_verified)

    def test_empty_string_proof_ref_raises(self):
        """Empty string proof_ref must not bypass authority invariant (Greptile P1)."""
        with self.assertRaises(ValueError):
            DiagnosticResult(
                status=DiagnosticStatus.VERIFIED,
                agent_message="ok",
                developer_fields={},
                proof_ref="",
            )

    def test_frozen_dataclass_prevents_mutation(self):
        """Post-construction proof_ref mutation must be blocked (Greptile P1)."""
        r = DiagnosticResult.unverifiable("no", {})
        with self.assertRaises((AttributeError, Exception)):
            r.proof_ref = "sha256:fake"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Fail-closed enforcement
# ---------------------------------------------------------------------------

class TestFailClosed(unittest.TestCase):
    """Non-pass states must be fail-closed — no silent pass."""

    def test_is_fail_closed_for_unverifiable(self):
        r = DiagnosticResult.unverifiable("no", {})
        self.assertTrue(r.is_fail_closed)

    def test_is_fail_closed_for_blocked(self):
        r = DiagnosticResult.blocked("blocked", {})
        self.assertTrue(r.is_fail_closed)

    def test_not_fail_closed_for_verified(self):
        r = DiagnosticResult.verified("ok", {}, {"e": 1})
        self.assertFalse(r.is_fail_closed)

    def test_is_verified_true_only_for_verified_status(self):
        self.assertTrue(DiagnosticResult.verified("ok", {}, {"e": 1}).is_verified)
        self.assertFalse(DiagnosticResult.unverifiable("no", {}).is_verified)
        self.assertFalse(DiagnosticResult.blocked("blocked", {}).is_verified)


# ---------------------------------------------------------------------------
# compute_proof_ref — deterministic hashing
# ---------------------------------------------------------------------------

class TestComputeProofRef(unittest.TestCase):
    """proof_ref hashing must be deterministic and content-sensitive."""

    def test_returns_sha256_prefixed(self):
        ref = compute_proof_ref({"a": 1})
        self.assertTrue(ref.startswith("sha256:"))
        self.assertEqual(len(ref), len("sha256:") + 64)

    def test_same_evidence_same_hash(self):
        ref1 = compute_proof_ref({"a": 1, "b": 2})
        ref2 = compute_proof_ref({"a": 1, "b": 2})
        self.assertEqual(ref1, ref2)

    def test_different_evidence_different_hash(self):
        ref1 = compute_proof_ref({"a": 1})
        ref2 = compute_proof_ref({"a": 2})
        self.assertNotEqual(ref1, ref2)

    def test_key_order_independent(self):
        ref1 = compute_proof_ref({"a": 1, "b": 2})
        ref2 = compute_proof_ref({"b": 2, "a": 1})
        self.assertEqual(ref1, ref2)

    def test_non_serializable_raises_value_error(self):
        """Non-serializable objects must be rejected to ensure deterministic hashing."""
        with self.assertRaises(ValueError) as ctx:
            compute_proof_ref({"obj": object()})
        self.assertIn("JSON-serializable", str(ctx.exception))

    def test_nested_non_serializable_raises_value_error(self):
        """Nested non-serializable objects must also be rejected."""
        with self.assertRaises(ValueError) as ctx:
            compute_proof_ref({"data": {"inner": object()}})
        self.assertIn("JSON-serializable", str(ctx.exception))


# ---------------------------------------------------------------------------
# AdvisoryCheck — advisory metadata
# ---------------------------------------------------------------------------

class TestAdvisoryCheck(unittest.TestCase):
    """Advisory checks are non-proof-bearing — advisory_only is always True."""

    def test_default_advisory_only_is_true(self):
        ac = AdvisoryCheck(name="llm_fallback")
        self.assertTrue(ac.advisory_only)

    def test_advisory_only_false_raises(self):
        """advisory_only=False must raise — structurally enforced contract."""
        with self.assertRaises(ValueError):
            AdvisoryCheck(name="x", advisory_only=False)

    def test_from_dict_coerces_integer_advisory_only(self):
        """from_dict must coerce 1 to True — cross-language APIs use int booleans."""
        ac = AdvisoryCheck.from_dict({"name": "test", "advisory_only": 1})
        self.assertTrue(ac.advisory_only)

    def test_from_dict_rejects_zero_advisory_only(self):
        """from_dict with advisory_only=0 coerces to False — must raise."""
        with self.assertRaises(ValueError):
            AdvisoryCheck.from_dict({"name": "test", "advisory_only": 0})

    def test_from_dict_rejects_string_advisory_only(self):
        """from_dict must reject string 'false' — bool('false') is True in Python."""
        with self.assertRaises(ValueError):
            AdvisoryCheck.from_dict({"name": "test", "advisory_only": "false"})

    def test_advisory_check_to_dict(self):
        ac = AdvisoryCheck(
            name="vlm_analysis",
            advisory_only=True,
            constraint_id="image_verifier.vlm_advisory_only",
            details={"vlm_verdict": "SUPPORTED", "vlm_confidence": 0.65},
        )
        d = ac.to_dict()
        self.assertEqual(d["name"], "vlm_analysis")
        self.assertTrue(d["advisory_only"])
        self.assertEqual(d["constraint_id"], "image_verifier.vlm_advisory_only")
        self.assertEqual(d["details"]["vlm_verdict"], "SUPPORTED")

    def test_advisory_check_from_dict(self):
        d = {"name": "nli", "advisory_only": True, "constraint_id": "graph.nli", "details": {}}
        ac = AdvisoryCheck.from_dict(d)
        self.assertEqual(ac.name, "nli")
        self.assertTrue(ac.advisory_only)

    def test_advisory_check_round_trip(self):
        ac = AdvisoryCheck(name="test", constraint_id="c", details={"x": 1})
        ac2 = AdvisoryCheck.from_dict(ac.to_dict())
        self.assertEqual(ac.name, ac2.name)
        self.assertEqual(ac.constraint_id, ac2.constraint_id)
        self.assertEqual(ac.details, ac2.details)


# ---------------------------------------------------------------------------
# developer_fields — Layer 2 structured evidence
# ---------------------------------------------------------------------------

class TestDeveloperFields(unittest.TestCase):
    """Layer 2: developer_fields carries constraint_id, evidence, advisory_checks."""

    def test_constraint_id_property(self):
        r = DiagnosticResult.unverifiable("no", {"constraint_id": "math.mode_ambiguous"})
        self.assertEqual(r.constraint_id, "math.mode_ambiguous")

    def test_constraint_id_none_when_absent(self):
        r = DiagnosticResult.unverifiable("no", {})
        self.assertIsNone(r.constraint_id)

    def test_advisory_checks_property_returns_list(self):
        r = DiagnosticResult.unverifiable("no", {
            "advisory_checks": [
                {"name": "llm", "advisory_only": True, "constraint_id": "test", "details": {}},
            ],
        })
        checks = r.advisory_checks
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0].name, "llm")
        self.assertTrue(checks[0].advisory_only)

    def test_advisory_checks_empty_when_absent(self):
        r = DiagnosticResult.unverifiable("no", {})
        self.assertEqual(r.advisory_checks, [])

    def test_advisory_checks_skips_invalid_items(self):
        """Property must skip malformed items (fail-closed, never raise)."""
        r = DiagnosticResult.unverifiable("no", {
            "advisory_checks": [
                {"name": "valid", "advisory_only": True, "details": {}},
                {"name": "invalid", "advisory_only": False, "details": {}},
                42,
                "garbage",
            ],
        })
        checks = r.advisory_checks
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0].name, "valid")

    def test_advisory_checks_accepts_existing_instances(self):
        ac = AdvisoryCheck(name="prebuilt", constraint_id="test")
        r = DiagnosticResult.unverifiable("no", {"advisory_checks": [ac]})
        checks = r.advisory_checks
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0].name, "prebuilt")

    def test_developer_fields_default_empty_dict(self):
        r = DiagnosticResult.unverifiable("no")
        self.assertEqual(r.developer_fields, {})


# ---------------------------------------------------------------------------
# Serialization — to_dict / from_dict
# ---------------------------------------------------------------------------

class TestSerialization(unittest.TestCase):
    """to_dict / from_dict must round-trip all fields."""

    def test_verified_round_trip(self):
        r = DiagnosticResult.verified(
            agent_message="Claim verified",
            developer_fields={"constraint_id": "test", "calculated": 4, "claimed": 4},
            evidence={"calculated": 4, "claimed": 4},
        )
        d = r.to_dict()
        self.assertEqual(d["status"], "VERIFIED")
        self.assertEqual(d["agent_message"], "Claim verified")
        self.assertIsNotNone(d["proof_ref"])
        self.assertTrue(d["is_authoritative"])

        r2 = DiagnosticResult.from_dict(d)
        self.assertEqual(r2.status, DiagnosticStatus.VERIFIED)
        self.assertEqual(r2.agent_message, r.agent_message)
        self.assertEqual(r2.proof_ref, r.proof_ref)
        self.assertEqual(r2.developer_fields, r.developer_fields)

    def test_to_dict_serializes_advisory_check_instances(self):
        """to_dict must serialize AdvisoryCheck instances to dicts (Sentry MEDIUM)."""
        ac = AdvisoryCheck(name="llm", constraint_id="test", details={"verdict": "yes"})
        r = DiagnosticResult.unverifiable("no", {"advisory_checks": [ac]})
        d = r.to_dict()
        checks = d["developer_fields"]["advisory_checks"]
        self.assertEqual(len(checks), 1)
        self.assertIsInstance(checks[0], dict)
        self.assertEqual(checks[0]["name"], "llm")

    def test_to_dict_json_serializable_with_advisory_checks(self):
        """to_dict output must be JSON-serializable even with AdvisoryCheck instances."""
        import json
        ac = AdvisoryCheck(name="nli", constraint_id="graph.nli", details={"label": "entailment"})
        r = DiagnosticResult.unverifiable("no", {"advisory_checks": [ac]})
        d = r.to_dict()
        payload = json.dumps(d)  # must not raise TypeError
        self.assertIn("nli", payload)

    def test_unverifiable_round_trip(self):
        r = DiagnosticResult.unverifiable(
            "Cannot verify",
            {"constraint_id": "test.missing", "advisory_checks": []},
        )
        d = r.to_dict()
        self.assertEqual(d["status"], "UNVERIFIABLE")
        self.assertIsNone(d["proof_ref"])
        self.assertFalse(d["is_authoritative"])

        r2 = DiagnosticResult.from_dict(d)
        self.assertEqual(r2.status, DiagnosticStatus.UNVERIFIABLE)
        self.assertIsNone(r2.proof_ref)

    def test_blocked_round_trip(self):
        r = DiagnosticResult.blocked("Blocked", {"constraint_id": "test.parse_error"})
        d = r.to_dict()
        self.assertEqual(d["status"], "BLOCKED")
        r2 = DiagnosticResult.from_dict(d)
        self.assertEqual(r2.status, DiagnosticStatus.BLOCKED)

    def test_from_dict_tolerates_string_status(self):
        d = {"status": "VERIFIED", "agent_message": "ok", "developer_fields": {}, "proof_ref": "sha256:abc"}
        r = DiagnosticResult.from_dict(d)
        self.assertEqual(r.status, DiagnosticStatus.VERIFIED)

    def test_from_dict_defaults_to_unverifiable(self):
        d = {"agent_message": "unknown"}
        r = DiagnosticResult.from_dict(d)
        self.assertEqual(r.status, DiagnosticStatus.UNVERIFIABLE)

    def test_from_dict_missing_agent_message_raises(self):
        """Missing agent_message must raise clear deserialization error."""
        with self.assertRaises(ValueError) as ctx:
            DiagnosticResult.from_dict({"status": "UNVERIFIABLE"})
        self.assertIn("agent_message", str(ctx.exception))

    def test_from_dict_invalid_status_raises_with_guidance(self):
        """Invalid status string must raise with valid options + from_legacy_dict pointer."""
        with self.assertRaises(ValueError) as ctx:
            DiagnosticResult.from_dict({"status": "CORRECTION_NEEDED", "agent_message": "x"})
        msg = str(ctx.exception)
        self.assertIn("CORRECTION_NEEDED", msg)
        self.assertIn("from_legacy_dict", msg)

    def test_from_dict_empty_agent_message_raises(self):
        with self.assertRaises(ValueError):
            DiagnosticResult.from_dict({"status": "UNVERIFIABLE", "agent_message": "  "})


# ---------------------------------------------------------------------------
# from_legacy_dict — migration helper for ad-hoc engine dicts
# ---------------------------------------------------------------------------

class TestFromLegacyDict(unittest.TestCase):
    """Migration helper converts fail-closed legacy states — NOT VERIFIED."""

    def test_correction_needed_becomes_unverifiable(self):
        legacy = {"is_correct": False, "status": "CORRECTION_NEEDED", "calculated_value": 3, "claimed_value": 4}
        r = DiagnosticResult.from_legacy_dict(legacy, engine="math")
        self.assertEqual(r.status, DiagnosticStatus.UNVERIFIABLE)
        self.assertIsNone(r.proof_ref)
        self.assertEqual(r.constraint_id, "math.legacy_inconclusive")

    def test_error_becomes_blocked(self):
        legacy = {"is_correct": False, "status": "ERROR", "error": "division by zero"}
        r = DiagnosticResult.from_legacy_dict(legacy, engine="math")
        self.assertEqual(r.status, DiagnosticStatus.BLOCKED)
        self.assertIsNone(r.proof_ref)
        self.assertEqual(r.constraint_id, "math.legacy_error")

    def test_syntax_error_becomes_blocked(self):
        legacy = {"is_correct": False, "status": "SYNTAX_ERROR", "error": "bad expr"}
        r = DiagnosticResult.from_legacy_dict(legacy, engine="math")
        self.assertEqual(r.status, DiagnosticStatus.BLOCKED)

    def test_blocked_legacy_becomes_blocked(self):
        legacy = {"is_correct": False, "status": "BLOCKED", "message": "tolerance exceeded"}
        r = DiagnosticResult.from_legacy_dict(legacy, engine="math")
        self.assertEqual(r.status, DiagnosticStatus.BLOCKED)
        self.assertEqual(r.constraint_id, "math.legacy_blocked")

    def test_inconclusive_becomes_unverifiable(self):
        legacy = {"is_correct": False, "status": "INCONCLUSIVE"}
        r = DiagnosticResult.from_legacy_dict(legacy, engine="image")
        self.assertEqual(r.status, DiagnosticStatus.UNVERIFIABLE)

    def test_verified_legacy_raises(self):
        legacy = {"is_correct": True, "status": "VERIFIED", "calculated_value": 4}
        with self.assertRaises(ValueError):
            DiagnosticResult.from_legacy_dict(legacy, engine="math")

    def test_is_correct_true_raises(self):
        legacy = {"is_correct": True, "status": "WHATEVER"}
        with self.assertRaises(ValueError):
            DiagnosticResult.from_legacy_dict(legacy, engine="math")

    def test_is_correct_integer_one_raises(self):
        """Legacy engines using 1 instead of True must be caught (identity bypass fix)."""
        legacy = {"is_correct": 1, "status": "WHATEVER"}
        with self.assertRaises(ValueError):
            DiagnosticResult.from_legacy_dict(legacy, engine="math")

    def test_is_correct_integer_zero_becomes_unverifiable(self):
        """Legacy engines using 0 instead of False must be handled (identity bypass fix)."""
        legacy = {"is_correct": 0, "status": "WHATEVER"}
        r = DiagnosticResult.from_legacy_dict(legacy, engine="math")
        self.assertEqual(r.status, DiagnosticStatus.UNVERIFIABLE)

    def test_unrecognized_truthy_raises(self):
        """Unrecognized legacy patterns with truthy is_correct must raise (fail-loudly)."""
        legacy = {"is_correct": "yes", "status": "UNKNOWN_STATUS"}
        with self.assertRaises(ValueError):
            DiagnosticResult.from_legacy_dict(legacy, engine="test")

    def test_no_status_no_is_correct_becomes_inconclusive(self):
        """When is_correct defaults to False with no error, result is inconclusive."""
        legacy = {"some_field": "value"}
        r = DiagnosticResult.from_legacy_dict(legacy, engine="test")
        self.assertEqual(r.status, DiagnosticStatus.UNVERIFIABLE)
        self.assertEqual(r.constraint_id, "test.legacy_inconclusive")

    def test_false_with_error_becomes_blocked(self):
        legacy = {"is_correct": False, "error": "something went wrong"}
        r = DiagnosticResult.from_legacy_dict(legacy, engine="logic")
        self.assertEqual(r.status, DiagnosticStatus.BLOCKED)
        self.assertEqual(r.constraint_id, "logic.legacy_error")

    def test_false_without_error_becomes_unverifiable(self):
        legacy = {"is_correct": False}
        r = DiagnosticResult.from_legacy_dict(legacy, engine="logic")
        self.assertEqual(r.status, DiagnosticStatus.UNVERIFIABLE)


# ---------------------------------------------------------------------------
# Integration — realistic diagnostic scenarios from blocked issues
# ---------------------------------------------------------------------------

class TestRealisticScenarios(unittest.TestCase):
    """Scenarios drawn from the blocked issues to validate the model fits."""

    def test_math_mode_ambiguous_tie(self):
        """#129: multi-mode dataset must be UNVERIFIABLE with modes in developer_fields."""
        r = DiagnosticResult.unverifiable(
            agent_message="Statistical claim inconclusive — dataset has multiple modes",
            developer_fields={
                "statistic": "mode",
                "modes": [1, 2],
                "modes_count": 2,
                "tie_detected": True,
                "max_frequency": 2,
                "constraint_id": "math_verifier.mode_ambiguous_tie",
            },
        )
        self.assertTrue(r.is_fail_closed)
        self.assertFalse(r.is_authoritative)
        self.assertEqual(r.developer_fields["modes"], [1, 2])
        self.assertTrue(r.developer_fields["tie_detected"])

    def test_math_irr_non_convergent(self):
        """#131: non-convergent IRR must be UNVERIFIABLE with convergence trace."""
        r = DiagnosticResult.unverifiable(
            agent_message="IRR could not be deterministically verified",
            developer_fields={
                "iterations": 100,
                "final_npv": "0.7",
                "converged": False,
                "constraint_id": "math_verifier.irr_non_convergent",
            },
        )
        self.assertTrue(r.is_fail_closed)
        self.assertFalse(r.developer_fields["converged"])

    def test_math_irr_convergent_verified_with_proof(self):
        """#131: convergent IRR with unique root must be VERIFIED with proof_ref."""
        evidence = {
            "iterations": 5,
            "final_npv": "0.00003",
            "converged": True,
            "sign_changes": 1,
            "uniqueness": "single_root",
        }
        r = DiagnosticResult.verified(
            agent_message="IRR verified — convergence proven",
            developer_fields={
                "iterations": 5,
                "final_npv": "0.00003",
                "converged": True,
                "sign_changes": 1,
                "uniqueness": "single_root",
                "constraint_id": "math_verifier.irr_convergence_proven",
            },
            evidence=evidence,
        )
        self.assertTrue(r.is_verified)
        self.assertTrue(r.is_authoritative)
        self.assertIsNotNone(r.proof_ref)

    def test_fact_verifier_llm_advisory_only(self):
        """#133/#190: LLM fallback must be UNVERIFIABLE with advisory_checks."""
        r = DiagnosticResult.unverifiable(
            agent_message="Claim could not be deterministically verified",
            developer_fields={
                "deterministic_verdict": "INSUFFICIENT_EVIDENCE",
                "evidence_coverage_ratio": 0.4,
                "advisory_checks": [
                    AdvisoryCheck(
                        name="llm_fallback",
                        advisory_only=True,
                        constraint_id="fact_verifier.llm_advisory_only",
                        details={"llm_verdict": "SUPPORTED", "llm_confidence": 0.65},
                    ).to_dict(),
                ],
                "provenance": {
                    "provider": "openai",
                    "model": "gpt-4",
                    "prompt_hash": "sha256:abc123",
                },
                "constraint_id": "fact_verifier.assistive_llm",
            },
        )
        self.assertTrue(r.is_fail_closed)
        self.assertFalse(r.is_authoritative)
        checks = r.advisory_checks
        self.assertEqual(len(checks), 1)
        self.assertTrue(checks[0].advisory_only)
        self.assertEqual(checks[0].details["llm_verdict"], "SUPPORTED")

    def test_logic_verifier_missing_declarations(self):
        """#162: missing variable declarations must be BLOCKED."""
        r = DiagnosticResult.blocked(
            agent_message="Logic verification blocked — variable declarations missing",
            developer_fields={
                "missing_declarations": ["x"],
                "constraint_id": "logic_verifier.explicit_declarations_required",
            },
        )
        self.assertTrue(r.is_fail_closed)
        self.assertEqual(r.developer_fields["missing_declarations"], ["x"])

    def test_secure_executor_verifier_unavailable(self):
        """#205: CodeVerifier unavailable must be UNVERIFIABLE with advisory basic_safety."""
        r = DiagnosticResult.unverifiable(
            agent_message="Code safety verification unavailable",
            developer_fields={
                "constraint_id": "secure_code_executor.verifier_unavailable",
                "advisory_checks": [
                    AdvisoryCheck(
                        name="basic_safety",
                        advisory_only=True,
                        constraint_id="secure_code_executor.basic_safety_advisory",
                        details={"is_safe": True, "reason": None},
                    ).to_dict(),
                ],
            },
        )
        self.assertTrue(r.is_fail_closed)
        self.assertFalse(r.is_authoritative)

    def test_attestation_consumption_missing_token(self):
        """#191: VERIFIED without attestation must be BLOCKED."""
        r = DiagnosticResult.blocked(
            agent_message="Verification blocked — proof artifact missing",
            developer_fields={
                "missing": "attestation_token",
                "policy": "mandatory",
                "constraint_id": "trust_gate.mandatory_attestation_missing",
            },
        )
        self.assertTrue(r.is_fail_closed)
        self.assertFalse(r.is_authoritative)

    def test_downstream_gate_rejects_non_authoritative(self):
        """Mechanical rule: proof_ref is None → reject for control flow."""
        results = [
            DiagnosticResult.verified("ok", {"constraint_id": "a"}, {"e": 1}),
            DiagnosticResult.unverifiable("no", {"constraint_id": "b"}),
            DiagnosticResult.blocked("blocked", {"constraint_id": "c"}),
        ]
        admitted = [r for r in results if r.is_authoritative]
        self.assertEqual(len(admitted), 1)
        self.assertEqual(admitted[0].constraint_id, "a")





# ---------------------------------------------------------------------------
# Issue #191 — enforce_trust_decision: consumption-side attestation enforcement
# ---------------------------------------------------------------------------

class TestEnforceTrustDecision(unittest.TestCase):
    """Issue #191: trust-boundary gates must enforce attestation presence."""

    def setUp(self):
        self.verified = DiagnosticResult.verified(
            agent_message="Math check passed",
            developer_fields={"constraint_id": "math.identity"},
            evidence={"result": 42},
        )
        self.unverifiable = DiagnosticResult.unverifiable(
            agent_message="Math check inconclusive",
            developer_fields={"constraint_id": "math.inconclusive"},
        )
        self.blocked = DiagnosticResult.blocked(
            agent_message="Math check blocked",
            developer_fields={"constraint_id": "math.blocked"},
        )

    # --- (a) VERIFIED + no token → BLOCKED ---

    def test_verified_no_token_returns_blocked(self):
        """VERIFIED without attestation token must return BLOCKED."""
        r = enforce_trust_decision(self.verified)
        self.assertTrue(r.is_fail_closed)
        self.assertEqual(
            r.developer_fields.get("constraint_id"),
            "trust_gate.mandatory_attestation_missing",
        )
        self.assertIn("proof artifact missing", r.agent_message.lower())

    # --- (b) VERIFIED + invalid token → BLOCKED ---

    def test_verified_invalid_token_returns_blocked(self):
        """VERIFIED with invalid token must return BLOCKED."""
        with patch("src.qwed_new.core.attestation.get_attestation_service") as mock_get:
            mock_svc = MagicMock()
            mock_svc.verify_attestation.return_value = (False, None, "signature invalid")
            mock_get.return_value = mock_svc

            r = enforce_trust_decision(
                self.verified,
                attestation_token="QWED_TEST_INVALID_TOKEN",
            )

        self.assertTrue(r.is_fail_closed)
        self.assertEqual(
            r.developer_fields.get("constraint_id"),
            "trust_gate.invalid_attestation_token",
        )
        self.assertIn("proof artifact invalid", r.agent_message.lower())

    # --- (c) VERIFIED + valid token → passes ---

    def _verified_claims(self) -> dict:
        """Build a claim set matching self.verified (proof_ref + status)."""
        return {
            "qwed": {
                "result": {"status": "VERIFIED", "engine": "math"},
                "proof_hash": self.verified.proof_ref,
            },
        }

    def test_verified_valid_token_passes(self):
        """VERIFIED with valid token (matching claims) must return the original."""
        with patch("src.qwed_new.core.attestation.get_attestation_service") as mock_get:
            mock_svc = MagicMock()
            mock_svc.verify_attestation.return_value = (True, self._verified_claims(), None)
            mock_get.return_value = mock_svc

            r = enforce_trust_decision(
                self.verified,
                attestation_token="QWED_TEST_VALID_TOKEN",
            )

        self.assertTrue(r.is_verified)
        self.assertEqual(r.constraint_id, "math.identity")
        self.assertIsNotNone(r.proof_ref)

    def test_verified_valid_token_with_query_passes(self):
        """VERIFIED with valid token + matching query_hash must pass."""
        with patch("src.qwed_new.core.attestation.get_attestation_service") as mock_get:
            mock_svc = MagicMock()
            claims = self._verified_claims()
            expected_qh = "sha256:" + hashlib.sha256(b"2+2=4").hexdigest()
            claims["qwed"]["query_hash"] = expected_qh
            mock_svc.verify_attestation.return_value = (True, claims, None)
            mock_get.return_value = mock_svc

            r = enforce_trust_decision(
                self.verified,
                attestation_token="QWED_TEST_VALID_TOKEN",
                query="2+2=4",
            )

        self.assertTrue(r.is_verified)
        self.assertEqual(r.constraint_id, "math.identity")

    # --- (d) Policy toggle: optional attestation ---

    def test_verified_optional_attestation_without_token_passes(self):
        """require_attestation=False must allow VERIFIED without token."""
        r = enforce_trust_decision(
            self.verified,
            require_attestation=False,
            attestation_token=None,
        )
        self.assertTrue(r.is_verified)
        self.assertEqual(r.constraint_id, "math.identity")

    def test_verified_optional_policy_still_blocks_invalid_token(self):
        """Even with optional policy, invalid token must still be blocked."""
        with patch("src.qwed_new.core.attestation.get_attestation_service") as mock_get:
            mock_svc = MagicMock()
            mock_svc.verify_attestation.return_value = (False, None, "bad sig")
            mock_get.return_value = mock_svc

            r = enforce_trust_decision(
                self.verified,
                require_attestation=False,
                attestation_token="QWED_TEST_BAD_TOKEN",
            )

        self.assertTrue(r.is_fail_closed)
        self.assertEqual(
            r.developer_fields.get("constraint_id"),
            "trust_gate.invalid_attestation_token",
        )

    # --- Fail-closed states pass through regardless ---

    def test_unverifiable_passes_through_without_token(self):
        """UNVERIFIABLE must pass through without attestation."""
        r = enforce_trust_decision(self.unverifiable)
        self.assertTrue(r.is_fail_closed)
        self.assertEqual(r.constraint_id, "math.inconclusive")

    def test_blocked_passes_through_without_token(self):
        """BLOCKED must pass through without attestation."""
        r = enforce_trust_decision(self.blocked)
        self.assertTrue(r.is_fail_closed)
        self.assertEqual(r.constraint_id, "math.blocked")

    def test_unverifiable_with_token_passes_through(self):
        """UNVERIFIABLE must pass through even with a token (attestation irrelevant)."""
        r = enforce_trust_decision(self.unverifiable, attestation_token="QWED_TEST_DUMMY_TOKEN")
        self.assertTrue(r.is_fail_closed)
        self.assertEqual(r.constraint_id, "math.inconclusive")

    # --- Edge cases ---

    def test_verified_verification_error_returns_blocked(self):
        """If attestation verification raises, result must be BLOCKED."""
        with patch("src.qwed_new.core.attestation.get_attestation_service") as mock_get:
            mock_svc = MagicMock()
            mock_svc.verify_attestation.side_effect = RuntimeError("crypto failure")
            mock_get.return_value = mock_svc

            r = enforce_trust_decision(
                self.verified,
                attestation_token="QWED_TEST_RAISING_TOKEN",
            )

        self.assertTrue(r.is_fail_closed)
        self.assertEqual(
            r.developer_fields.get("constraint_id"),
            "trust_gate.attestation_verification_error",
        )

    def test_verified_with_empty_token_is_blocked(self):
        """Empty string token should be treated as missing."""
        r = enforce_trust_decision(self.verified, attestation_token="")
        self.assertTrue(r.is_fail_closed)
        self.assertEqual(
            r.developer_fields.get("constraint_id"),
            "trust_gate.mandatory_attestation_missing",
        )

    # --- Claims binding: token must match result ---

    def test_claims_status_mismatch_blocks(self):
        """Token with status != VERIFIED must be blocked."""
        with patch("src.qwed_new.core.attestation.get_attestation_service") as mock_get:
            mock_svc = MagicMock()
            mock_svc.verify_attestation.return_value = (
                True,
                {"qwed": {"result": {"status": "FAILED"}}},
                None,
            )
            mock_get.return_value = mock_svc

            r = enforce_trust_decision(
                self.verified,
                attestation_token="QWED_TEST_MISMATCHED_STATUS_TOKEN",
            )

        self.assertTrue(r.is_fail_closed)
        self.assertEqual(
            r.developer_fields.get("constraint_id"),
            "trust_gate.claims_status_mismatch",
        )

    def test_claims_query_mismatch_blocks(self):
        """Token with wrong query_hash must be blocked."""
        with patch("src.qwed_new.core.attestation.get_attestation_service") as mock_get:
            mock_svc = MagicMock()
            mock_svc.verify_attestation.return_value = (
                True,
                {
                    "qwed": {
                        "result": {"status": "VERIFIED"},
                        "query_hash": "sha256:abc123",
                    }
                },
                None,
            )
            mock_get.return_value = mock_svc

            r = enforce_trust_decision(
                self.verified,
                attestation_token="QWED_TEST_WRONG_QUERY_TOKEN",
                query="some other query",
            )

        self.assertTrue(r.is_fail_closed)
        self.assertEqual(
            r.developer_fields.get("constraint_id"),
            "trust_gate.claims_query_mismatch",
        )

    def test_claims_proof_mismatch_blocks(self):
        """Token with proof_hash != result.proof_ref must be blocked."""
        with patch("src.qwed_new.core.attestation.get_attestation_service") as mock_get:
            mock_svc = MagicMock()
            mock_svc.verify_attestation.return_value = (
                True,
                {
                    "qwed": {
                        "result": {"status": "VERIFIED"},
                        "proof_hash": "sha256:wrongproof",
                    }
                },
                None,
            )
            mock_get.return_value = mock_svc

            r = enforce_trust_decision(
                self.verified,
                attestation_token="QWED_TEST_WRONG_PROOF_TOKEN",
            )

        self.assertTrue(r.is_fail_closed)
        self.assertEqual(
            r.developer_fields.get("constraint_id"),
            "trust_gate.claims_proof_mismatch",
        )

    # --- Claims binding: missing / malformed claims ---

    def test_claims_missing_qwed_blocked(self):
        """Token without qwed claims must be blocked (fail-closed)."""
        with patch("src.qwed_new.core.attestation.get_attestation_service") as mock_get:
            mock_svc = MagicMock()
            mock_svc.verify_attestation.return_value = (True, {}, None)
            mock_get.return_value = mock_svc

            r = enforce_trust_decision(
                self.verified,
                attestation_token="QWED_TEST_VALUE_NO_QWED_CLAIMS",
            )

        self.assertTrue(r.is_fail_closed)
        self.assertEqual(r.developer_fields.get("constraint_id"), "trust_gate.claims_missing")

    def test_claims_missing_result_blocked(self):
        """Token with qwed but no result must be blocked."""
        with patch("src.qwed_new.core.attestation.get_attestation_service") as mock_get:
            mock_svc = MagicMock()
            mock_svc.verify_attestation.return_value = (
                True,
                {"qwed": {"query_hash": "sha256:abc"}},
                None,
            )
            mock_get.return_value = mock_svc

            r = enforce_trust_decision(
                self.verified,
                attestation_token="QWED_TEST_VALUE_NO_RESULT_CLAIM",
            )

        self.assertTrue(r.is_fail_closed)
        self.assertEqual(r.developer_fields.get("constraint_id"), "trust_gate.claims_missing")

    def test_claims_qwed_not_dict_blocked(self):
        """Token where qwed is not a dict must be blocked."""
        with patch("src.qwed_new.core.attestation.get_attestation_service") as mock_get:
            mock_svc = MagicMock()
            mock_svc.verify_attestation.return_value = (True, {"qwed": "not_a_dict"}, None)
            mock_get.return_value = mock_svc

            r = enforce_trust_decision(
                self.verified,
                attestation_token="QWED_TEST_VALUE_QWED_NOT_DICT",
            )

        self.assertTrue(r.is_fail_closed)
        self.assertEqual(r.developer_fields.get("constraint_id"), "trust_gate.claims_missing")


if __name__ == "__main__":
    unittest.main()
