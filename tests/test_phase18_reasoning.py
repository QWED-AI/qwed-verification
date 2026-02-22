import unittest
from qwed_sdk.guards.reasoning_guard import SelfInitiatedCoTGuard


class TestPhase18ReasoningGuard(unittest.TestCase):
    """
    Test suite for Phase 18: Cognitive Alignment & Ecosystem Update.
    Specifically tests the SelfInitiatedCoTGuard for deterministically
    verifying an LLM's self-generated reasoning plan.
    """

    def setUp(self):
        self.milestones = ["Information Formation", "Trading", "Illegal Gains"]
        self.guard = SelfInitiatedCoTGuard(self.milestones)

    def test_initialization_validation(self):
        """Guard should reject empty milestone lists or non-string elements."""
        with self.assertRaises(ValueError):
            SelfInitiatedCoTGuard([])
            
        with self.assertRaises(TypeError):
            SelfInitiatedCoTGuard(["Information", 123])

    def test_verify_autonomous_path_success(self):
        """A complete reasoning plan should be verified."""
        plan = (
            "First, I will analyze Information Formation. Then I'll check if "
            "Trading occurred. Finally, I will determine if there were Illegal Gains."
        )
        result = self.guard.verify_autonomous_path(plan)
        
        self.assertTrue(result["verified"])
        self.assertIn("irac.issue", result)
        self.assertEqual(result["irac.issue"], "REASONING_FRAMEWORK_VERIFIED")
        self.assertIn("irac.rule", result)
        self.assertIn("irac.application", result)
        self.assertIn("irac.conclusion", result)

    def test_verify_autonomous_path_missing_elements(self):
        """An incomplete reasoning plan should be blocked and flag missing elements."""
        plan = (
            "I'm going to look at the Information Formation, and see if they made "
            "any Illegal Gains based on that."
        )
        result = self.guard.verify_autonomous_path(plan)
        
        self.assertFalse(result["verified"])
        self.assertEqual(result["risk"], "INCOMPLETE_REASONING_FRAMEWORK")
        self.assertIn("Trading", result["missing_elements"])
        self.assertNotIn("Information Formation", result["missing_elements"])
        self.assertNotIn("Illegal Gains", result["missing_elements"])

    def test_verify_autonomous_path_case_insensitivity(self):
        """The verification should match milestones case-insensitively."""
        plan = (
            "Step 1: INFORMATION FORMATION. Step 2: TRADING. Step 3: ILLEGAL gains."
        )
        result = self.guard.verify_autonomous_path(plan)
        self.assertTrue(result["verified"])

    def test_verify_autonomous_path_invalid_input(self):
        """The guard should handle non-string inputs gracefully via TypeError."""
        with self.assertRaises(TypeError):
            self.guard.verify_autonomous_path({"plan": "Information Formation"})


    def test_verify_autonomous_path_rejects_partial_matches(self):
        """Milestones must be whole-word matches, not substrings."""
        plan = (
            "We examine Information Formations, Tradings patterns, "
            "and Illegal Gainss."
        )
        result = self.guard.verify_autonomous_path(plan)
        self.assertFalse(result["verified"])
        self.assertEqual(len(result["missing_elements"]), 3)

if __name__ == "__main__":
    unittest.main()
