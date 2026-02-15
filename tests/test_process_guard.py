

from qwed_new.guards.process_guard import ProcessVerifier

class TestProcessVerifier:
    def setup_method(self):
        self.verifier = ProcessVerifier()

    def test_verify_irac_structure_valid(self):
        trace = """
        The Issue here is whether X breached the contract.
        The relevant Rule is Article 12.
        Applying this rule, X failed to deliver.
        The Conclusion is that X is liable.
        """
        result = self.verifier.verify_irac_structure(trace)
        assert result["verified"] is True
        assert result["score"] == 1.0
        assert len(result["missing_steps"]) == 0

    def test_verify_irac_structure_missing(self):
        trace = """
        The Issue is about breach.
        The Conclusion is X is liable.
        """
        result = self.verifier.verify_irac_structure(trace)
        assert result["verified"] is False
        assert result["score"] == 0.5  # 2 out of 4 present
        assert "rule" in result["missing_steps"]
        assert "application" in result["missing_steps"]

    def test_verify_irac_false_positives(self):
        # "tissue" should not match "issue"
        trace = """
        This is a tissue paper.
        Refer to the overruled case.
        No real study here.
        Inclusion of data.
        """
        result = self.verifier.verify_irac_structure(trace)
        # Should find NONE of the IRAC keywords
        assert result["score"] == 0.0
        assert len(result["missing_steps"]) == 4

    def test_verify_trace_milestones_valid(self):
        trace = "First we check jurisdiction, then we look at intent, and finally calculate damages."
        milestones = ["jurisdiction", "intent", "damages"]
        result = self.verifier.verify_trace(trace, milestones)
        assert result["verified"] is True
        assert result["process_rate"] == 1.0
        assert len(result["missed_milestones"]) == 0

    def test_verify_trace_milestones_partial(self):
        trace = "First we check jurisdiction."
        milestones = ["jurisdiction", "intent"]
        result = self.verifier.verify_trace(trace, milestones)
        assert result["verified"] is False
        assert result["process_rate"] == 0.5
        assert result["missed_milestones"] == ["intent"]

    def test_verify_trace_milestones_false_positives(self):
        # "flaw" should not match "law"
        trace = "There is a flaw in the argument."
        milestones = ["law"]
        result = self.verifier.verify_trace(trace, milestones)
        assert result["verified"] is False
        assert result["process_rate"] == 0.0
        assert result["missed_milestones"] == ["law"]

    def test_case_insensitivity(self):
        trace = "THE ISSUE IS KEY."
        result = self.verifier.verify_irac_structure(trace)
        assert "issue" not in result["missing_steps"]

    def test_empty_input(self):
        result = self.verifier.verify_irac_structure("")
        assert result["score"] == 0.0
        
        result = self.verifier.verify_trace("", ["check"])
        assert result["process_rate"] == 0.0
