import os
import time

import pytest

from qwed_new.guards.process_guard import ProcessVerifier


class TestProcessVerifier:
    def setup_method(self):
        self.verifier = ProcessVerifier()

    # ------------------------------------------------------------------
    # Basic IRAC structure verification
    # ------------------------------------------------------------------

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
        assert result["score"] == 0.5
        assert "rule" in result["missing_steps"]
        assert "application" in result["missing_steps"]

    def test_verify_irac_mechanism_field(self):
        result = self.verifier.verify_irac_structure("issue rule application conclusion")
        assert result["mechanism"] == "Regex Pattern Matching (Deterministic)"

    # ------------------------------------------------------------------
    # 1. IRAC regex detection edge cases
    # ------------------------------------------------------------------

    def test_irac_issue_keyword_question(self):
        result = self.verifier.verify_irac_structure("The question before us is clear.")
        assert "issue" not in result["missing_steps"]

    def test_irac_issue_keyword_problem_presented(self):
        result = self.verifier.verify_irac_structure("The problem presented is complex.")
        assert "issue" not in result["missing_steps"]

    def test_irac_rule_keyword_law(self):
        result = self.verifier.verify_irac_structure("The law is clear on this matter.")
        assert "rule" not in result["missing_steps"]

    def test_irac_rule_keyword_statute(self):
        result = self.verifier.verify_irac_structure("The statute applies here.")
        assert "rule" not in result["missing_steps"]

    def test_irac_rule_keyword_regulation(self):
        result = self.verifier.verify_irac_structure("The regulation requires compliance.")
        assert "rule" not in result["missing_steps"]

    def test_irac_rule_keyword_article_number(self):
        result = self.verifier.verify_irac_structure("See Article 5 of the treaty.")
        assert "rule" not in result["missing_steps"]

    def test_irac_rule_keyword_article_large_number(self):
        result = self.verifier.verify_irac_structure("Under Article 142 of the Constitution.")
        assert "rule" not in result["missing_steps"]

    def test_irac_application_keyword_analysis(self):
        result = self.verifier.verify_irac_structure("Our analysis shows this.")
        assert "application" not in result["missing_steps"]

    def test_irac_application_keyword_applying(self):
        result = self.verifier.verify_irac_structure("Applying the test to these facts.")
        assert "application" not in result["missing_steps"]

    def test_irac_application_keyword_in_this_case(self):
        result = self.verifier.verify_irac_structure("In this case the defendant failed.")
        assert "application" not in result["missing_steps"]

    def test_irac_conclusion_keyword_holding(self):
        result = self.verifier.verify_irac_structure("The holding of the court was clear.")
        assert "conclusion" not in result["missing_steps"]

    def test_irac_conclusion_keyword_verdict(self):
        result = self.verifier.verify_irac_structure("The verdict is guilty.")
        assert "conclusion" not in result["missing_steps"]

    def test_irac_conclusion_keyword_therefore(self):
        result = self.verifier.verify_irac_structure("Therefore the appeal is dismissed.")
        assert "conclusion" not in result["missing_steps"]

    def test_irac_all_missing(self):
        result = self.verifier.verify_irac_structure("Nothing relevant here at all.")
        assert result["verified"] is False
        assert result["score"] == 0.0
        assert len(result["missing_steps"]) == 4

    def test_irac_single_step_only(self):
        result = self.verifier.verify_irac_structure("The issue is important.")
        assert result["score"] == 0.25
        assert result["verified"] is False
        assert set(result["missing_steps"]) == {"rule", "application", "conclusion"}

    def test_irac_three_of_four(self):
        trace = "The issue is X. The rule says Y. Therefore Z."
        result = self.verifier.verify_irac_structure(trace)
        assert result["score"] == 0.75
        assert result["verified"] is False
        assert set(result["missing_steps"]) == {"application"}

    def test_irac_case_insensitive_mixed(self):
        trace = "ISSUE found. rUlE applies. APPLICATION done. CONCLUSION reached."
        result = self.verifier.verify_irac_structure(trace)
        assert result["verified"] is True
        assert result["score"] == 1.0

    def test_irac_keywords_mid_sentence(self):
        trace = "We note the issue, identify the rule, perform analysis, and reach a conclusion."
        result = self.verifier.verify_irac_structure(trace)
        assert result["verified"] is True
        assert result["score"] == 1.0

    # ------------------------------------------------------------------
    # 2. False positive avoidance
    # ------------------------------------------------------------------

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

    def test_false_positive_tissue_not_issue(self):
        result = self.verifier.verify_irac_structure("A tissue was found at the scene.")
        assert "issue" in result["missing_steps"]

    def test_false_positive_misrule_not_rule(self):
        result = self.verifier.verify_irac_structure("He wanted to misrule the kingdom.")
        assert "rule" in result["missing_steps"]

    def test_false_positive_overrule_not_rule(self):
        result = self.verifier.verify_irac_structure("The judge may overrule the objection.")
        assert "rule" in result["missing_steps"]

    def test_false_positive_exclusion_not_conclusion(self):
        result = self.verifier.verify_irac_structure("The exclusion of evidence was ordered.")
        assert "conclusion" in result["missing_steps"]

    def test_false_positive_reapplication_not_application(self):
        # In "reapplication", 'e' precedes 'a' of "application" — both word chars,
        # so \b does NOT fire. The regex correctly rejects this substring match.
        result = self.verifier.verify_irac_structure("Submit a reapplication form.")
        assert "application" in result["missing_steps"]

    def test_false_positive_bylaw_not_law(self):
        # In "bylaw", 'y' precedes 'l' of "law" — both word chars, so \b does
        # NOT fire before 'l'. The regex correctly rejects this substring match.
        result = self.verifier.verify_irac_structure("Check the bylaw provisions.")
        assert "rule" in result["missing_steps"]

    def test_false_positive_outlaw_not_law(self):
        result = self.verifier.verify_irac_structure("He was an outlaw.")
        assert "rule" in result["missing_steps"]

    def test_trace_false_positive_flaw_not_law(self):
        trace = "There is a flaw in the argument."
        milestones = ["law"]
        result = self.verifier.verify_trace(trace, milestones)
        assert result["verified"] is False
        assert result["process_rate"] == 0.0
        assert result["missed_milestones"] == ["law"]

    def test_trace_false_positive_substring_milestone(self):
        # "damages" should not match "damage" (word boundary)
        trace = "The damage was extensive."
        result = self.verifier.verify_trace(trace, ["damages"])
        assert result["verified"] is False
        assert "damages" in result["missed_milestones"]

    def test_trace_false_positive_prefix_in_word(self):
        # "intent" should not match inside "unintentional"
        trace = "It was unintentional harm."
        result = self.verifier.verify_trace(trace, ["intent"])
        assert result["verified"] is False
        assert "intent" in result["missed_milestones"]

    # ------------------------------------------------------------------
    # 3. Missing milestone detection
    # ------------------------------------------------------------------

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
        assert set(result["missed_milestones"]) == {"intent"}

    def test_trace_all_milestones_missing(self):
        trace = "This text mentions nothing relevant."
        milestones = ["jurisdiction", "liability", "damages"]
        result = self.verifier.verify_trace(trace, milestones)
        assert result["verified"] is False
        assert result["process_rate"] == 0.0
        assert set(result["missed_milestones"]) == {"jurisdiction", "liability", "damages"}

    def test_trace_single_milestone_present(self):
        trace = "We examined the jurisdiction of the court."
        milestones = ["jurisdiction"]
        result = self.verifier.verify_trace(trace, milestones)
        assert result["verified"] is True
        assert result["process_rate"] == 1.0
        assert result["missed_milestones"] == []

    def test_trace_single_milestone_absent(self):
        trace = "Nothing about courts here."
        milestones = ["jurisdiction"]
        result = self.verifier.verify_trace(trace, milestones)
        assert result["verified"] is False
        assert result["process_rate"] == 0.0
        assert set(result["missed_milestones"]) == {"jurisdiction"}

    def test_trace_milestone_case_insensitive(self):
        trace = "The JURISDICTION of the court was established."
        milestones = ["jurisdiction"]
        result = self.verifier.verify_trace(trace, milestones)
        assert result["verified"] is True
        assert result["process_rate"] == 1.0

    def test_trace_milestone_mixed_case_in_list(self):
        trace = "jurisdiction and liability were considered."
        milestones = ["JURISDICTION", "Liability"]
        result = self.verifier.verify_trace(trace, milestones)
        assert result["verified"] is True
        assert result["process_rate"] == 1.0

    def test_trace_many_milestones_partial(self):
        trace = "We reviewed jurisdiction and then examined liability."
        milestones = ["jurisdiction", "liability", "damages", "remedy", "standing"]
        result = self.verifier.verify_trace(trace, milestones)
        assert result["verified"] is False
        assert result["process_rate"] == 0.4
        assert set(result["missed_milestones"]) == {"damages", "remedy", "standing"}

    def test_trace_milestone_with_special_regex_chars(self):
        # Milestones with characters that are special in regex (dot, parens)
        trace = "See section 12.3 for details."
        milestones = ["12.3"]
        result = self.verifier.verify_trace(trace, milestones)
        # re.escape should handle the dot; "12.3" should match literally
        assert result["verified"] is True

    def test_trace_milestone_duplicate_in_list(self):
        # verify_trace does NOT deduplicate key_middle; both occurrences of
        # "jurisdiction" are found, giving 2/2 = 1.0.
        trace = "The jurisdiction is established."
        milestones = ["jurisdiction", "jurisdiction"]
        result = self.verifier.verify_trace(trace, milestones)
        assert result["verified"] is True
        assert result["process_rate"] == 1.0

    def test_trace_milestone_duplicate_mixed_found(self):
        # With duplicates, "jurisdiction" matches (twice) out of 3 entries -> 2/3.
        trace = "The jurisdiction was clear."
        milestones = ["jurisdiction", "jurisdiction", "liability"]
        result = self.verifier.verify_trace(trace, milestones)
        assert result["verified"] is False
        assert result["process_rate"] == pytest.approx(2 / 3)
        assert set(result["missed_milestones"]) == {"liability"}

    # ------------------------------------------------------------------
    # 4. Empty reasoning trace behaviour
    # ------------------------------------------------------------------

    def test_empty_irac_trace(self):
        result = self.verifier.verify_irac_structure("")
        assert result["verified"] is False
        assert result["score"] == 0.0
        assert len(result["missing_steps"]) == 4
        assert set(result["missing_steps"]) == {"issue", "rule", "application", "conclusion"}

    def test_empty_trace_with_milestones(self):
        result = self.verifier.verify_trace("", ["check"])
        assert result["verified"] is False
        assert result["process_rate"] == 0.0
        assert set(result["missed_milestones"]) == {"check"}

    def test_empty_trace_with_empty_milestones(self):
        # Empty key_middle list -> vacuously true (line 65 coverage)
        result = self.verifier.verify_trace("", [])
        assert result["verified"] is True
        assert result["process_rate"] == 1.0
        assert result["missed_milestones"] == []

    def test_nonempty_trace_with_empty_milestones(self):
        result = self.verifier.verify_trace("Some reasoning text here.", [])
        assert result["verified"] is True
        assert result["process_rate"] == 1.0
        assert result["missed_milestones"] == []

    def test_whitespace_only_irac_trace(self):
        result = self.verifier.verify_irac_structure("   \n\t\n   ")
        assert result["verified"] is False
        assert result["score"] == 0.0
        assert len(result["missing_steps"]) == 4

    def test_whitespace_only_trace_with_milestones(self):
        result = self.verifier.verify_trace("   \n\t  ", ["evidence"])
        assert result["verified"] is False
        assert result["process_rate"] == 0.0

    def test_newlines_only_irac_trace(self):
        result = self.verifier.verify_irac_structure("\n\n\n")
        assert result["verified"] is False
        assert result["score"] == 0.0

    # ------------------------------------------------------------------
    # 5. Malformed input handling
    # ------------------------------------------------------------------

    def test_irac_numeric_input(self):
        # Purely numeric text should not match any IRAC pattern
        result = self.verifier.verify_irac_structure("12345 67890 111213")
        assert result["verified"] is False
        assert result["score"] == 0.0

    def test_irac_special_characters_only(self):
        result = self.verifier.verify_irac_structure("!@#$%^&*()_+-=[]{}|;':\",./<>?")
        assert result["verified"] is False
        assert result["score"] == 0.0

    def test_irac_unicode_input(self):
        result = self.verifier.verify_irac_structure("Ley aplicable, cuestión jurídica, análisis del caso")
        assert result["verified"] is False
        # None of the English IRAC keywords should match Spanish text
        assert result["score"] == 0.0

    def test_irac_very_long_input(self):
        # Ensure no performance issues with large input
        trace = "The issue is X. " * 10000
        start = time.monotonic()
        result = self.verifier.verify_irac_structure(trace)
        elapsed = time.monotonic() - start
        perf_budget = float(os.getenv("PROCESS_GUARD_PERF_BUDGET_SEC", "5.0"))
        assert elapsed < perf_budget, (
            f"verify_irac_structure took {elapsed:.2f}s (budget: {perf_budget:.2f}s)"
        )
        assert "issue" not in result["missing_steps"]

    def test_trace_numeric_milestones(self):
        trace = "Step 1 and step 2 were completed."
        milestones = ["1", "2", "3"]
        result = self.verifier.verify_trace(trace, milestones)
        # "1" and "2" appear as word-bounded numbers
        assert result["process_rate"] == pytest.approx(2 / 3)
        assert "3" in result["missed_milestones"]

    def test_trace_special_char_milestone(self):
        # Known limitation: \b word boundaries fail for milestones starting/ending
        # with non-word chars (e.g. parentheses). The regex \b\(a\)\(1\)\b won't
        # match "(a)(1)" preceded by a space because \b needs a word-to-non-word
        # transition that doesn't exist there. This test documents current behavior.
        trace = "Use section (a)(1) for reference."
        milestones = ["(a)(1)"]
        result = self.verifier.verify_trace(trace, milestones)
        assert result["verified"] is False
        assert result["process_rate"] == 0.0

    def test_trace_multiline_input(self):
        trace = "Line one has jurisdiction.\nLine two has liability.\nLine three has damages."
        milestones = ["jurisdiction", "liability", "damages"]
        result = self.verifier.verify_trace(trace, milestones)
        assert result["verified"] is True
        assert result["process_rate"] == 1.0

    def test_irac_multiline_trace(self):
        trace = "Line 1: issue\nLine 2: rule\nLine 3: application\nLine 4: conclusion"
        result = self.verifier.verify_irac_structure(trace)
        assert result["verified"] is True
        assert result["score"] == 1.0

    def test_irac_keywords_with_punctuation(self):
        trace = "issue, rule; application: conclusion."
        result = self.verifier.verify_irac_structure(trace)
        assert result["verified"] is True
        assert result["score"] == 1.0

    def test_trace_tab_separated_content(self):
        trace = "jurisdiction\tliability\tdamages"
        milestones = ["jurisdiction", "liability", "damages"]
        result = self.verifier.verify_trace(trace, milestones)
        assert result["verified"] is True

    # ------------------------------------------------------------------
    # Case insensitivity (IRAC)
    # ------------------------------------------------------------------

    def test_case_insensitivity(self):
        trace = "THE ISSUE IS KEY."
        result = self.verifier.verify_irac_structure(trace)
        assert "issue" not in result["missing_steps"]

    def test_irac_lowercase(self):
        trace = "the issue and rule and application and conclusion"
        result = self.verifier.verify_irac_structure(trace)
        assert result["verified"] is True

    def test_irac_title_case(self):
        trace = "Issue Rule Application Conclusion"
        result = self.verifier.verify_irac_structure(trace)
        assert result["verified"] is True

    # ------------------------------------------------------------------
    # Constructor / init
    # ------------------------------------------------------------------

    def test_init_creates_four_patterns(self):
        v = ProcessVerifier()
        assert set(v.irac_patterns.keys()) == {"issue", "rule", "application", "conclusion"}

    def test_multiple_instances_independent(self):
        v1 = ProcessVerifier()
        v2 = ProcessVerifier()
        r1 = v1.verify_irac_structure("issue rule application conclusion")
        r2 = v2.verify_irac_structure("nothing here")
        assert r1["verified"] is True
        assert r2["verified"] is False
