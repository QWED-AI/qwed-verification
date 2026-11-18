"""The maths check on the NL and logic routes runs on the event loop (#645).

Its similarity layer compares the question with the system prompt, and
ratio() costs about the product of the two lengths: 15 to 30 ms on a crafted
2,000-character question. Its upper bounds are checked first, so a question
much longer or shorter than the system prompt skips it, with the same
verdict.
"""

from difflib import SequenceMatcher
from unittest.mock import patch

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from qwed_new.core.security import EnhancedSecurityGateway

# Fixed seed and no example database: the same examples on every run and in CI.
GATE = settings(max_examples=150, deadline=None, derandomize=True, database=None)
MIMIC = "Input mimics system prompt structure"


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("e" * 2000, id="one letter"),
        pytest.param("e " * 1000, id="letter and space"),
        pytest.param("12345 " * 333, id="numbers"),
    ],
)
def test_a_long_question_does_not_run_the_ratio(text):
    gateway = EnhancedSecurityGateway()
    with patch.object(SequenceMatcher, "ratio", side_effect=AssertionError("ratio ran")):
        assert gateway.detect_advanced_injection(text) == (True, None)


def test_the_system_prompt_is_still_refused():
    gateway = EnhancedSecurityGateway()
    is_safe, reason = gateway.detect_advanced_injection(gateway.system_prompt)
    assert is_safe is False
    assert reason.startswith(f"{MIMIC} (similarity: 100%)")


@st.composite
def near_the_prompt(draw):
    """The system prompt with slices cut, repeated or padded, so its length
    crosses both edges where the upper bounds stop the check."""
    text = EnhancedSecurityGateway().system_prompt
    for _ in range(draw(st.integers(min_value=0, max_value=4))):
        start = draw(st.integers(min_value=0, max_value=len(text)))
        end = draw(st.integers(min_value=start, max_value=len(text)))
        action = draw(st.sampled_from(["cut", "repeat", "pad"]))
        if action == "cut":
            text = text[:start] + text[end:]
        elif action == "repeat":
            text = text[:end] + text[start:end] + text[end:]
        else:
            filler = draw(st.sampled_from(["x", "7 ", "sum of ", "QWED "]))
            text = text[:start] + filler * draw(st.integers(min_value=1, max_value=60)) + text[start:]
    return text


@GATE
@given(near_the_prompt())
def test_the_similarity_verdict_is_the_ratio_verdict(text):
    gateway = EnhancedSecurityGateway()
    # Only text that reaches the similarity layer.
    assume(gateway.basic_gateway.detect_injection(text)[0])
    assume(len(text) <= gateway.max_input_length)
    assume(gateway._check_base64_encoding(text)[0])
    ratio = SequenceMatcher(None, text.lower(), gateway.system_prompt.lower()).ratio()
    reason = gateway.detect_advanced_injection(text)[1] or ""
    assert reason.startswith(MIMIC) is (ratio > gateway.similarity_threshold)
